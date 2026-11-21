# 凭据取用：从配置、内存到目录复制

## R — 原文 (Reading)

> SYSVOL 在所有经过身份验证的域用户或者域信任用户具有读权限的活动目录域范围内共享……该密码使用 AES-256 算法，但 2012 年微软公布了该密码的私钥，也就是说任何人都可以对其进行解密。

> — 《内网学习笔记合集-TeamsSix》· GPP / SYSVOL

> 上述中的 response 就可以理解为 net-ntlmhash，因此 ntlmhash 我们是可以拿来 hash 传递的，而 net-ntlmhash 不可以，但是 net-ntlmhash 也可以拿来做破解和 relay。

> — 《红蓝对抗之Windows内网渗透》· 4.1 ntlmhash 和 net-ntlmhash

> "This is the idea of exploiting or compromising a system by using the system design, functions, and configuration against itself."

> — 《Red Team Development and Operations》· Engagement Execution: Exploitation without Exploits

## I — 方法论骨架 (Interpretation)

这个能力解决的是「拿到一台机器后，怎么把凭据从『存在但看不见』变成『可复用的认证材料』」，以及一个更重要的判断：**我拿到的这个值，到底能用来干什么**。

先讲取材，按「成本从低到高、痕迹从小到大」排七层：

1. **配置层（不提权、零工具）**。SYSVOL 对全体域用户可读，管理员用组策略首选项批量下发本地管理员密码时，密码以 `cpassword` 写进 XML，而加密密钥由微软公开 → 等价明文。同一个逻辑下，web 目录的 `conn.asp` / `web.config` / `.env`、FTP 客户端保存的站点口令（常以可逆方式存储，星号查看器直接读出）、Xshell/MobaXterm 会话、Navicat 连接串、`.git` 里的历史配置，都是「运维工作的产物」——不需要破解，只需要知道去翻哪里。
2. **用户态加密层（DPAPI）**。Chrome/IE/Outlook/凭据管理器的密文都由 DPAPI 加密，密钥由用户主密钥派生，主密钥又由用户密码或 hash 保护。所以只要拿到该用户上下文（登录会话/明文/hash）或域备份密钥，就能**一次**解开所有软件的密文——把「逐个软件逆向」降级成「一次解密」。
3. **进程内存层（lsass）**。这里要先分清「为什么抓不到」：明文是否存在内存里由**认证包行为**决定，不由工具决定。三个变量：WDigest 的 `UseLogonCredential` 是否被置 0（2012R2+ 默认已集成 KB2871997）、KB2871997 是否移除了其它 SSP 的明文缓存、账户是否启用 Reversible Encryption。改了注册表但没触发重新登录，内存里仍是旧状态——这是最常见的误判。
4. **拦截层绕过**。抓不到 lsass 有三种不同原因，对应三条不同的路：**工具被杀** → 换微软签名的 procdump 或 ps1 版 mimikatz；**lsass 有 PPL 保护** → PPLdump 或 mimidriver 先去保护再 dump；**不想落工具** → RPC 加载 SSP、`misc::memssp`、或让 lsass 自己 dump。选择依据是「哪一层被拦」，不是「哪个工具更强」。
5. **目录复制层（DCSync）**。ntds.dit 被 AD 独占锁定，想拿它必须制造副本（VSS/ntdsutil），会在 DC 上创建快照、产生大量磁盘与日志动作。DCSync 不碰文件，它伪装成一台 DC 走 DRS 复制协议把账户拉过来，只产生目录复制审计。取舍点是**权限门槛**：有 Replicating Directory Changes 就走 DCSync（低噪声）；只有 DC 本地管理员而没有复制权限，才退到 VSS。
6. **人的路径**。域控本身往往打不动，但「人」是薄弱环节：域账号大量复用外部泄露/历史库的口令；而域用户的个人办公机里又存着它登录其它机器的 RDP 凭据（DPAPI 加密，可解密）。于是有一条不依赖漏洞的链：Kerberos 预认证枚举合法用户名（不需要密码、不触发登录失败计数）→ 撞已知口令库 → 用该身份找它的个人机（主机名常等于用户名）→ 登进去取 RDP 凭据 → 凭据里的账号往往就是域管。
7. **不用漏洞的层**。大量真实入侵不依赖代码漏洞，而依赖「功能被按非预期方式使用」：配置错误的网络规则、明文存放的凭据、宽松的内部互信。这类路径的额外价值是痕迹更小——「attacking a system without exploits looks very similar to the same activity performed by a network administrator」。

再讲**形态判定**，这是本卡最容易被跳过却最容易出错的一步：

- **NTLM hash**（SAM/NTDS/lsass 导出，32 hex，静态、与密码一一对应）→ 可直接作为认证材料提交，支持 P2H（Pass-the-Hash），也能做 RC4 的 kirbi。
- **Net-NTLM（response）**（网络侧抓包，会话相关）→ 不能重放成登录，但可以离线爆破（hashcat `-m 5500/5600`）或中继给第三方。
- **明文** → 一切可用，但要先验证复用范围。

判错形态的代价是双倍浪费：拿 response 去 P2H 必然失败，拿静态 hash 去等爆破而浪费窗口。

## A1 — 应用示例 (Application Example)

### 示例 1: 一个 root 口令滚出 61 台 Linux + 7 台 Windows
- **类型与来源**: 【亲历】163 酒仙桥六号部队《蝴蝶效应翻起的内网漫游巨浪》
- **问题/输入**: 通过 Web 入口拿到一台 Linux 主机的 root 权限。
- **方法论的使用**: 在入口机抓明文（配置文件、history、SSH 相关文件）→ 用该凭据对同网段跑 SMB/RDP/SSH/1433 的低线程撞库 → 每进一台新机立即重复取材，把新凭据并进字典 → 遇到不同系统（Linux / Windows 2003）换对应抓取方式（wce、strace 抓 ssh、星号密码查看器）。全程避免高线程（同一批文章里另一次因为「多按了几次回车，连接次数过多，IP 被锁定」直接断掉整条路）。
- **结论**: 凭据是复利资产，攻击面从「漏洞」转移到「凭据图」，速度取决于撞库速率而非漏洞挖掘能力。
- **结果**: 原书交代拿到 61 台 Linux 的 root 与 7 台 Windows 的 administrator 权限，作者原话「一个密码几乎打下这个网段的机器」。

### 示例 2: 从 8uFTP 到 conn.asp 到 sshd 内存的四跳取材
- **类型与来源**: 【亲历】163 酒仙桥六号部队《从 Java RMI 反序列化到内网沦陷》
- **问题/输入**: 通过 Java RMI 反序列化拿到第一台 Windows 主机。
- **方法论的使用**: ① 在 A 机发现 8uFTP，直接连进去后用星号密码查看器读出主站口令 B；② 在主站 web 目录翻 `conn.asp` 得到 sa 口令 C，用 sqlserver `exec` 反弹；③ 在 Linux 上用 `strace -xx -fp $(cat /var/run/sshd.pid)` 挂住 sshd，另一个终端触发一次登录，抓到明文口令 D（作者先试过直接破 Xshell 配置「其实是没破出来」，才换 strace）；④ 在 2003 机器上发现前人留下的后门，再得口令 E。
- **结论**: 运维工具本身就是凭据仓库，且凭据分散在多个位置——只翻一个位置就放弃是主要的效率损失。
- **结果**: 原书交代五组口令最终滚到 80+ 台主机。

### 示例 3: DCSync 与卷影拷贝的取舍
- **类型与来源**: 【例题】《渗透测试实战（第三版·红队版）》第 9 章 90 码线；【亲历】《内网学习笔记合集-TeamsSix》卷影拷贝章节
- **问题/输入**: 已拿到域管级权限，需要域内全部账户 hash（含 krbtgt）。
- **方法论的使用**: 先测当前身份能否 DCSync（`lsadump::dcsync /domain:x /user:krbtgt` 或 secretsdump 试拉）；能则只拉需要的账户以降低流量与日志量；不能（只有 DC 本地管理员、无复制权限）才退到 `vssadmin create shadow` 或 `ntdsutil "ac i ntds" "ifm" "create full c:\temp"`，拷出 `ntds.dit` + `reg save hklm\system`，离线解析后删快照。
- **结论**: 取舍轴是权限门槛与噪声，不是「哪个更彻底」；「删快照 ≠ 无痕」，VSS 在 DC 上留下的快照记录与事件日志本身就是证据。
- **结果**: CSK 案例选择了 DCSync 而非 VSS；TeamsSix 完整复现了 ntdsutil/vssadmin 两条路径，并指出 dcsync 抓 krbtgt 是各类检测规则的头号目标。

## A2 — 触发场景 (Future Trigger) ★

### 用户会在什么情境下需要它
1. 拿到一台主机，需要判断「先抓什么、抓得到什么」。
2. mimikatz 抓不到明文，需要判断是配置问题、PPL 保护还是工具被杀。
3. 手上有一个 hash，需要判断它能 P2H、能爆破，还是只能中继。
4. 已拿到域管级权限，需要在 DCSync 与卷影拷贝之间选。
5. 想找「不用漏洞」的路径（明文凭据、宽松互信、配置错误）。

### 语言信号（出现这些就该激活）
- 中文：「mimikatz 抓不到明文」「wdigest 怎么开」「lsass 被保护」「PPL dump」「SYSVOL 里有什么」「GPP 密码怎么解」「浏览器保存的密码怎么导」「导出 ntds.dit」「dcsync 还是卷影」「这个 hash 能 PTH 吗」「翻配置文件找密码」
- English: "why no cleartext password", "dump lsass blocked", "cpassword decrypt", "decrypt chrome passwords offline", "dump all domain hashes", "which hash type can pass-the-hash", "credentials in ftp client"

### 与相邻能力的区分
- 与 `domain-recon-path` 的区别：那张卡回答「去哪台机器取、值不值得去」，本卡回答「取什么、怎么取出来、取到的值能干什么」。
- 与 `password-attack-reuse` 的区别：本卡产出「认证材料」（hash/明文/票据材料），复用与喷洒的节奏与锁定控制在那张卡。
- 与 `ntlm-relay-coercion` 的区别：中继拿到的 Net-NTLM **不能** P2H（见本卡形态判定），所以中继是独立能力；本卡只说明「为什么它进不了 P2H 队列」。
- 与 `kerberos-ticket-abuse` 的区别：本卡到「拿到 krbtgt / 服务账户 hash」为止，制票与委派利用在那张卡。

## E — 可执行步骤 (Execution)

**必需输入**: ①一个已控主机与当前权限级别；②objective（要域管 / 要某个业务系统 / 要数据）；③已知的域信息（域名、DC，若没有先走 `domain-recon-path`）。缺 ② 必须先问——目标决定取材深度，只要一个业务系统时不该碰 DCSync。
**交付物与完成标准**: 一份「凭据台账」：每条含来源位置、形态（明文/NTLM/Net-NTLM/票据材料）、所属账户与权限、已验证可访问的目标、获取时间。完成标准是台账里没有「形态未标注」的条目，且每条都写了「验证过能登录什么」。

1. **先翻配置层（不提权、零工具）**
   - 做什么：`findstr /S /I cpassword \\<FQDN>\sysvol\<FQDN>\policies\*.xml`；翻 web 目录的 `conn.asp`/`web.config`/`.env`/`config.php`；翻 FTP 客户端（8uFTP/FileZilla）、Xshell/MobaXterm、Navicat、浏览器保存的密码；**同时**看基础设施配置文件里的连接串。
   - 完成标准：得到至少一组明文账号口令，或明确写下「配置层无可取凭据」。
   - 判停：若 SYSVOL 搜索无结果，注意前提是「配置组策略时填入过密码」，否则 XML 里根本没有 cpassword——不要在这里反复尝试，转第 2 步。

2. **判断是否需要用户上下文（DPAPI）**
   - 做什么：确认目标数据是否属 DPAPI 范围（浏览器密码、凭据管理器、Outlook）；确认能否拿到该用户上下文（已在其会话中 / 有明文 / 有 NTLM hash / 有域备份密钥）。
   - 完成标准：四者至少有一个；否则先解决上下文（提权到该用户或 SYSTEM）。
   - 判停：若用户改过密码且只有新 hash，旧主密钥解不开——需要旧 hash；跨机器拷 profile 时 SID 不匹配也解不开，直接放弃这条路。

3. **抓内存前先判「有没有明文」**
   - 做什么：看系统版本与补丁（2012R2+ 默认集成 KB2871997）；查 `HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest\UseLogonCredential`；需要时置 1 并**触发重新登录**（锁屏/注销/重启）再 dump。
   - 完成标准：知道「明文应该存在 / 不应该存在」的判断，而不是靠反复 dump 试。
   - 判停：若置 1 并重新登录后仍无明文，退回 hash + P2H/P2T 路线，不再纠缠明文（继续反复 dump 只会拉高 EDR 告警）。

4. **定位 lsass 的拦截层，选对应路径**
   - 做什么：区分「杀软报毒（工具层）/ 访问被拒（PPL 层）/ 无法上传（落地层）」；工具层换 procdump（`-accepteula -ma lsass.exe lsass.dmp`）或 ps1 版；PPL 层用 PPLdump 或 mimidriver `!processprotect /process:lsass.exe /remove`；落地层走 RPC 加载 SSP / `misc::memssp`。
   - 完成标准：拿到 dump 文件或 `kiwissp.log` 一类落盘产物；离线用 `sekurlsa::minidump` + `sekurlsa::logonPasswords` 解析成功。
   - 判停：若加载驱动被拦（会留下服务/驱动痕迹），停止并转「不落工具」路线；dump 文件体积大，外带前先评估流量侧暴露。

5. **标注每个值的形态**
   - 做什么：按来源判形态——SAM/NTDS/lsass 导出 = NTLM hash（32 hex）→ 可 P2H、可做 RC4 kirbi；Responder 抓包 = Net-NTLMv1/v2 → 只能爆破（`-m 5500/5600`）或中继。
   - 完成标准：台账每条都有形态字段；Net-NTLM 的条目不再出现在 P2H 候选里。
   - 判停：若把 Net-NTLM 拿去 P2H，立即停下——失败原因不是工具，是形态错。

6. **选域级取材路径（DCSync vs VSS）**
   - 做什么：先测复制权限；能 DCSync 就只拉需要的账户（`/user:` 指定）；不能才建快照/`ntdsutil ifm` 拷 `ntds.dit` + `reg save hklm\system`，离线解析后删快照。
   - 完成标准：拿到目标账户 hash；记录了本次动作在 DC 上留下的审计类型（目录复制审计 / 快照创建 + 事件日志）。
   - 判停：若只为拿一两个业务账户，不要拉全量——全量 dcsync 是检测规则的头号目标。

7. **走「人」的路径（域控打不动时）**
   - 做什么：`nmap -p 88 --script krb5-enum-users` + 字典枚举合法用户名（不触发失败计数）；与已有口令库碰撞；查 `net group "domain computers" /domain` 找与用户名同名的主机（个人办公机）；低风险时段登录后 `cmdkey /list` + 看 `%userprofile%\AppData\Local\Microsoft\Credentials\*`；提权到 SYSTEM 后 `dpapi::cred` + `sekurlsa::dpapi` 解明文。
   - 完成标准：得到域管账号口令，或其可访问的主机清单。
   - 判停：若 DPAPI 解密在普通用户权限下失败，先提权到 SYSTEM；跳过「找个人机」直接打服务器通常拿不到 RDP 凭据。

8. **验证复用并回绑 objective**
   - 做什么：每组新凭据只在小范围验证（避免锁定），按「能打开哪台此前进不去的主机」记录价值；达到 objective 即停。
   - 完成标准：台账里每组凭据都有「已验证可访问目标」。
   - 判停：若新增可访问主机数趋零，取材收敛，转 `lateral-execution-channels` 或 `password-attack-reuse`。

## B — 边界 (Boundary) ★

### 不要用的情况
- 目标部署了 Credential Guard / LSA 保护（RunAsPPL + Credential Guard）：lsass 里的派生凭据被虚拟化隔离，dump 出来拿不到可用材料，第 3–4 步整段失效。
- 环境强制禁用 NTLM：P2H 全面失效，只剩 Kerberos 路线（转 `kerberos-ticket-abuse`）。
- 只需要一个业务系统的访问权：此时应找该系统的应用层凭据（配置文件、会话），做域级取材属过度动作，噪声与收益不匹配。
- 目标是「测量检测能力」：DCSync 抓 krbtgt、VSS 建快照都是高置信告警，会立刻结束演练窗口，除非这就是要测的点。

### 已知失败模式
- **改了 WDigest 不重新登录**：内存里仍是旧状态，误判「改了也没用」（《红蓝对抗之Windows内网渗透》4.2 明确要求锁屏/注销/重启）。
- **在 2012R2 上期待多 SSP 明文**：作者实测「只有 wdigest 能抓到明文」，其它 SSP 的明文缓存已被 KB2871997 移除。
- **把工具层问题当权限问题**：工具被杀与 PPL 保护是两种不同的拦截，换错方向会浪费大量时间。
- **签名 ≠ 免检**：procdump 虽是微软签名，仍是 EDR 重点监控行为。
- **把 dcsync 当「无日志」**：目录复制有审计；抓 krbtgt 尤其显眼。
- **「删快照 ≠ 无痕」**：VSS 在 DC 上留下的快照记录与事件日志本身就是证据。
- **形态判错**：拿 Net-NTLM 去 P2H 必然失败；把静态 hash 丢进爆破队列是浪费窗口。
- **SYSVOL 空手而归**：管理员配置组策略时没填密码，XML 里就没有 cpassword。
- **解出的密码已被轮换**：盲目大面积尝试会触发锁定，必须小范围先验证。
- **DPAPI 跨机解不开**：SID 不匹配；只拿到文件没有密钥等于拿到密文。
- **只翻一个位置就放弃**：146 的凭据分散在 FTP 客户端、web 配置、sshd 内存、前人后门四处，任何一处单独都不足以走完全程。

### 作者与时代的局限
- 案例环境以 Windows Server 2008R2/2012R2/2016 为主。Win10/11 22H2 之后默认开启 LSA 保护（RunAsPPL）成为常态，第 4 步的 PPL 绕过需要内核级手段，成功率与稳定性显著下降，且蓝队对该行为的检测已成熟。
- 书中未覆盖 Windows Hello for Business / 无密码（FIDO2）环境：用户不再有可抓的口令 hash，DPAPI 主密钥的派生链被 TPM 保护，整条「抓 hash 复用」的路径在该环境下退化。
- `misc::memssp`、RPC 加载 SSP 这类「不落工具」手法依赖特定 Windows 版本的行为，新版对 SSP 加载有更严的签名与路径校验。
- 3-11 的「主机名等于用户名」在规范化命名（资产编号命名）的企业里不成立，该跳的可靠性依赖命名习惯这一未被点明的前提。
- 书中对「抓取行为本身被 EDR 记录」的讨论很少：现实里 procdump 打开 lsass 的句柄、驱动加载、`sekurlsa` 的内存读模式都是高置信行为特征，噪声评估要按当前 EDR 能力重做。

### 容易混淆的方法
- **DPAPI vs lsass**：前者解**磁盘上**的加密数据（浏览器密码、凭据管理器），后者解**内存里**的登录凭据。两者常被笼统称「抓密码」，但前提、权限、产物完全不同。
- **配置层明文 vs 抓取**：前者不提权、不落工具，只是「知道去哪翻」；把它当成需要提权的动作会白白提高噪声。
- **DCSync vs VSS**：前者走协议、只留复制审计；后者造副本、留快照与磁盘动作。不是「强弱」差别，是「权限门槛」差别。
- **P2H vs 中继**：P2H 用已知静态 hash 直接认证；中继不需要知道 hash，只借用在线认证过程。
- **PPL 绕过 vs 免杀**：前者绕的是「能不能读到 lsass」，后者绕的是「文件像不像恶意」，两条路互不替代。

### 授权与合规边界
> 待补充（用户自行填写）
