# Kerberos 票据伪造与委派滥用

## R — 原文 (Reading)

> 个人简单理解为 A 机器设置基于资源的约束委派给 B（设置 msDS-AllowedToActOnBehalfOfOtherIdentity 属性），则 B 可以通过 s4u 协议申请高权限票据对 A 进行利用。

> — 《红蓝对抗之Windows内网渗透》· 5.5.2 委派

> 1、白银票据不经过 KDC，因此白银票据日志相对于黄金票据会更少，同时白银票据的日志都在目标服务器上，域控上不会有日志。

> — 《内网学习笔记合集-TeamsSix》· 白银票据

> 当存在子父域时，默认其是双向信任。可以利用 sid history 跨域提权。

> — 《红蓝对抗之Windows内网渗透》· 5.4 域信任

## I — 方法论骨架 (Interpretation)

这个能力解决的是「拿到某类 hash 之后，怎么把它变成一张能用来访问资源的票」，以及在三条路（借合法机制、伪造票、跨信任越界）之间怎么选。

三条路的分界是**控制点在哪**：

**1. 委派（借机制）。** 三型的差别在「票从谁流向谁、控制点写在哪」：

| 类型 | 机制 | 控制点 | 前提 |
|---|---|---|---|
| 非约束委派 | 服务收到用户的 TGT 并缓存 | 目标机器自身的委派标志 | 能让目标收到高权限用户的认证（配合 SpoolSample/PetitPotam 强制回连） |
| 约束委派 | 服务被授权用 S4U2Proxy 代表用户访问**指定**下游服务 | `msDS-AllowedToDelegateTo`（写在**发起方**） | 该属性已配置，且目标 SPN 在清单里 |
| RBCD（基于资源的约束委派） | 目标自己声明「谁可以代表任何人来访问我」 | `msDS-AllowedToActOnBehalfOfOtherIdentity`（写在**被访问对象**） | 对目标有 `GenericWrite`/`WriteProperty`，或用 MachineAccountQuota（普通域用户默认可加 10 个机器账号）造一个可控机器账户 |

关键洞察是 RBCD 把控制点搬到了「被访问对象」上：不需要改域权限，只要对目标有写权限就能配。所以 RBCD 的入口判断不是「我是不是域管」，而是「我对哪台机器有写权限」。

**2. 伪造票（自己签）。** 金票伪造 TGT（用 krbtgt hash 加密），权限覆盖任意服务，但使用时仍需与 DC 交互，DC 侧留痕；银票伪造 TGS（用服务账户 hash 加密），只能访问指定服务，且不经过 KDC，日志只落在目标服务器上。取舍点是「要多大权限」与「能接受哪种日志」的交换：全域 → 金票；单服务低痕迹 → 银票。

**3. 跨信任越界。** 子域 krbtgt 签发的 TGT 里可以附加额外的 SID（`/sids:` 参数）。父域信任子域签发的票，于是把父域 Enterprise Admins 的 RID（519）塞进去，就得到父域企业管理员权限——不需要攻破父域任何一台机器，只需要子域的 krbtgt hash。前提是存在子父域双向信任。

贯穿三路的操作细节：
- **注入前先 `kerberos::purge`**：内存里有旧票会导致注入失败或走到错误的票。
- **验证必须用主机名**：票据绑定服务主体名，用 IP 访问 `\\<ip>\c$` 必然拒绝访问——这是最常见的「以为票无效」误判。
- **票有有效期**（默认 10 小时）：过期需重新注入，长行动要留重注入的路径。
- **银票的「访问被拒」有两种原因**：票本身无效，或该服务账户权限不足。二者现象相同，要通过「换一个 SPN 试同一张票」来区分。

## A1 — 应用示例 (Application Example)

### 示例 1: 非约束委派 + 强制回连 → 导票 → PTT
- **类型与来源**: 【亲历】《红蓝对抗之Windows内网渗透》· 5.5.2 委派
- **问题/输入**: 域内存在配置了非约束委派的机器，需要拿到域管的 TGT。
- **方法论的使用**: 发现：`Get-NetComputer -Unconstrained` 或 BloodHound `MATCH (c:Computer {unconstraineddelegation:true})`；利用：用 `SpoolSample.exe <dc> <target>` 让 DC 向目标机器发起认证（目标是配置了非约束委派的机器，会缓存 DC 机器账户的 TGT）；`sekurlsa::tickets /export` 导出票据；`kerberos::ptt` 注入；用主机名访问 DC 的 C$ 验证。
- **结论**: 非约束委派的利用需要「能强制目标认证 + 能导票」两个条件同时成立；缺前者就只是「发现了一台配置不当的机器」。
- **结果**: 原书给出完整命令链并复现；同节列出四条发现命令（非约束、约束、RBCD 落点、MachineAccountQuota）供不同环境选路。

### 示例 2: 金票 vs 银票的日志与权限交换
- **类型与来源**: 【亲历】《内网学习笔记合集-TeamsSix》· 黄金票据 / 白银票据
- **问题/输入**: 已分别拿到 krbtgt hash 与某服务账户 hash，需要决定用哪个、怎么验证。
- **方法论的使用**: 金票：备料 krbtgt hash + 域 SID → `kerberos::purge` → `kerberos::golden /domain:.. /sid:.. /krbtgt:.. /ptt` → `dir \\<主机名>\c$` 验证；银票：备料服务账户 hash + 目标 FQDN + 服务类型（cifs/ldap）+ 域名/域 SID → `kerberos::golden ... /service:cifs /rc4:<计算机账户hash> /ptt` → 同样用主机名验证。
- **结论**: 金票权限大但 DC 侧留痕；银票只到单服务但日志只在目标服务器上。这个交换在「要隐蔽」与「要范围」之间做选择。
- **结果**: 原书分别复现金票（导出 krbtgt → 制票 → 验证 → MSF 下利用）与银票（CIFS、LDAP 两种服务），并记录两个坑：用 IP 访问必然失败；票据注入内存默认有效期 10 小时。

### 示例 3: 子域金票塞父域 SID History
- **类型与来源**: 【亲历】《红蓝对抗之Windows内网渗透》· 5.4 域信任
- **问题/输入**: 已攻下子域，需要拿父域权限。
- **方法论的使用**: 取子域 krbtgt hash（`lsadump::lsa /patch`）；取父域 SID（`Get-DomainComputer -Domain <父域>` 或查 `Enterprise Admins` 组的 objectsid）；制票时加 `/sids:<父域SID>-519`：`kerberos::golden /user:Administrator /krbtgt:<hash> /domain:<子域> /sid:<子域SID> /sids:<父域SID>-519 /ptt`；用父域资源验证（`dir \\<父域DC>\c$`）。
- **结论**: 跨域不需要攻破父域任何机器，只需要子域 krbtgt + 信任关系形态正确。
- **结果**: 原书交代复现成功获取父域权限；也明确该方法的前提是「默认双向信任」这一形态，若信任关系不是该形态则前提不成立。

## A2 — 触发场景 (Future Trigger) ★

### 用户会在什么情境下需要它
1. 拿到 krbtgt hash 或服务账户 hash，需要决定造金票还是银票。
2. 发现域内有非约束/约束委派配置，需要判断能不能利用、怎么利用。
3. 对某台机器有写权限，需要判断能否用 RBCD 打通。
4. 已拿下子域，需要判断能否越到父域。
5. 票据注入后访问被拒，需要区分「票无效」与「权限不足」。

### 语言信号（出现这些就该激活）
- 中文：「金票银票区别」「krbtgt hash 能干什么」「委派怎么打」「RBCD 利用」「跨域怎么打」「sid history 提权」「票据注入后访问被拒」
- English: "golden ticket vs silver ticket", "unconstrained delegation abuse", "RBCD attack", "child domain to forest root", "s4u2proxy", "kerberos ticket injection"

### 与相邻能力的区分
- 与 `credential-extraction` 的区别：那张卡到「拿到 hash / 拿到 krbtgt」为止，本卡从 hash 开始造票。
- 与 `lateral-execution-channels` 的区别：那张卡用口令/hash 做 NTLM 或 WinRM 认证；本卡用票据做 Kerberos 认证，绕过 NTLM 限制。
- 与 `ntlm-relay-coercion` 的区别：本卡是「伪造/借票」，中继是「借在线 NTLM 认证」；强制认证（PetitPotam）在两张卡里都出现，但用途不同（本卡用于让目标缓存 TGT）。
- 与 `endpoint-persistence` 的区别：票据是「凭据层的长期访问」，重启后内存票消失；端点持久化是「主机层的自启动」。

## E — 可执行步骤 (Execution)

**必需输入**: ①域内可读 AD 的账户（发现阶段）；②可用的 hash 材料（krbtgt / 服务账户 / 机器账户）；③域名、域 SID（金票/银票必需）；④目标 SPN 与服务类型（银票必需）。缺 ③ 时金票银票都无法生成，先去 `credential-extraction` 补。
**交付物与完成标准**: 一份「票据利用记录」：选用路径与理由、备料清单、制票命令、注入结果、验证证据（用主机名访问成功）、票据有效期与日志落点。完成标准是用主机名访问目标成功，且知道这次动作在 DC 与目标上各留了什么。

1. **先做发现，不要先造票**
   - 做什么：`Get-NetComputer -Unconstrained`、`Get-DomainComputer -TrustedToAuth -Properties DnsHostName, MSDS-AllowedToDelegateTo`、查对哪些机器有 `GenericWrite/WriteProperty`、查 `MachineAccountQuota`（`Get-DomainObject -Identity "DC=.." -Properties ms-DS-MachineAccountQuota`）。
   - 完成标准：列出「可用的委派落点 / 可写的目标 / 能否造机器账户」三类机会。
   - 判停：若三类全无且有 krbtgt hash，走第 5 步伪造票；若连 krbtgt 也没有，回 `credential-extraction`。

2. **选委派类型**
   - 做什么：有非约束 + 能强制认证 → 非约束路线；`msDS-AllowedToDelegateTo` 已配置且目标 SPN 在清单里 → 约束路线；对目标有写权限或能造机器账户 → RBCD。
   - 完成标准：一句话写清「控制点在哪、我凭什么能写」。
   - 判停：若只有「发现了一台非约束委派机器」但无法强制任何高权用户来认证，该路径不成立，转 RBCD 或伪造票。

3. **执行委派利用**
   - 做什么：非约束 → `SpoolSample.exe <dc> <target>` 强制回连 → `sekurlsa::tickets /export` → `kerberos::ptt <kirbi>`；约束/RBCD → 造机器账户（`addcomputer.py`）或用现有账户 → 写 `msDS-AllowedToActOnBehalfOfOtherIdentity` → `getST.py -spn cifs/<target> -impersonate administrator` → 导入 ccache → 访问。
   - 完成标准：拿到可用的服务票并访问成功。
   - 判停：若约束委派打到清单外的服务，必然失败——换清单内的 SPN，不要怀疑票。

4. **注入前清票**
   - 做什么：`kerberos::purge` 清掉内存里的旧票；确认当前会话没有残留的同域票。
   - 完成标准：`klist` 里只剩本次要注入的票（或为空）。
   - 判停：若不清票就注入，现象是「访问走到旧身份」，会被误判为「票没用」。

5. **伪造票（金/银）**
   - 做什么：金票需 krbtgt hash + 域 SID；银票需服务账户 hash + 目标 FQDN + 服务类型（cifs/ldap 等）+ 域名/域 SID。`kerberos::golden /domain:.. /sid:.. /krbtgt:.. /ptt`；银票加 `/service:cifs /rc4:<hash>`。
   - 完成标准：注入成功，`klist` 能看到票。
   - 判停：若目标是「只访问一个服务且要低痕迹」选银票；若需要访问多服务/多主机选金票（但要接受 DC 侧留痕）。

6. **用主机名验证（强制）**
   - 做什么：`dir \\<主机名>\c$`（**不要用 IP**）；银票场景换一个同类型 SPN 再试一次以区分「票无效」与「权限不足」。
   - 完成标准：访问成功；或明确判定失败原因。
   - 判停：若用 IP 访问被拒，先改用主机名再判断——这是误判率最高的一步。

7. **跨域（存在子父域时）**
   - 做什么：取子域 krbtgt hash；取父域 SID（含 Enterprise Admins 的 objectsid）；制票加 `/sids:<父域SID>-519`；用父域 DC 的 `c$` 验证。
   - 完成标准：能访问父域资源。
   - 判停：若信任不是双向/不是父子形态，该方法前提不成立；只有子域 SID 而未取父域 SID 会制出无效票。

8. **记录有效期与日志落点**
   - 做什么：记录票据有效期（默认 10 小时）与重注入方式；记录本次动作的日志位置（金票 → DC；银票 → 目标服务器）。
   - 完成标准：报告里能回答「这次动作在哪台机器上留了什么」。
   - 判停：若行动窗口超过票据有效期，提前准备重注入路径，不要等到掉线。

## B — 边界 (Boundary) ★

### 不要用的情况
- 环境已启用 PAC 校验强化（如 KB5020805 之后的「强制 PAC 请求校验」与 KrbtgtFullPacSignature 策略）：部分金票/银票构造会被 KDC 拒绝，需要按补丁级别重新验证。
- 目标服务强制服务端签名/通道绑定（LDAP signing + channel binding）：银票访问 LDAP 会失败。
- 只有普通域用户权限、无任何写权限也无 krbtgt：本卡三条路全部不成立，先回 `credential-extraction`。
- 需要长期隐蔽：金票使用会与 DC 交互并在 DC 留痕，银票虽只在目标留痕但权限范围窄，两者都不适合「长期潜伏」。

### 已知失败模式
- **用 IP 访问**：票据绑定服务主体名，用 IP 必然拒绝访问（多份材料都把它列为第一坑）。
- **不 `kerberos::purge` 就注入**：旧票导致注入失败或走到旧身份。
- **把「访问被拒」一律当票无效**：银票权限不足时现象相同，需要用另一个 SPN 交叉验证。
- **约束委派打到清单外服务**：`msDS-AllowedToDelegateTo` 是白名单，清单外的服务一律失败。
- **把 RBCD 当「任意机器都能打」**：没有对目标的写权限就无从下手。
- **非约束委派只想「发现」不想「强制认证」**：缺少触发源时该配置无法利用。
- **票过期未重注入**：默认 10 小时，长行动中途掉线。
- **跨域前提错**：原文只给「默认双向信任」这一前提，信任形态不同则方法不成立。
- **只拿子域 SID 制跨域票**：会制出无效票，必须同时取父域 SID。

### 作者与时代的局限
- 案例基于 2019–2021 年的 AD 环境（Server 2008R2–2016 功能级别）。当前主流环境：Windows Server 2016 之后的「PAC 请求校验」与 KB5020805 的默认强化，使金票伪造的成功条件变严；RBCD 的利用仍有效，但 `MachineAccountQuota` 在多数企业已被设为 0。
- 未讨论「无密码/云身份」环境：Entra ID 与混合加入下，Kerberos 的作用面收窄，Primary Refresh Token 成为主要凭据形态，本卡不适用。
- 未讨论 Azure AD Connect 的 MSOL_ 账户与 DCSync 权限的关联（这在混合环境中常是比 krbtgt 更现实的路径）。
- 「默认 10 小时有效期」是环境相关值（域策略可改），书中把它当固定值，实际要现场确认。

### 容易混淆的方法
- **金票 vs 银票**：前者伪造 TGT（要 krbtgt）、覆盖任意服务、DC 留痕；后者伪造 TGS（要服务账户 hash）、覆盖单服务、只在目标留痕。不是「升级关系」。
- **委派 vs 伪造**：委派是借合法机制让 KDC 签票；伪造是自己签。前者不需要 krbtgt，后者需要。
- **RBCD vs 约束委派**：控制点分别在「被访问对象」与「发起方」，发现命令与利用前提都不同。
- **票据 vs 持久化**：票据在内存里，重启即失效；把它当持久化会在重启后全部落空。

### 授权与合规边界
> 待补充（用户自行填写）
