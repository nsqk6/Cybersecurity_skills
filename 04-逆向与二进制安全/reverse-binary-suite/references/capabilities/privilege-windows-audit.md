# 特权边界与 Windows 对象审计

## R — 原文 (Reading)

> Make sure the code that's going to drop privileges permanently is running with an effective user ID of 0. If it's not, it probably won't be able to drop privileges effectively.
> — 《The Art of Software Security Assessment》Ch9 Auditing Privilege-Management Code

> The possible actions a process can perform on a file descriptor are determined when the file descriptor is first created.
> — 《The Art of Software Security Assessment》Ch10 File Descriptors

> an application is immune to key squatting if it checks this value
> — 《The Art of Software Security Assessment》Ch11 Key and Value Squatting

## I — 方法论骨架 (Interpretation)

这张卡处理「特权程序的权限边界是否守得住」——横跨 UNIX 降权/fd 继承与 Windows 对象命名空间/搜索顺序/ACL/RPC。共同机制是：**权限判定只在某些时刻发生一次（open/创建句柄/命名对象首次创建），之后被固化的状态或可被抢占的名字会让「后来越权」成为可能**。

UNIX 降权审计先分「永久丢弃」和「临时切换」两条路径，再按各自清单逐项验。永久路径核：EUID 是否为 0（否则 `setuid()` 无法改三个 ID）→ `setgroups()` 是否清补充组 → RGID/SGID/EGID 是否都用 `setgid(getgid())` 落非特权组 → RUID/SUID/EUID 是否都用 `setuid(getuid())` 落非特权用户 → 清组是否发生在放弃 EUID=0 之前。非 root 的 setuid/setgid 程序须改用 `setresgid()/setresuid()`。临时路径核：组与补充组一起降、组先于用户降、再次降权前恢复特权、signals/debug API/设备文件的副作用。跨平台要命的细节：`setuid(realuid)` 在多数 UNIX 实现不改 saved set-user-ID（FreeBSD/NetBSD 是主要例外），所以在 EUID 已被 `seteuid(realuid)` 降到普通用户后再调 `setuid(realuid)` 是空操作，后面任何代码执行漏洞都能用 `seteuid(0)` 把 root 拿回来——尤其是选项解析里的 early exit 最典型。

fd 泄漏是同构问题：内核只在 `open()` 时做一次访问检查，之后改权限/属主/改名/删除都不影响已有 fd；`fork()` 复制 fd、`exec()` 默认保留 fd。所以「先以 root 打开敏感文件（/dev/kmem、日志、配置）、再降权、再执行用户指定程序」等于把 root 权限打包送人。查 `fcntl(fd,F_SETFD,FD_CLOEXEC)` 是否设置、exec 前是否有「关闭所有非标准 fd」循环；库函数（libkvm）内部打开的 fd 也会泄漏。setuid shell 脚本永远别用：内核看到 shebang 启动解释器、解释器按自己规则重解析参数/环境（元字符、globbing、`BASH_ENV`、以 `()` 开头的环境变量当函数定义——sudo 曾因此可提权），这层间接调用还引入 symlink 攻击面。

Windows 侧三条主线。① 对象权限：Windows 访问判定在「打开句柄时一次性完成」，之后句柄内权限不再复核；NULL DACL 表示「无限制」（几乎永远不正确）、空 DACL 表示「谁都不许」；ACE 顺序决定求值是否提前命中 allow 跳过 deny（低层 API 手工构造 ACL 时 deny 必须全部在 allow 之前）；「创建即用」与「后开」两条路径须施加同一套 ACL。② 搜索顺序劫持：`CreateProcess(NULL,"C:\Program Files\My App\my app.exe")` 在每个空格处试断，依次试 `C:\Program.exe`、`C:\Program Files\My.exe`……；DLL 按固定目录顺序搜索（XP 前应用目录→当前目录→System32→System→Windows→PATH，XP 起 SafeDllSearchMode 把当前目录后移）。审计不是找函数而是「列出所有会被搜索的位置，逐个判断攻击者能否写」，含 `.local` 重定向、`.manifest`、`KnownDLLs` 例外、服务 ImagePath 未引号及上级目录 ACL。③ 命名空间抢占：`Create*` 系列在对象已存在时通常**打开已存在对象而非失败**且忽略本次安全属性；注册表看 `lpdwDisposition == REG_CREATED_NEW_KEY`，文件/管道看 `CREATE_NEW`，命名管道单实例看 `FILE_FLAG_FIRST_PIPE_INSTANCE`；双向审服务端（被抢占）与客户端（连到假服务），影响可能是 DoS/信息泄露/借 impersonation 提权。

RPC 审计用十条清单：先横向找同进程注册的全部接口（`RpcServerRegisterIf*` 调用点，开发者常没意识到附属接口），再纵向查认证/模拟/状态机（上下文句柄只是「服务端指针的翻译」不是不透明安全令牌），最后才落到实现层内存破坏（IDL 未用 `/robust` 编译且参数未受限时）。无源码时用三跳指针定位处理函数：`RpcServerRegisterIf` → `RPC_SERVER_INTERFACE` → `InterpreterInfo` → `MIDL_SERVER_INFO.DispatchTable`，顺带读 endpoint、回调、格式串信息——这条链数据驱动、不依赖符号，在无符号二进制里也能稳定还原暴露的过程清单。

## A1 — 应用示例 (Application Example)

### 示例 1: rsync daemon 漏 setgroups 与 Sendmail 的 saved setgid
- **类型与来源**: 【转述】《The Art of Software Security Assessment》Ch9
- **问题/输入**: setuid 程序「调了 setuid(getuid())」是否就完成了降权？
- **方法论的使用**: 按永久/临时两条路径分意图；永久路径逐项核——EUID 是否为 0、`setgroups()` 是否清补充组、RGID/SGID/EGID 与 RUID/SUID/EUID 是否全落非特权值、清组是否先于放弃 EUID=0；在函数审计日志为每个函数补记 RUID/EUID/SUID、RGID/EGID/SGID/SUPP 及是否中途改权限。
- **结论**: 只看 `setuid(getuid())` 会漏掉 setgid+setuid 双属性程序与补充组；非 root 的 setuid daemon 不能用 `setgid(getgid())`/`setuid(getuid())`，须用 `setresgid()/setresuid()`。
- **结果**: CVE-2002-0080（rsync 漏 `setgroups()`）、Sendmail 8.12.0 由 setuid root 改 setgid smssp 后未清 saved setgid（Michał Zalewski 发现）、FreeBSD-SA-01:11.inetd `seteuid()` 后 `setegid()` 失败。

### 示例 2: SCM 可预测命名管道被抢占
- **类型与来源**: 【转述】《The Art of Software Security Assessment》Ch11/Ch12
- **问题/输入**: Windows 服务创建命名管道时，低权限用户能否先占住名字？
- **方法论的使用**: 列所有可预测名字的创建调用（`CreateNamedPipe`、`RegCreateKeyEx`、`CreateMutex/Event/Mailslot`）；查是否判断创建结果（管道看 `FILE_FLAG_FIRST_PIPE_INSTANCE`、注册表看 `REG_CREATED_NEW_KEY`）；查多实例池（`PIPE_UNLIMITED_INSTANCES` + `ConnectNamedPipe` 循环可能被抢占后排队尾）；双向审服务端与客户端（客户端有无校验对端身份）。
- **结论**: 命名对象空间全局共享，「先建先得」；服务「创建」到的其实是攻击者对象，所有读写进对方容器，若再对该对象施加高权限操作即提权或凭据窃取。
- **结果**: Windows 2000 SCM 使用可预测命名管道且不检查已存在管道，攻击者可先建管道并借服务账户模拟提权（Guardent, 2000）。

## A2 — 触发场景 (Future Trigger)

### 用户会在什么情境下需要它
1. 审计一个 setuid/setgid 守护进程，确认降权是否彻底、有没有留下 saved ID 或补充组。
2. 发现特权程序打开敏感文件后会 `exec` 外部程序，需要判断 fd 是否泄漏。
3. 审计 Windows 服务的安装路径与 DLL 加载，找未引号路径/可写目录的提权点。
4. 看到 `RegCreateKeyEx`/`CreateNamedPipe` 等命名对象创建，判断是否可被抢占（squatting）。
5. 审 RPC 应用或需要在无符号二进制里找 RPC 处理函数清单。

### 语言信号（出现这些就该激活）
- 中文：「这个 setuid 程序降权了吗」「is this daemon running as root」「setuid/setgid 审计」「临时降权后忘了恢复」「fd 泄漏」「close-on-exec」「降权后还能写日志文件吗」「未加引号的服务路径」「DLL 劫持」「DLL search order」「squatting」「命名管道抢占」「NULL DACL」「ACE 顺序」「RPC 审计」「context handle 安全」「IDL robust」「没有源码怎么审 RPC」
- English: "audit privilege dropping", "saved set-user-ID", "FD_CLOEXEC inherited handle", "unquoted service path", "DLL search order hijack", "key squatting", "pipe squatting", "NULL DACL", "RPC interface enumeration", "MIDL_SERVER_INFO"

### 与相邻能力的区分
- 与 `protocol-and-race-audit` 的区别：那张卡处理 UNIX 文件系统 TOCTOU（路径被换）与网络协议/TLV 解析；本卡处理 UNIX 降权/fd 继承与 Windows 对象命名空间/搜索顺序/ACL/RPC。
- 与 `injection-filter-audit` 的区别：`system()`/`popen()` 的命令注入面在那张卡；本卡关注「setuid 脚本这层间接调用本身」与环境变量过滤，以及服务路径被搜索劫持。
- 与 `binary-analysis-toolchain` 的区别：本卡的无符号 RPC 处理函数定位是「数据驱动链还原」（给审计对象），那张卡的脱壳/断点是「执行手法」。

## E — 可执行步骤 (Execution)

**必需输入**: 源码或可反编译二进制；程序安装属性（setuid/setgid/capability/服务账户）；目标 OS 版本与平台语义（BSD vs 非 BSD、XP 前后 DLL 搜索）；可枚举目录/对象 ACL 的工具（`icacls`/`accesschk`/`sdshow`）。缺 OS 版本时须列「按哪个版本假设」。

**交付物与完成标准**: ① 降权双路径核对表（含三类 UID/四类 GID 与顺序）；② fd 生命周期清单（打开时机、CLOEXEC、exec 前关闭）；③ Windows 可写搜索位置清单（服务路径/DLL/命名空间）；④ ACL 三查结论；⑤ RPC 十条清单审计结果与三跳指针定位的接口全集。完成标准：每个访问点都能回答「此刻是什么权限」「这个名字是谁创建的」。

1. **分意图走降权双路径**
   - 做什么：读完所有退出/跳转路径判定「永久丢弃」还是「临时切换」，得到意图表；永久路径逐项核 EUID=0、`setgroups()`、三个 GID、三个 UID、清组时序；非 root setuid/setgid 改用 `setresgid()/setresuid()`；临时路径核组与补充组一起降、组先于用户降、再次降权前恢复特权、signals/debug API/设备文件副作用；在函数审计日志补记每个函数的 RUID/EUID/SUID、RGID/EGID/SGID/SUPP。
   - 完成标准：降权双路径核对表，每个资源访问点可答「此刻权限」。
   - 判停：发现「临时降权区间内调 `setuid()` 想永久降」（saved setuid 仍在）→ 标为可 `seteuid(0)` 复原的提权；BSD 系例外须单独标注；early-exit 分支导致降权时点落在临时状态 → 重点标记。

2. **审 fd 泄漏与间接执行**
   - 做什么：找所有以高权限 `open()` 的敏感对象（/dev/kmem、/dev/mem、日志、配置、数据库）；查 `FD_CLOEXEC` 是否设置；追 fd 生命周期是否在 `fork()+exec()`（含 `system()`/`popen()`）前仍未关闭；查 exec 前是否有「关闭所有非标准 fd」循环；找 setuid 位落在脚本上的资产（`find / -perm -4000` 后核文件类型）与 C 程序里 `system()/popen()/exec*lp()` 路径。
   - 完成标准：fd 清单 + 间接执行链清单。
   - 判停：库函数（libkvm）内部打开的 fd 也要算；只清 `PATH`/`LD_*` 而漏 shell 特有变量（`BASH_ENV`、`()` 函数定义）→ 判为环境过滤不全；`execvp/execlp` 触发 ENOEXEC 回退到 shell → 重点标记。

3. **审 Windows 搜索顺序劫持**
   - 做什么：搜 `CreateProcess/ShellExecute(Ex)/WinExec`，检查可执行路径是否带引号，未引号且含空格则逐个空格切分列出被尝试的候选路径，逐个查 ACL；搜 `LoadLibrary/LoadLibraryEx`/隐式导入取 DLL 名，按目标 OS 版本列搜索顺序逐位置查可写性（含 `.local`、`.manifest`、`KnownDLLs` 例外）；服务场景额外查 ImagePath 未引号、服务二进制目录及上级目录 ACL。
   - 完成标准：可写候选位置清单 + 是否构成提权的判定。
   - 判停：只查当前目录忽略「应用目录 + PATH」→ 补；忘记 `ShellExecute` 可能交给 shell 处理器 → 标注；服务场景漏上级目录可写 → 补。

4. **审 Windows 对象权限三查**
   - 做什么：列应用创建的所有命名对象（mutex/event/section/pipe/service/file mapping）及其 `SECURITY_ATTRIBUTES`；判 NULL DACL（DACL 指针为空 → 任何人可读写改属主/ACL）与空 DACL 的区别；低层 API 手工构造 ACL 时查 deny ACE 是否全部排在 allow 之前；确认权限只在 `Create*/Open*` 时判定，高权限创建低权限持有即越权；确认「创建即用」与「后开」两路径施加同一套 ACL。
   - 完成标准：ACL 三查结论 + 越权路径清单。
   - 判停：把「空 DACL」当「无限制」→ 错；只审文件 ACL 不审内核对象 → 补；高层 API（自动排序 ACE）与低层 API（手工排序）之间混用假设 → 分开分析。

5. **审命名对象抢占（squatting）**
   - 做什么：列所有可预测名字的创建调用（`RegCreateKeyEx`、`CreateNamedPipe`、`CreateFile`（管道/设备）、`CreateMutex`、`CreateEvent`、`CreateMailslot`）；查是否判断创建结果（注册表 `lpdwDisposition==REG_CREATED_NEW_KEY`、文件/管道 `CREATE_NEW`、命名管道单实例 `FILE_FLAG_FIRST_PIPE_INSTANCE`）；查多实例池；双向审服务端与客户端（客户端有无校验对端身份）；判影响是 DoS/信息泄露/借 impersonation 提权。
   - 完成标准：抢占点清单 + 影响分级。
   - 判停：认为「名字里带 GUID 就安全」→ 看是否真随机；只查服务端漏客户端 → 补；忽略「抢占成功后原服务可能静默继续运行」。

6. **审 RPC 十条清单并定位接口**
   - 做什么：查同进程注册的其他 RPC 接口（全部 `RpcServerRegisterIf*` 调用点）；查上下文句柄是否严格、私有状态能否伪造、endpoint ACL、传输安全、自定义/弱/无认证、是否用状态机制承载安全状态、模拟与凭据、共享资源竞态、实现层内存破坏（IDL 未 `/robust` 且参数未受限）；无源码时沿 `RpcServerRegisterIf` → `RPC_SERVER_INTERFACE` → `InterpreterInfo` → `MIDL_SERVER_INFO.DispatchTable` 三跳定位全部处理函数，顺带记录 endpoint/回调/格式串。
   - 完成标准：十条清单逐项结论 + 接口与处理函数全集。
   - 判停：只看「主接口」漏附属接口 → 补；把上下文句柄当不透明安全令牌 → 破之（它只是服务端指针翻译）；只审参数解析跳过认证与模拟 → 补。

## B — 边界 (Boundary)

### 不要用的情况
- UNIX 文件系统 TOCTOU / 协议解析 / TLV 长度问题，转 `protocol-and-race-audit`。
- 命令注入 payload 构造与过滤器绕过，转 `injection-filter-audit`。
- 已拿到可控 EIP 的利用开发，转 `crash-to-exploit` / `mitigation-bypass-and-rop`。
- Android 系统应用弹窗劫持（UI 层权限提升，非本卡的传统特权限定），见 `unknown-binary-triage` 的 Manifest 路径（CU-6-25）。

### 已知失败模式
- 只看 `setuid(getuid())` 就判「已降权」，漏掉 setgid+setuid 双属性程序、补充组、以及「先用 `seteuid()` 临时降、再走 `setuid()` 想永久降」的组合（Ch9）。
- 在 FreeBSD/NetBSD 上测试通过就认为全平台安全——`setuid(realuid)` 的 saved set-user-ID 语义在多数 UNIX 与 BSD 相反（Ch9）。
- 只检查 `setuid()` 是否调用，不看 fd；把 `FD_CLOEXEC` 当默认行为；忽略库函数内部打开的敏感 fd（Ch10）。
- 认为「脚本内容可控就安全」；只清 `PATH`/`LD_*` 而漏 shell 特有变量；用 `execvp/execlp` 触发 ENOEXEC 回退到 shell（Ch10 sudo 案例）。
- 把「空 DACL」当「无限制」；只审文件 ACL 不审内核对象；在高层 API 与低层 API 之间混用 ACE 排序假设（Ch11）。
- 忘记 DLL 重定向（`.local`）会改变搜索优先级；服务场景漏掉「上级目录可写」（Ch11）。
- 认为「名字里带 GUID 就安全」；只查服务端漏客户端；忽略「抢占成功后原服务可能静默继续运行」（Ch11/Ch12）。
- RPC 审计只看主接口、把上下文句柄当安全令牌、跳过认证与模拟（Ch12）。

### 作者与时代的局限
- DLL 搜索顺序的「XP 前 / XP 起 SafeDllSearchMode」区分来自 2007 年前后的 Windows；现代 Windows 的 KnownDLLs、CFG、UAC、签名要求改变了可利用性，需按目标版本重测。
- `setuid()` 的 saved ID 语义以 FreeBSD/NetBSD 为「主要例外」是当时的结论；现代发行版实现可能有差异。
- 命名对象抢占案例（SCM 管道、mailslot）针对 Windows 2000；现代系统的对象命名空间权限已有收紧。
- RPC 三跳指针布局基于 MS RPC（DCE RPC）的 `RPC_SERVER_INTERFACE`/`MIDL_SERVER_INFO` 具体结构；其他 RPC 实现需找对应的注册数据结构。

### 容易混淆的方法
- 「搜索路径里放文件」（静态搜索顺序 + ACL，DLL 劫持）与「命名空间里抢名字」（运行时先创建者胜，squatting）是两种不同的抢占面。
- 「对象权限模型怎么审」（ACL 三查）与「创建语义」（是否先建先得）是同一对象的两层，前者看 DACL/ACE，后者看 `lpdwDisposition`/`CREATE_NEW`。
- 「fd 被继承」（对象没换但权限被继承）与「路径被换」（检查与使用不原子，属 `protocol-and-race-audit`）方向相反。
- 「永久 vs 临时降权」是程序意图的两条路径；把两者混在一个变量状态里正是 saved setuid 提权的根因。

### 授权与合规边界
> 待补充（用户自行填写）
