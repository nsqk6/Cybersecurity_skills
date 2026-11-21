# Windows 持久化点全量排查

## R — 原文 (Reading)

> 使用RunOnceEx 进行持久化- 隐藏自Autoruns.exe
> 1.发现一种技术来执行DLL 文件，而不会在登录时被autoruns.exe 检测到。需要管理员权限，不属于userland。

> — 《ATT&CK手册》· 三 Persistence「RunOnceEx (T1137)」

> 修改计划任务文件不会影响计划任务的执行，通过计划任务程序修改计划任务的属性或者禁止计划任务再启动后，会将计划任务内容写入到计划任务文件中

> — 《windows应急响应手册》· 常规安全检查 `0x06 计划任务` · 3–5

> 通过 sc query 指定名称查找显示的是 拒绝访问 …… 这样的话，可以将注册表遍历一遍，之后获取服务名称，挨个查询，看看有没有拒绝访问的

> — 《windows应急响应手册》· 知识点附录 `0x12 服务隐藏与排查` · 5/6/10

## I — 方法论骨架 (Interpretation)

这个能力解决的问题是：**"重启之后木马又活了，但 Autoruns / 任务计划程序 / services.msc 里找不到。"**

根因是排查工具与被排查对象用了不同的"权威源"。Windows 的持久化机制有多个互不同步的存储层，任何单点工具只能看到其中一层：

| 机制 | 权威源 | 常见误判 |
|---|---|---|
| 计划任务 | 注册表 `TaskCache\Tree`（名称/SD）+ `TaskCache\Tasks\{id}`（Actions/Triggers） | 只删 `C:\Windows\System32\Tasks` 下的 XML——任务照跑照显示 |
| 服务 | `HKLM\SYSTEM\CurrentControlSet\Services` + 每服务的 `Security`（SDDL） | 用 services.msc / `Get-Service` / `wmic` 看，被 deny ACE 的服务全部不可见 |
| WMI 事件订阅 | WMI 仓库对象（`__EventFilter` / `__EventConsumer` / `__FilterToConsumerBinding`），可存在于任意命名空间 | 只查 `root\subscription` |
| CLR 劫持 | 环境变量 `COR_ENABLE_PROFILING` / `COR_PROFILER` + `CLSID\{...}\InprocServer32` | 只查启动项与服务——劫持发生在运行时，不改任何文件 |
| 账户 | SAM `Users\Names`（名字）+ `Users\<RID>`（本体）；克隆账户看 F 值 | 只用 `net user`，`$` 结尾账户不可见；删名字不删 RID |
| Autoruns 视野外 | RunOnceEx `Depend`、NTFS 备用数据流（ADS）、COM `InprocServer32`、IFEO 调试器项、MSDTC 类 DLL 加载 | "跑过 Autoruns 没发现"当结论 |

因此排查的基本形态是：**先枚举权威源，再与工具视图做差集，最后逐项验证**。差集（工具看得见 vs 权威源里有）本身就是最强的异常信号——比如注册表里有这个任务、GUI 里没有，或 `sc query` 返回"拒绝访问"。

三条纪律：

1. **enumeration over inspection（枚举优先于目视）**。不一项目视，而是把权威源整表拉出来与基线比对。人眼找异常远不如差集可靠。
2. **处置必须动权威源**。删 XML 不删注册表 = 没删；删服务不删注册表项 = 残留；删账户名不删 RID = 账户仍在（且可能仍可登录）。
3. **处置后必须复验到"重启仍不复活"**。计划任务改注册表要重启 Schedule 服务才生效（普通权限重启无效），服务删除要复验注册表，WMI 处置要按 Binding → Consumer → Filter 顺序删再重查。

还要记住一条攻击者视角的对称性：攻击者写的清理/守护脚本，就是最好的排查清单。挖矿脚本里出现"写 `authorized_keys`、`*/30` 定时拉起、`chattr +i` 锁文件、`history -c`"，说明清单要加上 SSH 公钥、定时任务、文件不可变属性、历史记录。同样，`chattr +i` 与 `history -c` 这类痕迹本身就是"这台机器被人手动操作过"的证据。

## A1 — 应用示例 (Application Example)

### 示例 1: 计划任务的对照实验
- **类型与来源**: 【亲历】《windows应急响应手册》· 小技巧 `0x10 谁决定计划任务的执行结果`
- **问题/输入**: 客户环境出现"删掉可疑任务后，重启机器任务又回来"。
- **方法论的使用**: 建两个对照任务，一个只改 XML，一个只改注册表，观察哪个生效。结果：改 XML 多次执行仍是原动作（XML 只是缓存副本）；改注册表在重启 Schedule 服务后生效；把 `Tasks\{id}` 里 Actions 的一个 `00` 去掉，任务在 GUI 中消失但**仍在执行**，重启服务后才停。
- **结论**: 执行结果由注册表决定，GUI 的"消失"不等于"停止"。
- **结果**: 原书给出完整对照结论，并给出以 SYSTEM 打开任务管理器（`PsExec64.exe -i -s taskmgr /v`）重启 Schedule 服务的做法。

### 示例 2: SDDL 隐藏服务的六种手段全失效
- **类型与来源**: 【亲历】《windows应急响应手册》· 知识点附录 `0x12`；CU-4-04
- **问题/输入**: 一台主机端口仍在监听，但找不到对应服务。
- **方法论的使用**: 用 `sc sdset` 把某服务的查询权限对 IU/SU/BA 全部 deny，然后分别用 services.msc、`sc queryex`、`Get-Service`、`wmic service`、System Informer、以及 SYSTEM 权限重试——六种方式全部看不到。改用枚举法：注册表列出全部服务名（注册表权限通常没被改），逐个 `sc query`，被隐藏的返回"拒绝访问"，这个报错就是信标；再用 `sc qc` 取二进制路径与启动类型。
- **结论**: 隐藏的是"可见性"，不是"存在性"；高权限也解决不了 deny ACE。
- **结果**: 原书以 XblGameSave 服务为样本完成验证，并指出该方法只覆盖 SDDL 权限型隐藏，内存链表摘除型需另查。

### 示例 3: 隐藏账户与克隆账户（合成演练）
- **类型与来源**: 【合成演练】按本卡 E 段推演；机制出自《windows应急响应手册》· `0x03 账号信息`
- **问题/输入**: 常规账号检查"看起来正常"，但怀疑有人加过后门账号。
- **方法论的使用**: `net user` + `net localgroup administrators` 建基线 → `lusrmgr.msc` 找 `$` 结尾账户 → `wmic useraccount get Name,Status,sid` 列全量 → 读 `SAM\SAM\Domains\Account\Users\Names` 取差集 → 导出各 `00000*` 项与 `000001F4`（Administrator）比对 F 值，相同即疑似克隆。
- **结论**: 四路交叉覆盖四种不同隐藏手法；F 值相同说明复用了同一套权限描述。
- **结果**: 原书以 `admin$` 克隆 Administrator 为例，指出某工具删除时只删了 `Names\admin$`，`Users\000003EA` 仍在——账户实际未删除。

## A2 — 触发场景 (Future Trigger) ★

### 用户会在什么情境下需要它
1. 木马清完重启又活，Autoruns / 任务计划程序 / services.msc 都"看着干净"。
2. 端口在监听但找不到服务；服务列表里有一项配置页打不开。
3. 需要给一台机器做"是否仍有驻留"的终局确认（善后阶段）。
4. 怀疑存在隐藏账号或克隆账号。
5. 需要把持久化排查做成可重复执行的清单，而不是每次凭经验翻。

### 语言信号（出现这些就该激活）
- 中文：「重启又活了」「找不到启动项」「计划任务删了还在跑」「服务列表少了一个」「有没有后门账号」「克隆账号」「Autoruns 没发现是不是就干净了」
- English: "persistence beyond autoruns", "hidden scheduled task", "service not visible in services.msc", "WMI event subscription persistence", "CLR profiling hijack", "hidden local account"

### 与相邻能力的区分
- 与 `host-triage-parallel` 的区别：那张卡是五线并行总框架，本卡只把"系统线/服务线"做到点位级深度，并补齐"权威源与工具视图不一致"这一类判据。
- 与 `ir-evidence-order` 的区别：本卡是第 7 段"常规安全检查"的具体展开，不涉及取证顺序。
- 与 `log-forensics-integrity` 的区别：本卡靠"活体枚举"发现驻留；日志侧的证据（7045 服务创建、4698 任务创建）用于确认"何时被装"，两者互补。

## E — 可执行步骤 (Execution)

**必需输入**: 管理员权限、Windows 版本、该主机的正常软件基线（没有基线时先用同版本干净机器导一份）、是否允许重启服务/重启主机。缺"正常基线"必须先问，否则无法判断"异常"。

**交付物与完成标准**: 一份《持久化点位检查表》，每行含：点位、权威源路径、检查命令、结果（通过/命中/不适用）、命中详情、处置动作、复验结果。完成标准是"全部点位有结论，且命中项在重启后不复活"。

1. **建立基线**
   - 做什么：从同版本干净机器导出计划任务、服务、账户、环境变量、CLSID 清单各一份。
   - 完成标准：五份基线文件可按名称/路径做差集。
   - 判停：无干净机器时，改用"按创建时间排序 + 按签名/发布者过滤"作为替代判据。

2. **计划任务（三处交叉）**
   - 做什么：`schtasks /query` 与 `Get-ScheduledTask` 取全量；读 `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree` 与 `Tasks\{id}` 的 Actions/Author/Triggers；比对 `C:\Windows\System32\Tasks` 下 XML 与注册表内容。用 Autoruns 复核时取消 "Hide Microsoft entries" 与 "Hide Windows entries"。
   - 完成标准：三处一致；不一致项已解释。
   - 判停：发现"注册表有、GUI 无"或"XML 有、注册表无"，直接判高度可疑，进第 8 步处置。

3. **服务（枚举 + 信标 + 签名）**
   - 做什么：`Get-ChildItem "HKLM:\SYSTEM\CurrentControlSet\Services"` 取全部服务名；逐个 `sc.exe query`，收集返回"拒绝访问"的项；`sc.exe qc` 取 ImagePath；路径含空格时按可执行文件后缀切分而非 `-split ' '`；对每个路径跑 `Get-AuthenticodeSignature`，比对发布者 CN 是否属于微软。
   - 完成标准：服务总数与基线差异可解释；"拒绝访问"项与非白名单签名项全部有结论。
   - 判停：命中即进第 8 步；若只是签名缺失但路径与厂商一致（内部自研服务），标"待确认"而非直接判恶意。

4. **WMI 事件订阅（递归全命名空间）**
   - 做什么：`Get-CimInstance -ClassName __Namespace -Namespace "root"` 列命名空间与默认清单比对；遍历各命名空间查 `meta_class = 'CommandLineEventConsumer'`、`__EventFilter`、`__EventConsumer`、`__FilterToConsumerBinding`；核对 Filter 查询语句与 Consumer 命令行。
   - 完成标准：默认的 SCM Event Log 三件套之外无残留项。
   - 判停：发现非默认订阅，记录 Binding→Consumer→Filter 的删除顺序，进第 8 步。

5. **CLR 与其他运行时劫持**
   - 做什么：检查系统/用户环境变量 `COR_ENABLE_PROFILING`、`COR_PROFILER`；`reg query HKCU\Software\Classes\CLSID\` 与 HKLM 对应位置，逐个看 `InprocServer32` 指向的 DLL；同时对 `AppInit_DLLs`、`Image File Execution Options` 调试器项、`PATH` 与 `PATHEXT` 异常做一次过。
   - 完成标准：非开发/非 APM 环境无 profiling 变量；CLSID 指向的 DLL 均在系统目录且有签名。
   - 判停：命中后清理必须"变量 + CLSID 键"成对清除，只清一半会被重新启用。

6. **Autoruns 视野外的点位**
   - 做什么：查 RunOnceEx（`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx\<编号>\Depend`）；`dir /r` 查 NTFS ADS（`文件:流`）；查 COM 劫持（重点 HKCU 侧 `InprocServer32`）；查服务型 DLL 加载与 IFEO。
   - 完成标准：每类点位有明确"无异常"结论，而不是"没查"。
   - 判停：ADS 中发现可执行体或脚本，按恶意处理（正常软件极少用 ADS 存可执行载荷）。

7. **账户（四路交叉 + F 值）**
   - 做什么：按 A1 示例 3 的四路交叉；对每个 `00000*` 项与 `000001F4` 比对 F 值。查完 SAM 后**立即还原权限**。
   - 完成标准：账户总数与基线一致；无 `$` 结尾的可登录账户；无 F 值重复项。
   - 判停：删除隐藏账户必须"删 `Names\<name>` + 删 `Users\<RID>`"两处都做，删后重启复验。

8. **处置与复验**
   - 做什么：按机制分别处置——计划任务删注册表项 + 删 XML + 重启 Schedule 服务（需 SYSTEM）；服务 `sc stop` → `sc delete` → 复核注册表；WMI 按 Binding → Consumer → Filter 删除；账户两处删；CLR 成对清。全部处置完重启主机一次。
   - 完成标准：复验命令结果与预期一致（`schtasks /query /tn` 报找不到、`sc query` 报不存在、WMI 三件套为空、账户列表与基线一致），且重启后不复活。
   - 判停：若重启后复活，说明还有未发现的拉起链，回到第 1 步重做差集，不要重复处置同一项。

## B — 边界 (Boundary) ★

### 不要用的情况
- **非 Windows 主机**：Linux 的持久化面（systemd unit、cron、`rc.local`、`authorized_keys`、`ld.so.preload`、PAM）完全不同，本卡不适用。
- **已确认是内存马/无文件载荷且未重启**：此时磁盘上的持久化点可能确实干净，本卡会给"全部通过"的假阴性；应结合内存镜像与网络侧判断。
- **只做合规基线检查**：本卡是"找人为植入"，不是"查配置是否合规"，不要混用结论。

### 已知失败模式
- **把 Autoruns 结果当唯一结论**：RunOnceEx 的 `Depend`、ADS、COM 劫持都在其视野外（《ATT&CK手册》· Persistence 章明确以此为例）。
- **只查 HKLM 不查 HKCU**：多数 COM 劫持在用户侧即可生效，不需要管理员权限。
- **删 XML 当删任务**：执行由注册表决定（《windows应急响应手册》· `0x10`）。
- **用 GUI 目视代替枚举**：SDDL deny 后六种工具全部失效（同书 `0x12`）。
- **以 SYSTEM 权限试图绕过隐藏**：deny ACE 对 SYSTEM 同样生效。
- **只看注册表有没有 `Security` 子键就定性**：多个正常服务也有 Security 项，会大面积误报。
- **查完 SAM 忘记收回权限**：留下新的权限缺口。
- **删账户只删名字**：`Users\<RID>` 残留，账户仍存在。
- **处置后不重启复验**：Schedule 服务的注册表变更在服务重启前不生效，"删了但还在跑"会被误判为清除失败或清除成功。

### 作者与时代的局限
- 手册所有实验均在 Windows Server 2016 上完成，`TaskCache` 结构、SDDL 表现、Autoruns 默认过滤在不同版本有差异。
- 未覆盖 Windows 11 / Server 2022 新增机制（如部分 AppX 与推送式服务），也未覆盖 EDR 自身被滥用为持久化通道的情况。
- WMI 部分作者自述"在新建命名空间中注册事件订阅未能成功执行"，但仍要求检查——即该点位的命中率在原书语境下未被证实。
- 未讨论域环境下的持久化（GPO、SYSVOL 脚本、AD 对象 ACL、黄金票据），这些在真实企业入侵中出现频率很高。

### 容易混淆的方法
- **"服务隐藏"与"服务删除"**：前者注册表还在、只是查不到；后者注册表也没了。处置动作不同。
- **"克隆账户"与"被盗用的合法账户"**：前者是攻击者新建的、F 值与管理员相同；后者是合法账户被使用，要看登录日志。
- **"计划任务被禁用"与"计划任务被删除"**：禁用改的是注册表里的状态位，任务仍在，可被重新启用；删除才是移除。
- **"CLR 劫持"与"服务二进制替换"**：前者不改任何文件，只改运行时去哪里加载 DLL；后者替换可执行文件，签名校验会暴露。

### 授权与合规边界
> 待补充（用户自行填写）
