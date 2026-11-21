# 应急工具链与样本快检

## R — 原文 (Reading)

> Autoruns 能遍历所有列出开机自启项可能的位置。你可以过滤掉那些你需要启动的正常项，集中看那些侵入系统的东西。

> — 《Cybersecurity Blue Team Toolkit》· Chapter 2「Troubleshooting Microsoft Windows」→「Sysinternals」

> 这里面备注了发送给请求数据包的 pid 以及 tid，这样我们就找到了恶意进程

> — 《windows应急响应手册》· 隧道事件 `0x09 隧道处置流程`

> 1 . 只需读文件，不要做修改文件操作 2 . 尽量不要用多层递归，循环。 3 . 异常处理。 4 . 输出的格式化。 5 . 脚本运行权限最好不要用root 6 . 使用系统自带的命令或者工具，兼容各Linux 发行版本。

> — 《063-日志和应急的那些事》· 编写脚本进行分析 · 注意事项

## I — 方法论骨架 (Interpretation)

这个能力解决的问题是：**方法知道了，但手上该拿什么工具、以什么顺序跑、哪些参数会让证据消失。**

工具在应急中的价值不是"功能多"，而是**每个工具对应一个不可替代的证据面**。按证据面组织，而不是按工具名组织：

| 证据面 | 工具与关键动作 | 不可替代性 |
|---|---|---|
| 自启与驻留 | Autoruns（全量导出后过滤） | 一次枚举所有自启位置 |
| 运行态进程 | Process Explorer（路径/签名/父进程/模块/VirusTotal 查询） | 进程树 + 模块级视角 |
| 文件被谁占用 | `handle.exe <文件名>` → 持有者 pid | 解决"文件正在使用/删了又出现" |
| 进程的"暂停—恢复" | PsSuspend / 资源监视器 / System Informer | 保留状态但切断行为，可逆 |
| 会话 | PsLoggedOn（读 `HKEY_USERS`） | 判断本机有谁登录 |
| 命令级审计 | `netsh trace` → `etl2pcapng` → Wireshark 包注释取 pid | 隧道/无端口语义流量的唯一落点 |
| 网络证据 | Wireshark（capture filter vs display filter） | 全量留存 + 分析期收敛 |
| 执行痕迹 | forfiles / AmcacheParser / AppCompatCacheParser / PECmd（Eric Zimmerman 工具链） | 回答"这个 exe 跑过没有" |
| 宏样本 | `oledump.py`（找 `M` 段） + VBA_Password_Bypasser | 不执行即可读完整逻辑 |
| 勒索时间线 | Everything 按后缀排序定加密起点 | 秒级定位加密开始时间 |
| 日志管道 | `netstat -ano` 查 UDP 514 占用 + 服务状态 + 测试消息 | 区分"没发/没通/没解析" |
| 批量巡检 | 自写只读脚本（六条红线） | 无 EDR 环境下的唯一规模化手段 |

五条使用纪律：

1. **便携优先、只读优先**。Sysinternals 可从 U 盘运行、不落地安装；所有工具先以只读方式跑（`handle` 查占用、`PsSuspend` 挂起、`netsh trace` 抓包），不要一上来就"清理"。
2. **两个过滤器不能混**。capture filter 在抓取阶段就丢弃未匹配的包（抓不到就是永久没有），display filter 只过滤"看到的"（原始包仍在）。应急场景默认不加 capture filter，用 display filter 收敛视野。
3. **工具也会骗你**。Autoruns 默认隐藏 Microsoft/Windows 条目，`taskschd.msc` 看不到注册表里的任务，`services.msc` 看不到 SDDL 隐藏的服务，`ps` 看到的可能不是全部进程。每个工具都要知道它的视野边界（详见 `persistence-sweep-windows`）。
4. **在副本上跑解析器**。Amcache/ShimCache/Prefetch 解析、宏提取、文件恢复，全部在镜像或副本上做；原件封存。
5. **脚本是工具，也是风险**。应急脚本跑在生产服务器上，任何写操作、深递归、未捕获异常都可能把"安全事件"变成"业务事故"。

关于第 5 点的六条红线，值得逐条对应失败模式：只读（避免改文件/误删）、少递归（避免 IO 打满与栈溢出）、异常处理（避免单个检查项报错中断整轮）、输出格式化（避免结果无法机器处理）、非 root（限制误操作半径）、用系统自带命令（避免依赖缺失与版本差异）。输出设计上，把 pid、service、源端口、目标端口、协议、user、filename 作为字段标注，便于把多个单点事件关联成溯源流。

## A1 — 应用示例 (Application Example)

### 示例 1: 从一段流量落到一个进程
- **类型与来源**: 【亲历】《windows应急响应手册》· 隧道事件 `0x09`；CU-4-05
- **问题/输入**: 主机与某个境外 IP 有异常通信，但 `netstat` 看不到对应进程（ICMP/DNS 隧道无端口语义）。
- **方法论的使用**: 从流量设备拿到对端 IP → 方案 A：Microsoft Message Analyzer 开始本地追踪，按 IP 过滤，details 面板读出 pid 与启动命令行；方案 B（无 MMA）：`netsh trace start persistent=yes capture=yes tracefile=.\icmp_capture.etl` → 复现流量 → `netsh trace stop` → `etl2pcapng.exe in.etl out.pcapng` → Wireshark 打开，按对端 IP 过滤，在 Packet comments 里读到 pid/tid → 用 pid 取进程路径与命令行。
- **结论**: 隧道程序的流量特征可随意伪装，但"必然有一个进程在与该 IP 通信"是不变量；所以定位路径是"IP → 进程"，不是"认工具特征"。
- **结果**: 原书两套方法均给出实际流程与截图，并指出 MMA 已停止开发，新系统上可能装不上，需要方案 B 兜底。

### 示例 2: 不点"启用内容"也能读完宏
- **类型与来源**: 【亲历】《018-疫情期间竟然还有这种病毒》
- **问题/输入**: 收到一个要求"启用宏"的 doc，需要判断它做什么。
- **方法论的使用**: 复制到隔离分析机；用 `oledump.py` 解析 OLE 结构，找标记为 `M`（Macro）的数据段；`oledump.py -s <段号> -v` 导出宏源码，直接读；若 VBA 工程被密码保护，用 `VBA_Password_Bypasser` 绕过伪加密（Office 对 VBA 工程只做伪加密）；需要看结构时用 OLE 结构查看器；只有在隔离环境确需动态验证时才启用宏，并按住 Shift 越过 `AutoOpen`。
- **结论**: 最安全的分析路径是"根本不给它执行机会"；沙箱只给行为摘要，静态提取给完整逻辑。
- **结果**: 原书演示了 `M` 段定位与伪加密绕过流程，并提醒文档可能携带 0day（如 CVE-2017-11882 类），静态解析更安全。

### 示例 3: 日志收不到的三步排障（合成演练）
- **类型与来源**: 【合成演练】按本卡 E 段推演；步骤与端口出自《Cybersecurity Blue Team Toolkit》· Chapter 9「SolarWinds Kiwi」
- **问题/输入**: 日志平台上某台网络设备的日志一直是空白。
- **方法论的使用**: 先在平台侧发一条测试消息，看控制台是否回显（不回显说明问题在平台自身）；再检查采集服务状态（start/stop/ping）；再 `netstat -ano` 查 UDP 514 是否被其他进程占用；结束占用进程并重启服务，确认重新绑定 514 后设备日志恢复入库。
- **结论**: 集中日志的第一层故障几乎总在链路而非规则；从最靠近平台的一端往外推，每步砍掉一半故障域。
- **结果**: 原书未给出该场景的最终结论；同时提醒 UDP 无连接、不确认送达（丢包不报错），"没收到"不等于"设备没发"。

## A2 — 触发场景 (Future Trigger) ★

### 用户会在什么情境下需要它
1. 需要在不能装 EDR/Sysmon 的客户环境里，用便携工具完成取证。
2. 怀疑文件被占用/删了又出现，需要找持有者。
3. 需要在不执行样本的前提下读懂宏/脚本逻辑。
4. 需要抓包但担心"抓漏了"，不确定该用哪个过滤器。
5. 需要写一个能在生产服务器上安全运行的批量巡检脚本。
6. 日志平台上某类设备的日志突然没有，需要排"采集链路"。

### 语言信号（出现这些就该激活）
- 中文：「用什么工具查」「Sysinternals 怎么用」「文件删不掉提示占用」「抓包太大怎么办」「宏病毒怎么分析」「写个批量巡检脚本」「syslog 收不到日志」
- English: "Sysinternals for IR", "handle.exe locked file", "capture filter vs display filter", "analyze malicious macro safely", "safe read-only triage script", "UDP 514 already in use"

### 与相邻能力的区分
- 与 `host-triage-parallel` 的区别：那张卡给"看哪五条线"，本卡给"每条线上用什么工具、什么参数、什么视野边界"。
- 与 `persistence-sweep-windows` 的区别：本卡只讲工具能力；点位级判据与处置顺序在那一张。
- 与 `log-forensics-integrity` 的区别：本卡的 syslog 排障是"日志进不进得来"，那张是"进来之后可不可信"。

## E — 可执行步骤 (Execution)

**必需输入**: 目标主机与操作系统版本、可用工具集（是否允许带 U 盘/是否可下载）、是否有管理员权限、是否允许抓包（性能影响）、样本是否已隔离。缺"是否允许装工具"必须先问，否则方案无法执行。

**交付物与完成标准**: 一份《工具执行记录》，含：工具名与版本、命令与参数、输出文件与哈希、执行时间与执行人、结论。完成标准是"每个结论都能由一条命令的输出复现"。

1. **准备工具集（只读优先）**
   - 做什么：Sysinternals Suite（Autoruns/Process Explorer/handle/PsSuspend/PsLoggedOn/PsExec）、Wireshark + etl2pcapng、Eric Zimmerman 工具链、`oledump.py` + VBA_Password_Bypasser、写保护 U 盘与独立解释器环境。
   - 完成标准：工具可运行且不依赖目标机安装。
   - 判停：若环境禁止带外部工具，退化为系统自带命令（`wmic`/`sc`/`schtasks`/`netstat`/`reg`/PowerShell）。

2. **进程与服务**
   - 做什么：Process Explorer 看进程树、路径、签名、加载模块；`handle.exe <文件>` 找占用者；`sc query` 逐服务查（捕获取"拒绝访问"）；`Get-AuthenticodeSignature` 批量校验服务二进制。
   - 完成标准：可疑进程有路径/签名/父进程；被占用文件的持有者 pid 明确。
   - 判停：命中"拒绝访问"或非白名单签名，转 `persistence-sweep-windows`。

3. **自启与会话**
   - 做什么：Autoruns 全量导出后过滤正常项（并取消隐藏 Microsoft/Windows 条目）；PsLoggedOn 确认本机会话。
   - 完成标准：剩余条目可逐条解释来源；登录用户与工单/资产归属一致。
   - 判停：Autoruns 干净不等于系统干净，必须补 `persistence-sweep-windows` 的视野外点位。

4. **抓包（需要网络证据时）**
   - 做什么：默认不加 capture filter，只按接口/网段做最小收敛；抓够时长后停止；分析期用 display filter（`ip.addr == x`、`tcp.port eq 25`）逐步收敛；记录起止时间、接口、过滤器设置。
   - 完成标准：原始包完整留存；结论可复现。
   - 判停：若磁盘不足，按时间切片落盘，不要用 capture filter 换取空间。

5. **命令级定位（隧道/瞬时连接）**
   - 做什么：`netsh trace start persistent=yes capture=yes tracefile=...` → 复现 → `netsh trace stop` → `etl2pcapng.exe` → Wireshark 按对端 IP 过滤看 Packet comments 中的 pid/tid。
   - 完成标准：拿到 pid 与可执行文件路径。
   - 判停：不知对端 IP 时先做流量分析（`traffic-hunt-c2`），不要盲抓。

6. **执行痕迹解析**
   - 做什么：按时间窗 `forfiles /m *.exe /d +YYYY/M/D /s /p c:\ /c "cmd /c echo @path @fdate @ftime"`；`AmcacheParser.exe -f ... --csv` 取路径与 SHA1；`AppCompatCacheParser.exe --csv ./` 看是否执行过；`PECmd.exe -d C:\Windows\Prefetch --csv c:\temp` 取运行次数与首末时间；补 UserAssist/RunMRU/RecentDocs/Jump Lists/SRUM。
   - 完成标准：候选文件有"是否执行过 + 何时 + 几次"的结论。
   - 判停：Server 版无 Prefetch/SRUM（原书已在 Server 2016 验证），改用 Amcache + ShimCache + 4688，不要据此断定"没运行过"。

7. **样本快检（隔离环境）**
   - 做什么：宏文档走 `oledump.py` 静态提取；勒索样本先按后缀/勒索信/邮箱三线索定家族 → 查公开解密工具 → 用 Everything 按后缀排序定加密起点 → 查加密前时间窗的创建/执行记录。
   - 完成标准：能说出"这是什么类型的样本、做了什么、有无现成解密方案"。
   - 判停：需要逆向或动态分析时，标注"超出现有能力"并移交，不要在分析机上双击。

8. **批量巡检脚本**
   - 做什么：按六条红线写（只读、少递归、异常处理、结构化输出、非 root、系统自带命令）；输出字段统一（name/level/service/user/filename/port/protocol/pid/msg）；先在同类发行版小范围试跑。
   - 完成标准：脚本在目标机跑完不改变任何文件；输出可被聚合。
   - 判停：若脚本需要写文件，写到临时目录并在记录中说明；生产服务器上现写现跑是禁止项。

9. **日志管道排障**
   - 做什么：平台侧发测试消息 → 查采集服务状态 → `netstat -ano` 查 UDP 514 占用 → 结束占用进程并重启服务 → 确认设备日志恢复。
   - 完成标准：日志恢复入库；占用进程可识别。
   - 判停：若链路通但仍无日志，转解码问题（`detection-rule-engineering` 的 1002 分支）。

## B — 边界 (Boundary) ★

### 不要用的情况
- **目标机已被 EDR 强管控**：多数工具会被拦截，需改用平台自带采集能力。
- **不允许抓包的生产核心**：抓包对性能有影响，且可能捕获敏感数据，需评估后再做。
- **样本可能携带 0day**：动态执行一律在隔离环境，静态优先。
- **需要司法级证据**：本卡工具链多为便捷工具，不满足取证规范（写保护、哈希链、见证），需专用取证设备与流程。

### 已知失败模式
- **用 capture filter 先行收窄**：抓不到即永久没有（原书明确"不抓你没指定的"）。
- **把 `.etl` 直接丢给 Wireshark**：无法解析，必须先 `etl2pcapgen` 转换。
- **在宿主机双击样本/启用宏**：分析行为本身导致失陷。
- **用 VirusTotal 0 检出当结论**：新样本常为 0 检出。
- **只跑一次 Autoruns 就结案**：视野外点位全漏。
- **`-split ' '` 切服务路径**：含空格路径被切错，误报大量正常服务。
- **用 root 跑带写操作的脚本**：误操作半径最大化。
- **脚本无异常处理**：一条命令不存在导致整轮中断。
- **MMA 在新系统上装不上**：无兜底方案时卡住（原书已提示）。
- **在 Server 版因 Prefetch 为空断定"没运行过"**：该版本默认不开启。

### 作者与时代的局限
- MMA 已停止开发，`netsh trace` 在新版本 Windows 上的行为与性能开销需实测。
- Eric Zimmerman 工具链对最新 Windows 版本的产物格式支持存在滞后（Amcache 结构多次变更）。
- 宏分析工具依赖 OLE 复合文档格式，对 OOXML + 远程模板（remote template injection）这类"文档本身无宏"的手法覆盖不足。
- 原书未涉及内存取证工具（DumpIt/FTK/Volatility）的具体使用，本卡也未展开——这是明显的缺口，需另行补齐。
- 脚本六条红线面向 Linux；Windows 侧的等价纪律（不写系统目录、不用 `-Force` 批量删、先导出再改）原书未系统化。

### 容易混淆的方法
- **"capture filter"与"display filter"**：前者丢包不可恢复，后者只影响显示。
- **"挂起"与"结束进程"**：PsSuspend 可逆，taskkill 不可逆。
- **"Autoruns 干净"与"系统干净"**：前者只覆盖其已知自启位置。
- **"静态提取"与"沙箱动态"**：前者给完整逻辑但可能漏掉运行时解混淆，后者给行为但丢失分支。
- **"工具输出"与"结论"**：工具给原始数据，结论需要交叉验证。

### 授权与合规边界
> 待补充（用户自行填写）
