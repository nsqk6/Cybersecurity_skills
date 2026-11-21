# 命令行取证组合

## R — 原文 (Reading)

> "This could be very helpful to identify which program has initiated a specific network connection."
>
> — 《Linux 101 Hacks》· Hack 98 Netstat Command

> "A system administrator can use this command to get some idea on what users are executing on the system."
>
> — 《Linux 101 Hacks》· Hack 95 lsof commands

> "For auditing purpose, it may be beneficial to display the timestamp along with the command"
>
> — 《Linux 101 Hacks》· Hack 50 Display TIMESTAMP in history

## I — 方法论骨架 (Interpretation)

这个能力解决的是「在一台主机上发现异常迹象后，如何用系统自带命令把网络现象落到进程实体、把进程落到文件与用户、把命令历史落到时间线」。它覆盖三类问题：这个外连是谁发起的、这个账号/进程在干什么、这些操作发生在什么时候。核心判断是：**单看网络四元组只能看到"现象"，必须增加一列 `PID/Program name` 才能过渡到"实体"；而连接表是易失数据，进程退出即消失，所以取证动作有严格的先后顺序。**

机制是三条命令互补成一条证据链。`netstat -tap` 在连接表上多出 `PID/Program name` 列，把网络事件映射回进程；只看 `-an` 全是 IP:PORT，无法归因。`lsof` 把所有"打开的文件"统一成一张表——普通文件、目录、设备、socket 都是文件，所以一条命令能回答三类问题：某用户开了什么（`-u`）、某文件被谁持有（`lsof <path>`）、某进程开了什么（`-p`）；FD 列能看到 `cwd`、`txt`（可执行体）、`mem`（加载的库）等语义。`history` 加 `HISTTIMEFORMAT` 后每条记录带绝对时间，才能与 auth/web/应用日志对齐构造时间线。三者的交叉点是 PID：netstat 给 PID，lsof 用它反查进程打开了什么，history 给这个账号执行过什么命令。

为什么要组合而不是单用一条？因为每条命令只覆盖一个维度，且各有一条致命限制：netstat 的连接表易失；lsof 裸跑输出数百行、缺乏指向性；history 是用户可控数据、且时间戳只对设置之后的记录生效。组合起来既能互相印证（同一 PID 交叉验证），又能用"不可篡改的维度"补"可篡改的维度"。读完这段的人应能在脑子里跑一遍：先抓易失连接 → 落到 PID → lsof 展开进程/文件/用户 → history 对齐时间线，并清楚每一步的证据强度。

## A1 — 应用示例 (Application Example)

### 示例 1: netstat -tap 把外连落到进程
- **类型与来源**: 【例题】《Linux 101 Hacks》Hack 98 Netstat Command
- **问题/输入**: 服务器上看到一个非常规端口的 ESTABLISHED 连接，问"是哪个程序发起的"。
- **方法论的使用**: `netstat -tap` 看 ESTABLISHED 与 LISTEN，重点看非常规端口与外部地址；记录可疑行的 `PID/Program name`（连接表是快照，进程退出即消失）；只关心监听面用 `netstat --tcp --listening --programs`；需要纯数字不做反解用 `netstat --tcp --numeric`。
- **结论**: 不带 `-p` 只能看到四元组和状态（`0.0.0.0:5666 LISTEN`），无法回答"这个外连是谁发起的"；加 `-p` 后多出 PID/Program 列，才能继续用进程路径追下去。
- **结果**: 原书示例行 `tcp 0 0 dev-db:ssh cpe-76-...:4682 ESTABLISHED 11717/sshd: ramesh`。

### 示例 2: lsof 反查文件持有人与账号行为
- **类型与来源**: 【例题】《Linux 101 Hacks》Hack 95 lsof commands
- **问题/输入**: 「文件删不掉说被占用」，或「这个账号在干什么」。
- **方法论的使用**: `lsof -u <user>` 看该账号当前进程与连接（含 ESTABLISHED 行）；`lsof /bin/vi` 反查某文件被哪些进程持有；读 FD 列判断性质（`txt` = 执行的二进制，`cwd` = 工作目录）；与 netstat 交叉验证同一 PID。
- **结论**: lsof 把普通文件、目录、设备、socket 统一成一张表，字段固定为 COMMAND/PID/USER/FD/TYPE/DEVICE/SIZE/NODE/NAME；裸跑 `lsof` 输出数百行缺乏指向性，作者自己说 "may not be very meaningful except to give you a rough idea"，`lsof | wc -l` 只能看规模、不构成证据。
- **结果**: 原书示例 `lsof -u ramesh` 显示 `sshd 7163 ramesh 3u IPv6 ... TCP dev-db:ssh->... (ESTABLISHED)`。

### 示例 3: history 打开绝对时间戳对齐时间线
- **类型与来源**: 【例题】《Linux 101 Hacks》Hack 50 Display TIMESTAMP in history
- **问题/输入**: 需要把 shell 命令历史与其他带时间的日志对齐，构造入侵时间线。
- **方法论的使用**: `export HISTTIMEFORMAT='%F %T '` → `history | more` 验证格式；写入 `/etc/profile`（全员）或 `~/.bash_profile`（个人）对新会话生效；取证时先复制 `~/.bash_history` 原件，再解析副本；与其他带时间的日志逐条对齐。
- **结论**: history 默认只有序号和命令文本，无法与其他日志对齐；但时间戳"只对设置之后新写入的记录生效"，旧条目永远补不上，所以价值在"事前统一配置"而非"事后开启"。
- **结果**: 原书示例 `1  2008-08-05 19:02:39  service network restart`。

## A2 — 触发场景 (Future Trigger) ★

### 用户会在什么情境下需要它
1. 服务器出现可疑外连或非常规监听端口，需要知道是哪个进程发起的。
2. 某个账号行为异常，或某文件"被占用删不掉"，需要展开该用户/进程打开的文件与连接。
3. 事后回溯"某段时间发生了什么"，需要把命令历史与其他日志对齐构造时间线。
4. 需要交叉验证：netstat 看到的 PID 与 lsof 看到的进程是否一致。

### 语言信号（出现这些就该激活）
- 中文：「这个外连是什么程序发起的」「服务器有异常连接」「文件删不掉说被占用」「这个账号在干什么」「对齐入侵时间线」「看下命令历史的时间」
- English: "which process owns this connection", "who holds this file open", "what users are executing on the system", "correlate shell history with logs"

### 与相邻能力的区分
- 与 `untrusted-file-inspection` 的区别：本卡用命令行工具从"连接/进程/文件表"做归因与取证，相邻卡在编辑器里安全检视单个可疑文件（只读、禁 shell、超长行、swap 残留）。发现可疑文件后要"看内容" → 相邻卡。
- 与 `text-processing-pipeline` 的区别：本卡产出"谁/何时"的归因结论，相邻卡对文本流做统计聚合；把 netstat/lsof/history 的输出做大规模统计时用相邻卡。
- 与 `permission-operations` 的区别：本卡的 lsof 可看到进程权限上下文，但"找 suid 提权面"的风险面枚举归相邻卡。

## E — 可执行步骤 (Execution)

**必需输入**: 目标主机访问方式（本机或等价 shell）；要回答的问题（外连归因 / 账号行为 / 时间线）；可疑 IP、端口、用户名或文件名中的至少一个；取证时点。缺"可疑线索"时必须先问——裸跑三条命令没有指向性。

**交付物与完成标准**: 一条"现象→进程→文件/用户→时间"的证据链，含具体 PID、程序名、用户、时间戳；完成标准是同一 PID 在 netstat 与 lsof 中交叉一致，且时间能与至少一条其他日志对齐。

1. **先抓易失连接**
   - 做什么：`netstat -tap` 看 ESTABLISHED 与 LISTEN，重点看非常规端口/外部地址；记录可疑行的 PID/Program name；只关心监听面用 `netstat --tcp --listening --programs`，纯数字用 `--numeric`。
   - 完成标准：拿到至少一个"连接四元组 → PID/程序名"的映射。
   - 判停：若连接已断、表为空，说明易失数据已丢失，转用 lsof 的进程维度或 history 时间线，不要在此反复刷新。

2. **用 lsof 展开进程实体**
   - 做什么：对上一步的 PID 做 `lsof -p <PID>`；反查占用文件用 `lsof <path>`；看账号用 `lsof -u <user>`；读 FD 列识别 `txt`/`cwd`/`mem`/socket。
   - 完成标准：能说出该进程的可执行体路径、工作目录、打开的关键文件与连接。
   - 判停：若进程已退出、lsof 无输出，回到第 1 步记录的快照信息；若目标是"某账号在干什么"而非特定 PID，直接用 `-u` 分支。

3. **交叉验证同一 PID**
   - 做什么：把 netstat 的 PID/Program 与 lsof 的 COMMAND/PID 对照；两者一致才作为归因结论。
   - 完成标准：PID 与程序名在两条命令中一致。
   - 判停：若不一致（PID 复用、命令名被替换），标注为"证据冲突"，不要强行归因，扩大到 history 与时间线再判断。

4. **对齐时间线**
   - 做什么：取证时先复制 `~/.bash_history` 原件再解析副本；若事前已配置 `HISTTIMEFORMAT`，按 `%F %T` 解析每条命令；与 auth/web/应用日志逐条对齐。
   - 完成标准：至少一条命令能与外部日志的时间戳对上，形成有序事件序列。
   - 判停：若旧记录无时间戳，明确标注"这段时间无法从 history 还原"，不要用"history 里没有"推断"没发生操作"——同书 Hack 60/64 显示 history 可被 `history -c` 清空、被 `HISTIGNORE` 忽略，是用户可控数据。

5. **保全原件与结论归档**
   - 做什么：`~/.bash_history`、`.swp`（见 `untrusted-file-inspection`）、连接表快照都先复制再分析；结论记录每条证据的来源命令与采集时点。
   - 完成标准：原件未被分析动作改写，结论可追溯采集时点。
   - 判停：若只能在原位置操作且会改写原件，先停手并记录限制。

## B — 边界 (Boundary) ★

### 不要用的情况
- 目标不是本机、无法读到进程/文件信息——netstat `-p` 与 lsof 的进程列会受限。
- 只是想看本机开放了哪些端口（常规运维巡检）——`netstat -an` 或 `ss` 即可，不必上取证组合。
- 事件发生在取证之前，易失连接已消失——只能靠 history/日志，不要假装连接表还能复原。
- 需要枚举 suid 提权面或改权限——转 `permission-operations`。

### 已知失败模式
- **只看 `-an` 无法归因**：《Linux 101 Hacks》Hack 98——全是 IP:PORT，回答不了"这个外连是谁发起的"。
- **易失数据未先抓**：同 Hack 98——看的时候连接已断，表里是空的；连接表是快照、进程退出即消失。
- **裸跑 lsof**：同书 Hack 95——输出数百行，作者说 "may not be very meaningful except to give you a rough idea"；`lsof | wc -l` 只能看规模、不构成证据。
- **事后才设 HISTTIMEFORMAT**：同书 Hack 50——旧记录仍无时间，容易误以为"这段时间没有操作"；history 是用户可控数据（同书 Hack 60 的 `history -c`、Hack 64 的 `HISTIGNORE`），不能当可靠审计源。
- **反解拖慢/误导**：netstat 不做 `--numeric` 时会做 DNS 反解，外部地址显示成域名可能掩盖真实 IP。

### 作者与时代的局限
- 示例基于 `netstat`，现代发行版已转向 `ss`（`netstat` 常被标记废弃）；原理相通但命令名与参数需替换。
- `HISTTIMEFORMAT` 依赖 bash，且只对设置后的新记录生效——这个限制是机制性的，不是配置问题。
- lsof 查看其他用户进程需要相应权限，作者一句带过，未展开权限模型。

### 容易混淆的方法
- `netstat` 从"连接"看进程，`lsof` 从"进程/文件"看打开了什么——方向相反、互为补充，不要只用一条就下结论。
- "history 里没有" ≠ "没发生"：history 可被清空/忽略/无时间戳，只能作为线索源而非审计事实。
- 本卡的 lsof 看到的是"进程打开了什么"，`permission-operations` 的 suid 枚举看到的是"哪些程序有提权面"，两者都在主机上但回答不同问题。

### 授权与合规边界
> 待补充（用户自行填写）
