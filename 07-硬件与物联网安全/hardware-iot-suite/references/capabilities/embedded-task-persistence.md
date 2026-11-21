# 嵌入式任务持久化：MCU 固件与 cron

## R — 原文 (Reading)

> "You can compose a set of instructions on a remote device, and then upload that script to the Arduino, where the script is stored in flash memory. Immediately, the Arduino begins executing what's in the script... Even if you press the hardware button to reset the Arduino, the currently loaded sketch continues to play."
>
> — 《Hacking Raspberry Pi》Chapter 19, Understanding the Arduino Development Workflow

> "To create a repeating operating system-level job that snaps a picture every minute, turn to Bash shell scripting and the age-old Linux command cron." / "*/1 * * * * /home/pi/camscript.sh"
>
> — 《Hacking Raspberry Pi》Chapter 16, Task: Setting Up a Time-Lapse Webcam

## I — 方法论骨架 (Interpretation)

这个能力解决的是"让一段逻辑在无人值守设备上持续、自动地跑下去"，并把两条技术路线——MCU 闪存固件与带 OS 设备上的 cron 定时任务——放在同一个决策框架里选择和执行。把两者放在一起，是因为它们回答的是同一个需求的两种答案："断电重启后还要继续干活，该用哪种？"答案的分界线是：**任务是否只需单一闭环动作、是否需要 OS**。

核心机制分两层：

第一层是 MCU 固件驻留。去掉操作系统反而得到最强的驻留性：固件（sketch）写入闪存后上电即执行、复位不丢失、无文件系统可损坏、无登录可撤销、耗电极低。代价是没有通用工具链与网络栈，只能做单一动作。适用于"只需要在无人值守时持续做一件事"（周期采样、串口桥、状态保持），而不是需要交互的场合。这也是判断"该用 SBC 还是该用 MCU"的分界线：需要 OS 才用 SBC。执行上要在宿主写 sketch 并选对板型/串口上传，断电重启验证自动恢复。

第二层是 cron 周期固化。无人值守设备的"持续行为"通常由两层构成：一个幂等的小脚本（做一件事）+ 一个调度器（保证它反复发生）。把逻辑写进脚本而不是交互式命令，才能在无人登录时也运行；交给 cron 则在系统层触发，不依赖图形会话。脚本内用时间戳命名输出，避免覆盖，也天然形成时间线证据。执行上要注意 cron 的工作目录与交互式不同、脚本无执行权限会静默失败、以及书中"六字段含 Year"口径与主流五字段 cron 不符——照抄含年份的表达式会不生效。

为什么把两者放一起：因为它们代表"持久化"的两种根本不同的Mechanism——固件驻留是"逻辑本身就是设备"（无 OS、无文件系统、无登录），cron 是"OS 之上调度脚本"。选错路线的代价很大：让需要网络/多任务的需求跑在 MCU 上会直接不可行；让只需单一动作的需求跑在 SBC+cron 上则增加不必要的复杂度和故障面（OS 可能损坏、服务可能被关）。把选择判据和执行步骤写在一个能力里，让读者先判"要不要 OS"再动手。

## A1 — 应用示例 (Application Example)

### 示例 1: Arduino sketch 存闪存、复位继续运行

- **类型与来源**: 【转述】《Hacking Raspberry Pi》Chapter 19, Understanding the Arduino Development Workflow
- **问题/输入**: 作者要说明为什么 Arduino 适合无人值守持续做一件事。
- **方法论的使用**: 按 E 段第 1 步判定任务只需单一闭环动作、无需 OS → 选 MCU；在有 OS 的宿主上写 sketch，`Tools > Board`、`Tools > Serial Port` 选对设备节点上传；断电重启验证无需人工干预即运行；需要修改时重新上传覆盖。
- **结论**: 去掉 OS 得到最强驻留性——上电即执行、复位不丢、无文件系统可坏、无登录可撤销、耗电极低；作者称 Arduino 为"dumb terminal"。
- **结果**: 作者强调脚本存 flash、复位后继续、"理论上永远"运行。

### 示例 2: cron 每分钟抓拍并归档

- **类型与来源**: 【亲历】《Hacking Raspberry Pi》Chapter 16, Task: Setting Up a Time-Lapse Webcam
- **问题/输入**: 作者要用 Pi Camera 做延时摄影，需要每分钟自动拍一张并归档。
- **方法论的使用**: 按 E 段第 3 步：写 `camscript.sh` 并 `sudo chmod +x`；脚本内先取时间戳变量再调用采集命令，归档到固定目录，每次产生唯一文件名；`crontab -e` 添加 `*/1 * * * * /home/pi/camscript.sh`；等一个周期检查输出目录文件按周期增长；并留出"再加一行做上传"的扩展点。
- **结论**: 幂等脚本 + 系统级调度器 = 无人登录也持续运行；时间戳命名天然形成时间线证据。
- **结果**: 作者用该组合实现每分钟抓拍并复制到指定目录。

### 示例 3: 【合成演练】cron 表达式照抄书中六字段导致不生效

- **类型与来源**: 【合成演练】按本卡 E 段"已知失败模式"推演，非原书案例
- **问题/输入**: 读者照书中"六字段（含 Year，1900-3000）"的口径写了含年份的 cron 表达式，任务未触发。
- **方法论的使用**: 按 E 段第 3 步的判停条件，主流 cron 实现为五字段、无年份字段；以目标发行版的 `man 5 crontab` 为准改写为五字段；同时确认脚本用绝对路径（cron 工作目录不同）、有可执行权限。
- **结论**: 书中 cron 字段口径与主流实现不符，照抄会静默失败；须以目标的 man 手册为准。
- **结果**: 这是按规则推演的失败与纠正路径，不代表任何真实现场的结果。

## A2 — 触发场景 (Future Trigger)

### 用户会在什么情境下需要它
1. 要让设备在无人值守、断电重启后仍持续做一件事（周期采样、串口桥、抓拍），需要选 MCU 还是 SBC+cron。
2. 写好了单动作脚本，要让它系统级周期触发，且不依赖图形/登录会话。
3. cron 配了却不生效，需要排查字段口径、工作目录、执行权限。
4. 评估"该用 SBC 还是 MCU"——任务是否需要网络、存储、多任务。

### 语言信号（出现这些就该激活）
- 中文：「怎么让设备断电重启后还自动干活」「MCU 还是 SBC」「firmware persistence on microcontroller」「定时执行脚本」「cron 不生效」「scheduled task on embedded linux」
- English: "persistent task on microcontroller", "cron not firing on embedded Linux", "MCU vs SBC for unattended job", "sketch survives reset", "schedule script every minute"

### 与相邻能力的区分
- 与 `board-bus-peripheral-interfacing` 的区别：后者解决"板子之间物理上怎么连、电平怎么匹配"，本能力解决"逻辑怎么持续运行"。一个管连接，一个管执行。
- 与 `default-creds-minimal-services` 的区别：后者裁剪的是"常驻服务"（CU-1-14），本能力管的是"周期触发任务"（cron）与"无 OS 固件"；常驻服务与定时任务调度机制不同。
- 与 `boot-chain-card-imaging` 的区别：后者改 SBC 的启动介质（内核/固件/参数），本能力的 MCU 固件是"无 OS 的固件常驻"；一个改可写 SD 卡，一个烧 MCU 闪存。

## E — 可执行步骤 (Execution)

**必需输入**: 目标 MCU 可烧写且有宿主做编译上传（固件路线）；或有可执行脚本与常驻服务身份（cron 路线）；明确任务是否只需单一闭环动作、是否需要 OS。缺"是否需要 OS"的判定则两条路线选不出来。

**交付物与完成标准**: 一段已上传并断电验证的 MCU 固件，或一条已生效的 crontab 条目 + 按周期增长的输出。完成标准为"无需人工干预即运行"或"输出文件按周期增长"。

1. **判定路线：MCU 还是 SBC+cron**
   - 做什么：问任务是否只需单一闭环动作、是否需要 OS（网络/存储/多任务）。
   - 完成标准：只需单一动作且无需 OS → MCU；需要 OS → SBC+cron。
   - 判停：需要网络/存储/多任务却想用 MCU → 不可行，转 SBC 路线；作者明确 MCU 无 OS、无图形。

2. **[固件路线] 选板型与串口并上传**
   - 做什么：在有 OS 的宿主上写 sketch；`Tools > Board`、`Tools > Serial Port` 选对设备节点（如 AlaMode 是 `/dev/ttyS0`，Uno 是 `/dev/ttyACM0`）；上传。
   - 完成标准：IDE 显示上传成功。
   - 判停：选错板型/串口会传到错误设备，上传前核对节点。

3. **[cron 路线] 写脚本并赋予权限**
   - 做什么：写幂等小脚本，先取时间戳变量再调用采集命令并归档到固定目录；`sudo chmod +x`；脚本内用绝对路径。
   - 完成标准：可直接执行；每次产生唯一文件名。
   - 判停：脚本无执行权限会静默失败；相对路径在 cron 下工作目录不同，会找不到文件。

4. **[cron 路线] 配置调度并验证口径**
   - 做什么：`crontab -e` 添加条目（如 `*/1 * * * * /home/pi/camscript.sh`）；以 `man 5 crontab` 为准确认字段数。
   - 完成标准：任务出现在 crontab 中；表达式符合目标实现。
   - 判停：书中"六字段含 Year"口径与主流五字段不符，照抄不生效，必须以目标 man 手册为准。

5. **验证自动恢复 / 周期触发**
   - 做什么：固件路线断电重启验证无需人工干预即运行；cron 路线等一个周期检查输出。
   - 完成标准：自动运行；输出按周期增长。
   - 判停：固件路线失败先查上传节点；cron 路线失败先查权限与路径，再看日志。

6. **输出与留痕**
   - 做什么：汇总路线选择理由、脚本/固件要点、验证记录。
   - 完成标准：文档可被第三方复核。

## B — 边界 (Boundary) ★

### 不要用的情况
- 任务需要网络栈、文件系统或多任务时，MCU 路线不适用（作者明确 MCU 无 OS、无图形）。
- 设备没有常驻 OS/守护进程时，cron 路线不适用——转 MCU 固件路线。
- 需要强实时或毫秒级精确触发时，cron 的最小粒度（分钟）与系统负载抖动可能不满足。
- 只需一次性动作、不需要"持续"时，本能力的持久化设计是多余复杂度。

### 已知失败模式
- **选错板型/串口**（《Hacking Raspberry Pi》Ch19）：AlaMode 是 `/dev/ttyS0`、Uno 是 `/dev/ttyACM0`，选错传到错误设备。
- **cron 字段口径错误**（Ch16）：书中称"六字段（含 Year，1900-3000）"，主流 cron 为五字段、无年份字段；照抄含年份表达式不生效。
- **相对路径与无执行权限**（Ch16）：cron 工作目录与交互式不同，相对路径找不到文件；脚本无执行权限静默失败。
- **MCU 能力误判**（Ch19）：以为 MCU 能跑网络/存储/多任务——作者明确其只适合单一动作。

### 作者与时代的局限
- 书中的 Arduino IDE 工作流、板型/串口命名是特定年代；现代 MCU 开发工具链（PlatformIO、Arduino CLI 等）已变化，但"写→上传→断电验证"的机制不变。
- cron 的字段口径是作者笔误/特定实现差异；今天主流是五字段（Vixie cron）或带秒的七字段（Quartz），须以目标实现为准。
- 作者未讨论 systemd timer、容器化调度等现代替代方案，这些超出本书范围。

### 容易混淆的方法
- **MCU 固件 vs SBC cron**：前者无 OS、逻辑存闪存、复位不丢；后者依赖 OS 与守护进程调度脚本。分界线是"是否需要 OS"。
- **cron 周期任务 vs 常驻服务**（CU-1-14）：cron 按时间触发一次性动作，常驻服务持续运行监听；裁剪服务时不要混淆。
- **覆盖上传 vs 改启动介质**（CU-1-15）：MCU 重新上传覆盖固件、无残留配置；SBC 改 SD 卡启动分区是持久配置改动，机制不同。
- **幂等脚本 vs 交互式命令**：只有写进脚本才能在无人登录时运行；交互式命令不具备持久性。

### 授权与合规边界
> 待补充（用户自行填写）
