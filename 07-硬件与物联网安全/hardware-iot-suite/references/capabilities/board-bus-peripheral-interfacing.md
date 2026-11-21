# 板级总线与外设连接

## R — 原文 (Reading)

> "Comment out the following line in the configuration file with a # such that it appears like this: #blacklist spi-bcm2708. Performing this action prevents SPI from being disabled on your Raspberry Pi."
>
> — 《Hacking Raspberry Pi》Chapter 20, Task: Enabling SPI on Your Raspberry Pi

> "although the GPIO has two 5V pins, the GPIO voltage levels are tolerant only of 3.3V signals, and there is not built-in overvoltage protection on the Raspberry Pi. Consequently, if you are not careful you can fry your Pi."
>
> — 《Hacking Raspberry Pi》Chapter 20, Anatomy of the GPIO

> "This connection method does not require a logic level converter, as long as you configure the Pi as a master device and the Arduino as a slave device... The advantage to this method is that you free up both the USB bus as well as the serial pins on both devices. The disadvantage is that configuration is difficult."
>
> — 《Hacking Raspberry Pi》Chapter 19, Connecting the Arduino and the Raspberry Pi

## I — 方法论骨架 (Interpretation)

这个能力解决的是"要让一块板卡和另一个器件/另一块板卡连起来干活，该选哪条总线、怎么把总线打开、怎样不把板子烧掉"。它把三件强相关但常被割裂的事——总线启用、电平安全、连接方式选型——统一到一个决策顺序上：**先选连接方式（资源权衡）→ 再打开对应总线（软件配置）→ 最后保证电气安全（电平转换）**。顺序错了，要么接口不可用却以为是硬件缺失，要么接上了瞬间烧板。

核心机制分三层：

第一层是总线启用。许多发行版默认把非必需总线控制器（SPI/I2C）列入 modprobe 黑名单以省电/避免冲突，`/dev/spidev*` 因此不存在。要用总线就得先解除黑名单再加载封装库。这条对硬件攻防都成立：防守方可用黑名单减少暴露的物理接口；分析方要会判断"接口不可用"是硬件缺失还是软件禁用。

第二层是电平安全。板上有 5V 引脚只代表"能取电"，不代表"IO 能承受 5V"。SoC 的 IO 单元没有钳位保护，5V 直接打进 GPIO 会经保护二极管灌电流，轻则损坏该引脚，重则击穿核心。跨电平连接必须显式做电平转换（分压电阻或专用转换器）。同类风险出现在 I2C：主从配置错误时上拉/驱动冲突同样会造成过压。作者两次点名该风险：GPIO 无过压保护、I2C 主从配错"easily fry your Pi with an overvoltage"。

第三层是连接方式选型。三种方式各有代价：USB 最简单但占端口且需供电；GPIO 串口省 USB 但要电平转换并占掉串口；I2C 同时省 USB 与串口、且主从正确时免转换器，但配置最易错。选型判据是"哪项资源最稀缺"与"是否愿意承担配置风险"，而不是"哪种更高级"。对外设受限的植入式设备，省下 USB 口往往比省事更重要。

为什么这样做：因为"接口不可用"和"接上烧板"是两个独立维度，前者是软件配置问题，后者是电气底线问题。把它们放进一个能力，就是让执行者在选方式时同时考虑"这条总线能不能打开"和"这条线接上去安不安全"，避免"选了 I2C 省口却配错主从烧板"这类作者原话警告的后果。

## A1 — 应用示例 (Application Example)

### 示例 1: 解除 SPI 黑名单并装 py-spidev

- **类型与来源**: 【亲历】《Hacking Raspberry Pi》Chapter 20, Task: Enabling SPI on Your Raspberry Pi
- **问题/输入**: 作者要用 SPI 访问 Gertboard 的 A/D、D/A 芯片，但 `/dev/spidev*` 不存在。
- **方法论的使用**: 按 E 段第 2 步：编辑 `/etc/modprobe.d/raspi-blacklist.conf`，在 `blacklist spi-bcm2708` 行首加 `#`；`sudo reboot` 使模块可加载，`ls /dev/spidev*` 确认设备节点出现；装用户态封装（`apt-get install git`，`git clone ...py-spidev`，`python setup.py install`），确认 `import spidev` 成功。
- **结论**: "接口不可用"先查软件禁用，而不是断定硬件缺失；只注释文件不装封装库仍读不到数据。
- **结果**: 作者按此流程为 `atod.py`/`dtoa.py`/`dad.py` 解除 SPI 限制。

### 示例 2: I2C 主从配错会烧板

- **类型与来源**: 【转述】《Hacking Raspberry Pi》Chapter 19, I2C 连接；Chapter 20, Anatomy of the GPIO
- **问题/输入**: 用 I2C 连接 Pi 与 Arduino，作者要说明为什么这条方式"优点突出但配置困难"。
- **方法论的使用**: 按 E 段第 1、3 步：明确 Pi 为主、Arduino 为从，总线上只有一个主设备；作者指出只要主从正确就不需要电平转换器（因为 I2C 开漏/上拉特性），若配错主从则上拉/驱动冲突，原话警告"easily fry your Pi with an overvoltage"。
- **结论**: I2C 免转换器的前提恰恰是"主从正确"——省事与烧板只差一个配置项。
- **结果**: 原书给出该警告与优缺点对比，未给烧板实测数据。

### 示例 3: 【合成演练】为省 USB 口选 I2C 却配错主从

- **类型与来源**: 【合成演练】按本卡 E 段规则与书内警告推演，非作者亲历
- **问题/输入**: 一块外接设备可用 USB 或 I2C 连接，现场 USB 口已被占满，决定用 I2C 省口。
- **方法论的使用**: 按 E 段第 1 步列出约束（USB 口不足、无空闲串口）→ 选 I2C；第 3 步准备电气条件时，明确 Pi 主、对端从，确认只有一个主设备；第 4 步验证通信前先用万用表确认信号线静态电平，避免上电瞬间过压。
- **结论**: 选型解决"哪条总线"，电气安全解决"接上会不会烧"，两者都要走完。
- **结果**: 这是按规则推演的处置路径，不代表任何真实现场的结果。

## A2 — 触发场景 (Future Trigger)

### 用户会在什么情境下需要它
1. `/dev/spidev*` 或 I2C 设备节点不存在，要判断是硬件缺失还是软件禁用，并打开它。
2. 两块板卡（如 Pi 与 Arduino）要连起来，需要在 USB / 串口 / I2C 之间选型。
3. 要把 5V 器件接到 3.3V GPIO，需要确认是否需要电平转换器、怎么接才不烧板。
4. 评估一个物理接口的暴露面——防守方想知道"黑名单能不能减少可用接口"。

### 语言信号（出现这些就该激活）
- 中文：「/dev/spidev 不存在」「树莓派开 SPI」「5V 传感器接 3.3V 会不会烧」「level shifter 必要吗」「两块板怎么连最合适」「省 USB 口接法」
- English: "enable SPI on Linux SBC", "I2C vs serial vs USB", "5V logic to 3.3V GPIO", "do I need a level shifter", "blacklist spi-bcm2708"

### 与相邻能力的区分
- 与 `power-supply-hardware-reliability` 的区别：后者管"电源轨"（5V 是否稳、电流够不够），本能力管"信号电平"（3.3V/5V 逻辑）与总线连接。有 5V 引脚不代表 IO 能承受 5V 逻辑。
- 与 `boot-chain-card-imaging` 的区别：后者改启动介质（内核/固件/参数），本能力改的是运行期的总线使能与外设连接；一个在启动层，一个在板级接口层。
- 与 `embedded-task-persistence` 的区别：后者让逻辑持续运行（固件/cron），本能力解决"板子之间物理上怎么连、电平怎么匹配"。

## E — 可执行步骤 (Execution)

**必需输入**: 两块可编程板卡或板卡 + 外设；明确的端口/资源预算（可用 USB 口数、串口是否被占用、有无转换器）；root 权限；万用表（电平验证）；目标平台的接口命名（SPI/I2C/串口）。缺"资源预算"则第 1 步选型无依据。

**交付物与完成标准**: 一份连接方式选型结论 + 一条已打开且可通信的总线 + 一份电气安全检查记录。完成标准为"`/dev/spidev*` 或对应节点存在"、"`import spidev` 等封装库可用"、"能收到对端数据"、"信号线静态电平不超过 3.3V"。

1. **列约束并选连接方式**
   - 做什么：列出可用 USB 口数、是否需串口做其他用途、是否已有转换器；按稀缺资源选型（口不够→I2C/串口；不想配→USB）。
   - 完成标准：选定一种方式。
   - 判停：若为省口选 I2C，必须同时接受"配置最易错、主从配错会烧板"的风险；不愿承担则选 USB。

2. **打开选定总线**
   - 做什么：SPI 场景编辑 `/etc/modprobe.d/raspi-blacklist.conf`，注释 `blacklist spi-bcm2708` 行；`sudo reboot` 后 `ls /dev/spidev*` 确认节点。
   - 完成标准：设备节点出现。
   - 判停：若新内核已用 `dtparam=spi=on` 取代黑名单文件、找不到旧文件名，改用新方式（书中文件名过时）；只注释不装封装库仍读不到数据，转第 3 步。

3. **准备电气条件**
   - 做什么：USB 需带供电 Hub（防从板抢电）；串口需在信号线加电平转换/分压（目标端输入 ≤ 3.3V）；I2C 明确 Pi 为主、从设备为从，总线上只有一个主设备。
   - 完成标准：接线与配置匹配，电平条件满足。
   - 判停：认为"Arduino 有 3.3V 引脚所以能直连"是错误——3V3 引脚供电仅约 50mA 且信号仍是 5V 逻辑；先接线后上电、带电插拔杜邦线会瞬间打火。

4. **装封装库并验证通信**
   - 做什么：装用户态封装并 `import`；上电前用万用表确认信号线静态电平；验证能收到对端数据。
   - 完成标准：链路可用；电平未超限。
   - 判停：若通信失败，先查电平（烧板风险）再查配置；不要反复热插拔尝试。

5. **输出与留痕**
   - 做什么：汇总选型理由、总线配置、电气检查记录。
   - 完成标准：文档可被第三方复核。

## B — 边界 (Boundary) ★

### 不要用的情况
- 目标总线在硬件上根本不存在（板卡无 SPI/I2C 控制器）时，软件启用无效。
- 没有万用表、无法验证信号电平时，不要做跨 3.3V/5V 连接——烧板风险不可控。
- 需要高速、长距离或隔离通信时，SPI/I2C/串口的板级短距假设不成立，需另选方案。
- 仅需要"设备能否被发现"而不涉及物理连接时，转 `device-discovery-exposure-assessment`。

### 已知失败模式
- **黑名单文件名过时**（《Hacking Raspberry Pi》Ch20）：新内核用 `dtparam=spi=on` 取代 `raspi-blacklist.conf`，照抄书内文件名找不到文件。
- **GPIO 无过压保护**（Ch20）：有 5V 引脚不代表 IO 容忍 5V，直接接入会经保护二极管灌电流，轻则损引脚重则击穿核心。
- **3V3 引脚供电仅约 50mA**（Ch19）：以为"有 3.3V 引脚就能直连 5V 器件"是错误——供电能力弱且信号仍是 5V 逻辑。
- **I2C 主从配错烧板**（Ch19）：作者原话"easily fry your Pi with an overvoltage"。
- **USB 不加供电 Hub**（Ch19→Ch06）：从板抢电导致主板欠压重启。

### 作者与时代的局限
- 书中的 `blacklist spi-bcm2708`、`raspi-blacklist.conf` 是 Raspbian Wheezy 时代产物；现代 Raspberry Pi OS 用设备树 overlay（`dtparam=spi=on`），配置方式已变但"先解除禁用再验证节点"的机制不变。
- 作者以 Gertboard、Arduino Uno 为例，板型/引脚布局是特定年代；今天的板卡型号与电平容限需查当前规格。
- 本书是工程手册，不涉及总线协议层的攻击（如 SPI 固件提取、I2C 地址扫描的对抗），这些不在本能力范围。

### 容易混淆的方法
- **总线启用 vs 总线选型**：CU-1-18 解决"总线能不能用"，CU-1-20 解决"选哪条总线"；先选后开，顺序不能反。
- **电源轨 vs 信号电平**：CU-1-06 是 5V 供电质量，CU-1-19 是 GPIO 信号电平；两者都是"电"但失效机理不同。
- **5V 引脚取电 vs 5V 逻辑输入**：板上有 5V 输出引脚不等于 IO 能接受 5V 信号，这是最常见的烧板误解。
- **免转换器 ≠ 无风险**：I2C 免电平转换器的前提是主从正确；把它理解为"任何情况下都不用转换"会导致烧板。

### 授权与合规边界
> 待补充（用户自行填写）
