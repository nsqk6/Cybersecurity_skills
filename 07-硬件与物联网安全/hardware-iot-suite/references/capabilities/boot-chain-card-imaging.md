# 启动链与整卡镜像操作

## R — 原文 (Reading)

> "The Raspberry Pi kernel, firmware, and boot files are located on the FAT32 /boot partition (the only part of the SD card that is readable by Windows)." / "The cmdline.txt configuration file contains low-level commands that are sent directly to the Raspbian Linux firmware at boot time."
>
> — 《Hacking Raspberry Pi》Chapter 18, A Historical Footnote；Chapter 5 分区结构

> "sudo dd if=image_file_name.img of=/dev/diskXsY bs=2M" / "It's important to note that we want to flash the entire contents of the card and not an individual partition."
>
> — 《Hacking Raspberry Pi》Chapter 4, Task: Creating a Raspbian SD Card in OS X

> "the Foundation programmed the SoC such that a so-called sticky bit is turned on when any of the following conditions is detected... this is a flip flop circuit that, once tripped, remains in place and is used by the distributors to detect whether you set your Pi to warranty-breaking settings."
>
> — 《Hacking Raspberry Pi》Chapter 18, Warranty Implications of Overclocking

## I — 方法论骨架 (Interpretation)

这个能力解决的是"拿到一台嵌入式设备的物理访问权之后，怎么理解和操作它的启动链与存储镜像，以及怎么从硬件层找篡改痕迹"。它把三件事——启动分区改写、整卡克隆还原、芯片内一次性标记取证——统一到一个核心判断上：**对这类设备，物理接触等价于启动链控制；而"当前状态"可以被"历史痕迹"证伪**。

核心机制分三层：

第一层是启动分区可写。典型嵌入式启动链把"引导所需的一切"放在一个无权限模型的分区里：任何 PC 插上卡就能读写内核、GPU 固件与启动参数，不需要通过目标系统的登录。于是物理接触 = 启动链控制——可改内核、改启动参数、替换固件镜像，目标 OS 的账户与权限体系完全不起作用。评估设备安全性时必须把启动介质是否可拆卸、是否加密、是否校验列为独立维度。

第二层是整卡按字节克隆。嵌入式设备的"系统"就是存储卡的原始字节布局：分区表 + 启动分区 + 根文件系统。按文件复制会丢掉引导扇区、权限位与符号链接，必须整盘按字节复制（dd）。这同一个动作有三个用途：批量部署相同配置、备份取证镜像、把一台已配置好的设备完整复制成多台——也就是"设备身份复制"的技术基础。注意克隆保真复制（含已被植入的状态），与"只改特定文件"是不同操作。

第三层是芯片内历史痕迹。厂商在硅片里留了不可逆的审计位（sticky bit / OTP 熔丝）：超过安全阈值（温度上限调高、强制 Turbo、关闭电流限制并超压）即熔断式置位，用户态无法清除。这给取证一个可靠判据——日志可删、可改的文件痕迹可清除，但熔丝不可逆。检查方式是读 CPU Revision 值并与同型号基线比对。

为什么把三者放一起：因为它们构成一条完整的"物理访问 → 操作 → 取证"链路。改写启动链是"植入"，整卡克隆是"复制/保全现场"，OTP 标记是"找不可伪造的历史证据"。三者共享同一前提——设备是可物理接触、启动介质是可拆卸的——共享同一风险——选错 `of=` 覆盖本机盘、改错内核无旁路、把可清除痕迹当成不可伪造证据。

## A1 — 应用示例 (Application Example)

### 示例 1: 用整卡 dd 完成刷写与备份

- **类型与来源**: 【亲历】《Hacking Raspberry Pi》Chapter 4, Task: Creating a Raspbian SD Card in OS X
- **问题/输入**: 作者要在 OS X 上把 Raspbian 镜像刷到 SD 卡，并解释各参数。
- **方法论的使用**: 按 E 段第 1–3 步：`diskutil list` 识别目标设备节点，确认是整盘 `disk2` 而非分区 `disk2s1`；`diskutil unmountdisk /dev/diskN` 卸载但不弹出；`sudo dd if=<img> of=/dev/diskN bs=2M` 写入；还原时反向 `dd if=/dev/diskN of=<backup.img> bs=2M`。
- **结论**: 必须刷整卡而非单分区，才能保住引导扇区、权限位与符号链接；dd 绰号"Data Destroyer"。
- **结果**: 作者在 Windows 用 Win32 Disk Imager、在 OS X 用 dd 完成刷写并解释 `if/of/bs` 各参数。

### 示例 2: 用 sticky bit 判断设备是否被超规格使用

- **类型与来源**: 【亲历】《Hacking Raspberry Pi》Chapter 18, Warranty Implications of Overclocking（图 18.1）
- **问题/输入**: 作者要验证超压是否留下不可逆痕迹、重启是否清除。
- **方法论的使用**: 按 E 段第 4 步：`cat /proc/cpuinfo` 取 Revision 值并记录；书中口径为 Revision > 1000 判定 sticky bit 已置位（曾被设为破坏性参数）；交叉验证 `/boot/config.txt` 是否残留 `force_turbo`、`temp_limit`、`current_limit_override`；确认重启、刷系统都不清除。
- **结论**: 硬件层 OTP 痕迹比日志更难伪造；但只覆盖"厂商定义为越界"的参数，阈值随批次/固件变化需同型号基线。
- **结果**: 作者贴出超压前后 `/proc/cpuinfo` 的 Revision 对比并验证重启不复位。

### 示例 3: 【合成演练】改 cmdline.txt 植入启动参数

- **类型与来源**: 【合成演练】按本卡 E 段规则与书中"启动分区可写"事实推演，非作者亲历
- **问题/输入**: 拿到一台基于 SD 卡启动的设备，评估其启动链是否可被物理篡改。
- **方法论的使用**: 按 E 段第 1 步确认启动介质为可插拔 SD；第 2 步挂载启动分区，枚举内核、`start.elf` 类 GPU 固件、`cmdline.txt`、`config.txt`，得到可改文件清单；第 3 步判定修改后果（改参数 → 换内核 → 换固件，风险递增），选最小改动点；第 4 步先备份原文件再改，确保可回滚。
- **结论**: 物理接触 = 启动链控制；评估要看介质是否可拆卸、是否加密、是否校验。
- **结果**: 这是按规则推演的评估路径，不代表对任何真实现场的改动结果。

## A2 — 触发场景 (Future Trigger)

### 用户会在什么情境下需要它
1. 拿到一台设备的存储卡，想枚举可改的启动组件、判断物理接触能改到什么程度。
2. 批量部署相同配置的设备，或备份/取证一份设备镜像，需要整卡按字节复制。
3. 怀疑一台设备被人动过，想找"当前状态无法伪造的历史痕迹"（如超频/超压）。
4. 评估设备安全性时，需要把"启动介质是否可拆卸/加密/校验"列为独立维度。

### 语言信号（出现这些就该激活）
- 中文：「拔下 SD 卡能不能植入」「boot partition tampering」「启动参数在哪改」「批量做卡」「备份设备镜像」「dd 克隆 SD 卡」「这台设备被人动过吗」「硬件层有没有篡改痕迹」
- English: "SD card boot tampering", "dd clone SD card", "FAT32 boot partition writable", "OTP fuse forensics", "sticky bit overclock detection", "image whole card not partition"

### 与相邻能力的区分
- 与 `device-discovery-exposure-assessment` 的区别：后者在网络/射频层"找到并识别"设备，本能力在拿到设备之后"改写或复制"其启动介质。一个在联网阶段，一个在物理接触阶段。
- 与 `power-supply-hardware-reliability` 的区别：后者 Shift 旁路是配置层恢复（临时忽略超频项），本能力是真正改写启动介质；前者是"救回来"，后者是"改进去/复制走"。
- 与 `board-bus-peripheral-interfacing` 的区别：后者改运行期总线使能与外设连接，本能力改启动介质（内核/固件/参数）；一个在启动层，一个在板级接口层。

## E — 可执行步骤 (Execution)

**必需输入**: 能接触设备或拿到其存储卡；读卡器、root 权限；了解该平台引导文件命名；目标卡容量 ≥ 源卡（克隆时）；同型号基线（OTP 比对时）。缺"物理接触"则整卡操作与启动分区改写均不可执行；缺"同型号基线"则 OTP 判定只能给"可能"结论。

**交付物与完成标准**: 一份可改组件清单 + 一份整卡镜像（或克隆卡）+ 一份硬件痕迹取证结论。完成标准为"镜像大小等于卡容量且可还原引导"、"改动点已备份可回滚"、"OTP 判定有同型号基线佐证"。

1. **确认启动介质形态**
   - 做什么：确认是可插拔 SD / eMMC / SPI flash；判定是否需拆机。
   - 完成标准：明确介质类型与接触方式。
   - 判停：若介质不可拆卸且无调试接口，物理接触路径不通，转 `device-discovery-exposure-assessment` 走网络侧。

2. **枚举启动分区组件**
   - 做什么：挂载启动分区，枚举内核、`start.elf` 类 GPU 固件、`cmdline.txt`、`config.txt`，得到可改文件清单。
   - 完成标准：清单齐备。
   - 判停：若新版 `/boot` 只剩单一 `start.elf`，旧版 `cp arm240_start.elf start.elf` 的改法无效，不要照抄。

3. **[改写分支] 判定改动后果并备份**
   - 做什么：改参数（内存划分/启动选项）→ 替换内核 → 改固件，风险递增；选最小改动点；先备份原文件再改。
   - 完成标准：选定最小改动点；原文件已备份可回滚。
   - 判停：改错内核导致不启动且无 Shift 旁路（那仅针对超频项）时，用备份恢复，不要反复试错。

4. **[克隆分支] 整卡按字节复制**
   - 做什么：`diskutil list` / `lsblk` 识别整盘节点（如 `disk2` 而非 `disk2s1`）；`diskutil unmountdisk /dev/diskN` 卸载但不弹出；`sudo dd if=<img> of=/dev/diskN bs=2M` 写入；反向 `dd if=/dev/diskN of=<backup.img> bs=2M` 还原。
   - 完成标准：无报错完成；镜像大小等于卡容量。
   - 判停：`of=` 选错会覆盖本机磁盘（"Data Destroyer"）——写入前反复核对设备节点；大卡恢复到小卡会截断，目标卡容量必须 ≥ 源。

5. **[取证分支] 读 OTP / 一次性标记**
   - 做什么：`cat /proc/cpuinfo` 取 Revision 值；按书中口径 Revision > 1000 判 sticky bit 已置位；交叉验证 `/boot/config.txt` 是否残留 `force_turbo`、`temp_limit`、`current_limit_override`；与同型号基线比对。
   - 完成标准：形成"曾被改动"或"未触发"结论，并有配置残留佐证。
   - 判停：该位不可复位，重启/刷系统都不清除；未触发阈值的改动不留痕，不能据此说"没被动过"。

6. **输出与留痕**
   - 做什么：汇总可改组件清单、镜像校验值、取证结论。
   - 完成标准：文档可被第三方复核。

## B — 边界 (Boundary) ★

### 不要用的情况
- 启动介质不可拆卸、无调试接口、无物理接触路径时，本能力的改写/克隆分支不适用。
- 只需"识别设备型号"而不涉及物理操作时，转 `device-discovery-exposure-assessment`。
- 目标设备启用安全启动/启动链校验/存储加密时，改启动分区或克隆后篡改会被校验拦截，本能力的"物理接触=启动链控制"前提不成立。
- 目标卡容量小于源卡时，整卡还原会截断，不可执行。

### 已知失败模式
- **`of=` 选错覆盖本机盘**（《Hacking Raspberry Pi》Ch4）：作者直言 dd 绰号"Data Destroyer"；必须确认整盘节点而非分区节点。
- **不卸载直接写**（Ch4）：写入缓存不一致，镜像不可用。
- **旧固件改法失效**（Ch18）：新版 `/boot` 无 `arm240_start.elf`，照抄 `cp` 命令无效。
- **改错内核无旁路**（Ch18 vs Ch07）：Shift 旁路仅针对超频项，内核改坏无此救命通道。
- **OTP 判据覆盖有限**（Ch18）：只覆盖厂商定义为越界的参数，未触发阈值不留痕；Revision 编码随批次/固件变化，需同型号基线。
- **克隆含被植入状态**：整卡保真复制会把已植入的改动一并复制，混淆"干净基线"与"已改设备"。

### 作者与时代的局限
- 书中以 FAT32 `/boot`、`start.elf`、`cmdline.txt` 为特定年代 Raspberry Pi 的布局；现代设备多用 U-Boot、统一固件、A/B 分区与安全启动，启动链结构已不同。
- Revision > 1000 的 sticky bit 判据是特定 SoC/固件实现；今天 OTP/熔丝机制因芯片而异，需查当前平台文档。
- 本书是工程手册，作者未讨论安全启动绕过、固件签名校验对抗或加密存储的破解；把"物理接触=完全控制"无条件外推是误用。

### 容易混淆的方法
- **改写 vs 克隆**（CU-1-15 vs CU-1-16）：克隆保真复制整卡（含已植入状态），修改只动特定文件；两者目的不同，混用会污染基线。
- **可清除痕迹 vs 不可清除痕迹**（CU-1-15 vs CU-1-17）：外部可写介质上的改动可被还原/覆写，OTP 熔丝不可逆；取证价值不同。
- **启动链改写 vs 配置旁路**：本能力的改写是持久改动，`power-supply-hardware-reliability` 的 Shift 旁路是本次临时忽略；后者救不回内核改坏。
- **整卡镜像 vs 文件级备份**：文件级无法还原引导能力；只有按字节整卡复制才保住分区表、引导扇区、权限位与符号链接。

### 授权与合规边界
> 待补充（用户自行填写）
