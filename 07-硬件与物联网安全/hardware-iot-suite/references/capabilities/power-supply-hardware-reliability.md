# 供电与硬件可靠性排查

## R — 原文 (Reading)

> "Remember that the standard power draw of the Model B board is 500mA. The amount of energy in a battery pack is ordinarily given in milliampere hours (mAh). This means that a 1,000mAh battery pack can deliver 1000mA of power for one hour, or 500mA for two hours."
>
> — 《Hacking Raspberry Pi》Chapter 16, Adding a Rechargeable Battery Pack to Your Pi Camera

> "The main problem with cheap power supplies is that they don't deliver a solid 5V of direct current (DC) to the PCB. If the power supply delivers too much juice, the board can fry. If the power supply doesn't deliver enough power, the Pi will shut down at worst and operate erratically at best."
>
> — 《Hacking Raspberry Pi》Chapter 2, A 5V Power Supply

> "Instead, unplug the Pi, wait a couple of minutes, and then power on the device while holding down the Shift key. This disables any overclocking settings for the current boot only."
>
> — 《Hacking Raspberry Pi》Chapter 18, The Manual Method (Note: Help! My Pi Won't Boot)

## I — 方法论骨架 (Interpretation)

这个能力解决的是嵌入式/单板机现场最常见的两类"玄学问题"：**设备行为异常（随机重启、SD 卡坏、外设掉线）到底是不是供电引起的；以及电池能撑多久、超频改坏了怎么救回来**。把这三件事——续航估算、供电质量排查、超频旁路恢复——放在一个能力里，是因为它们都是"硬件物理层"问题，症状都容易被误判为软件 bug，且排查顺序高度一致：先看电源/电气，再看配置，最后才看代码。

核心机制分三层：

第一层是续航定量估算。续航 = 容量 ÷ 平均电流。关键是"平均"包含所有负载：主板标称 + USB 外设（每只约 100mA 量级）+ 无线网卡。因此加装 Wi-Fi 或摄像头必须重算，否则电池标称时长大幅缩水。第二判据是供电口电流能力：作者实测选 2.1A 口而非 1A 口。还要按最坏情况打折（温度、老化、转换损耗），并用实测或较大值规避书中 500/700mA 的口径不一致。

第二层是供电质量排查。电压跌落与纹波会造成无规律挂起、重启、SD 卡写坏——现象酷似软件 bug 或"刷砖"。板载电容只能吸收短时波动，不能补偿持续欠压。判据是"换高质量电源后现象消失"，不是看日志。操作上先断开除电源外全部外设，用万用表测 TP1(红) 对 TP2(黑) 约 5V，再逐个加回外设重测，确认加载后电压不塌陷。

第三层是配置层旁路恢复。启动参数写在 `/boot/config.txt`，一旦超频/超压参数超出芯片能力，系统在能读取配置前就挂死。厂商在引导阶段保留按键旁路：启动瞬间按住 Shift 忽略超频项，使系统以安全频率起来，从而有机会改回文件。这是"改坏了还能进去"的救命通道，必须在改动前就知道；旁路只对本次启动生效，不改文件下次仍失败。

为什么这样做：因为把随机崩溃归给软件会浪费大量时间在错误方向；而"能亮就行"的充电器、按小值算的续航、不知道 Shift 旁路就硬断电，都是把可恢复问题变成重装甚至烧板的常见错误。把物理层排查固化成"症状分级→测量→替换→复测"的流程，就把玄学变成了可核验的工程判断。

## A1 — 应用示例 (Application Example)

### 示例 1: 3300mAh 电池"超过 6 小时连续供电"

- **类型与来源**: 【亲历】《Hacking Raspberry Pi》Chapter 16, Adding a Rechargeable Battery Pack to Your Pi Camera
- **问题/输入**: 作者给 Pi Camera 加可充电电池组，需要估算能连续供电多久。
- **方法论的使用**: 按 E 段：列出全部负载（Model B 标称 500mA + 外设）；用续航=容量÷平均电流算得保守时长；按最坏情况打折；选供电口电流 ≥ 峰值（作者选 2.1A 而非 1A）。
- **结论**: 续航公式简单，但"平均电流"和"供电口能力"两个隐藏变量决定估算是否可信。
- **结果**: 作者用 3300mAh 电池推断"超过 6 小时连续供电"（第 16 章）。

### 示例 2: 用 TP1/TP2 实测 5V 排查欠压

- **类型与来源**: 【亲历+转述】《Hacking Raspberry Pi》Chapter 2, A 5V Power Supply；Chapter 3 Task
- **问题/输入**: 同事在 eBay 买的"兼容电源"被烧过板；作者要确认供电是否正常。
- **方法论的使用**: 症状分级（随机重启/文件系统只读/外设掉线）先怀疑供电；断开除电源外全部外设，仅上电，用万用表测 TP1(红) 对 TP2(黑) 约 5V；逐个加回外设重测，确认加载后电压不塌陷；换名牌电源/带供电 USB Hub 复测，现象应消失。
- **结论**: 判据是"换电源后现象消失"，不是看日志；过压是不可逆损坏，欠压致不稳或关机。
- **结果**: 作者用 TP1/TP2 实测 5V（第 3 章 Task）；转述同事烧板经历。

### 示例 3: 按住 Shift 救回超频改坏的 Pi

- **类型与来源**: 【转述】《Hacking Raspberry Pi》Chapter 18, The Manual Method (Note: Help! My Pi Won't Boot)
- **问题/输入**: 改了 `/boot/config.txt` 的超频/超压参数后设备无法启动。
- **方法论的使用**: 断电等数十秒让电容放电；按住 Shift 上电保持到出现启动输出，系统以默认频率起来；编辑 `/boot/config.txt` 回退 `arm_freq/core_freq/over_voltage` 到已知安全值；正常重启验证可自启动。
- **结论**: 旁路只对本次启动生效，必须在改动前就知道这条通道；不按 Shift 多次硬断电会连带损坏 SD 卡文件系统。
- **结果**: 作者以提示框形式给出该恢复手法，未给具体参数值。

## A2 — 触发场景 (Future Trigger)

### 用户会在什么情境下需要它
1. 设备随机重启、SD 卡反复写坏、外设间歇掉线，想确认是不是电源问题而不是软件 bug。
2. 要给定量回答"这块电池能撑多久""加个网卡后续航掉多少"。
3. 改了超频/超压参数后设备起不来，需要一次性的旁路恢复手段。
4. 现场部署前评估电源余量，避免"能亮就行"的充电器在负载增加后欠压。

### 语言信号（出现这些就该激活）
- 中文：「Pi 老是自己重启」「SD 卡老坏」「这块电池能撑多久」「加个网卡续航掉多少」「改了 config.txt 起不来了」「boot with shift」「random reboots / undervoltage」
- English: "random reboots on Pi", "undervoltage SD card corruption", "battery runtime for pi", "overclock bricked my pi", "boot with shift key"

### 与相邻能力的区分
- 与 `board-bus-peripheral-interfacing` 的区别：本能力管"电源轨"（5V 是否稳、电流是否够），后者管"信号电平"（3.3V/5V 逻辑转换）和总线选型。电源不稳和信号过压是两种不同的物理失效。
- 与 `boot-chain-card-imaging` 的区别：后者管启动介质的改写/克隆（可删可复制的痕迹），本能力的 Shift 旁路是配置层恢复手段；后者是攻击面，前者是救恢复。
- 与 `remote-node-addressing` 的区别：后者让设备可达，本能力保证设备"活着且稳定"；设备反复重启时寻址无从谈起。

## E — 可执行步骤 (Execution)

**必需输入**: 万用表；可复现的故障现象（对排查）或电池容量与全部外设清单（对估算）；物理接触设备与键盘（对 Shift 旁路）；root 权限（改 config.txt）。缺"可复现现象"则排查无起点，缺"外设清单"则续航估算不可信。

**交付物与完成标准**: 一份供电诊断结论（是否供电问题 + 证据）+ 一份续航估算（保守时长 + 打折说明）+ 必要时一份旁路恢复记录。完成标准为"换电源后现象消失"、"部署窗口 ≥ 任务时长"、"回退配置后自启动成功"。

1. **症状分级与假设**
   - 做什么：随机重启/文件系统只读/外设掉线 → 先怀疑供电，不改代码；续航问题 → 先列负载清单。
   - 完成标准：明确走"排查"还是"估算"分支。
   - 判停：若现象可稳定复现且与某条命令强相关，可能是软件问题，本能力排查完供电后转相应软件能力。

2. **[估算分支] 计算续航**
   - 做什么：列出全部负载并累加得总平均电流 I；用 续航(h)=容量(mAh)÷I(mA) 计算；按最坏情况打折（温度/老化/转换损耗）；选供电口电流 ≥ 峰值（书中选 2.1A 而非 1A）。
   - 完成标准：得到保守时长；部署窗口 ≥ 任务时长。
   - 判停：若书中 500/700mA 口径不一，取较大值或实测，否则高估续航；容量标注常为电芯值，经升压后实际可用更低。

3. **[排查分支] 测量电压**
   - 做什么：断开除电源外全部外设，仅上电；用万用表测 TP1(红) 对 TP2(黑) 约 5V；逐个加回外设重测。
   - 完成标准：约 5V 且加载后电压不塌陷。
   - 判停：若加载某外设后电压塌陷，定位该外设供电问题，转第 4 步换带供电 USB Hub。

4. **[排查分支] 替换复测**
   - 做什么：换名牌电源/带供电 USB Hub 复测。
   - 完成标准：现象消失，确认是供电问题。
   - 判停：若换电源后现象仍在，停止供电假设，转其他方向（配置/软件）。

5. **[恢复分支] Shift 旁路**
   - 做什么：断电等数十秒放电；按住 Shift 上电到出现启动输出；编辑 `/boot/config.txt` 回退 `arm_freq/core_freq/over_voltage`；正常重启验证。
   - 完成标准：系统以默认频率起来并可自启动。
   - 判停：若不按 Shift 而多次硬断电，可能损坏 SD 卡文件系统，把可恢复问题变成重装；旁路只本次生效，不改文件下次仍失败。

6. **输出与留痕**
   - 做什么：汇总诊断结论、测量数据、估算过程、恢复记录。
   - 完成标准：文档可被第三方复核。

## B — 边界 (Boundary) ★

### 不要用的情况
- 故障与供电无物理关联（如纯应用层 bug、配置语法错误）时，本能力的测量流程不适用。
- 没有万用表或无法物理接触设备时，无法做电压测量与 Shift 旁路。
- 设备由 5V 逻辑器件和扩展板构成、涉及信号电平而非电源轨时，转 `board-bus-peripheral-interfacing`。
- 需要在不停机的线上系统上做排查时，断电测量会中断服务，需另安排窗口。

### 已知失败模式
- **口径不一致导致高估续航**（《Hacking Raspberry Pi》Ch2 vs Ch16）：第 2 章写 Model B 为 700mA，第 16 章写 500mA；按小值算会高估，必须用实测或取大值。
- **容量标注虚高**（Ch16）：容量常为电芯值，经升压转换后实际可用更低。
- **"能亮就行"的充电器**（Ch2）：廉价电源不送稳定 5V，过压烧板、欠压不稳/关机；板载电容不能补偿持续欠压。
- **反复硬断电**（Ch18）：改坏配置后不按 Shift 而多次硬断电，连带损坏 SD 卡文件系统。
- **旁路只本次生效**（Ch18）：不改 `/boot/config.txt` 则下次启动仍失败。

### 作者与时代的局限
- 书中以 Model B 的 500/700mA 为基准，是特定硬件年代的数值；今天不同板卡功耗差异大，必须按实测或当前型号规格重算。
- TP1/TP2 测试点位置是特定板的布局，新型号可能不同；测量前需查该板原理图或测试点标注。
- 作者以 Raspbian Wheezy 的 `config.txt` 为例；现代固件引导参数命名与旁路键可能因板卡/固件而异，需以平台文档为准。

### 容易混淆的方法
- **电源轨 vs 信号电平**：CU-1-06 是 5V 供电质量，CU-1-19 是 GPIO 的 3.3V 信号容限；"有 5V 引脚"不代表 IO 能承受 5V 逻辑。
- **续航估算 vs 供电质量**：CU-1-05 算"能撑多久"（容量/电流），CU-1-06 查"稳不稳"（电压/纹波）；前者是量，后者是质。
- **配置旁路 vs 启动链改写**：Shift 旁路是临时忽略超频项，不改文件；`boot-chain-card-imaging` 是真正改写启动介质，两者作用与后果不同。
- **过压烧板 vs 欠压重启**：前者不可逆、瞬间损坏；后者表现为不稳/重启，可恢复；处置方式完全不同。

### 授权与合规边界
> 待补充（用户自行填写）
