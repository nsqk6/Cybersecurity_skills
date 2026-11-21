# 硬件与物联网安全 — 域总览

## 这个域在真实工作中解决什么问题

这个域处理的是"廉价单板机/嵌入式设备作为可被接触、可被部署、可被连回的实体"所带来的安全与工程问题。它不涵盖渗透测试全流程，而是聚焦两簇真实任务：一是把设备改造成网络隐身/远程节点（搭建出口链路、稳定寻址、发现与暴露评估）；二是板级硬件与启动链工程（供电可靠性、总线与电平、启动介质改写与克隆、固件持久化）。来源只有一本单板机工程手册《Hacking Raspberry Pi》，作者未涉及固件逆向、JTAG、无线破解，因此本域能力边界严格收敛到书中有原文依据的部分。

## 能力地图

| 二级分类 | 能力 slug | 中文标题 | 重要性 | promotion |
|---|---|---|---|---|
| 侦察 | `device-discovery-exposure-assessment` | 设备发现与暴露面评估 | high | promoted |
| 工具链 | `covert-remote-access-chain` | 远程隐身接入链路的搭建与保护范围判定 | medium | router |
| 工具链 | `board-bus-peripheral-interfacing` | 板级总线与外设连接 | high | router |
| 工程化 | `remote-node-addressing` | 远程节点寻址与现场部署 | medium | router |
| 工程化 | `power-supply-hardware-reliability` | 供电与硬件可靠性排查 | high | router |
| 工程化 | `embedded-task-persistence` | 嵌入式任务持久化：MCU 固件与 cron | medium | router |
| 审计 | `default-creds-minimal-services` | 默认凭据与最小服务加固 | critical | promoted |
| 逆向分析 | `boot-chain-card-imaging` | 启动链与整卡镜像操作 | critical | promoted |

分类覆盖：侦察(1)、工具链(2)、工程化(3)、审计(1)、逆向分析(1) — 5/5 全覆盖。共 8 个能力，3 个 promoted（上限 3）。

## 域的共性失败模式

1. **把物理层症状误判为软件 bug**：随机重启/SD 卡坏先查供电，不是先改代码；判据是换电源后现象消失，而非看日志。
2. **把"匿名"当"机密"**：VPN/Tor 只解决"谁在访问"，不解决"内容是否可读"；出口段明文照样被嗅探。
3. **把"扫不到/看不到"当"不存在"**：隐藏 SSID 不出现在扫描列表，OUI 会随外接网卡漂移，静态地址/设备可能只是换了地址。
4. **把"有 5V 引脚"当"IO 能承受 5V 逻辑"**：GPIO 无过压保护，I2C 主从配错会烧板；电源轨与信号电平是两种失效。
5. **把可清除痕迹当不可伪造证据**：启动分区、日志都可改可删；只有 OTP/熔丝这类硬件层一次性标记才不可逆，且只覆盖厂商定义的越界参数。
6. **照抄过时口径/命令**：书中 cron 六字段含 Year（主流五字段）、`raspi-blacklist.conf`（新版用 `dtparam=spi=on`）、Model B 500/700mA 口径不一、`sysv-rc-conf` 在 systemd 无效——均须以当前平台 man/文档为准。
7. **dd 选错 `of=` 或大卡恢复小卡**：整卡按字节复制时节点写错会覆盖本机盘（"Data Destroyer"），容量不匹配会截断。
8. **改配置失联无回滚**：静态地址配错、盲关服务/console、改坏内核且不知 Shift 旁路，都把可恢复问题变成重装或彻底失联。

## 覆盖说明：书贡献了哪些能力

唯一来源书《Hacking Raspberry Pi》按章节贡献如下：

- **Chapter 17（VPN/代理/Tor/地理定位）**：贡献 `covert-remote-access-chain`（01/02/03）与 `device-discovery-exposure-assessment` 的被动暴露部分（09）。
- **Chapter 15（公网暴露）**：贡献 `remote-node-addressing`（04）。
- **Chapter 16（电池/延时摄影 cron）**：贡献 `power-supply-hardware-reliability` 的续航部分（05）与 `embedded-task-persistence` 的 cron 部分（22）。
- **Chapter 2 / 18（供电/超频/启动分区/最小服务）**：贡献 `power-supply-hardware-reliability` 的供电与旁路部分（06/07）、`default-creds-minimal-services`（13/14）、`boot-chain-card-imaging` 的启动分区与 OTP 部分（15/17）。
- **Chapter 7（无头/SSH/VNC/Wi-Fi）**：贡献 `device-discovery-exposure-assessment` 的发现与隐藏 SSID 部分（08/10）、`default-creds-minimal-services` 的默认凭据与明文 VNC 部分（11/12）。
- **Chapter 4 / 5（SD 卡刷写/分区）**：贡献 `boot-chain-card-imaging` 的整卡克隆部分（16）与启动分区事实（15）。
- **Chapter 19 / 20（Arduino/I2C/SPI/GPIO）**：贡献 `embedded-task-persistence` 的 MCU 固件部分（21）与 `board-bus-peripheral-interfacing`（18/19/20）。

22 个候选单元全部并入 8 个能力，无丢弃、无独立 router 单元。详见 `coverage-audit.md`。
