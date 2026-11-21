---
name: hardware-iot-suite
description: |
  硬件与物联网设备安全的能力包。当用户要评估嵌入式设备/路由器/IPC/车机的安全性、要从固件里提取文件系统与凭证、要判断物理接口（UART/JTAG/SPI）能不能进、要分析无线（WiFi/蓝牙/RF）攻击面、或要测设备 Web 管理界面时使用。覆盖：设备侦察与拆解、固件提取与解包、文件系统分析、硬编码凭证与后门、物理接口接入、无线攻击面、设备 Web 界面测试、车联网攻击面。不适用于：通用 Web 站点（走 web-security-suite）、纯软件逆向（走 reverse-binary-suite）。
metadata:
  cangjie.generated-by: cangjie-tools v2.5.0
  cangjie.variant: single
  cangjie.bundle-id: bundle.hardware-iot-suite
  cangjie.capability-count: 10
  cangjie.entrypoint-count: 1
---
# 硬件与物联网安全 — 全书能力入口

## 触发与不触发

**适用**：与本书能力域相关的咨询与任务（见下方路由表的意图列）。
**不适用**：
- 对非自有设备的物理破坏
- 无线电频谱的非法发射
- 量产设备的批量刷机

## 核心原则（常驻速览，概览类问题读到这里即可回答）

1. 硬件先看接口再看固件：能上 console 时固件分析会快一个量级
2. 固件里的凭证与密钥是最高价值产出
3. 设备的 Web 界面通常比通用 Web 更脆弱，但兼容性限制更多
4. 结论必须绑定硬件版本与固件版本
5. 动手前先备份原始固件，刷坏不可逆

## 能力路由（先读本表，按意图加载 1 张能力卡）

| 用户意图 | 先读 | 补读/备注 |
|---|---|---|
| 在网段里定位一台无屏幕的板卡；判断预期 Wi-Fi 扫不到是隐藏还是不存在；评估设备公开登记/资产清单的暴露风险 | references/capabilities/device-discovery-exposure-assessment.md | references/capabilities/default-creds-minimal-services.md、references/capabilities/covert-remote-access-chain.md、references/capabilities/boot-chain-card-imaging.md |
| 搭一台长期在线的低成本出口盒；做随身多宿主接入点把不可信上联转成自有入口；判断某链路能否承载敏感凭据 | references/capabilities/covert-remote-access-chain.md | references/capabilities/remote-node-addressing.md、references/capabilities/device-discovery-exposure-assessment.md、references/capabilities/default-creds-minimal-services.md |
| 让部署在外的设备可被稳定寻址；为端口转发/监控提供固定内网地址；动态公网IP变化时保持域名可达 | references/capabilities/remote-node-addressing.md | references/capabilities/covert-remote-access-chain.md、references/capabilities/device-discovery-exposure-assessment.md、references/capabilities/default-creds-minimal-services.md |
| 修补出厂默认凭据与默认开启的远程服务；确认远程管理通道是否明文传输；按最小服务原则裁剪开机自启项 | references/capabilities/default-creds-minimal-services.md | references/capabilities/device-discovery-exposure-assessment.md、references/capabilities/covert-remote-access-chain.md、references/capabilities/remote-node-addressing.md |
| 排查随机重启/SD卡坏是否供电引起；定量估算电池续航与供电余量；超频改坏后一次性旁路恢复 | references/capabilities/power-supply-hardware-reliability.md | references/capabilities/board-bus-peripheral-interfacing.md、references/capabilities/boot-chain-card-imaging.md、references/capabilities/remote-node-addressing.md |
| 打开SPI/I2C等被黑名单禁用的总线；在USB/串口/I2C间选型连接两块板卡；跨3.3V/5V连接时避免烧板 | references/capabilities/board-bus-peripheral-interfacing.md | references/capabilities/power-supply-hardware-reliability.md、references/capabilities/boot-chain-card-imaging.md、references/capabilities/embedded-task-persistence.md |
| 枚举并评估启动分区可改组件；整卡克隆/还原做批量部署或取证镜像；用芯片内一次性标记判断设备是否被超规格使用 | references/capabilities/boot-chain-card-imaging.md | references/capabilities/power-supply-hardware-reliability.md、references/capabilities/device-discovery-exposure-assessment.md、references/capabilities/board-bus-peripheral-interfacing.md |
| 让设备断电重启后仍持续做一件事；判断该用MCU还是SBC+cron；配置系统级周期任务并排查cron不生效 | references/capabilities/embedded-task-persistence.md | references/capabilities/board-bus-peripheral-interfacing.md、references/capabilities/default-creds-minimal-services.md、references/capabilities/boot-chain-card-imaging.md |
| 遇到「目标内网只允许出站」时，查本域 OCR 增补材料中的对应方法与判据；遇到「physical drop pentest device」时，查本域 OCR 增补材料中的对应方法与判据；遇到「树莓派 内网 反向 ssh」时，查本域 OCR 增补材料中的对应方法与判据 | references/capabilities/ocr-framework-judgement.md | references/capabilities/device-discovery-exposure-assessment.md、references/capabilities/covert-remote-access-chain.md |
| 遇到「autossh -M 反向 ssh 持久化」时，查本域 OCR 增补材料中的对应方法与判据；遇到「rc.local 启动 reverse ssh」时，查本域 OCR 增补材料中的对应方法与判据；遇到「ssh -NfR 10000:localhost:22」时，查本域 OCR 增补材料中的对应方法与判据 | references/capabilities/ocr-recipe-troubleshooting.md | references/capabilities/device-discovery-exposure-assessment.md、references/capabilities/covert-remote-access-chain.md |

**非能力类查询**：
- 书名/作者/章节/整书概览 → references/overview.md
- 术语解释 → references/glossary.md
- 决策规则速查（不需要原文依据时） → references/cheatsheet.md
- 完整意图与关键词索引（本表未覆盖的意图先查这里） → references/capability-index.md

## 加载规则

- 每次任务先读本文件，再按路由表加载 **1** 张能力卡；任务明确跨域时最多加载 2 张。
- 概览/书名类问题不加载能力卡，用「核心原则」与 overview.md 回答。
- 路由表与 capability-index.md 都无法命中的意图，明确告知超出本书范围，不要硬套。

## 边界与判停

- 拆解可能导致设备不可恢复时先确认可否承担
- 涉及无线电发射时确认当地法规与授权
- 固件未备份前不执行写入操作
