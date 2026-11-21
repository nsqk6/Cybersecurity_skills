# 应急响应与蓝队 — 术语与能力速查

## 能力速查（每条含义取自对应能力卡的 I 段）

| 术语 / 能力 | 英文或 slug | 在本域语境下的含义 |
|---|---|---|
| 攻击者身份溯源 | `attacker-attribution` | 这个能力解决的问题是： 已有攻击者的某个锚点（一个 uid、一个域名、一封邮件、一次扫描连接），能不能收敛到"是谁" |
| 抑制与隔离决策 | `containment-decisions` | 这个能力解决的问题是： 事件正在发生，必须立刻决定"断什么、不断什么、先救什么" |
| 蓝队基础能力建设与暴露面收敛 | `defense-readiness-baseline` | 这个能力解决的问题是： 预算、人力、时间都有限，蓝队能力应该按什么顺序建，才不会建出一堆互不衔接的设备和规则 |
| 检测规则与日志管道工程 | `detection-rule-engineering` | 这个能力解决的问题是： 告警写了一堆，但要么不响，要么响得没人看 |
| 检测覆盖度与有效性验证 | `detection-validation-coverage` | 这个能力解决的问题是： "设备装了、规则写了、告警没响"，到底是没攻击，还是坏了 |
| 主机现场多线并行排查 | `host-triage-parallel` | 这个能力解决的问题是： 拿到一台（或一批）可疑主机，不知道从哪查起，也不知道查到什么程度算查完 |
| 影响范围圈定与攻击链回溯 | `incident-scoping` | 这个能力解决的问题是： 一台机器确认失陷后，"还有没有别的"和"从哪进来的"这两个问题都必须回答，否则清理等于没做 |
| 应急响应取证与处置顺序 | `ir-evidence-order` | 这个能力解决的问题是： 事件已确认，但现场只有一次，而接下来每一个动作都会销毁一部分证据 |
| 应急工具链与样本快检 | `ir-toolchain` | 这个能力解决的问题是： 方法知道了，但手上该拿什么工具、以什么顺序跑、哪些参数会让证据消失 |
| 日志取证与完整性反推 | `log-forensics-integrity` | 这个能力解决的问题是： 攻击者会清日志，而"日志里没有可疑记录"到底是"没发生"还是"被删了"，必须能区分 |
| Windows 持久化点全量排查 | `persistence-sweep-windows` | 这个能力解决的问题是： "重启之后木马又活了，但 Autoruns / 任务计划程序 / services.msc 里找不到 |
| 流量形状与隐蔽信道狩猎 | `traffic-hunt-c2` | 这个能力解决的问题是： 流量全程加密、没有解密能力，甚至没有已知恶意 IOC，还能不能发现 C2 与外传 |

## 卡片中出现的英文术语

- `Reading`（见对应能力卡上下文）
- `Interpretation`（见对应能力卡上下文）
- `Application Example`（见对应能力卡上下文）
- `filename`（见对应能力卡上下文）
- `Future Trigger`（见对应能力卡上下文）
- `Execution`（见对应能力卡上下文）
- `Boundary`（见对应能力卡上下文）
- `ACL/VLAN`（见对应能力卡上下文）
- `OK/Fault/Diff/N/A`（见对应能力卡上下文）
- `PID`（见对应能力卡上下文）
- `suspend`（见对应能力卡上下文）
- `resume`（见对应能力卡上下文）
- `Sysinternals/Sysmon/EDR`（见对应能力卡上下文）
- `capture filter vs display filter`（见对应能力卡上下文）
- `Macro`（见对应能力卡上下文）
- `start/stop/ping`（见对应能力卡上下文）
- `remote template injection`（见对应能力卡上下文）
- `DumpIt/FTK/Volatility`（见对应能力卡上下文）
- `utmp/wtmp/lastlog`（见对应能力卡上下文）
- `T1137`（见对应能力卡上下文）
- `Actions/Triggers`（见对应能力卡上下文）
- `SDDL`（见对应能力卡上下文）
- `ADS`（见对应能力卡上下文）
- `Administrator`（见对应能力卡上下文）
- `DGA`（见对应能力卡上下文）
- `TXT/MX/CNAME`（见对应能力卡上下文）
- `Windows`（见对应能力卡上下文）
- `Linux`（见对应能力卡上下文）
- `domain fronting`（见对应能力卡上下文）
- `JA3/JA4`（见对应能力卡上下文）

> 术语释义以能力卡正文为准；本表只做索引，不另作解释。
