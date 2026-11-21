---
name: blue-team-ir-suite
description: |
  应急响应与蓝队防守的能力包。当用户的主机疑似被入侵要排查、要按顺序取证、要判断某个异常进程/计划任务/网络连接是不是后门、要处置勒索或挖矿事件、要从日志里定位入侵入口、要建检测规则、或要设计企业安全防护体系时使用。覆盖：应急响应流程与取证顺序、Windows/Linux 持久化点排查、日志与流量分析、事件分级、溯源反制、检测工程、蓝队体系与实战演习组织。不适用于：主动攻击与渗透测试（走 web-security-suite / intranet-redteam-suite）。
metadata:
  cangjie.generated-by: cangjie-tools v2.5.0
  cangjie.variant: single
  cangjie.bundle-id: bundle.blue-team-ir-suite
  cangjie.capability-count: 15
  cangjie.entrypoint-count: 1
---
# 应急响应与蓝队 — 全书能力入口

## 触发与不触发

**适用**：与本书能力域相关的咨询与任务（见下方路由表的意图列）。
**不适用**：
- 对目标实施攻击或渗透
- 漏洞挖掘与利用开发
- 纯合规条文抄写

## 核心原则（常驻速览，概览类问题读到这里即可回答）

1. 先止损再取证，但止损动作本身不能销毁证据
2. 取证顺序由易失性决定：内存与网络连接先于磁盘，磁盘先于日志归档
3. 任何结论都要有至少两个独立证据源交叉验证
4. 检测规则必须可维护，宁少而准不要多而扰
5. 先确认可见性再谈检测：没有日志的地方等于盲区

## 能力路由（先读本表，按意图加载 1 张能力卡）

| 用户意图 | 先读 | 补读/备注 |
|---|---|---|
| 演习/实战后需要给出"攻击方是谁"的结论，而不是只有 IP。；收到钓鱼邮件，需要判断是谁发的、是否与已知团伙相关。；有扫描器/爆破工具在打自己的蜜罐，想反查其来源与工具使用者。 | references/capabilities/attacker-attribution.md | references/capabilities/incident-scoping.md、references/capabilities/containment-decisions.md、references/capabilities/detection-validation-coverage.md |
| 事件刚确认，需要决定"先断网还是先取证""要不要关机"。；勒索正在进行，需要判断先隔离、先查备份还是先解密。；一线人员还在路上，需要给现场人员一个"现在就做"的动作。 | references/capabilities/containment-decisions.md | references/capabilities/ir-evidence-order.md、references/capabilities/incident-scoping.md、references/capabilities/persistence-sweep-windows.md |
| 要从零搭蓝队能力，或给现有能力排优先级（"先上 SIEM 还是先做资产"）。；年度预算/规划要回答"下一步该投什么"，且需要解释"为什么现在不买某类产品"。；攻防演习前需要收缩攻击面。 | references/capabilities/defense-readiness-baseline.md | references/capabilities/detection-validation-coverage.md、references/capabilities/detection-rule-engineering.md、references/capabilities/containment-decisions.md、references/capabilities/incident-scoping.md |
| 要写检测规则，但不知道从哪下手、写到什么程度算合格。；规则写了却不生效，或某类设备的日志从来没有告警。；告警太多、一线开始批量忽略，需要降噪但不丢真阳性。 | references/capabilities/detection-rule-engineering.md | references/capabilities/detection-validation-coverage.md、references/capabilities/log-forensics-integrity.md、references/capabilities/traffic-hunt-c2.md |
| 要回答"我们的检测能力到底怎么样"，而不是"我们买了什么"。；攻击进来了但没告警，需要归因（规则？覆盖？平台？人？）。；需要向管理层/审计证明管控措施"确实在工作"。 | references/capabilities/detection-validation-coverage.md | references/capabilities/detection-rule-engineering.md、references/capabilities/defense-readiness-baseline.md、references/capabilities/traffic-hunt-c2.md |
| 拿到一台可疑主机（或一批），需要一份"从哪查起、查到什么算完"的清单。；单点排查已经做过（只看了进程/只看了启动项），但给不出结论，怀疑有遗漏。；需要交叉验证某条线索：告警说是木马，但进程列表看起来正常。 | references/capabilities/host-triage-parallel.md | references/capabilities/ir-evidence-order.md、references/capabilities/persistence-sweep-windows.md、references/capabilities/log-forensics-integrity.md |
| 一台机器确认失陷，需要回答"还有没有别的机器"。；需要写事件报告的"影响范围"章节，但只有零散证据。；内网失陷但不知道入口，日志多处缺失。 | references/capabilities/incident-scoping.md | references/capabilities/ir-evidence-order.md、references/capabilities/containment-decisions.md、references/capabilities/attacker-attribution.md |
| 客户/领导说"机器中招了，先杀毒重启吧"，需要有人把顺序掰回来。；刚接手一个已确认的入侵事件，需要一份"现在这一步做什么、交付什么"的作业单。；需要在"业务止血"和"证据保全"之间做取舍，且必须向非技术方解释理由。 | references/capabilities/ir-evidence-order.md | references/capabilities/containment-decisions.md、references/capabilities/host-triage-parallel.md、references/capabilities/incident-scoping.md |
| 需要在不能装 EDR/Sysmon 的客户环境里，用便携工具完成取证。；怀疑文件被占用/删了又出现，需要找持有者。；需要在不执行样本的前提下读懂宏/脚本逻辑。 | references/capabilities/ir-toolchain.md | references/capabilities/host-triage-parallel.md、references/capabilities/persistence-sweep-windows.md、references/capabilities/log-forensics-integrity.md |
| 攻击者明显清过日志（history 空、日志有断层），需要判断"还能不能还原"。；需要判断某份日志能不能作为结论依据（而不是"日志里这么写的"）。；需要从"日志缺失"反推攻击时间窗与操作范围。 | references/capabilities/log-forensics-integrity.md | references/capabilities/host-triage-parallel.md、references/capabilities/traffic-hunt-c2.md、references/capabilities/detection-rule-engineering.md |
| 木马清完重启又活，Autoruns / 任务计划程序 / services.msc 都"看着干净"。；端口在监听但找不到服务；服务列表里有一项配置页打不开。；需要给一台机器做"是否仍有驻留"的终局确认（善后阶段）。 | references/capabilities/persistence-sweep-windows.md | references/capabilities/host-triage-parallel.md、references/capabilities/ir-evidence-order.md、references/capabilities/log-forensics-integrity.md |
| 只有 NetFlow/全流量，没有解密能力，需要判断"有没有 C2"。；IDS 说没问题，但主机侧明显异常（CPU 高、DNS 请求暴增），怀疑隧道。；需要区分"正常的大流量"与"数据外传"。 | references/capabilities/traffic-hunt-c2.md | references/capabilities/log-forensics-integrity.md、references/capabilities/ir-toolchain.md、references/capabilities/detection-rule-engineering.md |
| 遇到「我们要搞攻防演练」时，查本域 OCR 增补材料中的对应方法与判据；遇到「蓝队怎么准备」时，查本域 OCR 增补材料中的对应方法与判据；遇到「演练复盘怎么做」时，查本域 OCR 增补材料中的对应方法与判据 | references/capabilities/ocr-framework-judgement.md | references/capabilities/attacker-attribution.md、references/capabilities/containment-decisions.md |
| 遇到「指标体系怎么建」时，查本域 OCR 增补材料中的对应方法与判据；遇到「Delphi 法怎么用」时，查本域 OCR 增补材料中的对应方法与判据；遇到「专家调查表几轮」时，查本域 OCR 增补材料中的对应方法与判据 | references/capabilities/ocr-recipe-troubleshooting.md | references/capabilities/attacker-attribution.md、references/capabilities/containment-decisions.md |
| 遇到「策略优化怎么做」时，查本域 OCR 增补材料中的对应方法与判据；遇到「为什么不能拆东墙补西墙」时，查本域 OCR 增补材料中的对应方法与判据；遇到「安全管理策略要审什么」时，查本域 OCR 增补材料中的对应方法与判据 | references/capabilities/ocr-counter-example.md | references/capabilities/attacker-attribution.md、references/capabilities/containment-decisions.md |

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

- 可能破坏证据的操作（重启、格式化、清日志）一律先停止并确认
- 事件仍在扩散时优先隔离，取证让位于止损
- 无法确认样本性质时先在隔离环境分析，不在生产机执行
