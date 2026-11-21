---
name: ai-llm-security-suite
description: |
  AI 与大模型安全的能力包。当用户要评估一个 LLM 应用/Agent 的安全性、要测提示注入与越狱能不能突破约束、要分析 RAG 与工具调用的信任边界、要判断模型输出被污染的影响、或要设计 Agent 系统的权限隔离时使用。覆盖：提示注入与越狱、上下文与指令层级、RAG 投毒与检索边界、工具调用与 Agent 权限、输出处理与下游注入、模型与数据面风险、防护与评测。不适用于：传统 Web 漏洞（走 web-security-suite）、模型训练与调优。
metadata:
  cangjie.generated-by: cangjie-tools v2.5.0
  cangjie.variant: single
  cangjie.bundle-id: bundle.ai-llm-security-suite
  cangjie.capability-count: 11
  cangjie.entrypoint-count: 1
---
# AI与大模型安全 — 全书能力入口

## 触发与不触发

**适用**：与本书能力域相关的咨询与任务（见下方路由表的意图列）。
**不适用**：
- 模型训练、微调与对齐研究
- 对第三方服务的滥用与资源消耗攻击
- 生成违法或有害内容的越狱请求

## 核心原则（常驻速览，概览类问题读到这里即可回答）

1. LLM 没有可靠的安全边界：系统提示不是强制约束，只是强偏好
2. 区分「模型被说服」与「系统被攻破」，后者才是有实质危害的漏洞
3. 凡是模型输出进入下游执行链的地方都是注入点
4. Agent 的危害等于它持有的工具权限，权限审计优先于提示词加固
5. 评测要可复现：同一提示在不同模型/温度下结果不同，必须固定条件

## 能力路由（先读本表，按意图加载 1 张能力卡）

| 用户意图 | 先读 | 补读/备注 |
|---|---|---|
| 设计 Agent 纵深防御的层次与投入顺序；把模型自审迁移为外置独立复核；用提议者-审核者与换模态做事前审批和事后验证；建立双向回归集，治理误拒绝与默认放行 | references/capabilities/defense-in-depth-architecture.md | references/capabilities/prompt-injection-surface-and-separation.md、references/capabilities/execution-safety-and-server-truth.md、references/capabilities/tool-supply-chain-vetting.md |
| 清点新增感知工具带来的注入入口与隐蔽载体；用来源标记与 Chat Template 角色做指令/数据分离；识别直接/间接/代码库三类注入载荷并定位失效层；新工具上线前跑注入回归 | references/capabilities/prompt-injection-surface-and-separation.md | references/capabilities/defense-in-depth-architecture.md、references/capabilities/rag-permission-and-poisoning-defense.md、references/capabilities/jailbreak-prompt-construction.md |
| 按四类口径盘点 Prompt 敏感信息泄露面；判定一次攻击的后果落在文本还是真实系统；两者兼有时按更高危的注入面处置；记录判定依据，避免把推论写成作者结论 | references/capabilities/exposure-and-consequence-taxonomy.md | references/capabilities/prompt-injection-surface-and-separation.md、references/capabilities/jailbreak-prompt-construction.md、references/capabilities/defense-in-depth-architecture.md |
| 评估第三方 MCP/Skill/Tool 是否可安全接入；判定工具组合是否构成高危攻击链；审计 description 投毒、同名遮蔽与 Skill 脚本；用 tool_filter 与绝对路径根目录做最小暴露 | references/capabilities/tool-supply-chain-vetting.md | references/capabilities/execution-safety-and-server-truth.md、references/capabilities/prompt-injection-surface-and-separation.md、references/capabilities/defense-in-depth-architecture.md |
| 把策略判定事实从模型自报改为服务端查库；用 Sidecar 与调用前回调拦截单次高危调用；用语义解析拦下 shell 命令的等价变形；选隔离层级、控网络出口并为不可逆操作两段式 | references/capabilities/execution-safety-and-server-truth.md | references/capabilities/tool-supply-chain-vetting.md、references/capabilities/defense-in-depth-architecture.md、references/capabilities/prompt-injection-surface-and-separation.md |
| 保证多租户知识库检索不越权、不串味；审计召回命中以支持事后回溯；防止知识库投毒与检索内容触发副作用；入库内容做投毒审查 | references/capabilities/rag-permission-and-poisoning-defense.md | references/capabilities/prompt-injection-surface-and-separation.md、references/capabilities/memory-and-self-evolution-boundaries.md、references/capabilities/execution-safety-and-server-truth.md |
| 防止状态栏/系统提醒被写成高信任注入点；防止注入经反思通道固化为常驻指令；为自进化系统划三条不可越边界；保留版本与 diff 审计以支持回滚 | references/capabilities/memory-and-self-evolution-boundaries.md | references/capabilities/rag-permission-and-poisoning-defense.md、references/capabilities/defense-in-depth-architecture.md、references/capabilities/tool-supply-chain-vetting.md |
| 规定多方委托下 Agent 效忠谁、对外说什么；测试泄底价、过度拒绝与重复施压三个失效轴；为 A2A 配 mTLS、审计与凭证基线；保护 Agent Card 发现端点 | references/capabilities/agent-trust-boundary.md | references/capabilities/prompt-injection-surface-and-separation.md、references/capabilities/adversarial-reward-and-game-deception.md、references/capabilities/defense-in-depth-architecture.md |
| 识别角色扮演/虚拟化/令牌拆分/框架融合等手法与失效层；判定模板跨模型是否可移植；判定直接索取手法是否已因安全水位提升而失效；为每种失效层给出对称防守面建议 | references/capabilities/jailbreak-prompt-construction.md | references/capabilities/exposure-and-consequence-taxonomy.md、references/capabilities/ai-assisted-vuln-research.md、references/capabilities/prompt-injection-surface-and-separation.md |
| 构造双阶段漏洞助手提示词；走 AI 辅助漏洞研究四步工作流；用测试反馈闭环把 POC 逼近触发；换模型时重调手法而非照搬模板 | references/capabilities/ai-assisted-vuln-research.md | references/capabilities/jailbreak-prompt-construction.md、references/capabilities/exposure-and-consequence-taxonomy.md、references/capabilities/tool-supply-chain-vetting.md |
| 判断奖励/反馈信号是否可被外部操纵；判对抗者类型与玩家确定性脆弱性；用 Hedge/Exp3 随机化加权抵抗自适应操纵；判静态/重复博弈的欺骗边界并设计可报复机制 | references/capabilities/adversarial-reward-and-game-deception.md | references/capabilities/agent-trust-boundary.md、references/capabilities/defense-in-depth-architecture.md、references/capabilities/jailbreak-prompt-construction.md |

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

- 验证会消耗大量第三方 API 配额时先确认
- 涉及真实用户数据的测试必须先脱敏
- 发现可执行任意工具的 Agent 时优先报告而非继续扩大利用
