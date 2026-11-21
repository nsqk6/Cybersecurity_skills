# AI与大模型安全 — 域总览

## 这个域在真实工作中解决什么问题

当 Agent 从「回答问题」走向「读外部内容并动手改世界」，安全问题从内容合规变成行为控制：网页、PDF、邮件、工具返回都可能携带指令，工具组合起来能把私有数据送出去，超时重试会把一次转账变成两次，自我进化会把一次注入固化成跨会话的常驻能力。本域的能力覆盖从上下文信任边界、工具接入与运行时门控、检索与记忆持久化、服务端真值与执行兜底，到整体纵深架构与护栏评估、越狱载荷归因与对抗奖励判断的完整链路。它服务的真实任务是：让 Agent 在不可信输入面前「能读不被劫持、能调不被滥用、能记不被污染、能错不被放大」，并且在面对攻击载荷时能判清它落在哪一层、该往哪加固。

## 能力地图

| 二级分类 | 能力（slug） | 中文标题 | 晋级 | 一句话决策规则 |
|---|---|---|---|---|
| 服务端逻辑 | `defense-in-depth-architecture` | Agent 三层护栏与独立审查架构 | promoted | 按被绕过难度排三层护栏，复核迁出同一上下文并双向评估 |
| 服务端逻辑 | `prompt-injection-surface-and-separation` | 注入面清点与指令/数据分离 | promoted | 按工具清点入口与隐蔽载体，来源标记+角色分离并把封堵落到执行侧 |
| 审计 | `tool-supply-chain-vetting` | 第三方工具/MCP/Skill 准入审查 | promoted | 四元组判组合、description 当不可信文本审、tool_filter 收窄能力面 |
| 审计 | `jailbreak-prompt-construction` | 越狱提示词构造与失效判定 | promoted | 按七个失效层归类手法，用跨模型与时代判据判有效性并给对称防守面 |
| 服务端逻辑 | `execution-safety-and-server-truth` | 工具执行安全与服务端真值校验 | router | 事实取服务端真值，调用前门控+语义解析+隔离，不可逆两段式不重试 |
| 审计 | `exposure-and-consequence-taxonomy` | 泄露面与攻击后果分类判据 | router | 四类口径盘点泄露，按后果落层区分注入与越狱再路由 |
| 服务端逻辑 | `rag-permission-and-poisoning-defense` | RAG 权限过滤与投毒注入防御 | router | ACL 下推召回阶段，检索内容只许改措辞不许触发副作用 |
| 工程化 | `memory-and-self-evolution-boundaries` | 记忆与自进化安全边界 | router | 状态栏代码维护，反思输入分可信，自改写进待验证区且安全机制只读 |
| 服务端逻辑 | `agent-trust-boundary` | 委托忠诚与多 Agent 信任边界 | router | Harness 层写死忠诚守则，A2A 用 mTLS+审计+header 凭证 |
| 工具链 | `ai-assisted-vuln-research` | AI 辅助漏洞研究与 POC 迭代 | router | 双阶段造助手，走背景→研究→生成 POC→反馈迭代四步 |
| 服务端逻辑 | `adversarial-reward-and-game-deception` | 对抗奖励操纵与博弈欺骗边界 | router | 随机化 Hedge/Exp3 替代贪心，一次性交互改造成可报复的重复博弈 |

- 共 11 个能力，4 个 promoted（对外独立入口，已达上限），7 个 router（域内路由入口）。
- 二级分类覆盖：服务端逻辑 6、审计 3、工程化 1、工具链 1，四个指定枚举全部覆盖。
- 45 个候选单元全部落卡，无遗漏无重复；单元与能力的映射见 `books/ai-security/coverage-audit.md`。

## 域的共性失败模式

1. **同一上下文自证清白**：注入内容与判定依据住在一起，模型对「我是否被操纵」的判断本身可被操纵；任何同上下文产出只能算建议。
2. **只做上下文层就以为防住注入**：提示词警告 + 输入过滤只降成功率，缺执行层与数据层兜底；来源标记挡不住"照做"。
3. **逐项合规、合起来外传**：单看每个工具都合理，私有数据 + 不可信内容 + 对外通道三者齐备即闭合攻击链，持久记忆再把它放大成跨会话。
4. **把模型自报当事实**：`cabin_class`、`current_time` 等由模型填参，守门逻辑被一个错误值绕过；`expected_*` checklist 只是自我陈述，不承担安全责任。
5. **信息进上下文后才过滤**：越权文档一旦被召回，生成阶段无法可靠剔除；生成后过滤只能兜底。
6. **高信任通道被投毒**：状态栏/`<system-reminder>` 紧邻待生成 token，模型几乎无条件相信；程序记忆自改写更把注入固化成常驻指令。
7. **字符串规则被等价变形绕过**：`$(echo rm)`、`find -exec`、`curl -o /etc/...` 让关键字黑名单失效；venv 被误当隔离。
8. **指标方向性错误**：只测拦截率把护栏调成误拒绝机器，「有歧义就判合规」把边界样本系统性放行，两者都让安全指标与真实可用性脱节。
9. **把模板当成品**：越狱/注入载荷的有效性依赖 `Prompt × AI 理解 = 输出质量`，换模型需重调；安全水位提升使"直接索取"型手法整体过时。
10. **确定性即脆弱**：策略固定不变时对抗者可把自己收益最大化（后悔值 RE⩾n/2），一次性交互无未来追责时对方敢欺骗背叛。

## 覆盖说明：哪些书贡献了哪些能力

- **《深入理解AI AGENT-zh-CN》**（主来源，贡献 16 个单元，覆盖 8 张卡）：
  - 1.2.5 护栏分层、误拒绝 → `defense-in-depth-architecture`
  - 2.4.7 提示注入、来源标记、状态栏投毒、Skill 审查 → `prompt-injection-surface-and-separation`、`tool-supply-chain-vetting`
  - 2.6.4 状态更新 → `memory-and-self-evolution-boundaries`
  - 3.2 RAG 权限过滤与注入边界 → `rag-permission-and-poisoning-defense`
  - 4.3 MCP 与 Skill Hub → `tool-supply-chain-vetting`
  - 4.6 执行工具（Sidecar、隔离、幂等） → `execution-safety-and-server-truth`、`defense-in-depth-architecture`
  - 5.1.9 Coding Agent 安全（致命三要素、语义解析、忠诚、隔离） → `tool-supply-chain-vetting`、`execution-safety-and-server-truth`、`agent-trust-boundary`
  - 5.2.2 代码作为业务规则约束 → `execution-safety-and-server-truth`
  - 9.3.2 持续进化安全边界 → `memory-and-self-evolution-boundaries`
- **《Agentic Design Patterns》**（贡献 4 个单元）：
  - 第 4 章 反思 → `defense-in-depth-architecture`
  - 第 8 章 记忆管理（程序记忆自改写为架构事实，注入风险为显式标注的安全推论） → `memory-and-self-evolution-boundaries`
  - 第 10 章 MCP → `tool-supply-chain-vetting`
  - 第 15 章 A2A → `agent-trust-boundary`
  - 第 18 章 Guardrails（歧义默认放行反例、before_tool_callback） → `defense-in-depth-architecture`、`execution-safety-and-server-truth`
- **《Prompt 越狱手册》**（batch-2 新增，贡献 16 个单元，覆盖 5 张卡）：
  - 直接/间接/代码库注入 → `prompt-injection-surface-and-separation`、`exposure-and-consequence-taxonomy`
  - Prompt 泄露四类口径、注入与越狱后果区分 → `exposure-and-consequence-taxonomy`
  - 角色扮演、虚拟化、令牌拆分、CO-STAR 框架融合、目标嵌套、多语调、反馈词、模板失效、安全水位 → `jailbreak-prompt-construction`
  - 米斯特漏洞助手、四步 POC 工作流 → `ai-assisted-vuln-research`
- **《深度强化学习（中文版-彩色）》**（batch-2 新增，贡献 4 个单元）：
  - 第 2 章对抗多臂赌博机（奖励诱惑、确定性玩家脆弱、Hedge/Exp3）与第 12 章静态/重复博弈 → `adversarial-reward-and-game-deception`
  - 其余「对抗」命中多为 GAN/GAIL 生成对抗训练，按候选批次无产出登记不硬凑。
- **事实/推论纪律**：`memory-and-self-evolution-boundaries` 卡的「反思写入常驻指令」、`adversarial-reward-and-game-deception` 卡的「迁移到已部署自适应系统」、`exposure-and-consequence-taxonomy` 卡的「后果落层判据」均为安全推论，已逐处标注原文句依据与推理链，未写成作者结论。
