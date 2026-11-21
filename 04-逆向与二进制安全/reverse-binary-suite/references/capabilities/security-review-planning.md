# 威胁建模与审计规划

## R — 原文 (Reading)

> This process is most effectively applied during the design (or a refactoring) phase of development and is updated as modifications are made in later development phases. It can, however, be integrated entirely at later phases of the SDLC.
> — 《The Art of Software Security Assessment》Ch2 Threat Modeling

> You shouldn't put too much effort into isolating security-related information yet because at this phase you aren't certain what's relevant to security.
> — 《The Art of Software Security Assessment》Ch2 Information Collection

> This application review process is divided into four basic phases: 1. Preassessment... 2. Application review—This phase is the primary phase of the assessment.
> — 《The Art of Software Security Assessment》Ch4 Process Outline

## I — 方法论骨架 (Interpretation)

这张卡解决「一次代码审计从哪下手、怎么排优先级、怎么在时间内交付」的问题。核心洞察是：审计最大的浪费是在不重要的模块上花时间，所以第一步不是读代码，而是产出一张「哪些组件值得先看」的排序表。

五阶段威胁建模是这张地图的生成器：① 收集信息（文档、访谈、源码轮廓）→ 列出资产、入口点、外部实体、外部信任级别、主要组件、使用场景六项；② 用 DFD 画架构（context → level-0 → level-1），标信任边界，每个跨边界箭头都能说出「谁校验数据」；③ 用攻击树枚举攻击路径，节点标 AND（缺任一子条件即不能达成父目标）或 OR（任一即可），根节点是攻击者目标而非漏洞类型；④ 对每条威胁写摘要并用 DREAD 五项（Damage/Reproducibility/Exploitability/Affected users/Discoverability）各打 1–10 分，总分÷5，≤3 低、4–7 中、≥8 高；⑤ 把威胁分累加到组件上，按分从高到低排审计顺序。缓解节点作为「降权」而非「删除」挂在树上，且必须验证真实生效后才加——过早把缓解当结论会淡化整条高危分支。

信息收集阶段有一条反直觉纪律：早期不要按「是否安全相关」过滤，因为你此时不确定什么相关；先广收，再用固定六要素收敛检查。文档类信息一律标「需对实现验证」——设计文档常与实现不符，照文档做模型会把已废弃的安全路径当有效；开发者访谈也需交叉验证，因为开发者本人的误解本身可能就是漏洞成因。

评审结构按文档可信度三选一：文档准确 → top-down（从威胁模型往实现推，但对判定「非安全相关」的路径追加抽查）；无文档/不可信 → hybrid（先确定六项高层特征做最小可用模型，边审边补，这是「更常见」的默认选择）；要最高彻底度且时间充足 → bottom-up（从实现归纳，每轮迭代后更新一份非正式设计模型）。执行节奏用四阶段 + 日循环：Preassessment 定目标/访问级别/时间盒；Application review 按 Plan（选 2–8 小时可达成目标）→ Work（详细记笔记）→ Reflect（自问：学到了什么 / 是否在最有价值组件上 / 是否钻牛角尖）日循环，每轮 Reflect 后重选策略；Documentation 按固定字段出报告（位置、类别、描述、前置条件、业务影响、修复、风险、严重性、概率）；Remediation support 复核修复是否真堵住、是否引入新问题。关键洞察是设计/逻辑类漏洞最容易在评审**末期**发现（那时对代码最熟），所以不要先把设计评审做完再进代码，而应作为并行目标反复回访。

工期用 KLOC 估算：100–1000 LOC/h 随语言/文档/风格变化，先抽样定系数再按组件算工时；>50KLOC 的项目按规模效应打折（前期建立模式识别，后续更快）；超支时从「组件风险分最低」处削减范围。最后，Web 应用实施期按五个交互面切分代码（参数、session、OS/文件、数据库、HTML 输出），把安全控制定位到具体代码，而不是通读业务模型。

## A1 — 应用示例 (Application Example)

### 示例 1: OpenSSH 无威胁模型时的替代路径
- **类型与来源**: 【转述】《The Art of Software Security Assessment》Ch4 Case Study: OpenSSH
- **问题/输入**: 对 OpenSSH 做实现评审，但没有现成威胁模型可用。
- **方法论的使用**: 不强行套五阶段建模，改用 RFC + 实现知识直接列攻击向量；按 preassessment → implementation analysis → high-level attack vectors → documentation 走完整四阶段；从 util/框架层逐行读建立基础认知，再按候选点法（CP1/CP3）压缩搜索空间；每轮 Reflect 后重选策略。
- **结论**: 五阶段地图是手段而非目的；当文档不可用时，hybrid 的「先用高层特征建最小模型、边审边补」比空转建模更有效。
- **结果**: 原书按此流程完成 OpenSSH 案例评审并产出报告。

### 示例 2: 用 DREAD 把威胁分落到组件上决定审计顺序
- **类型与来源**: 【转述】《The Art of Software Security Assessment》Ch2 Table 2-2（暴力破解登录威胁打分）
- **问题/输入**: 一个应用有多条威胁、多个组件，时间不够，先审哪个？
- **方法论的使用**: 对每条威胁按五维各打 1–10 分并记录明细（不只记总分），总分÷5 得威胁分；建立「组件 × 风险分」表，把每条威胁的分加到所属组件；从最高分组件开始审；同时按 KLOC 估算组件工时，把总工时与预算比对，超支则从最低风险分组件开始砍范围。
- **结论**: DREAD 的真正用法是第二步——把「威胁排序」转成「代码审计工作量分配」，而非对外披露评分。
- **结果**: 原书给出「暴力破解登录」威胁的五维打分示例；作者也承认有经验审计者可凭对同类系统的理解给出更优顺序，此时服从判断而非分数。

## A2 — 触发场景 (Future Trigger)

### 用户会在什么情境下需要它
1. 被要求「审一个项目」，但不知道从哪个模块开始、需要多少时间、怎么向客户解释优先级。
2. 没有设计文档或文档明显与实现不符，需要在 top-down / bottom-up / hybrid 之间做选择。
3. 审计进行到一半失去方向，或发现时间花在低价值模块上，需要重新校准节奏。
4. 需要一份结构化的审计报告字段模板，并复核修复是否真正堵住漏洞。

### 语言信号（出现这些就该激活）
- 中文：「这个项目从哪开始审」「先审哪块」「一次代码审计怎么安排」「没有设计文档怎么审」「top-down 还是 bottom-up」「这个项目要审多久」「报价怎么估」「审到一半没方向了」「这些漏洞怎么排优先级」
- English: "how do I scope a code review", "threat model this app", "how to structure a security assessment", "how long does a code review take", "top-down vs bottom-up audit", "how to rate severity"

### 与相邻能力的区分
- 与 `source-audit-dataflow` 的区别：本卡覆盖「评审前的地图 + 执行节奏 + 交付」（评审管理），那张卡覆盖「选定组件后怎么沿数据流找漏洞」（取材手法）；威胁建模的产物（组件风险分）正是那张卡的输入。
- 与 `injection-filter-audit` 的区别：Web 五交互面切分只是本卡的实施期入口定位，具体注入判定在那张卡。

## E — 可执行步骤 (Execution)

**必需输入**: 至少一项——设计文档 / 访谈 / 可运行实例 / 源码轮廓；明确交付时间与访问级别。完全无文档时退化为 hybrid 最小建模，但需标注「模型待验证」。

**交付物与完成标准**: ① 六要素清单（资产、入口点、外部实体、信任级别、组件、使用场景）；② DFD + 信任边界；③ AND/OR 攻击树；④ 威胁 DREAD 分与组件风险分表；⑤ 带工期的审计计划；⑥ 日循环笔记与最终报告（固定字段）。完成标准：每个组件都有风险分与工时估计，审计顺序可解释。

1. **收集信息（先广收后收敛）**
   - 做什么：不限主题收材料（设计/部署/用户文档、标准 RFC、源码轮廓、系统轮廓）；逐项填六要素；对每条信息标可信度，文档类标「需对实现验证」；开发者访谈做交叉验证。
   - 完成标准：六项都有具体条目而非「待定」。
   - 判停：若某要素只能靠文档且无法验证 → 标为假设，第 2 步画 DFD 时列为重点抽查对象。

2. **画 DFD 与信任边界**
   - 做什么：context diagram → level-0 → 必要时 level-1，标信任边界；对每个跨边界箭头问「谁校验数据」；沿信任链上溯找最外层可攻击点，把「只监听 127.0.0.1」「私有协议」等假设一律标高风险。
   - 完成标准：每个跨边界数据流都有校验主体，信任闭包的最弱点被标出。
   - 判停：若设计文档与实现冲突 → 以实现为准，更新模型（作者明确警告文档漂移）。

3. **建 AND/OR 攻击树并算 DREAD**
   - 做什么：根节点写攻击者目标；逐层判定 AND（缺任一子条件即失败）还是 OR（任一即可）；只沿安全相关路径分解；对已验证的缓解措施加圆形节点（降权而非删除）；每条威胁按五维打 1–10 分、总分÷5，≤3 低 / 4–7 中 / ≥8 高，记录五维明细。
   - 完成标准：攻击树根节点可落到具体组件，威胁清单带五维分数。
   - 判停：若某缓解措施未验证 → 不加入树，保留整条分支；若经验判断与分数冲突 → 服从判断并记录理由。

4. **排组件优先级与估工期**
   - 做什么：建「组件 × 风险分」表，把威胁分累加到组件；从最高分组件开始审；抽样读代码定速率系数（C/C++ 取下限，内存安全语言上调）；组件工时 = KLOC×1000÷速率；>50KLOC 按规模效应打折；与预算比对，超支从最低风险分组件砍范围。
   - 完成标准：带分数组件清单 + 带工时审计计划。
   - 判停：若用统一速率乘总行数导致大项目工期虚高 → 打折修正；忽略注释质量等语言无关变量会导致估算偏差，需复核。

5. **执行四阶段与日循环**
   - 做什么：Preassessment 定目标/访问级别/时间盒/收信息；Application review 按 Plan（2–8 小时目标）→ Work（详细笔记）→ Reflect（学到了什么 / 是否在高价值组件 / 是否钻牛角尖 / 笔记够不够）循环，每轮 Reflect 后重选策略，随理解加深从简单策略转向需更多上下文的策略；设计评审作为并行目标反复回访。
   - 完成标准：每日有 plan/work/reflect 记录，策略随理解演进。
   - 判停：若发现做成瀑布（先设计评审完再写代码审计）→ 立即改为并行回访；只做 Work 不做 Reflect → 强制暂停做 Reflect。

6. **出报告与复核修复**
   - 做什么：按固定字段写报告（位置、类别、描述、前置条件、业务影响、修复、风险、严重性、概率）；Remediation support 复核修复是否真堵住、是否引入新问题；对 Web 应用用五交互面（参数、session、OS/文件、数据库、HTML 输出）定位安全控制到具体代码；补两步覆盖——枚举全部可达功能、对每个功能设一个攻击目标再反查代码。
   - 完成标准：报告字段齐全，修复经回归验证。
   - 判停：若修复后同类问题在别处重复出现 → 回到 `source-audit-dataflow` 做同类模式全库搜索。

## B — 边界 (Boundary)

### 不要用的情况
- 目标是单个明确漏洞点（已知一处溢出要判可利用性）时，不需要全流程威胁建模，转 `memory-integer-audit`。
- 纯黑盒 fuzz 战役的目标选择与投入产出，属 `fuzzing-campaign`，本卡的可挖性排序口径（业务损失）不同。
- 3.0 阶段的运营评审/部署配置（Ch3 被蒸馏时跳过）不在本卡范围。

### 已知失败模式
- 早期按「是否安全相关」过滤信息，把后来才发现关键的组件提前丢掉（Ch2 Information Collection）。
- 把设计文档当事实、开发者访谈不做交叉验证——开发者误解本身可能就是漏洞成因（Ch2）。
- 照文档做模型而不对实现验证，把已废弃的安全路径当有效（Ch2 Threat Modeling 自述警告）。
- 过早把缓解措施加进攻击树，导致整条高危分支被淡化；缓解未验证就标记（如假定过滤器覆盖所有编码形式）（Ch2 Threat Identification）。
- 把流程做成瀑布（先设计评审完再写代码审计），错过「越审越懂」的红利；只做 Work 不做 Reflect（Ch4）。
- 用统一速率乘总行数，导致大项目工期虚高、小项目工期虚低（Ch4 Timelines）。

### 作者与时代的局限
- DREAD 是评审内部排序工具，作者声明「No model is perfect」，不用于对外披露评分；与 CVSS 口径不同。
- KLOC 速率 100–1000 LOC/h 的跨度达一个数量级，是经验基线，需按本团队实测校准；规模效应修正是经验法则而非精确定律。
- 五阶段威胁建模最适合设计/重构阶段，作者承认可整体后移到 SDLC 后期，但此时文档漂移风险更高。
- Web 五交互面来自 2007 年前后的 Web 应用形态（query string/session/CGI/PHP）；现代 SPA、微服务、API 网关的交互面需扩展。

### 容易混淆的方法
- 「五阶段威胁建模」（评审前地图）与「四阶段评审流程」（执行+交付+回归）是包含关系的不同层，前者不覆盖后者。
- 「DREAD 组件排序」（内部工作量分配）与「CVSS 严重性」（对外披露口径）不可混用。
- 「top-down / bottom-up / hybrid」是评审结构选择；`source-audit-dataflow` 的正向/反向数据流追踪是选定结构后的取材手法。

### 授权与合规边界
> 待补充（用户自行填写）
