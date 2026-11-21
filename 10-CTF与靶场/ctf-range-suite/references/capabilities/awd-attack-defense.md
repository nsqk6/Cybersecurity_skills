# AWD 攻防节奏与 flag 通道

## R — 原文 (Reading)

> 1. web 主要是向目标服务器发送 http 请求，返回 flag 2. bin 主要是通过 exploit 脚本读取 /home/username 下某个文件夹下的 flag 文件

> — 《ctf-all-in-one》1.1 CTF 简介 · 线下赛 AWD 模式

> As soon as the game begins, all participants should back up the source code of their web topics, but they often leave out another important backup, the database backup.

> — 《Handbook for CTFers》Ch11 · The importance of backup

> The more accurate way is to split the traffic packets by connections, run the service locally to simulate the service environment, and send the content received in each connection to the local server to determine if the local server will crash (PWN challenges) or if the local server will get the flags directly.

> — 《Handbook for CTFers》Ch11 · How to quickly locate effective attack traffic

## I — 方法论骨架 (Interpretation)

这张卡处理与解题赛（Jeopardy）完全不同的竞赛形态：**AWD（Attack With Defense，攻防赛）**。这里 flag 定时轮换、check 不过扣分、对手实时修改服务，所以「做对一道题」不是目标，「在持续变化的对抗里稳定得分且不丢分」才是。卡的核心由三个判断串成：**flag 从哪条通道出来 → 开赛先备份什么与预写什么 → 如何从全场流量里稳定拿到对手的 payload**。

**第一判断：flag 通道决定 exp 终点**。书中的二分很干脆：Web 题「向目标服务器发送 HTTP 请求，返回 flag」，请求构造对就直接拿到；Bin 题「通过 exploit 脚本读取 `/home/username` 下某个文件夹下的 flag 文件」，exp 终点是任意文件读或命令执行，而不是交互式 shell。这直接决定 exp 怎么写：Web 构造能返回 flag 的请求；Bin 写「读指定路径」的脚本。在需要批量打全场时，写成 `interactive()` 的 exp 完全无法自动化，这是新手最常犯的错。一轮进攻包含四环节：拿到可用利用点 → 构造非交互 exp → 执行并取回 flag → 提交；任何环节需要人工介入，周期就会被拉长到赶不上下一轮轮换。所以「非交互」「自动化」不是工程洁癖，而是轮换周期倒逼的硬约束。

**第二判断：开赛先备份源码 AND 数据库，并预写脚本**。AWD 的扣分来自 check 失败，而 check 往往依赖「普通用户能否正常登录」这类状态。只备份源码、不备份数据库，一旦改了用户密码或库里关键数据，服务就会被判异常而扣分，且恢复需联系主办方——这是作者亲历的扣分教训。赛前准备还包括：扫 C 段 IP 备用（主办方可能不公布 IP 段）、积累常见 CMS/CVE 的 exp（比赛常断网）、预写 flag 自动提交脚本、批量利用脚本、抓流量脚本与混淆流量脚本。**混淆流量的随机 payload 类型要多样**，否则会被对手提取特征写出过滤规则。备份的作用是让被打崩后能快速回滚，改弱口令是防最廉价手段，check 自检是确认改动没破坏功能验证。

**第三判断：流量定位从「关键词搜索」升级到「按连接拆分本地回放」**。抢到一血后，快速从全场流量复现攻击就能追平分。两种定位法按准确度递增：一是用 Pcap Search 这类平台按 flag 关键字/目录搜索并导出重放脚本，快但容易被混淆流量规避；二是按连接把流量拆开，本地搭同款服务，逐条回放每个连接的内容，看本地服务是否崩溃（PWN）或直接产出 flag——**以「本地是否复现效果」为判据**，不依赖 payload 里有没有明文关键词，因此更准。平台可按需要二次开发（改 zio 脚本为 pwntools、加正则匹配 flag、写 SCP/HTTP 自动下载脚本）。回放越快，越能与一血队伍均分。

**贯穿逻辑：流量是双向资产**。对手的 payload 必须经过你的服务才能得分，因此你机器上天然留着他的样本；你自己的 payload 也要经过别人的服务，同样会留下样本。所以「抓别人的」与「藏自己的」是同一件事的两面：既要从抓到的流量里复现攻击，也要给打全场的 exp 加混淆流量防止被复用。解题赛里 payload 从不需要隐藏，AWD 里这是结构性特征。防守也不是一次性「修好漏洞」，而是在对手持续改配置的环境里维持服务可用。

**三判断的关系**：第一判断决定单条 exp 的形态，第二判断决定整场比赛的生存底线（备份与自动化），第三判断决定进攻侧的 payload 来源。三者共同服务于「缩短一次得分周期 + 降低被反打概率」，而不是「把题做透」。

## A1 — 应用示例 (Application Example)

### 示例 1: 原书 1.1 的 AWD 规则与流量反打经验
- **类型与来源**: 【转述】《ctf-all-in-one》1.1 CTF 简介 · 线下赛 AWD 模式
- **问题/输入**: 线下 AWD 赛，flag 五分钟一轮，被拿则均分，check 失败扣分由正常队伍均分。
- **方法论的使用**: 开赛先跑通己方服务并确认本队 flag 位置；按 Web/Bin 分通道写 exp（Web 构造取 flag 的 HTTP 请求，Bin 写读指定路径的非交互脚本）；把提交自动化、备份服务配置、改弱口令；抓入站流量找未混淆的 payload 复现反打；自己的 payload 加混淆流量防止被抓。
- **结论**: AWD 得分是「进攻效率 × 防守稳定性」，两者都要自动化；流量是双向资产。
- **结果**: 原书以经验形式给出规则与反打思路，未附具体赛果数据。

### 示例 2: 作者因漏备份数据库被扣分的亲历
- **类型与来源**: 【亲历】《Handbook for CTFers》Ch11 · The importance of backup
- **问题/输入**: AWD 比赛中作者改了用于 check 的普通用户密码。
- **方法论的使用**: 因只备份源码、没有数据库备份，无法自行恢复，只能联系主办方重置，并被扣分。正确做法是开赛即 `mysqldump -u user -p choosedb > /tmp/db.sql`，两份备份都可独立恢复；同时预写并测试 `post_answer()` 提交函数（给假 flag 能成功提交）。
- **结论**: 数据库备份与源码备份同等重要；check 依赖的状态数据一旦改动就要能立刻回滚。
- **结果**: 原书记载作者因此被扣分并需联系主办方，未给具体分值。

### 示例 3: 按连接拆分回放定位有效攻击
- **类型与来源**: 【转述】《Handbook for CTFers》Ch11 · Traffic Analysis
- **问题/输入**: 抢到一血后，想从全场流量里复现攻击追平分。
- **方法论的使用**: 先把流量导入 Pcap Search 按 flag 关键词/目录搜索得候选（注意对手可能已混淆，命中不全）；再按连接拆分流量，本地搭同版本服务，逐连接回放，看本地服务是否崩溃（PWN）或直接出 flag；必要时二次开发平台（正则匹配 flag、pwntools 导出、SCP/HTTP 自动下载）。
- **结论**: 本地复现效果是比关键词更准的判据；回放越快越能与一血均分。
- **结果**: 原书推荐 MaskRay/pcap-search 及玩家 fork 的改 pwntools/正则版本，未给具体比赛结果。

### 示例 4: 【合成演练】Web 与 Bin 通道的 exp 终点差异
- **类型与来源**: 【合成演练】按本卡第 2 步规则推演，非原书案例，不代表真实赛果。
- **问题/输入**: 同一场 AWD 中同时有 Web 与 Bin 两道题，均已取得可用利用点。
- **方法论的使用**: Web 通道 exp 终点写成「发送一条 HTTP 请求并从响应解析 flag 字符串」；Bin 通道写成「通过任意文件读/命令执行读取 flag 路径并打印字符串」，都不进入 `interactive()`。完成判据统一为「脚本非交互跑完能在标准输出打印 flag」。
- **结论**: 通道不同导致 exp 终点形态不同，但共同要求可自动化、非交互。
- **结果**: 合成演练不编造现实结果；判停点是「若 exp 需人工输入才能取 flag，判为未完成，回第 2 步改写」。

## A2 — 触发场景 (Future Trigger) ★

### 用户会在什么情境下需要它
1. 参加线下 AWD 赛，开赛第一时间不知道该做什么。
2. 写好了 pwn exp，但发现需要 `interactive()` 才能拿 flag，无法批量打全场。
3. flag 每五分钟轮换，手工提交跟不上节奏。
4. 自己的服务总在 check 中被判失败，想知道防守侧要补哪些动作。
5. 改了普通用户密码后服务异常，想知道赛前该备份什么。
6. 流量太多，按 flag 关键词搜不到对手的 payload（可能被混淆）。
7. 想利用抓到的流量反打，同时担心自己的 payload 被别人抓走。

### 语言信号（出现这些就该激活）
- 中文：「AWD 怎么打」「攻防赛先做什么」「awd 脚本怎么写」「flag 轮换怎么自动提交」「check 不过扣分」「AWD 备份什么」「数据库要不要备份」「AWD 流量太多怎么找 payload」「对手混淆了流量怎么办」「如何定位有效攻击」「payload 混淆」
- English: "how to play attack-defense CTF", "AWD flag rotation", "AWD exploit automation", "AWD preparation checklist", "AWD backup database", "capture traffic replay", "locate effective attack traffic", "check service defense"

### 与相邻能力的区分
- 与 `pwn-opening-protection-read` 的区别：那张卡解决「单道题怎么打下来」，本卡解决「整场比赛怎么组织进攻与防守」。AWD 里 pwn exp 的终点由本卡决定（读文件而非 shell），具体利用仍由那张卡及其下游提供。
- 与 `blind-rop-brop` 的区别：BROP 终点是 shell 且试探节奏慢；AWD 的轮换与对手干扰使这种慢节奏通常不适用。
- 与 `misc-forensics-and-encoding` 的流量分析区别：那里从单个 pcap 找「被隐藏的数据」，本卡从全场流量找「能复现漏洞的请求」。
- 与 `lab-workflow-and-triage` 的区别：那张卡管靶场推进的阶段顺序与止损，本卡管竞赛的攻防运营。

## E — 可执行步骤 (Execution)

**必需输入**: 赛制确认（flag 轮换周期、check 判定规则、计分方式）；己方服务与 flag 路径；题目类型（Web/Bin）；数据库访问权限；可写脚本环境；能拿到全场流量。不清楚轮换周期与 check 规则时先向主办方确认，不要按解题赛假设开工。
**交付物与完成标准**: 一套可非交互运行的自动化 exp + 提交脚本，加防守动作清单（源码备份、数据库备份、弱口令、check 自检），再加一套流量定位/回放流程；判据是「flag 轮换后无需人工介入即可继续提交」且「己方服务能通过 check」且「能从流量复现至少一条有效攻击」。

1. **开赛跑通己方服务与 flag 位置**
   - 做什么：启动/确认己方服务，确认本队 flag 位置与读取方式；用一条请求或一个脚本稳定取到本队 flag。
   - 完成标准：能用非交互方式稳定打印本队 flag。
   - 判停：服务起不来或取不到 flag → 先修环境，不进入进攻阶段。

2. **同步完成双备份与预写脚本**
   - 做什么：开赛即备份源码与数据库（`mysqldump ... > /tmp/db.sql`），两份都可独立恢复；扫 C 段 IP 备用；预写并测试 `post_answer()` 提交函数（假 flag 能提交成功）；预写批量利用 + 抓流量 + 混淆流量脚本（随机 payload 类型要多样）。
   - 完成标准：两份备份可恢复；提交函数测试通过；脚本可循环处理整段 IP 且自身流量不易被特征提取。
   - 判停：只备份源码不备份数据库 → check 依赖的状态改动后无法回滚；混淆流量只发单一类型 → 会被对手写过滤规则。

3. **按题型定 exp 终点**
   - 做什么：Web 构造能返回 flag 的 HTTP 请求；Bin 写「读指定路径」的 exp（任意文件读/命令执行），终点打印 flag 字符串，不用 `interactive()`。
   - 完成标准：脚本非交互跑完能在标准输出打印 flag。
   - 判停：exp 仍需人工输入 → 判为未完成，回本步改写；Bin exp 只能给 shell → 转 `pwn-opening-protection-read` 第 5 步找最小读取原语。

4. **提交自动化与防守基线**
   - 做什么：把取 flag 与提交串成自动化脚本适配轮换周期；改弱口令、确认 check 项能通过；被改数据后用备份回滚。
   - 完成标准：flag 轮换后无需人工介入即可提交；己方服务通过 check；配置与数据库有可恢复备份。
   - 判停：check 失败时优先排查服务可用性与配置/数据改动，不要在进攻侧加码。

5. **关键词搜索与按连接回放**
   - 做什么：导入 Pcap Search 按 flag 关键词/目录搜候选并导出重放脚本；再按连接拆分流量，本地搭同版本服务逐连接回放，看是否崩溃（PWN）或直接出 flag；必要时二次开发平台（正则 flag、pwntools 导出、自动下载）。
   - 完成标准：确认至少一条有效攻击流量并用于修复与反打。
   - 判停：只按关键词搜遇到混淆会漏掉有效攻击（作者明确提示 experienced attackers obfuscate traffic），必须走本地回放；不搭本地环境就回放无法区分有效攻击与噪声。

6. **反打并保护自己的 payload**
   - 做什么：用抓到的 payload 反打对手服务；自己的打全场 exp 加入多样化混淆流量。
   - 完成标准：能从流量复现至少一条可用 payload；自己的 payload 有混淆措施。
   - 判停：拿到的 payload 已失效（flag 已轮换或服务已改）→ 回第 3 步重新构造，不反复打旧 payload。

## B — 边界 (Boundary) ★

### 不要用的情况
- 解题赛（Jeopardy）：flag 静态、可反复试错，本卡的轮换节奏、流量反打、check 扣分逻辑都不适用。
- 题目环境不允许抓包或没有共享网络可见性：第 5/6 步的流量定位无法进行，只能做前 4 步。
- 目标服务崩溃后不恢复：AWD 的 check 扣分逻辑下，打崩服务可能让己方也失分，需按赛制判断是否值得。
- 只有单题、无全场批量需求：自动化收益下降，但仍建议保留非交互 exp 与双备份。

### 已知失败模式
- 把 pwn exp 写成 `interactive()`：需要批量打全场时无法自动化（1.1）。
- 自己拿到 flag 后不先在本机/中立机测试就往对方打：payload 会被别的队伍抓走；写打全场 exp 时必须加混淆流量（1.1）。
- 只备份源码不备份数据库：作者改了 check 用的普通用户密码，无备份只能联系主办方重置并扣分（Ch11）。
- 混淆流量只发单一类型随机 payload：被对手分析特征写出过滤规则（Ch11）。
- 依赖比赛现场联网找 exp：断网时无从下手（Ch11）。
- 只按 flag 关键词搜流量：遇到混淆就漏掉有效攻击（Ch11 明确提示）。
- 不本地搭环境就盲目回放：无法区分有效攻击与噪声请求（Ch11）。
- 不备份服务配置：被对手打崩后无法恢复，check 持续失败扣分（1.1）。
- 反复打已失效的旧 payload：flag 轮换后同一 payload 时效很短。
- 只顾进攻不管 check：check 失败由正常队伍均分扣分，可能抵消进攻收益。

### 作者与时代的局限
- ctf-all-in-one 1.1 对 AWD 只有规则与经验性描述，没有给出具体自动化脚本或流量工具；Handbook Ch11 补了备份、脚本与回放方法，但仍以示例脚本为主。
- 规则（flag 五分钟一轮、被拿均分、check 失败均分扣分）是当时特定赛事做法，现代 AWD 变体规则不同，需按实际赛制调整。
- 混淆流量的具体手段本书只给「一定要加、类型要多样」的结论，未展开实现。
- 两本书都没有覆盖防守侧的补丁制作（给自己的服务打补丁同时保持 check 通过），这是现代 AWD 的重要能力。

### 容易混淆的方法
- **AWD 的 Bin exp 终点 vs 解题赛 pwn 终点**：前者是读文件/命令执行并打印 flag，后者常是拿 shell 后 `interactive()`。
- **流量反打 vs 重放**：反打是用抓到的 payload 打对手服务；重放是把同一请求再发一次，flag 轮换后单纯重放往往失效。
- **关键词搜索 vs 本地回放**：前者快但会被混淆规避，后者以「本地是否复现效果」为判据更准。
- **check 通过 vs 服务不被打崩**：check 是主办方功能验证；服务可能未被攻破但配置/数据被改导致 check 失败，两者都要管。
- **源码备份 vs 数据库备份**：前者保代码可恢复，后者保 check 依赖的状态可恢复，缺一不可。

### 授权与合规边界
> 待补充（用户自行填写）
