# Web 漏洞判型与利用通道选择

## R — 原文 (Reading)

> Following this feature, it is easy to determine whether the input point is character-based, i.e., whether it is wrapped in quotation marks (either single or double quotation marks, in most cases single quotation marks).

> — 《Handbook for CTFers》Ch1 · SQL Injection Basics / Numeric and Character

> SSRF vulnerabilities are typically found in scenarios where there are calls to external resources, such as social service sharing features, image recognition services, website capture services, remote resource requests … etc.

> — 《Handbook for CTFers》Ch2 · SSRF Vulnerability Finding and Testing

> The XSS can be triggered is related to the order in which the browser renders the page. Our payload is in the tag attribute. Before triggering the event, the browser has decoded the payload once.

> — 《Handbook for CTFers》Ch2 · XSS Filtering and Bypass

> In contrast to the various Web vulnerabilities mentioned earlier, there is no fixed format for presenting logical vulnerabilities. To exploit logic holes, participants need to have a good understanding of business processes.

> — 《Handbook for CTFers》Ch3 · Logic Flaws in CTFs

## I — 方法论骨架 (Interpretation)

这张卡处理 Web 题里「已经看到一个可疑输入点，但不知道它属于哪类漏洞、该走哪条利用通道」的阶段。它把四种形态差异很大的问题放在一起，是因为它们的共同决策结构一致：**先做一次低成本判型，再选对通道，最后才构造 payload**。判错型的代价是把后续所有工作做在错误通道上——把字符型 SQLi 当数字型会让闭合与注释全部失效；把属性位置的 XSS 当标签间 XSS 会被 HTML 编码吃掉；把逻辑漏洞当注入找会一无所获。

**第一段：SQLi 用 `3-1` / `2a` 判数字型还是字符型**。判据来自数据库的类型转换行为，不需要看源码。数字型参数没有被引号包裹，`id=3-1` 会被 MySQL 先算成 2，页面返回与 `id=2` 相同；字符型参数被引号包裹，`id=3-2` 作为字符串比较，结果不符合预期（页面空），再发 `id=2a`，MySQL 把字符串强制转成 2，页面恢复，即确认字符型。判型完成后才进入 union 或盲注：字符型用单引号闭合 + `--%20`/`%23` 注释剩余语句，数字型直接 union，按「库 → 表（`group_concat(table_name) where table_schema=database()`）→ 列」顺序取。两个失败模式：只看一次响应会在「页面本身为空」时假阴性，必须用 `2a` 复核；union 不控制结果行数（用 `limit 1,1` 或 `id=-1`）会让目标数据落在第二行而页面只显示一行，误判「没查到」。

**第二段：SSRF 先找「服务器会替你发请求」的功能，再用协议阶梯扩面**。识别线索是功能而非参数名：分享、图片识别、网页抓取、远程资源请求（如 WordPress xmlrpc.php）、XML 解析等场景中都可能有可控 URL。确认后用 `file://` 读本地文件、`dict://` 探服务版本、`gopher://` 发送任意 TCP 内容（Redis/MySQL/FastCGI）。gopher 载荷有稳定套路：本地用相同客户端做一次正常操作并抓包（`socat -v tcp-listen:1234,fork tcp-connect:localhost:6379` 抓 Redis 写 crontab），剥掉方向标记 `>`/`<` 与 `+OK` 返回行，把 `\r`/`\n` 换成 `%0d`/`%0a` 并 URL 编码，填入 gopher URL；**改 IP/端口时必须同步改长度字段**（`172.28.0.3`→`172.28.0.33` 时 `$56`→`$57`）。只拿 `file://` 读到 `/etc/passwd` 就收手是最常见的浪费。

**第三段：XSS 按「输出点在哪一层」选绕过，而不是堆 payload**。先定位回显落在标签之间、标签属性内、还是 `<script>` 变量里：属性内时浏览器在事件触发前已把实体编码解码一次，所以把 `onerror` 里的代码做 HTML 实体编码（`&#x61;...`）可穿过代码层过滤（`str_replace("script","")` 也能用 `<scrscriptipt>` 双写绕过）；JS 变量内时若只过滤引号不过滤反斜杠，可用 `\` 让前后两个注入点「跨点闭合」，或用 `eval(window.name)`、`String.fromCharCode` 避开被过滤字符；富文本场景用 fuzz 找未过滤标签；有 CSP 头时单独分析允许的来源。忘掉「先解码再触发事件」的顺序会误判实体编码无效；在 JS 变量场景只闭合引号忽略 `\` 无法逃逸。

**第四段：逻辑漏洞没有固定 payload，靠画业务流程图**。判据是：需要组合多个业务功能点、常见于复杂业务系统、部署成本高所以在 CTF 里少见。思路从「找某个漏洞」转成「问哪些正常功能串起来会越权」：列出注册、登录、绑定、找回、跳转、分享等功能及参与角色，找「带状态的操作」（如带 Token 的绑定链接）和「能诱导他人访问的功能」（任意跳转、发给管理员的链接），串起来验证角色变化。典型链是：普通用户可绑定 OAuth 账号（带 Token）+ 任意地址跳转 + 管理员会自动访问指定链接 → 把跳转目标设成带 Token 的绑定页，管理员一点就把 OAuth 账号绑到管理员账户，随后用该账号登录拿 flag。用扫注入/XSS 的方式找逻辑漏洞只会一无所获。

**四者的共同纪律**：判型/定位阶段的输出是一句可验证的结论（数字型？URL 参数可控？属性位置？哪两个功能组合？），只有结论确定后才进入通道构造；构造时只改变必要成分（闭合符、协议、实体编码、跳转目标），并同步更新所有依赖字段（长度字段、注释编码、参数序号）。

## A1 — 应用示例 (Application Example)

### 示例 1: `3-1` / `2a` 判 SQLi 类型并 union 取数
- **类型与来源**: 【例题】《Handbook for CTFers》Ch1 1.2.1.1 / 1.2.1.2
- **问题/输入**: 一个 `id` 参数可疑，不知道数字型还是字符型。
- **方法论的使用**: 发 `id=3-1` 与 `id=2` 比对，回显一致判数字型，随后 `id=-1 union select 1,group_concat(table_name)...` 取出 `wp_user`；另一例发 `id=3-2` 页面空、`id=2a` 恢复，判为字符型，用 `id=2%27%23` 闭合成功。
- **结论**: 类型判据来自数据库强制转换，不必看源码；判错型会让闭合与注释全部失效。
- **结果**: 原书记录取出 `wp_user` 表名与字符型闭合成功，具体 flag 未给。

### 示例 2: gopher 打 Redis 写 crontab
- **类型与来源**: 【例题】《Handbook for CTFers》Ch2 2.1.3.2
- **问题/输入**: 找到可控 URL 参数，怀疑能打内网 Redis。
- **方法论的使用**: 用 `socat -v tcp-listen:1234,fork tcp-connect:localhost:6379` 本地抓到 redis-cli 写 crontab 的原始字节流；去掉 `>`/`<` 与 `+OK` 行，把换行换成 `%0d%0a` 并 URL 编码，填入 gopher URL；回显中出现 5 个 `+OK` 即确认；改反弹 IP 时把长度字段 `$56` 同步改为 `$57`。
- **结论**: gopher 载荷必须本地抓包构造，照抄网上串会因版本/认证差异失败；长度字段是高频陷阱。
- **结果**: 原书记载返回 5 个 `+OK`，同节还给出 MySQL 抓包（`tcpdump -i lo port 3306 -w /pcap/mysql.pcap`）与 PHP-FPM 前提。

### 示例 3: 属性点与 JS 变量点的两类 XSS 绕过
- **类型与来源**: 【例题】《Handbook for CTFers》Ch2 XSS Filtering and Bypass
- **问题/输入**: 输入被过滤，不知道怎么绕。
- **方法论的使用**: 输出在属性点时，对事件代码做实体编码：`<img src=x onerror="&#x61;&#x6c;&#x65;&#x72;&#x74;&#x28;&#x31;&#x29;" />`；富文本点用 `<scrscriptipt>` 双写绕过 `str_replace("script","",...)`；两个 `htmlentities(...,ENT_QUOTES)` 输出点因 `gb18030` 与未过滤 `\`，用反斜杠跨点闭合；payload 藏在 `location.hash` 绕过服务端过滤。
- **结论**: 先定输出层，再选实体编码/双写/跨点闭合；不分层就套 `<script>` 会被编码吃掉。
- **结果**: 原书给出各类 payload 与 Fig. 2.82，未给具体 flag。

### 示例 4: X-NUCA 2018 blog 的 OAuth 绑定链
- **类型与来源**: 【例题】《Handbook for CTFers》Ch3 Logic Flaws in CTFs
- **问题/输入**: 每个功能单独看都正常，拿不到 flag。
- **方法论的使用**: 画功能与角色图：普通用户可发起带 Token 的 OAuth 绑定、站点有任意地址跳转、管理员会自动访问指定链接；把跳转目标设成带 Token 的绑定页；管理员点击后 OAuth 账号被绑到管理员账户；用该账号登录取 flag。
- **结论**: 逻辑漏洞的 payload 是「功能组合」而非字符串；不理解 OAuth 授权流程就判断不了 Token 绑定的副作用。
- **结果**: 原书记载用 OAuth 账号登录管理员账户取 flag（Fig. 3.73）。

## A2 — 触发场景 (Future Trigger) ★

### 用户会在什么情境下需要它
1. 发现一个可疑参数，但不知道是数字型还是字符型 SQLi，不确定怎么闭合。
2. 找到 URL 参数，怀疑能打内网，但不知道从哪个协议入手。
3. gopher 串照抄过来打不通，改了 IP 之后服务解析错乱。
4. XSS payload 被过滤，堆了很多 payload 都无效。
5. 每个业务功能都正常，但组合起来似乎能越权，不知道怎么串。
6. union 注入「成功」但页面不显示目标数据，怀疑结果行位置不对。

### 语言信号（出现这些就该激活）
- 中文：「怎么判断 SQL 注入类型」「id=1 改成什么能测注入」「数字型字符型区别」「SSRF 从哪里找」「gopher 打 redis 怎么构造」「url 参数能打内网吗」「XSS 被过滤了怎么绕」「输出在属性里怎么打」「逻辑漏洞怎么找」「每个功能都正常但拿不到 flag」
- English: "how to identify SQLi type", "numeric vs character SQL injection", "how to find SSRF", "build gopher payload", "XSS filter bypass by output context", "htmlentities bypass", "business logic flaw CTF", "OAuth binding chain"

### 与相邻能力的区分
- 与 `web-recon-source-leak` 的区别：那张卡在「找入口/拿源码」阶段；本卡在已经发现具体漏洞后判型与选利用通道。
- 与 `file-read-and-include` 的区别：那张卡处理任意文件读/包含这一类具体漏洞；本卡的 SQLi/SSRF/XSS/逻辑各有独立通道。
- 与 `rce-egress-and-shell` 的区别：SSRF 借服务器作跳板访问内网但不依赖系统 shell；命令执行外带是在已拿到命令执行点后解决「看不见结果」。

## E — 可执行步骤 (Execution)

**必需输入**: 可访问的 Web 目标与一个可疑输入点；能观察回显或响应差异；本地可起同版本服务并抓包（SSRF 分支）；能看到过滤后的输出（XSS 分支）；能识别业务角色（逻辑分支）。缺任一支的前提时先回 `web-recon-source-leak` 补侦察。
**交付物与完成标准**: 一份「判型结论 + 通道方案」：写明漏洞类型、选中的通道、关键参数（闭合符/协议/编码/长度字段/功能链），以及一个可复现的最小请求序列。判据是构造出的请求能产生预期效果（页面差异、内网服务回显、浏览器触发、角色变化）。

1. **SQLi 判型**
   - 做什么：对数字参数发 `id=3-1` 与 `id=2` 比对；不同则发 `id=2a` 复核；字符型用单引号闭合 + `--%20`/`%23`，数字型直接 union。
   - 完成标准：一句话结论「数字型 / 字符型」，并能用 union 按库→表→列取出目标字段名。
   - 判停：页面本身为空时不要凭一次响下结论，用 `2a` 复核；union 加 `limit 1,1` 或 `id=-1` 控制结果行数，避免目标数据落在未显示的行。

2. **SSRF 发现与协议阶梯**
   - 做什么：枚举「服务器主动发起请求」的功能点，确认 URL 参数响应随目标变化；依次试 `file:///etc/passwd`、`dict://` 探版本，再决定要不要 gopher。
   - 完成标准：确认协议未被白名单限制，找到可用的 URL 参数。
   - 判停：白名单限制住 file/dict/gopher 时停止扩面，转其他漏洞类型；只有 `file://` 可读不算完成，应评估 gopher 打内网服务的可能。

3. **gopher 载荷构造**
   - 做什么：本地起同版本服务，用相同客户端做一次正常操作并抓包；剥掉方向标记与返回行，换行 `%0d/%0a` + URL 编码，填入 gopher URL；改 IP/端口时同步改长度字段。
   - 完成标准：回显出现预期条数的 `+OK`（书中为 5 条）或目标服务执行了修改后的命令。
   - 判停：照抄网上串失败时回本地抓包重做；改 IP 必须同步改 `$NN` 长度数字，否则协议解析错乱。

4. **XSS 输出层定位与绕过**
   - 做什么：确定回显在标签间/属性内/JS 变量内；属性内做实体编码，JS 变量内试 `\` 跨点闭合或 `window.name`/`String.fromCharCode`，富文本 fuzz 标签与双写，有 CSP 单独分析来源。
   - 完成标准：浏览器打开即触发，或构造出合法 JS 语句。
   - 判停：不分层就套 `<script>` 无效时回本步重新定位；忘记「先解码再触发事件」顺序会误判实体编码无效。

5. **逻辑链组合与验证**
   - 做什么：列出功能与角色图；找带状态的操作与能诱导他人访问的功能；串起来执行并观察角色变化。
   - 完成标准：以普通身份获得管理员权限或读到后台 flag。
   - 判停：用扫注入/XSS 的方式找逻辑漏洞无效，必须回到流程图；只看单个功能会漏掉「单独无害、组合越权」的链。

## B — 边界 (Boundary) ★

### 不要用的情况
- 入口是文件读/包含参数：本卡的 SQLi/SSRF/XSS 判型不适用，转 `file-read-and-include`。
- 已经拿到命令执行点、只是看不到结果：转 `rce-egress-and-shell`，本卡不处理外带通道。
- 目标是版本库泄露或源码注释线索：转 `web-recon-source-leak`。
- 逻辑漏洞题但没有任何多步业务流程（只有一个输入框）：本卡第 5 步不适用。

### 已知失败模式
- SQLi 只看一次响应就下结论，遇到「页面本身为空」假阴性，必须用 `2a` 复核（Ch1 1.2.1.2）。
- union 不控制结果行数，目标数据落在第二行而页面只显示一行，误判「没查到」（Ch1）。
- 忘记 URL 编码（空格 `%20`、`#` `%23`）让注释失效（Ch1）。
- 只拿 `file://` 读到 `/etc/passwd` 就收手，漏掉 gopher 打内网服务的更大面（Ch2）。
- 改反弹 IP 时忘记同步改长度数字（`56`→`57`），协议解析错乱（Ch2 2.1.3.2）。
- 照抄网上 gopher 串不本地抓包，服务版本或认证差异导致失败（Ch2）。
- 不分层就套 `<script>`，在属性点被 HTML 编码吃掉；JS 变量场景只闭合引号忽略 `\`，无法跨点逃逸（Ch2）。
- 用扫注入/XSS 的方式找逻辑漏洞，一无所获；只看单个功能，漏掉组合越权（Ch3）。

### 作者与时代的局限
- SQLi 判型依赖 MySQL 的强制转换行为；其他数据库（PostgreSQL/Oracle）的隐式转换规则不同，需重新确认探针语义。
- gopher 载荷示例基于当时的 Redis/MySQL/PHP-FPM 版本与认证配置，现代服务默认认证/协议变化后抓包内容需重做。
- XSS 绕过示例针对特定 `str_replace`/`htmlentities` 写法与 `gb18030` 编码，现代框架默认转义与 CSP 策略已变化。
- 逻辑漏洞案例依赖 OAuth 2.0 的特定绑定流程与「管理员自动访问」的赛制设定，实战中未必存在。
- 四段都没有覆盖 WAF 层的绕过（属于过滤发生位置的另一个维度）。

### 容易混淆的方法
- **数字型 `3-1` 与字符型 `2a`**：前者靠算术被提前计算，后者靠字符串被强制转换，两个探针回答不同问题。
- **SSRF 与任意文件读**：SSRF 借服务器作跳板访问它才能到达的内网地址；文件读直接让应用读路径。
- **XSS 的「输出层」与「过滤位置」**：本卡按输出上下文（标签间/属性/JS 变量）分类，WAF/代码层是过滤发生的位置，两者正交。
- **逻辑漏洞与认证绕过**：后者有明确技术缺陷，逻辑漏洞是「功能设计组合」的问题。

### 授权与合规边界
> 待补充（用户自行填写）
