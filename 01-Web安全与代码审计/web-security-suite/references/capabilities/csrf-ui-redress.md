# CSRF 与点击劫持：判断「这个请求能不能被借身份发出」

## R — 原文 (Reading)

> "This request has three key features that make it vulnerable to CSRF attacks:"
>
> 译：这个请求具备三个关键特征，使它易受 CSRF 攻击。

> — 《The Web Application Hacker's Handbook》Ch13 / Cross-Site Request Forgery

> "UI redress attacks are designed to allow a third-party site to induce user actions on another domain even if anti-CSRF tokens are being used."
>
> 译：UI redress 攻击的目的，就是即便目标使用了 anti-CSRF token，也能诱导用户对另一个域执行操作。

> — 同上 / UI Redress

> "防御CSRF的Token，是根据'不可预测性原则'设计的方案，所以Token的生成一定要足够随机，需要使用安全的随机数生成器生成Token。"
>
> — 《白帽子讲 Web 安全》4.3.3 Anti CSRF Token

## I — 方法论骨架 (Interpretation)

这一族问题的共同前提是浏览器的三条硬规则：**cookie 会自动随请求发出**；**同源策略只阻止「读响应」，不阻止「发请求」**；**表单/图片/脚本可以跨域加载**。由此推出 CSRF 成立的三个必要条件，缺一不成立：

1. 该请求执行**特权动作**（建管理员、改密码/邮箱、转账、下单、授权、删除）。
2. 会话**只靠 cookie 识别**，请求里没有其他不可预测值（token、nonce、验证码、时间戳）。
3. 攻击者能**预先确定全部参数**（无随机值、无需先读取的值）。

所以判定顺序不是「看有没有 token 字段」，而是「逐条否证这三个条件」。看到请求里没有名为 `csrf_token` 的参数就报 CSRF，是最常见的误判——token 可能换了名字、可能在 header 里、可能由 JS 注入。

Token 之所以能封死这条路，靠三条同时成立：**随机性**（安全随机源，不是 `rand()`）、**保密性**（放表单/请求体，不放 URL，防 Referer 泄漏）、**绑定会话并一次性消耗**（防重放与跨会话使用）。任何一条不满足，防护就有缺口：可预测的 token 等于没有；只绑用户不绑会话的 token 可被交叉使用；只保护流程中某一步的 token 可被「先请求未保护的第一步」绕过。

点击劫持是同一族里的另一条路：它**不需要读 token**，只需要让受害者在目标页面里亲手点那个按钮——表单里带的是目标自己生成的 token，对服务器而言请求完全正常。因此判据是「请求是否由目标界面内的真实交互产生」，而不是「有没有 token」。这也解释了为什么 `X-Frame-Options`/CSP `frame-ancestors` 才是它的正解，而不是加 token。

## A1 — 应用示例 (Application Example)

### 示例 1: 用三个条件否证一个「疑似 CSRF」
- **类型与来源**: 【转述】《The Web Application Hacker's Handbook》Ch13（eBay 2004，Dave Armstrong）
- **问题/输入**: 一个「出价」请求，参数为 `item=...&price=...`。
- **方法论的使用**: ① 确认动作是特权动作（会改变拍卖状态、涉及资金）；② 抓包确认会话只靠 `Cookie`，请求体里无 token/nonce；③ 确认参数全部可预测（物品号公开、价格可自定）；④ 写一个本地 HTML：`<img src="https://target/bid?item=X&price=1">` 或用隐藏表单自动提交；⑤ 在已登录该站的同一浏览器打开此 HTML → 出价成功即确认。
- **结论**: 三个条件同时满足，纯 CSRF 成立。
- **结果**: 原书说明该问题还衍生出「借拍卖描述里的 `<img>` 做站内 OSRF」与「校验图片时的 TOCTOU（先返真图后改跳转）」。

### 示例 2: token 在，但防护仍不成立
- **类型与来源**: 【例题】《The Web Application Hacker's Handbook》Ch13（`/auth/395/`、`/auth/404/`、`/auth/398/`）
- **问题/输入**: 表单里有 `csrf_token`，删除后请求被拒。
- **方法论的使用**: ① 删 token / 置空 / 换成另一账号的 token / 重复使用同一 token → 任一被接受即防护有缺陷；② 判断绑定关系：用 A 会话的 token 配 B 会话的 cookie → 若成功，token 未绑会话；③ 找「只保护第二步」的流程：先请求未保护的第一步拿 token，再提交第二步 → 能完成即绕过；④ 找「token 在 URL 里 + 整个会话复用同一 token」：用 CSS `getComputedStyle` 做客户端历史嗅探暴力枚举；⑤ 测重定向：若响应 302 到含 token 的 URL，浏览器会自动跟随并带上 token → 该防御无效。
- **结论**: token 的有效性要靠「不可预测 + 绑会话 + 每个敏感请求都校验」三条同时成立，只存在字段不算防护。
- **结果**: 原书以该组实验演示 token 复用、绑定缺失与重定向三类缺陷。

### 示例 3: 有 token 也能被点击劫持
- **类型与来源**: 【转述】《The Web Application Hacker's Handbook》Ch13 / Framebusting Defenses（Stanford 2010 研究）
- **问题/输入**: 一个「确认转账」页面有 anti-CSRF token，直接伪造请求失败。
- **方法论的使用**: ① 确认页面可被 iframe：响应无 `X-Frame-Options`（或该路径未覆盖）；② 在攻击页放透明 iframe 指向该页，用 CSS 把「确认」按钮对准诱饵按钮；③ 诱导用户点击 → 请求带着目标自己生成的 token 提交，服务器视为正常；④ 若目标有 framebusting：试覆盖 `top.location` 使其异常、hook `onbeforeunload` 并用 204 中止跳转、给 iframe 加 `sandbox` 禁脚本、借 IE XSS filter 选择性禁用 framebusting 脚本；⑤ 检查移动版/旧版路径（常漏配 `X-Frame-Options`）。
- **结论**: 点击劫持绕过的不是 token，而是「请求必须由攻击者构造」这个前提。
- **结果**: 原书引用 2010 年 Stanford 对 500 个顶级站点的研究——每一例 framebusting 都能被绕过。

### 示例 4: 同源判定决定「能不能读」
- **类型与来源**: 【例题】《Web 应用安全权威指南》3.2 被动攻击与同源策略
- **问题/输入**: 攻击页 `trap.example.com` 用 iframe 嵌入 `example.jp`，尝试读取其中的密码框。
- **方法论的使用**: ① 确认同源三条件（scheme/host/port 全等）→ 两者跨源；② 查交互载体：`iframe` 能加载但 JS 读不到内部文档；`img` 能加载并自动带 Cookie 但读不到像素；`script` 能加载且**在发起页的源下执行**（JSONP 可能泄密）；`form action` 可任意跨域提交；③ 得出结论：只能「发」不能「读」→ 属 CSRF 面，不属信息泄露面。
- **结论**: 「能发」与「能读」是两条完全不同的能力，决定了该走 CSRF 还是信息泄露路径。
- **结果**: 原书以该双站环境演示三类被动攻击，读取被同源策略拒绝。

## A2 — 触发场景 (Future Trigger) ★

### 用户会在什么情境下需要它
1. 发现一个「改密码/改邮箱/转账」请求只带 cookie，想知道能否伪造。
2. 请求里有 token，需要判断这个 token 到底有没有用（能不能复用、能不能跨账号）。
3. 多步表单（确认页）看起来有防护，想验证能否跳过中间步骤。
4. 目标页面能被 iframe，想知道点击劫持是否可行、`X-Frame-Options` 是否覆盖到该路径。
5. 手上有 XSS，想知道能否用它绕过 CSRF token（或反过来，token 是否让 XSS 更难利用）。
6. 需要向开发解释「为什么加了 token 还会被点击劫持」。

### 语言信号（出现这些就该激活）
- 中文：「CSRF 怎么确认」「这个请求能伪造吗」「只有 cookie 鉴权」「有 token 还能 CSRF 吗」「token 能不能复用」「多步表单防 CSRF」「点击劫持怎么测」「X-Frame-Options 绕过」
- English: "CSRF proof of concept", "session riding", "anti-CSRF bypass", "CSRF token reuse", "clickjacking", "UI redress", "X-Frame-Options bypass", "same-origin policy"

### 与相邻能力的区分
- 与 `xss-context-runtime` 的区别：CSRF 读不到响应、不执行脚本；XSS 在目标域执行 JS，能读 token 并让 CSRF 防护失效（原书称此场景为 XSRF）。
- 与 `access-control-idor` 的区别：越权用自己的账号访问别人的资源；CSRF 用受害者自己的身份执行操作。
- 与 `server-request-injection` 的开放重定向区别：开放重定向让浏览器跳到外域（一次性），CSRF 让浏览器向目标域发请求（改变状态）。
- 与 `auth-session-bypass` 的区别：那张卡解决「怎么进系统」，本卡解决「进去之后如何借他人身份执行动作」。

## E — 可执行步骤 (Execution)

**必需输入**: 一个「改变状态」的接口与其完整请求；受害者视角的已登录会话（同浏览器或"记住我"持久 cookie）；能托管页面的位置。缺「已登录会话」就无法验证，只能做静态判断。

**交付物与完成标准**: 一份「接口 → 三条件逐条结论 → PoC（HTML/表单）→ 影响」记录；完成标准是 PoC 在已登录浏览器里打开后，服务端状态确实改变（或明确给出「被哪一条防护挡住」）。

1. **列敏感动作并抓请求**
   - 做什么：从映射结果挑出会改状态的接口（建管理员、改密码/邮箱、转账、下单、授权、删除、绑定第三方）；抓完整请求，记录方法、参数、header、cookie。
   - 完成标准：每个接口都有「方法 + 全部参数名 + 是否 GET」。
   - 判停：纯 GET 的敏感操作本身就是缺陷（可被 `<img>` 触发），优先记录。

2. **三条件逐条否证**
   - 做什么：① 是否特权动作；② 是否只靠 cookie 识别会话（有无 token/nonce/验证码/时间戳/自定义头）；③ 参数是否全部可预测（有无随机值、是否需先读取）。
   - 完成标准：三条各自给出「成立/不成立 + 证据」。
   - 判停：任一条不成立 → 纯 CSRF 不成立，但转第 4 步（可能是点击劫持）或 `xss-context-runtime`（可能是 XSS）。

3. **构造 PoC 并验证**
   - 做什么：GET 用 `<img src=...>`；POST 用隐藏字段表单 + `document.forms[0].submit()`；在已登录该应用的同一浏览器打开；观察服务端状态（不是页面提示）。
   - 完成标准：状态改变可复现，且能说明「受害者只需访问攻击页」。
   - 判停：被拒 → 进第 4 步测防护强度，不要直接放弃。

4. **测 token 三条属性**
   - 做什么：① 随机性——采样多个 token 看长度/字符集/是否含时间戳或用户信息；② 保密性——token 是否出现在 URL/Referer 里；③ 绑定与一次性——用 A 会话 token 配 B 会话 cookie、重复使用同一 token、只保护第二步的流程、302 携带 token 的重定向。
   - 完成标准：每条给出「有效/无效 + 复现方式」。
   - 判停：token 强随机 + 绑会话 + 每请求校验 + 不出现在 URL → 转第 6 步（点击劫持）。

5. **多阶段流程的绕过**
   - 做什么：先请求未保护的第一步拿 token，再提交第二步；或直接请求最后一步（跳过中间确认）；或把参数提交到「不该出现的位置」（另一阶段/另一功能）。
   - 完成标准：能完成本应被拦的动作。
   - 判停：服务端在最后一步做全量重校验时本路失败。

6. **点击劫持可行性**
   - 做什么：检查响应是否带 `X-Frame-Options: deny/sameorigin` 或 CSP `frame-ancestors`（含该路径是否被覆盖、移动版是否漏配）；放透明 iframe + CSS 对齐诱饵按钮；需要输入时用脚本选择性转发 keystroke；需要拖拽时劫持 drop 事件。
   - 完成标准：受害者在诱饵页点击后，目标完成动作且 token 正常提交。
   - 判停：`deny`/`sameorigin` 且覆盖全部路径 → 本路不可行；有 framebusting 时按第 6 步的四条尝试。

7. **有 XSS 时的组合判断**
   - 做什么：存储型 XSS 可直接读同响应里的 token；反射型 XSS 若所在页面本身受 token 保护，则跨站请求因缺 token 而进不到漏洞代码路径 → 需找「未受保护功能上的反射 XSS」或「token 只绑用户 + 登录表单无 CSRF」的多阶段链。
   - 完成标准：能说清「XSS 让哪一道防护失效」。
   - 判停：XSS 无法触达受保护路径时，组合链不成立。

## B — 边界 (Boundary) ★

### 不要用的情况
- 请求带强随机 token 且绑会话、每个敏感请求都校验、token 不出现在 URL：纯 CSRF 不成立，应转点击劫持或放弃。
- 接口强制 `Content-Type: application/json` 且校验 `Origin`/自定义头：普通表单发不出，纯 CSRF 难度大幅上升（但不等于安全，仍需验证是否有其他入口）。
- 目标页面 `X-Frame-Options: deny` 且无遗漏路径：点击劫持不可行。

### 已知失败模式
- **「没有名为 csrf_token 的参数」就报 CSRF**：token 可能改名、放 header、由 JS 注入；必须先确认「是否只靠 cookie」。
- **只删 token 就下结论**：漏掉「token 不绑会话」「只保护某一步」「302 自动携带」三类缺陷。
- **只看单步**：多阶段流程不加 token 仍是 CSRF（分两次发即可）。
- **把 Referer 校验当可靠防御**：可被伪造/被策略移除，原书明确只当辅助。
- **把「多阶段确认」当防御**：攻击者按顺序发两次即可。
- **忽略短 token + URL 传递 + 会话内复用**：可在客户端用 CSS 历史嗅探暴力枚举，无需发请求。
- **只测主站**：移动版与主站共享会话，但常漏配 `X-Frame-Options`。
- **认为「有 framebusting 就安全」**：原书引用的研究显示顶级站点全部可绕；但也不能反过来说「没有 framebusting 就一定有洞」——需实测。

### 作者与时代的局限
- 书中成书时 `SameSite` cookie 尚未普及。现代浏览器默认 `SameSite=Lax` 已挡住大量跨站 POST，判定时必须先确认 cookie 的 SameSite 属性——`Lax` 下顶层 GET 导航仍会带 cookie，POST 不带；`None` 则等同旧行为。
- 书中建议「关键操作从 GET 改为 POST」，但 `SameSite=None` + 顶层导航仍可能被利用，需结合 token。
- Flash 相关的 Referer 伪造、cookie 设置技巧已全面失效。
- CSP `frame-ancestors` 已取代 `X-Frame-Options` 成为主防线，书中只提到前者雏形。

### 容易混淆的方法
- **CSRF vs 点击劫持**：前者请求由攻击者页面构造（无 token），后者由目标页面内的真实点击产生（带 token）。
- **CSRF vs 越权**：前者借受害者身份，后者用自己的身份访问别人的资源。
- **CSRF vs 开放重定向**：前者改变服务端状态，后者只让浏览器跳转。
- **token 防重放 vs 防 CSRF**：防重放要求一次性消耗，防 CSRF 只要求不可预测；把两者混同会导致「用户回退后表单永久失效」这类体验问题。

### 授权与合规边界
> 待补充（用户自行填写）
