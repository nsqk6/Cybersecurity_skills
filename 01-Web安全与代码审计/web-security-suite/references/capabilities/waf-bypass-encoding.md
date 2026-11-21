# 拦截层绕过：先定位「在哪一层失效」，再选对应的变形手法

## R — 原文 (Reading)

> "The main problem with this kind of approach is that there are multiple ways to reach the same goal; therefore, every small change of the attack payload must be added to the blacklist, otherwise you have a WAF bypass!"
>
> 译：这类方法的主要问题是：达到同一目标有多种写法；因此攻击载荷每有一处小改动，都必须加进黑名单，否则就存在一个绕过。

> — 《Encoding And Filtering》1.2.2 Web Application Firewall

> "例如order by被拦截，既不是order触发了waf，也不是by，是它们的组合触发了waf。"
>
> — 《163酒仙桥六号部队__048-waf绕过拍了拍你》

> "Although many would argue that having these is better than nothing at all, in many cases they may create a false sense of security..."
>
> 译：很多人会说有总比没有好，但在很多情况下，这类设备会制造虚假的安全感……

> — 《The Web Application Hacker's Handbook》Ch18 / Web Application Firewalls

## I — 方法论骨架 (Interpretation)

「被拦了怎么办」是一个**定位问题**，不是「换 payload」问题。拦截可能发生在六层，每层的失效点与手法完全不同；搞错层，就会在原理上根本不成立的手法上无限循环。

| 失效层 | 现象 | 手法 |
|---|---|---|
| 规则匹配（黑名单） | 改一个字符仍被拦，说明匹配的是语义关键字 | 等价改写（改函数名/标签/取值方式） |
| 编码/规范化 | 单层编码被拦、双层通过 | 多重编解码、Unicode 过编码、字符等价物 |
| 协议理解 | 换 `Content-Type`/方法/同名参数就放行 | multipart 伪装、GET↔POST、HPP、分块 |
| 解析不一致 | WAF 与后端读的不是同一个值 | 文件名后缀差异、charset（如 `ibm037`）、`..;/` |
| 检测能力上限 | 超长参数/大量参数时漏检 | 参数溢出、缓冲区溢出 |
| 流量不经过 | 直连源 IP 就通了 | 找源站、同网段、SSRF 从内部发起 |

三条必须先做的判断：

1. **是 WAF 还是应用自己**。WAF 拦通常返回固定拦截页/异常状态码/直接断连；应用过滤则是内容被改写或返回业务错误。原书明确：设备层绕过成功 ≠ 应用层过滤不存在，后者要靠源码或 fuzz 单独确认。
2. **"最小触发组合"是什么**。规则型 WAF 常按「多词共现」拦截：`order by` 被拦可能既不是 `order` 也不是 `by`，而是组合。所以正确顺序是**先单词级 fuzz，再组合级 fuzz**，定位到最小组合后再动手拆。
3. **设备 ≠ 补偿控制**。即便绕过失败，也不能因为「有 WAF」就降低测试深度：WAF 看不见映射、认证、会话、访问控制、业务逻辑、DOM 型 XSS，也会因应用在设备之后还会解码而失效。

变形手法的选择顺序应按「成本从低到高」：等价改写（最便宜，语义不变）→ 编码层（需要知道解码次数与位置）→ 协议层（需要知道后端是否支持）→ 绕开设备（需要拿到源站）。跳到最后一步往往是浪费时间。

## A1 — 应用示例 (Application Example)

### 示例 1: 先 fuzz 出「被拦的最小关键字组合」
- **类型与来源**: 【亲历】《163酒仙桥六号部队__048-waf绕过拍了拍你》（云锁实测）
- **问题/输入**: 一个 SQL 注入点，`order by` 整串被拦。
- **方法论的使用**: ① 单词 fuzz：把 `and`、`order`、`by`、`select` 逐个单独发，记录哪些单独放行；② 组合 fuzz：把放行的词两两/三三拼起来发，找出触发拦截的最小组合（本例为 `order` + `by` 共现）；③ 对触发组合插入 `/**/`（或 `/*!order*/`）切断词形 → 再发确认放行；④ 仍拦时用 `%23A%0A`（`#A` + 换行）把语句断成两行 → 后端注释掉伪造部分、换行后继续执行真实语句；⑤ 最终 payload：`/*!order*//**/%23A%0A/**/%23A%0A/*!by*//**/2` 判出列数。
- **结论**: 不知道「拦的是哪个词」时，任何变形都是盲试；先定位组合，再拆组合。
- **结果**: 作者在 18 行自写测试代码上用云锁实测通过；同时记录 `AnD 1=1`、`/!ANd/ 1=1` 仍被拦（该 WAF 对大小写与内联注释做了归一化），只有 `&&` 与「拆分后重新拼接」放行。

### 示例 2: 分块传输的三个硬前提
- **类型与来源**: 【亲历】《163酒仙桥六号部队__042-唯快不破的分块传输绕WAF》
- **问题/输入**: POST 注入点，关键字被 WAF 按整串匹配。
- **方法论的使用**: ① 把被拦请求改成 POST（GET 无 body，无法分块）；② 加 `Transfer-Encoding: xchunked`（注意原文实测需写 `xchunked` 而非 `chunked`，写标准值会被识别）；③ 按块切分关键字（`un` / `ion sel` / `ect`），每块前写十六进制长度；④ 逐块发送看响应；⑤ 量大时用 Burp 的 `chunked-coding-converter` + `sqlmap -r post.txt --proxy` 自动化。
- **结论**: 分块把「语义由分隔符决定」变成「语义由长度前缀决定」，WAF 在单块里看不到完整词形，后端拼回去仍得到原语句。
- **结果**: 作者在重保项目中用该法跑通 sqlmap；同篇明确「无法绕过代码本身的检测」——应用层若自己过滤了关键字，分块毫无作用。

### 示例 3: JSON 的 `\u` 转义
- **类型与来源**: 【亲历】《163酒仙桥六号部队__029-从Fastjson绕WAF到打穿网闸》
- **问题/输入**: Fastjson payload 的 `@type` 被防火墙按字面拦。
- **方法论的使用**: ① 原 payload 发包确认被拦，用二分法改一处发一次定位被拦字段；② 只把被拦片段转成 `\uXXXX`（`@type` → `\u0040\u0074\u0079\u0070\u0065`），其余保持原样；③ 发包看 VPS 是否收到回连；④ 成功后立刻验证能否出网，决定后续走反弹还是回显。
- **结论**: JSON 规范允许 `\uXXXX` 表示任意字符，解析器在还原后才交给 Fastjson，而 WAF 在原始字节上匹配——语义不变、字面不匹配。
- **结果**: 作者用该变形绕过防火墙，VPS 收到请求。

### 示例 4: 字符等价物与规范化顺序
- **类型与来源**: 【例题】《Encoding And Filtering》1.1.1.4 Unicode Encoding
- **问题/输入**: 反馈页对 `EVIL` 做黑名单，入库前转小写。
- **方法论的使用**: ① 确认存在变换：输入 `İ`（U+0130）看回显是否变成 `i`，输入 `ſ`（U+017F）看是否变成 `S`；② 判断变换与过滤的先后：提交 `Evİl intent, as usual!` → 通过检查，入库后变 `evil`，说明过滤在前、变换在后；③ 按目标关键字构造等价字符：尖括号用 `＜`(U+FF1C)/`﹤`(U+FE64)/`‹`(U+2039)；④ 触发变换后观察 sink 行为。
- **结论**: 过滤与规范化顺序颠倒，就会出现「检查时不是敏感词、落库/输出时变成敏感词」。
- **结果**: 原书以该例说明最佳适配映射（best-fit mapping）可绕过审查，并给出 `ⓓⓡⓞⓟⓣⓐⓑⓛⓔ` → `drop table` 的同类示例。

### 示例 5: 分块只影响自己，走私影响别人
- **类型与来源**: 【亲历】《163酒仙桥六号部队__066-由一次渗透测试引发的HTTP请求走私思考》
- **问题/输入**: 响应头同时出现 `Transfer-Encoding` 与 `Content-Length`，前面还有 ATS。
- **方法论的使用**: ① 确认前后端分离（响应头有 ATS、TE 与 CL 并存）；② 测 CL.TE：`Content-Length` 设为「包含后半段的总长」+ `Transfer-Encoding: chunked`，body 里先放正常块再放 `GET /404 HTTP/1.1` → 下一个请求返回 404 即命中；③ 测 TE.CL：`Content-Length: 4` + `Transfer-Encoding: chunked` + 块长 `7c` 包裹恶意请求；④ 用 Burp HTTP Request Smuggler 与 `defparam/smuggler` 交叉验证；⑤ **关掉 Repeater 的自动更新 content-length**（原文特别提醒，这是「本地测不出来」的最常见工具坑）。
- **结论**: 走私的成因是前后端对「body 到哪结束」理解不同，多出来的字节被后端当成下一个请求的开头。
- **结果**: 作者用「捕获下一个用户 cookie」与「反射 XSS 弹窗」证明危害。

## A2 — 触发场景 (Future Trigger) ★

### 用户会在什么情境下需要它
1. payload 一发就被拦，不知道是 WAF、应用过滤还是 CDN。
2. 试了大小写、注释、编码都不行，需要判断「是不是原理上就不成立」。
3. sqlmap 全红，想知道该用 tamper、分块还是手注。
4. 想知道目标前是什么设备、规则大概长什么样。
5. 有 JSON/XML 接口，关键字被拦，需要不改变语义的变形。
6. 设备层绕过了但业务还是失败，需要区分「设备拦」与「应用过滤」。
7. 拿到 webshell 但 `disable_functions` 禁了命令函数。

### 语言信号（出现这些就该激活）
- 中文：「WAF 拦了怎么绕」「payload 一直被拦」「试了编码还是不行」「分块传输怎么用」「sqlmap 全红怎么办」「有没有 WAF」「@type 被拦了」「disable_functions 怎么绕」「注释绕过没用」
- English: "WAF bypass techniques", "which layer does WAF fail", "chunked transfer encoding bypass", "unicode escape bypass", "double encoding", "homoglyph bypass", "request smuggling CL.TE", "bypass disable_functions", "LD_PRELOAD php rce"

### 与相邻能力的区分
- 与 `injection-channel-selection` 的区别：本卡只解决「载荷能不能到达 sink」；到达之后的通道选择回那张卡。
- 与 `xss-context-runtime` 的区别：那张卡的「过滤器三分类」处理应用代码的清洗缺陷；本卡处理外部设备与协议层。两者可叠加，判断顺序是先看响应差异再归因。
- 与 `deserialization-rce` 的区别：本卡的 `\u` 变形是为那张卡服务的；`disable_functions` 是拿到执行后的下一段。
- 与 `recon-asset-surface` 的区别：那张卡只记录「有设备、大概是谁」，不展开绕过。

## E — 可执行步骤 (Execution)

**必需输入**: 一个稳定可复现的「被拦/未被拦」对照；目标技术栈（决定编码层与解析层手法）；能改原始报文的代理。缺「对照」就只能盲试，效率极低。

**交付物与完成标准**: 一份「拦截层 → 证据 → 生效手法 → 残余限制」的记录；完成标准是同一条语义的请求在绕过前后都能稳定复现（拦/放），且能说清「绕的是设备还是应用」。

1. **确认有没有设备、是哪一类**
   - 做什么：基线请求记录 `Server`/`X-Powered-By`/`Set-Cookie`/状态码；发一次恶意请求对比：是否出现新 Cookie、Server 头被改写/消失、`406`（mod_security）、`999`（WebKnight）、固定拦截页文案、直接断连；用 `wafw00f`/`nmap --script http-waf-fingerprint` 交叉。
   - 完成标准：能说出「有/无设备 + 大概率是哪家」。
   - 判停：CDN 会统一改写 Server 头导致误判，需用拦截页文案与 Cookie 交叉；只发一种攻击类型可能被 passive 模式放行，需多发几种。

2. **分层定位：先规则层**
   - 做什么：对单个关键字做最小变形（大小写、`/**/`、`%26%26`、等价函数），每次只改一处并重放。
   - 完成标准：找出「触发拦截的最小特征」。
   - 判停：有反应说明是纯规则匹配 → 走第 5 步等价改写；无反应 → 第 3 步。

3. **协议层**
   - 做什么：改 `Content-Type: multipart/form-data`；GET↔POST 互换；同名参数污染；追加 `Transfer-Encoding: xchunked` 并分块；换 charset（如 `ibm037`）。
   - 完成标准：同一语义在新协议形态下放行。
   - 判停：后端不支持 chunked 时分块无效；`Transfer-Encoding` 写标准 `chunked` 常被识别，需按目标实测。

4. **解析层与「绕开设备」**
   - 做什么：利用 WAF 与后端的解析差异（文件名/后缀、路径 `..;/`、`%20`、`//`）；都无效才考虑直连源 IP、同网段、用 SSRF 从内部发起。
   - 完成标准：证明「WAF 读到的值与后端读到的值不同」。
   - 判停：直连源 IP 需要先拿到源站地址；这一步风险与影响面最大，应放在最后。

5. **等价改写（最便宜的一层）**
   - 做什么：按类别替换同一语义——弹窗：`alert(1)` → `prompt(8)`/`confirm(8)`/`alert(/xss/.source)`/`window[/alert/.source].call(this,8)`；取 cookie：`alert(document.cookie)` → `with(document)alert(cookie)`；标签：`<img src=x onerror=...>` → `<svg/onload=...>`/`<video src=x onerror=...>`；盲注：`' or 1=1` → `' or 6=6`/`' or 0x47=0x47`/`or char(32)=' '`/`or 6 is not null`；联合查询：`UNION SELECT` → `UNION ALL SELECT`；路径：`/etc/passwd` → `/too/../etc/far/../passwd`/`/etc//passwd`；webshell 名：`c99.php` → `augh.php`。
   - 完成标准：每次只改一处，能指出「哪个写法过了、哪个没过」。
   - 判停：语义等价对白名单校验（只允许特定字符集）无效；基于语法树的规则仍会命中结构相同的请求。

6. **编码层（多重编解码与字符等价）**
   - 做什么：观察参数形态（含 `%`、`=` 结尾、长度 4 的倍数、base64 字符集）→ 逐层解码到明文，记录层数与顺序 → 判断各层在哪解（URL 在 Web 服务器、base64 常在业务代码）→ 按「过滤后解码」的层数重新编码（单层 `%3C`、双层 `%253C`）；Unicode 过编码（`%E5%98%8A` 代 `%0A`）；字符等价物（`İ`→`i`、`ſ`→`S`、`＜`→`<`）。
   - 完成标准：过滤看到无害串、sink 看到可执行串。
   - 判停：编码层数与实际解码层数不一致时 payload 会变成纯文本；框架对 `+`/空格互转会破坏 base64。

7. **组合拆分（SQL 场景）**
   - 做什么：单词 fuzz → 组合 fuzz → 对触发组合插 `/**/` 或 `/*!word*/` 切断词形 → 仍拦则用 `%23A%0A` 把语句断成两行（注意插在关键字**之间**而非句尾）。
   - 完成标准：`order by N` 这类被拦语句能正常执行并返回预期结果。
   - 判停：WAF 对大小写与内联注释都做归一化时（如云锁），本路失败，改试 `&&` 或分块。

8. **执行层限制（`disable_functions`）**
   - 做什么：读 `phpinfo` 确认被禁函数与扩展；按「OS + 扩展 + 能否写文件」选：漏网函数（`proc_open`/`pcntl_exec`）→ Windows COM（`new COM('WScript.shell')`）→ Linux `LD_PRELOAD`（劫持 `mail()` 调用链或 `__attribute__((constructor))`）→ Bash 破壳（`mail()` 第五参数）→ `imap_open` 的 `-oProxyCommand` → `mod_cgi` + `.htaccess`。
   - 完成标准：在受限环境下执行一条系统命令。
   - 判停：每条都有硬前提（COM 需 `com.allow_dcom` 与 dll、LD_PRELOAD 需 `mail()`/`error_log()` 未被禁、破壳需 bash ≤4.3、imap 需 `imap.enable_insecure_rsh=On`、mod_cgi 需 `AllowOverride all`）；前提不满足时不是方法失效，是环境不支持。

9. **收尾：区分设备与应用**
   - 做什么：绕过成功后，把同一语义的「干净」请求再发一次，看应用自身是否也做了过滤（内容被改写/业务报错）；若应用也拦，回到第 5 步按应用层缺陷处理。
   - 完成标准：报告里能写清「绕过了哪一层、还剩哪一层」。
   - 判停：把「设备绕过成功」当「漏洞可利用」是常见误报。

## B — 边界 (Boundary) ★

### 不要用的情况
- 目标使用白名单式校验（只允许 `[A-Za-z0-9]`、只允许枚举值）：等价改写、编码、字符等价物全部无效，别耗。
- 目标用语义分析/正则化引擎（解码后再匹配、AST 级检测）：`\u` 转义、多重编码、注释拆分多数失效。
- 只是「扫描器报红」而没有手工确认拦截层：可能根本不是 WAF，而是应用返回了业务错误。
- `disable_functions` 环境下所有替代通道的硬前提都不满足（无扩展、无写权限、bash 已打补丁）：接受失败，换目标。

### 已知失败模式
- **一上来就套 tamper 列表**：不知道拦的是哪个词、哪一层，变形越多越乱。
- **`Transfer-Encoding: chunked` 写标准值**：常被 WAF 识别，原文实测需 `xchunked`。
- **分块后忘了「应用层仍可能过滤」**：原文明确「无法绕过代码本身的检测」。
- **keep-alive/Pipeline 绕过**：原文标注「发送两个请求，但绕过失败，被云锁拦截，此种方法现在基本失效」。
- **走私验证时开着 Repeater 的自动 content-length**：长度被自动改写，本地永远测不出来。
- **只看浏览器渲染判断头注入**：必须看原始响应头。
- **把「有 WAF」当降低测试深度的理由**：WAF 看不见映射/认证/会话/访问控制/业务逻辑/DOM XSS。
- **把「WAF 没拦」当「没有漏洞」**：设备放行不等于应用安全。

### 作者与时代的局限
- 书中的产品特征（云锁、WebKnight、mod_security 的 406）与具体绕过写法随版本变化很快；方法（分层定位 + 最小触发组合）稳定，具体 payload 需按目标重测。
- `Transfer-Encoding` 混淆（`xchunked`、tab 前缀、双 TE）在不同代理组合下差异极大，不能照抄。
- 现代 WAF 多已做「解码后匹配」与「语义分析」，纯编码绕过的成功率显著下降；但「解析不一致」（WAF 与后端读不同值）仍是长期有效的一类。
- `disable_functions` 的五条通道多依赖已废弃扩展（`imap`、`COM`）或老版本 bash，容器化环境命中率低；`LD_PRELOAD` 仍较通用但需能落 `.so`。

### 容易混淆的方法
- **WAF 绕过 vs 应用过滤器绕过**：前者是设备层（签名/协议/解析），后者是代码层（清洗/编码/截断）；判断顺序是先看响应差异再归因。
- **分块传输 vs 请求走私**：前者让 WAF 读不懂（只影响自己这条），后者让前后端理解不一致（能影响他人请求）。
- **编码绕过 vs 字符等价绕过**：前者改变字节表示，后者改变字符本身（Unicode 同形/大小写折叠）。
- **设备指纹 vs 中间件指纹**：前者是安全设备（WAF/IPS），后者是应用容器（Tomcat/WebLogic）；指纹特征与对应手法不同。

### 授权与合规边界
> 待补充（用户自行填写）
