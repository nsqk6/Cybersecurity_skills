# 认证量化与发现定级闸门

## R — 原文 (Reading)

> their relevance must be confirmed with respect to five axes: Damage potential - the damage that can result from exploiting the vulnerability; Reproducibility - ease of reproducing the attack; Exploitability - ease of executing the attack; Affected users - the number of users affected by the attack; Discoverability - ease of discovering the vulnerability.

> — 《mobile-security-testing-guide》Mobile App Security Testing / "Exploitation"

> The recommended timeout may be between 10 minutes and two hours, depending on the app's sensitivity. / If the logout is correctly implemented on the server, an error message or redirect to the login page will be sent back to the client. / The probability of finding a match for 6-digit values with a 30-second time step within 72 hours is more than 90%.

> — 《mobile-security-testing-guide》Mobile App Authentication Architectures / Session Timeout、User Logout、2FA

> On the iPhone 4, the passcode-guessing rate is roughly 9.18 guesses per second. This means that, at worst, a four-digit passcode will be guessed in 18 minutes.

> — 《iOS Hacker's Handbook》Chapter 3 "Attacking User Passcodes"

## I — 方法论骨架 (Interpretation)

这个能力回答的是测试收口阶段的两类需求：**「认证类控制到底算不算合格（能不能用数字说话）」**和**「扫描器报了一堆，哪些是真问题、该定什么级别」**。它把「量化判定」和「定级闸门」两件事放一起，因为两者共享一个精神——把主观判断折算成可复算的客观依据：认证用四条量化线和口令强度公式，发现用五轴模型和可达性核验。

核心机制分两块。第一块是**认证量化**：会话/OTP/口令四类测试都有可核对的数值线——①会话超时应在 10 分钟–2 小时区间（按 App 敏感度），超出或不存在即失败；②登出后重放登出前请求，若返回相同响应即服务端会话未销毁/token 未失效（失败）；③OTP 端点连续投递 10–15 个随机值后仍接受正确值即存在爆破面（6 位 + 30 秒步长 + 72 小时窗口命中概率 >90%）；④口令爆破列表 ≤25 条，全程无锁定/无 CAPTCHA 即失败。口令策略本身另有量化线：最小 10 字符、最大约 128（不阻碍 passphrase）、四类字符满足 3/4，再补 zxcvbn 猜测次数分档（0:<10³、1:<10⁶、2:<10⁸、3:<10¹⁰、4:≥10¹⁰）把强度折算成离线爆破成本，策略应能拒绝 score ≤2 的口令。设备解锁口令则是另一套——iOS 的 PBKDF2 用硬件 UID 参与且迭代随 CPU 调整，使口令只能在该设备上在线猜测，速率被硬件锁定（iPhone 4 约 9.18 次/秒），于是强度折算为最坏穷举时间：4 位数字 10⁴/9.18≈18 分钟、6 位字母数字进入「数年」量级，搜索空间口径 10ⁿ/36ⁿ/71ⁿ。第二块是**发现定级闸门**：五轴模型逐轴回答「打坏多严重、能否稳定复现、实施门槛、影响面、被发现多容易」，任一轴趋零都显著降低实际风险——做法是记录最弱的「卡脖子轴」而非打总分，并把该轴写成利用前提（如「需已越狱设备 + 用户交互一次」），让读者能复算出同一定级。可达性核验则是更早的一道闸——扫描器按「浏览器模型」报 CSRF/XSS，但移动端会话 Cookie 存在 App 自己的存储，用户点恶意链接跳到系统浏览器（独立 Cookie 仓），攻击链第一步就断；判定标准是「在移动端执行路径上，攻击者能否把输入送达并让受害者凭据自动附上」，存储型 XSS 只有在 WebView 且导出了 JS 接口时才可能升级为命令执行。

为什么放一起：这两块都是「给结论加客观依据」——认证量化给「合格/不合格」画数值线，五轴与可达性给「报不报、报多级」加人工闸门。它们共享「不盲信工具/不凭感觉」的纪律，且在报告阶段连续使用：先用可达性确认攻击链存在，再用五轴定轻重，认证类发现则用四条量化线直接判。读完应能跑：对每条认证控制套数值线 → 对每条扫描告警写出攻击链并判可达 → 对保留项五轴打分记录最弱轴 → 成文时把前提写清楚。

**多端认证差分与组合利用补充**（Bug Bounty Bootcamp + 泰阿手册 + 黑客秘笈补充）：认证的另一类高价值问题来自"同一功能多端实现不一致"，靠横向对比而非单端量化发现。①**App vs Web 认证授权差分**——服务端可能误以为 App 是可信客户端而放宽校验，把两端实现同一功能的请求逐项对比认证头、令牌校验、对象 ID 处理，任一端缺校验即暴露 IDOR 或失效认证。②**2FA 多端覆盖差异**——2FA 常只加在 Web 登录页，API、旧客户端/胖客户端、其他应用端点可能缺失；拿到凭据后枚举所有身份验证入口逐一尝试，别在主门户被 2FA 拦下就放弃。③**mfa 标志翻转**——对比 2FA 开/关两态的登录请求，定位客户端可控的 `mfa`/`code` 参数，在启用态把它改回 `"mfa":null,"code":""`，若响应跳回 dashboard 即绕过（前提是服务端信任客户端标志）。④**会话缺陷 + XSS 组合**——App 的令牌复用/超长会话/cookie 不过期单独看危害有限，但与同域 XSS 组合后攻击者拿到 cookie 可在受害者登出或改密后继续接管账户；cookie 设了 HttpOnly 则直读失效需换路径。这几条把"认证"从单端量化扩展到跨端差分与攻击链组合，定级时同样回到五轴（影响面、利用门槛）。

## A1 — 应用示例 (Application Example)

### 示例 1: Burp Intruder 口令爆破（CU-2-17）
- **类型与来源**: 【转述】《mobile-security-testing-guide》Mobile App Authentication Architectures
- **问题/输入**: 自有测试账号，要验证登录接口的限速与口令策略。
- **方法论的使用**: (1) 把正确口令 `12345` 追加到 ≤25 条的字典末尾；(2) Burp Intruder 跑爆破；(3) 通过响应长度与状态码差异识别出成功口令；(4) 全程未被锁定/未出验证码即判「限速失败」。
- **结论**: 爆破类测试会锁号，原文建议放到测试最后做；用超过 25 条的字典触发了锁定反而会误判为「有防护」，必须控制在口径内。
- **结果**: 原书记载以 Burp Intruder 演示通过响应长度与状态码差异识别成功口令 `12345`。

### 示例 2: CSRF 在移动端的假阳性核验（CU-2-03）
- **类型与来源**: 【转述】《mobile-security-testing-guide》Avoiding False Positives
- **问题/输入**: 扫描器报了一个 Web 侧 CSRF，要判断在移动端是否成立。
- **方法论的使用**: (1) 逐条写出攻击链（谁投放、受害者如何触发、凭据是否自动附带）；(2) 检查会话凭据存放位置与 WebView/外部浏览器边界——用户点击的恶意链接在默认浏览器打开，它有独立 Cookie 存储，攻击链断在第一步；(3) 对 WebView 内存储型 XSS 进一步确认是否暴露 JS Bridge，有则升级评级，无则降为「最佳实践缺失」。
- **结论**: 判定标准不是「代码里有没有这个模式」而是「在移动端执行路径上攻击者能否把输入送达且凭据自动附上」；不要盲信扫描工具输出。
- **结果**: 原文以 CSRF 需两个前提（诱导已登录用户点链接、浏览器自动附带 Cookie）逐条对照移动端说明为何不成立。

### 示例 3: iPhone 4 设备口令最坏时间（CU-2-22）
- **类型与来源**: 【亲历】《iOS Hacker's Handbook》Chapter 3 "Attacking User Passcodes" Table 3.3
- **问题/输入**: 评估 iPhone 4 上不同长度/字符集的设备解锁口令强度。
- **方法论的使用**: (1) 取实测猜测速率约 9.18 次/秒（用脚本计时若干次猜测取平均，勿用他机型外推）；(2) 估算搜索空间：4 位数字 10⁴、字母数字 36ⁿ、含符号 71ⁿ；(3) 最坏时间 = 搜索空间 / 速率；(4) 附加折扣——「an intelligent dictionary attack may be much more efficient」，实际强度低于纯穷举。
- **结论**: 4 位数字 ≈18 分钟、6 位字母数字进入「数年」量级；iOS 的 UID 绑定使离线破解不可行，用桌面 GPU 算力估算会低估强度；UI 层的指数退避与「错误若干次抹除」是策略层防护，与硬件速率叠加而非替代。
- **结果**: 原书 Table 3.3 给出 4 位数字 18 分钟、字母数字 19 天、再长依次 196 年 / 755 千年 / 复杂字符集 2700 万年。

## A2 — 触发场景 (Future Trigger)

### 用户会在什么情境下需要它
1. 定级争议：「这个漏洞该定什么级别」「怎么排优先级」「扫描器报了 CSRF/XSS 算不算」「how to rate mobile findings / DREAD」。
2. 认证量化：「会话超时多久算合格」「登出后 token 还有效吗」「OTP 能不能爆破」「密码策略怎么算合格」「password policy review / zxcvbn score」。
3. 设备口令：「设备密码几位才安全」「PIN 能被爆破吗」「iOS passcode brute force feasibility」。
4. 报告收口：「哪些发现能写进报告」「利用前提怎么写让读者能复算」。
5. 多端认证差分：「App 和网页权限不一样」「同一个功能两端表现不同」「App 的 2FA 怎么绕」「网站有 2FA 还要测 API 吗」「XSS 和会话怎么组合」。

### 语言信号（出现这些就该激活）
- 中文：「定级」「优先级」「五轴」「会话超时」「登出失效」「OTP 爆破」「口令策略」「zxcvbn」「密码几位的」「扫描器误报」「假阳性」「攻击链」「多端认证不一致」「mfa 参数」「IDOR 只在 App 端」。
- English: "how to rate mobile findings / DREAD", "session timeout best practice", "logout token still valid", "OTP brute force", "password policy review / zxcvbn score", "iOS passcode brute force feasibility", "is this a false positive in mobile", "mobile vs web authorization difference", "bypass 2FA by tampering mfa parameter", "2FA only on web not API", "chain XSS with long lived session"。

### 与相邻能力的区分
- 与 `<attack-surface-scoping>` 的区别：后者做「列全攻击面 + 剔不可达 + 分阶段」，本能力做「对已确认发现定级」；五轴模型是后者 Exploitation 阶段的下游闸门，可达性核验与后者的「可达性收敛」同源但本能力针对 Web 类告警。
- 与 `<ios-platform-security-testing>` 的区别：后者的生物识别是「本地门禁」，本能力的认证量化是「服务端会话/OTP/口令策略」；本地门禁永远不能替代服务端校验。
- 与 `<component-exposure-and-exploitation>` 的区别：后者用「权限成本 + 上下文等级」给 IPC 组件定级，本能力用五轴给通用发现定级；两者都产出「利用前提」，但口径不同（前者是权限/上下文，后者是五轴）。

## E — 可执行步骤 (Execution)

**必需输入**: 已完成真实利用（五轴打分需有利用记录，无记录时只是猜测）；自有测试账号（锁定类测试会锁号，原文建议放最后）；拦截代理可重放；认证策略的源码或注册/改密界面（纯黑盒需逐一试错反推）；设备口令速率测试需已越狱设备与可调用 MKBUnlockDevice 的工具。缺利用记录时不得给出五轴定级。

**交付物与完成标准**: 认证类产出「四条量化线 + zxcvbn 分档 + 最坏时间」的判定表；发现类产出「攻击链可达性结论 + 五轴最弱轴 + 利用前提」。完成标准：每条结论读者能据此复算出同一定级；每条认证项有数值依据而非主观判断。

1. **（会话）超时量化**
   - 做什么：登录后每隔 5 分钟访问受保护资源，记录首次被拒时间点 → 与 10min–2h 区间比对。
   - 完成标准：超出、过短或不存在即失败。
   - 判停：只看客户端有无超时提示不算，必须验证服务端是否真的失效。

2. **（登出）重放验证**
   - 做什么：登录 → 访问私有资源 → 登出 → 重放该请求 → 看是否仍返回数据。
   - 完成标准：若返回与登出前相同响应即服务端会话未销毁/token 未失效（失败）；正确实现应返回错误或重定向登录页。
   - 判停：客户端删除 token 不代表服务端失效，必须看服务端响应。

3. **（OTP/锁定）爆破面测试**
   - 做什么：抓一次 2FA 请求 → 先发 10–15 个随机 OTP 再发正确值 → 仍通过判存在爆破面；把正确口令追加到 ≤25 条字典末尾跑爆破 → 全程未锁定/未出验证码即失败。
   - 完成标准：OTP 与锁定各有结论；6 位 + 30 秒步长 + 72 小时窗口命中 >90% 作为风险依据。
   - 判停：锁定类测试放最后做，避免第一天就锁死账号；字典超过 25 条触发锁定会误判为「有防护」。

4. **（口令策略）量化核对**
   - 做什么：定位所有口令校验函数（注册、改密、重置三条路径都调用同一策略）→ 核对长度 10/128 与 3-of-4 复杂度 → 用 zxcvbn 对典型弱口令打分 → 验证服务端限速配套。
   - 完成标准：策略能拒绝 score ≤2 的口令；前端与服务端校验一致。
   - 判停：只验前端正则忽略服务端会失效；策略过严逼用户写便签反而降低安全性（原文对「禁止粘贴」的批评同理）。

5. **（设备口令）最坏时间计算**
   - 做什么：取实测猜测速率（勿用他机型外推）→ 估算搜索空间（10ⁿ/36ⁿ/71ⁿ）→ 最坏时间 = 空间 / 速率 → 附加字典攻击折扣。
   - 完成标准：给出可算的强度结论与 MDM 策略依据。
   - 判停：用桌面 GPU 算力估算会低估强度（UID 绑定）；忽略指数退避与抹除策略会高估可行性。

6. **（假阳性）攻击链可达核验**
   - 做什么：对每条扫描告警写出攻击链（谁投放、受害者如何触发、凭据是否自动附带）→ 检查会话存储与 WebView/外部浏览器边界 → 链接跳出系统浏览器（独立 Cookie）判不可利用 → WebView 存储型 XSS 进一步确认 JS Bridge。
   - 完成标准：每条告警有「链是否存在」的明确结论；有 JS 接口则升级评级，无则降为最佳实践缺失。
   - 判停：因为「移动端不会有 XSS」而漏掉 WebView + JS 接口的真实利用链是错的。

7. **（多端差分）认证授权对比与组合利用**
   - 做什么：列 Web 门户/API/旧客户端/App 各端点全部认证入口 → 对同一功能逐项对比认证头、令牌校验、对象 ID 处理（找 IDOR/失效认证）→ 逐入口用凭据试登录查 2FA 覆盖 → 对比 2FA 开/关两态定位 `mfa`/`code` 参数并尝试翻转为 `"mfa":null,"code":""` → 审会话令牌复用/超长/不过期并在同域找 XSS 尝试组合接管。
   - 完成标准：每条差异有跨端对照证据；组合利用有"登出/改密后仍可访问"的实证。
   - 判停：只测一端就下"权限没问题"结论会漏；服务端不信任客户端标志时 mfa 翻转无效；cookie 设 HttpOnly 时 XSS 直读失效需换路径；在主门户被 2FA 拦下就放弃会漏掉 API/旧客户端薄弱入口。

8. **（定级）五轴打分与成文**
   - 做什么：对每条保留漏洞逐轴打分并写下依据 → 标出最弱「卡脖子轴」→ 把该轴写成利用前提（如「需已越狱设备 + 用户交互一次」）。
   - 完成标准：读者能据此复算出同一定级；报告不含未验证的扫描器告警。
   - 判停：只算 Damage potential 一轴会把所有「能读本地文件」报成高危；忽略 Discoverability 会把需逆向才能发现的缺陷当成随时可利用；无利用记录时五轴打分只是猜测，回第 6 步补证据。

## B — 边界 (Boundary)

### 不要用的情况
- 尚未做真实利用时：五轴打分只是猜测，先完成利用验证（`<attack-surface-scoping>` 的 Exploitation 阶段）。
- 需要精确 CVSS 向量（含时间/环境原子度量）时：五轴是粗粒度闸门，不含这些原子度量。
- 目标是 IPC 组件危害定级：用 `<component-exposure-and-exploitation>` 的权限成本 + 上下文等级口径，不用五轴。
- Web 服务端会话架构评审（非移动 App 场景）：本能力聚焦移动端认证测试，服务端深度审计不在范围。

### 已知失败模式
- 在测试第一天就跑爆破，把账号锁死导致后续用例无法执行；只看客户端有无超时提示而不验证服务端；用超过 25 条的字典触发锁定却误判为「有防护」（`mobile-security-testing-guide` Authentication Architectures）。
- 只验前端正则忽略服务端同样校验；策略过严逼用户写便签，降低可用性反而降低安全性（同书）。
- 直接照抄 DAST 报告把 Web 侧 CSRF 当移动端高危；或因「移动端不会有 XSS」漏掉 WebView + JS 接口的真实利用链（同书 Avoiding False Positives）。
- 只算 Damage potential 一轴把所有「能读本地文件」报成高危；忽略 Discoverability 导致需逆向才能发现的缺陷被当成「随时会被利用」（同书 Exploitation）。
- 用桌面 GPU 算力估算 iOS 口令（UID 绑定使离线破解不可行，会低估强度）；忽略 UI 层指数退避与抹除策略（iOSHH Ch3）。

### 作者与时代的局限
- 五轴模型（Damage/Reproducibility/Exploitability/Affected users/Discoverability）与 DREAD 同源，是粗粒度报告闸门，不是 CVSS 替代品；MSTG 写作时的数值口径（10min–2h、25 条字典、10–15 个 OTP）是经验基线，需按目标 App 敏感度调整。
- iPhone 4 的 9.18 次/秒与 Table 3.3 的时间表是历史硬件数据；现代 iPhone 的 Secure Enclave 与迭代策略已不同，量级结论不可直接外推，但「速率 × 搜索空间」的计算框架仍成立。
- zxcvbn 分档（0–4）是其写作时的版本口径，新版本评分阈值可能变化。
- CSRF/XSS 假阳性判断基于「恶意链接在系统浏览器打开、Cookie 仓独立」的模型，对 WebView 内嵌浏览或 PWA 等新形态需重新判定边界。

### 容易混淆的方法
- 「认证量化」与「发现定级」：前者给认证控制画合格线（数值），后者给发现画上报线（五轴）；两者都在报告阶段用，但对象不同。
- 「会话/OTP 测试」与「口令强度」：前者测限速与失效（CU-2-17），后者测口令本身强度（CU-2-18）；互补但判据不同。
- 「服务端口令策略」与「设备解锁口令」：前者算策略合规与 zxcvbn 分档，后者算硬件绑定下的在线爆破成本，不可混用。
- 「五轴」与「CVSS」：五轴不含时间/环境原子度量，是给渗透测试报告用的粗粒度闸门，不是 CVSS 向量。

### 授权与合规边界
> 待补充（用户自行填写）
