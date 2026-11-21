# WebView 与客户端入口注入

## R — 原文 (Reading)

> Loading cleartext content is the single biggest mistake that can be made when implementing a WebView, because this opens it up to various forms of abuse from Man-in-the-Middle (MitM) attacks such as ARP poisoning.
> — 《Mobile App Hackers Handbook》Chapter 7 "Misusing Insecure Communications / WebViews"（Table 7.2）

> This issue is present on all API versions prior to 17… any application that has been compiled with an android:targetSdkVersion attribute… of less than 17 will also be vulnerable, regardless of the device it is running on.
> — 《Mobile App Hackers Handbook》Chapter 7 "CVE-2012-6636—ADDJAVASCRIPTINTERFACE ARBITRARY CODE EXECUTION"

> the key to determining the client-side attack surface is to understand exactly what types of files and protocols each application is willing to consume.
> — 《The Mac Hackers Handbook》Chapter 3 "Cutting into the Client Side"

## I — 方法论骨架 (Interpretation)

这个能力解决「客户端有哪些输入入口，注入之后能调到什么能力」。它把三类入口串成一条攻击链：**内容从哪来 → 注入什么 → 调到什么 Java/原生能力**。

**WebView 内容源判定**：WebView 危害上限由配置决定，而默认值里一半是「危险但默认开」：`setAllowContentAccess` 默认 true（触达 content provider）、`setAllowFileAccess` 默认 true（`file://` 读本地）、`setAllowUniversalAccessFromFileURLs` 在 API≤15 默认 true（file:// 页面跨源读任意文件，≥16 才默认 false）、`setSavePassword` 默认 true；`setJavaScriptEnabled` 默认 false，一旦打开就把上面这些串成链。判断顺序必须是：**先确定内容从哪来**（明文 HTTP？外部可控 URL？file://？），再查开关。同一配置在「只加载自家 HTTPS 页」时无害，在「加载 intent 传入的 URL」时就是任意代码执行。还要注意 `onReceivedSslError → handler.proceed()` 这一行——它让 HTTPS 变成可 MITM。

**JS bridge 可用性判据**：`addJavascriptInterface` 把 Java 对象挂到 JS 全局变量。API<17 时 JS 能反射调用任意 public 方法（`getClass().forName('java.lang.Runtime')...exec()`），API≥17 后只有 `@JavascriptInterface` 标注的方法可见。判据是两段式：**bridge 是否存在 × targetSdk 是否 <17**。决定行为的是 targetSdk 而不是设备版本——老 APK 装新手机仍能用反射打。即使 ≥17，也要看被注解方法是否返回敏感数据或执行敏感动作（取 IMEI、读文件），配合注入点仍是有效漏洞。

**URL scheme / BROWSABLE / 文件格式**：自定义 scheme 是全系统可调用入口，任何 App/网页都能投递任意参数，且 iOS 对同名 scheme 无归属仲裁。测试分五步：枚举注册（`CFBundleURLSchemes`）、定位 handler（`application:openURL:options:`）、判参数/来源是否校验、功能探测（空 scheme 与畸形参数）、模糊（FuzzDB 字典 + 看 `.ips` 崩溃日志）。Android 侧对应 `BROWSABLE` Activity：筛出含该 category 的组件，用 `adb shell am start -a VIEW -d <url>` 传入任意 URL，外部域名被打开即任意 URL 打开；进一步看请求是否携带 auth 令牌——携带则升级为账户接管。客户端攻击面由「应用愿意消费哪些文件类型/协议」决定，读 Info.plist 的 CFBundleDocumentTypes 与 LaunchServices 关联库，挑冷门格式（仅 QuickTime 支持的 `.atr`）作为 fuzzing 目标。

**模糊测试配方**：选目标（冷门度 × 代码年龄 × 漏洞历史）→ 生成（变异 vs 规范驱动，改动控制在「足以触发但不会被立刻拒绝」的甜点区）→ 投递（可重复入口）→ 监控（捕获异常并留存样本）。没有监控和样本留存，跑再多也判不出结果。

## A1 — 应用示例 (Application Example)

### 示例 1: MyBrowser 的 WebView 链
- **类型与来源**: 【亲历】《Mobile App Hackers Handbook》Chapter 7 "WebViews" 与 CVE-2012-6636 节
- **问题/输入**: 一个把 URL 从 intent extra 取出加载的浏览器类 App。
- **方法论的使用**: 搜 `WebView`/`loadUrl`/`setJavaScriptEnabled`/`addJavascriptInterface` 得加载点；判定 URL 来源为 `getIntent().getStringExtra("URL")`（外部可控）；读 getSettings 发现 `setAllowUniversalAccessFromFileURLs(true)` + `setJavaScriptEnabled(true)`；构造 `file:///data/data/com.malicious.app/exploit.html`（恶意文件需 world readable）在目标应用内执行并外传文件。同时 `scanner.misc.checkjavascriptbridge` 给出 `targetSdkVersion=15` 的反射 RCE 结论。
- **结论**: 内容注入（本例的 file:// 加载）与 JS 桥能力（本例的反射 RCE）需串联才构成完整链；只报「开了 JS」会被「页面是我们自己的」驳回。
- **结果**: 原书交代该 MyBrowser 示例可被利用，未给出真实世界项目的利用结果。

### 示例 2: BROWSABLE Activity 任意 URL（合成演练）
- **类型与来源**: 【合成演练】按本卡 E 段规则推演，非任何真实目标结果
- **问题/输入**: 用户说「怎么测 App 任意 URL 打开」。
- **方法论的使用**:
  1. 用 jadx/apktool 反编译，打开 AndroidManifest.xml，筛出含 `android.intent.category.BROWSABLE` 的 Activity。
  2. 对每个执行 `adb shell am start -n <pkg>/<component> -a android.intent.action.VIEW -d google.com`，同时在 Burp 跟踪请求。
  3. 外部域名被打开即成立；检查该请求是否携带 auth 令牌或 PII，携带则升级为账户接管。
- **结论**: 只验证「能打开链接」不检查令牌会把可升级漏洞报成低危；不遍历所有 BROWSABLE activity 会漏掉真正可利用组件。
- **结果**: 原书（泰阿条目 61）给出该配方，未提供本演练的真实结果；最差情况也能拿「类 XSS」奖励。

## A2 — 触发场景 (Future Trigger) ★

### 用户会在什么情境下需要它
1. 「WebView 有什么风险」「JS 开关要不要报」「加载 http 页面算漏洞吗」。
2. 「addJavascriptInterface 安全吗」「JS 桥怎么打」「WebView 能执行命令吗」。
3. 「URL scheme 怎么测」「deep link 有没有越权」「App 深度链接漏洞」。
4. 「怎么对一个文件解析器做 fuzz」「模糊测试跑不出结果」「要 fuzz 什么格式」。
5. 「App 任意 URL 打开怎么测」「怎么测 BROWSABLE 组件」。

### 语言信号（出现这些就该激活）
- 中文：「WebView」「JS 开关」「明文加载」「JS 桥」「addJavascriptInterface」「URL scheme」「deep link」「BROWSABLE」「任意 URL 打开」「模糊测试」「冷门格式」
- English: "WebView security settings", "allowUniversalAccessFromFileURLs", "addJavascriptInterface RCE", "javascript bridge Android", "URL scheme testing iOS", "test arbitrary url open in android app", "mutation vs generation fuzzing", "client-side attack surface"

### 与相邻能力的区分
- 与 `android-component-and-provider-exploitation` 的区别：Activity 打的是「导航跳过鉴权」，本卡打的是「往 WebView/入口里注入内容并调用能力」。
- 与 `network-visibility-and-tls-validation` 的区别：那张卡判「HTTPS 内容看不看得见」，本卡判「WebView/入口能否被外部内容注入」；`handler.proceed()` 是两者的交界点。
- 与 `attack-surface-and-endpoint-discovery` 的区别：那张卡把 WebView 与 scheme 列为边界，本卡深入配置开关与利用链。

## E — 可执行步骤 (Execution)

**必需输入**: 可反编译的 APK/IPA；能构造发往目标组件的 intent 或控制网络位置；对 JS 桥需找注入点（明文 HTTP/可控 URL/可覆盖的本地 html）；URL scheme 测试需 IPA 或越狱设备且 Frida/IDB/Needle 任一可用；客户端 fuzz 需可用样本与可重复入口。
**交付物与完成标准**: WebView 加载点清单与配置判定表；JS 桥可用性结论（含 targetSdk）；scheme/BROWSABLE 处理结果；模糊测试的崩溃样本与对应输入。

1. **WebView 加载点与内容源**
   - 做什么：搜 `WebView`/`loadUrl`/`setJavaScriptEnabled`/`addJavascriptInterface` 得加载点；对每个加载点判 URL 来源（硬编码自家域名/服务端下发/intent extra/明文 HTTP）；读 getSettings 对照默认表标出危险项。
   - 完成标准：每个加载点标注「外部可控」与「明文」；配置表逐项有结论。
   - 判停：只看到 `setJavaScriptEnabled(true)` 不要报漏洞——必须同时证明内容源不可信；漏掉 service/receiver 里 new 出的实例会导致面不全。

2. **组合判定与 PoC**
   - 做什么：外部可控 URL + JS 开启 + universal access 开 → 构造 `file:///data/data/<恶意包>/exploit.html`；若 URL 只能 https 但 `onReceivedSslError` 里 `handler.proceed()` 放开 → 改判 MITM 可注入。
   - 完成标准：PoC 有明确触发路径与预期效果。
   - 判停：恶意文件需 world readable；不要编造「成功外传文件」结果，按实际观察记录。

3. **JS 桥两段判定**
   - 做什么：搜 `addJavascriptInterface` 拿注入变量名与 Java 类，列 public 方法（老 SDK）或 `@JavascriptInterface` 方法（新 SDK）；读 `<uses-sdk targetSdkVersion>`——<17 判反射 RCE 可用，≥17 判只能调标注方法；用 `scanner.misc.checkjavascriptbridge -a <pkg>` 复核（需先 `module install javascript`）。
   - 完成标准：bridge 是否存在与 targetSdk 分界各有结论；注入点明确。
   - 判停：以设备版本代替 targetSdk 判断是错的；只报「用了 addJavascriptInterface」不给注入路径会被驳回；注意 `org.chromium.content.browser.addPossiblyUnsafeJavascriptInterface` 另一个入口。

4. **scheme / BROWSABLE 处理**
   - 做什么：iOS 侧 `grep -A 5 -nri urlsch Info.plist` 或 `rabin2 -zzq` 枚举 scheme，`frida-trace -U <app> -m "*[* *openURL*]"` 定位 handler，hook 比较函数判来源是否校验，直接打开空 scheme/畸形参数探测，FuzzDB 字典模糊并看 `/private/var/mobile/Library/Logs/CrashReporter` 的 `.ips`；Android 侧筛 BROWSABLE Activity 并用 `am start ... -d <url>` 逐个测，检查请求是否带 auth 令牌。
   - 完成标准：参数/来源校验结论；畸形参数是否有隐藏界面/崩溃；BROWSABLE 列表逐个有结果。
   - 判停：只验证「scheme 能打开 App」就收工不够；只测 universal links（有 AASA 校验）会漏遗留自定义 scheme；别拿系统保留 action 当被测 App 行为。

5. **客户端 fuzz 配方**
   - 做什么：选目标（冷门格式 × 代码年龄 × 漏洞历史）→ 优先多特性合法样本做变异、必要时规范驱动生成 → 解决可重复投递入口 → attach 调试器捕获异常并保存触发样本。
   - 完成标准：每个崩溃对应具体输入文件；未覆盖行用 code coverage 定位后回灌静态精读。
   - 判停：只做变异式就断言「无漏洞」不成立（TRACE 等方法分支永远不会被生成）；改动过大全被拒要找 "sweet spot"；无监控/无样本留存的测试无效。

## B — 边界 (Boundary) ★

### 不要用的情况
- 页面完全可信且不可外部控制时，`setJavaScriptEnabled(true)` 本身不是漏洞。
- 系统保留 action 或 universal links（有 AASA 校验）不等同于遗留自定义 scheme。
- 没有监控或样本留存能力时，不要投入大规模 fuzzing。

### 已知失败模式
- 看到 `setJavaScriptEnabled(true)` 就报漏洞，忽略内容源可信度；忽略 `onReceivedSslError` 的 `handler.proceed()`；只测 UI 可见 WebView 漏掉 service/receiver 里的实例（MAHH Ch7 WebViews）。
- 以设备版本代替 targetSdkVersion 判断 JS 桥；只报用了 addJavascriptInterface 不给注入路径（同书 CVE-2012-6636）。
- 只验证 scheme 能打开 App 不测参数与来源；只测 universal links 漏遗留 scheme；把非公开 API（如 `LSApplicationWorkspace.openSensitiveURL:`）当被测 App 行为（MSTG iOS Platform APIs）。
- 只验证 BROWSABLE 能打开链接而不检查 auth 令牌，把可升级为账户接管的漏洞报低危；不遍历所有 BROWSABLE activity（泰阿条目 61）。
- 只做变异式 fuzz 就断言没漏洞；改动幅度过大输入全被拒；无监控或无样本留存（iOS Hacker's Handbook Ch6）。
- 只盯服务端监听端口忽略客户端自动处理的文件格式，遗漏更大攻击面；假设所有格式都被充分测试（Mac Handbook Ch3）。

### 作者与时代的局限
- WebView 默认值表基于 MAHH 成书时的 API 分界（API 16/17）；新平台默认值与 `addJavascriptInterface` 行为已变化，需按目标 targetSdk 重新核对。
- targetSdkVersion 决定行为而非设备版本这一点在老 APK 装新机时成立；随平台统一行为变更，新版本限制可能不同。
- 客户端 fuzz 的「冷门格式高产」是经验判据，具体可达性需按目标平台裁剪（见 `mobile-pentest-lifecycle` 的可达性闸门）。
- iOS 模拟器 x86 架构限制使 scheme/fuzz 的行为与真机不同。

### 容易混淆的方法
- **内容注入 vs 桥能力**：本卡把二者串成链，但判定要分开——先证明能注入什么内容，再证明能调到什么 Java 能力。
- **BROWSABLE vs Web 开放重定向**：前者是 Android intent 组件层面的 URL 处理，验证工具是 adb；后者是浏览器侧行为。
- **变异式 vs 生成式 fuzz**：前者改合法样本、快但难深入；后者依规范构造、成本高但覆盖分支，两者互补。

### 授权与合规边界
> 待补充（用户自行填写）
