# 攻击面切分与测试面规划

## R — 原文 (Reading)

> An attacker who is seeking to find vulnerabilities in an application should consider multiple approaches and testing perspectives. The three high-level components to consider for each application are shown in Figure 7.1 and discussed in the list that follows.

> — 《Mobile App Hackers Handbook》Chapter 7 "Attacking Android Applications" 开篇（Figure 7.1 及说明）

> Preparation - defining the scope of security testing… Intelligence Gathering - analyzing the environmental and architectural context of the app… Mapping the Application… Exploitation… Reporting…

> — 《mobile-security-testing-guide》General Testing Guide / Mobile App Security Testing / "Penetration Testing"

> The attack surface is the code that processes attacker-supplied input. If Apple has a vulnerability in some code, and either the attacker can't reach it or Apple doesn't ship the code at all in iOS, an attacker cannot base an exploit on this vulnerability.

> — 《iOS Hacker's Handbook》Chapter 1 "The Reduced Attack Surface"

## I — 方法论骨架 (Interpretation)

这个能力回答的是一个项目最开头的问题：**拿到一个移动应用，我到底该测什么、按什么顺序测、哪些问题值得测**。它把三件事拧成一股：用「信任边界」把 App 切成分层攻击面（而不是按时间阶段或按工具顺手程度），用「前置规划」把范围、构建变体、测试环境、敏感数据清单在动手前锁定，用「可达性」把不可达的候选问题提前剔除。

核心机制是三层过滤。第一层是**分层**：MAHH 给出「容器 / 通信 / 服务端」三视角——容器层看沙箱与组件、通信层看信道与证书、服务端层看后端；MSTG 的六项未校验清单（IPC/scheme、用户输入、WebView、网络、存储、运行环境）则把它细化成可直接填表的否定式清单。分层的价值在于「谁能打、打成什么样算数」在各层完全不同，混在一起会拿客户端可控输入冒充服务端危害，或把需要 root 的问题写成远程可利用。第二层是**规划**：MSTG 的五阶段（准备→情报→映射→利用→报告）规定前后依赖，Mapping 的测试用例是 Exploitation 的输入，Exploitation 的结果才是 Reporting 的唯一素材；同时向客户索取 release 与 debug 两个构建变体——release 验防护强度，debug 关掉防护把业务逻辑测完；再按要回答的问题选模拟器/真机/越狱（或 root）三档环境。第三层是**收敛**：先定义敏感数据（at rest/in use/in transit 三态布点），再用「缺陷存在 × 输入可达」剔除不可达项，用「减漏洞/加固利用/限损害」三层核对防护布局是否只查了一层。

为什么这样做：移动测试的常见失败不是「不会用工具」，而是「测了一堆不算数的问题」——扫描器告警直接进报告、把桌面 CVE 套到移动端、只测网络存储漏掉 IPC、没拿 debug 包硬刚防护耗光时间。这套方法把「判什么算数」前移到动手之前，用分层防漏、用规划防偏、用可达性防误报，最后交付的是「每个结论都能追溯到分层位置、所用环境与利用记录」的可复算报告。读完后即使没读过原书，也应该在脑子里能跑一遍：先切层列清单 → 锁范围/变体/环境/敏感数据 → 逐层映射候选漏洞并写用例 → 实际利用确认 → 剔不可达 → 按五轴定级 → 成报告。

**测试顺序与端点发现分支**（Bug Bounty Bootcamp + Mac 手册 + 泰阿手册补充）：规划阶段还有两条提高命中率的经验。①**先 Web 后 App 的差分策略**——同一产品线的移动 App 通常是 Web 版的简化子集，先在 Web 端用成熟方法枚举接口与认证、产出已知问题清单，再转 App 端只找基线之外的差异（"App 有而 Web 无"的接口/功能），避免一上来就在门槛更高的移动环境里重复挖共性漏洞。②**端点差集的两种来源**——运行时用 Burp 拦 App 敏感操作的出站流量，静态用 `apkurlgrep -a app.apk` 免解压抽 URL，两者结果与 Web 端点基线做差集得到 App 独有端点（静态 URL 可能失效或为第三方地址，需运行时验证）。③**设备与环境配置**——设备组合 = 常规机（观察真实用户态）+ root/越狱机（注入、Hook、绕过固定）+ 双端模拟器（快速还原回滚），用备用机而非主力机。④**自动化的使用时机**——MobSF 等工具自动化的是"已知模式"部分，须先手工走通一遍解包/代理/pinning 判定、能解释每步在做什么，再引入自动化批量执行并复核误报，自定义实现回到手工路径。⑤**静态定可疑区 + 动态验可达**——静态找可疑代码（如 malloc+strcpy）但难判输入是否可控，动态 fuzz 无误报但难达深层且太异常会被快速拒绝，两者互补：静态定可疑区交动态验证，动态难达区用代码覆盖率反向定位；判据是"输入有效性"（太异常被拒、不够异常不触发）。⑥**客户端文件格式攻击面**——由"应用愿意消费哪些文件类型/协议"决定，读 Info.plist 的 CFBundleDocumentTypes → `lsregister -dump` 查 LaunchServices 关联库 → 挑冷门格式（仅某应用支持的稀有扩展名）作为 fuzz 高产目标，别只盯服务端端口。

## A1 — 应用示例 (Application Example)

### 示例 1: Sieve 密码管理器的三视角拆解
- **类型与来源**: 【转述】《Mobile App Hackers Handbook》Chapter 7 各节（作者亲历案例，原书 Figure 7.1 框架的落地示例）
- **问题/输入**: 拿到一个名为 Sieve 的 Android 密码管理器 APK，要判断它有哪些独立成立的测试面。
- **方法论的使用**: 按容器/通信/服务端三栏切分——容器层列出导出组件（PWList Activity、DBContentProvider、FileBackupProvider、两个 Service）与可备份/debuggable 属性；通信层列出 `NetBackupHandler` 的 HTTPS 备份通道；服务端层标注本书不覆盖但需反查「客户端绕过后服务端是否仍拒绝」。三栏各自独立取证：容器层用 drozer 拉起 PWList 直接列出账号（无需 PIN），通信层发现空实现的 `X509TrustManager` 未装 CA 即可读到备份请求体，两者各自成立、互不依赖。
- **结论**: 三视角把「导出组件绕过登录」与「证书校验缺陷」判成两个独立漏洞，而不是混成一句「这个 App 不安全」；服务端栏的反查防止把「只做展示、校验在服务端」的功能误报为客户端漏洞。
- **结果**: 原书交代容器层与通信层问题分别独立成立，并作为后续各节的贯穿示例。

### 示例 2: Preview 与 iOS 的 PDF 模糊测试命中率对比
- **类型与来源**: 【转述】《iOS Hacker's Handbook》Chapter 1 "The Reduced Attack Surface"（Charlie Miller 的 PDF 模糊测试）
- **问题/输入**: 同一批 PDF 模糊测试样本，分别在 macOS Preview 与 iOS 上运行，要判断桌面端的解析漏洞在移动端是否成立。
- **方法论的使用**: 按「缺陷 × 可达」逐跳验证——样本能触发 Preview 上百次崩溃，说明缺陷存在；但在 iOS 上只有约 7% 出问题，因为大量解析路径未被 MobileSafari 编译进来（如 .psd 不被解析）。任一跳「组件是否存在/是否被裁剪」不成立即降级。
- **结论**: 同一份代码在桌面上是漏洞、在 iOS 上不成立；移动端攻击面更小不是直觉，而是可用命中率量化的事实。
- **结果**: 原书给出 7% 的命中率量级证据，据此确立「先证明可达，再讨论危害」的降级规则。

### 示例 3: 【合成演练】从零规划一个社交 App 的首次评估
- **类型与来源**: 【合成演练】严格按本卡 E 段规则推演，不引用现实测试结果。
- **问题/输入**: 一个自有测试账号、一个 release APK、一个关掉防护的 debug APK、一台测试机与一台对照机；需求是「做一次完整评估，报告里不要有未验证的东西」。
- **方法论的使用**: (1) 准备阶段锁定范围/级别/敏感数据清单（凭据、PII、设备标识）；(2) 情报阶段画「App—网络—后端」信任边界草图；(3) 映射阶段按六项清单填出 scheme 名、WebView 类、后端域名、存储 API，逐行标「已校验/未校验」，未校验项写成可执行用例；(4) 在 debug 包上跑完业务用例，在 release 包上跑防护韧性用例；(5) 对每条候选逐跳做可达性验证；(6) 五轴打分记录最弱轴。
- **结论**: 交付物是一张「候选→用例→利用记录→可达性→最弱轴→定级」的追溯表。
- **结果**: 合成演练不产生现实结果；若按此流程，预期是报告里每条发现都能对应到客户能改的代码或配置。

## A2 — 触发场景 (Future Trigger)

### 用户会在什么情境下需要它
1. 项目启动会：「这个 App 要怎么做安全测试」「从哪几个方向看一个移动应用」「帮我做一次 App 渗透测试，怎么排期分几步」。
2. 拿到包但不知从何下手：「APK 拿到了下一步干嘛」「先测网络还是先看组件」「测试范围怎么定才不漏」。
3. 客户只给一个包或环境受限：「客户只给了生产包」「有证书固定/越狱检测测不下去」「模拟器能不能测安全」「要不要越狱机」。
4. 报告收口阶段：「扫描器报了一堆，哪些该写进报告」「这个 CVE 对我们 App 有影响吗」「移动端攻击面是不是比桌面小」。
5. 差分与端点发现：「移动端和 Web 先搞哪个」「App 有没有隐藏接口」「怎么快速列 App 的接口」「做移动测试要准备什么设备」「MobSF 能替代手工吗」。

### 语言信号（出现这些就该激活）
- 中文：「从哪下手」「测试范围」「攻击面有哪些」「分几步」「先测什么」「怎么排期」「哪些能不测」「怎么定级」「只给了生产包」。
- English: "how do I approach a mobile app assessment", "attack surface of an Android/iOS app", "pentest scope and methodology", "mobile attack surface checklist", "is this vulnerability reachable on iOS", "simulator vs real device for pentest", "mobile vs web first", "find untested mobile endpoints", "extract urls from apk", "mobile testing lab devices", "can MobSF replace manual testing"。

### 与相邻能力的区分
- 与 `<component-exposure-and-exploitation>` 的区别：本能力是分层与规划（决定测哪些面、用什么包与环境），后者是其中「客户端容器层」内部对组件导出的具体判定与利用规则。本能力输出的是清单和范围，后者输出的是单个组件的可利用性结论。
- 与 `<auth-and-findings-triage>` 的区别：本能力做「列全 + 剔不可达 + 分阶段」，后者做「对已确认的发现定级」；五轴模型是本能力 Exploitation 之后的下游闸门。
- 与常规渗透测试的「信息收集→打点→横向」不同：这里按信任边界分层，而非按攻击时间阶段；横向移动不是移动 App 评估的核心切面。

## E — 可执行步骤 (Execution)

**必需输入**: 目标包（APK/IPA）或应用名与包名；测试级别（如 MASVS L1/L2）；敏感数据定义或业务方联系人；至少一个可控设备或模拟器；缺「敏感数据清单」时必须先向业务方索取，缺「书面范围/授权文件」属合规占位（见 B 段）不在此能力技术流程内处理。

**交付物与完成标准**: 一张信任边界清单（每层/每类有具体实现与「已校验/未校验/不适用」标注）+ 一份测试计划（范围、构建变体、环境、敏感数据三态检查点、逐条用例）+ 一张可达性追溯表。完成标准：每条候选漏洞都有对应用例、利用记录与可达性判定；每条结论能追溯到所用分层与环境。

1. **切分信任边界并建清单**
   - 做什么：按三视角（容器/通信/服务端）建三栏，或按六项未校验清单（IPC/scheme、用户输入、WebView、网络、存储、运行环境）各建一行，填入该 App 的具体实现（scheme 名、WebView 类、后端域名、存储 API）。
   - 完成标准：每层/每行都有具体条目，且标注「已校验/未校验/不适用」；补齐通知、剪贴板、扩展、键盘等遗漏边界。
   - 判停：若某栏完全填不出内容，说明信息不足，跳到第 2 步先补情报，不要臆造条目。

2. **锁定范围、构建变体与测试环境**
   - 做什么：逐条过级别清单确定测试级别；向客户索取 release + debug 两个变体并书面确认 debug 关掉了哪些控制；按「要回答的问题」映射最低可行环境——有源码的存储检查→模拟器，TLS/scheme→真机，反调试/脱壳/Keychain dump→越狱或 root 机。
   - 完成标准：变体与控制差异清单齐全；每条计划中的结论都标注了所用环境；限制（如未在越狱环境验证固定绕过）写入报告范围。
   - 判停：若客户只给生产包，把限制写进报告并主要走 release 韧性路线，转 `<transport-security-testing>` 或 `<unpacking-and-hook>` 处理防护；不要因缺 debug 包而停工。

3. **定义敏感数据并三态布点**
   - 做什么：产出敏感数据清单（凭据、PII、可识别设备标识、声誉数据、法定义务数据、保护其他数据的密钥），对每类数据在 at rest（落盘位置）、in use（内存/剪贴板/快照）、in transit（网络通道）三态设检查点。
   - 完成标准：清单每项能对应到 App 中的字段或文件；每个落盘位置标注「命中/未命中」。
   - 判停：若清单缺失且业务方无法提供，把「清单缺失」本身写成发现项，并用原文六类兜底，不要跳过。

4. **映射候选漏洞并写可执行用例**
   - 做什么：结合 SAST/DAST 与手工探索，把清单里「未校验」项转成具体漏洞假设，写出可执行的利用用例并按危害排序。
   - 完成标准：每条候选漏洞都有对应用例；黑盒模式下 Mapping 阶段允许显著变长。
   - 判停：若某候选无法写出用例（不知道输入怎么送达），标记为「待可达性验证」而非直接上报。

5. **实际利用并可达性收敛**
   - 做什么：对每条候选实际发起利用确认 true/false positive；逐跳验证「输入从哪进、经哪些组件、到达哪段代码」，对每条路径核对组件在目标平台是否存在/被裁剪；按「减漏洞/加固利用/限损害」三层核对防护布局。
   - 完成标准：每条保留的漏洞都有可复现的利用记录；不可达项标注断点位置并降级；任一层防护空缺写成「纵深缺失 + 最坏后果」。
   - 判停：任一跳不成立即把该候选降级为「不可利用」，转 `<auth-and-findings-triage>` 做定级；验证为假阳性的直接剔除。

6. **（可选差分策略）先 Web 后 App 收敛范围**
   - 做什么：对同组织的 Web 应用先完成常规挖掘，枚举接口与认证机制形成基线 → 转 App 端只找基线之外差异；端点用运行时 Burp 流量与静态 `apkurlgrep -a app.apk` 两路做差集，得到 App 独有端点 → 作为优先施测目标。
   - 完成标准：能列出"App 有而 Web 无"的端点/功能清单，每条标注来源（运行时/静态）。
   - 判停：跳过 Web 基线会在高门槛环境里重复挖共性漏洞；静态 URL 未验证就当有效目标会浪费时间；App 未绕过 pinning 抓不到流量时差集无从建立。

7. **报告成稿**
   - 做什么：执行摘要、范围与方法、信息来源、按优先级排序的发现、逐条修复建议。
   - 完成标准：每条发现都能对应到「客户能改的代码或配置」，且能追溯到分层位置、所用环境、利用记录与最弱轴。
   - 判停：若某发现无法对应到具体可改项，退回第 5 步补证据，不要写进正式报告。

## B — 边界 (Boundary)

### 不要用的情况
- 已经进入单点漏洞验证阶段（已知某个导出 provider 要测注入）时，不必再跑完整切分流程——直接用 `<provider-data-extraction>` 等专项能力。
- 纯二进制漏洞利用或内核/基带层面的研究（签名内核、堆利用、ROP）：本能力的分层是 App 测试视角，颗粒度不匹配，原书作者也明确把这类逐段抽读后判定为「二进制利用而非 App 测试方法论」。
- 需要给出某个漏洞的精确 CVSS 向量时：本能力只做粗粒度闸门，不含时间/环境原子度量。

### 已知失败模式
- 把渗透测试压缩成「扫一遍出报告」：原文明确指出很多项目因时间/预算被限制在 "mapping via automated scanners"，导致结论未经利用验证（《mobile-security-testing-guide》警告）。
- 只测网络与存储两块「工具最顺手」的面，漏掉 IPC/URL scheme 这类无默认工具路径的信任边界（《mobile-security-testing-guide》六项清单）。
- 把桌面端 CVE 直接套到移动端：同一库不等于同一解析路径；iOS 的 PDF 命中率仅 7%（《iOS Hacker's Handbook》Ch1）。
- 只拿生产包硬刚固定+越狱检测，把大部分时间耗在绕过工具上，业务漏洞没测；或只拿 debug 包得出「未发现防护问题」的错误结论（《mobile-security-testing-guide》双构建）。
- 只查了 PIE 就认为「加固到位」：防护三层必须叠加，沙箱只降低后果不阻止触发（《iOS Hacker's Handbook》Ch1）。

### 作者与时代的局限
- 三视角框架出自 MAHH 的 Android 章节，作者明确把 Internet server 漏洞排除在本书范围外（"This chapter does not cover vulnerabilities found in Internet servers."），服务端层在本域只包含「反查客户端绕过是否仍被服务端拒绝」这一动作，不含服务端漏洞方法。
- 越狱/越狱工具的分层与越狱能力描述来自 iOS 7 时代（如 Pangu9、limera1n、iPhone 4 速率 9.18 次/秒），现代 iOS 与 Android 版本的防护默认值为强；结论需要按目标版本重新核对，不可直接沿用数值。
- 模拟器不可用于黑盒逆向的判断基于 iOS 模拟器是 x86 高层模拟；Android 模拟器是全硬件模拟，可直接动态分析，两者不可混用同一结论。

### 容易混淆的方法
- 「分层」与「阶段」：三视角/六项清单是按信任边界切，五阶段是按项目时间推进，一个定「测什么」一个定「何时测」，不要互相替代。
- 「攻击面枚举」与「可达性收敛」：六项清单负责列全，可达性降级负责剔除不可达项；只列不剔会得到满是假阳性的报告，只剔不列会漏掉无工具入口的边界。
- 「setJavaScriptEnabled(true)」不等于 WebView 漏洞：必须同时证明内容源不可信，这是 `<webview-client-injection>` 的判据，不要在本能力里直接下结论。

### 授权与合规边界
> 待补充（用户自行填写）
