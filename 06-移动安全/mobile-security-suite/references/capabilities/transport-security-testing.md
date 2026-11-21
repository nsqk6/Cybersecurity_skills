# 传输校验与 pinning 对抗

## R — 原文 (Reading)

> Sometimes when proxying an application, you will immediately see HTTPS traffic without installing the Burp CA certificate on the device. How did this happen?

> — 《Mobile App Hackers Handbook》Chapter 7 "Web Traffic Inspection → Finding HTTPS Content / SSL Validation Flaws"

> Our test approach is to gradually relax security of the SSL handshake negotiation and check which security mechanisms are enabled. 1. … make sure that there is no certificate added to the trust store … 2. Now, install the Burp certificate … 3. If executing the instructions from the previous step doesn't lead to traffic being proxied through burp, it may mean that the certificate is actually pinned…

> — 《mobile-security-testing-guide》iOS Network APIs / "Dynamic Analysis → Server certificate validation"

> 如果您已经成功设置了移动设备与代理的配合，但仍然无法看到目标应用程序的交通流量，那么该应用程序可能已经实现了证书固定。

> — 《Bug Bounty Bootcamp》第 23 章 Bypassing Certificate Pinning

> 隐形代理主要是用于测试富客户端应用或者是非浏览器代理方式的应用，当我们设置了它，访问这些应用时，将通过非代理的方式，直接连接Burp Proxy的监听端口。

> — 《burpsuite使用手册》第四章 SSL 和 Proxy 高级选项

> The first option that comes to mind is patching the certificate pinning functions out of the code using the techniques explained in the previous section. However, this task can be tough. This is where runtime manipulation tools work wonderfully.

> — 《Mobile App Hackers Handbook》Chapter 7 "Additional Testing Techniques → Patching Applications / Manipulating the Runtime"

## I — 方法论骨架 (Interpretation)

这个能力回答的是抓包场景里最常卡住的问题：**「我配好代理了，为什么看不到 HTTPS 流量？是校验没做、做了 pinning、还是双向认证缺证书？」** 它把「判定防护层级」和「按层突破」合成一条流程，核心是**用单一观测量（代理能否看到流量）反推防护档位**，而不是猜代码里「看起来像不像做了校验」。

核心机制三块。第一块是**三档判定的排查顺序**：先不装代理 CA 抓一次——若能看到明文，说明应用主动关掉了校验（最常见两种写法：`TrustManager.checkServerTrusted()` 空实现，甚至 `getAcceptedIssuers()` 返回 null；或 `HostnameVerifier` 恒返回 true，含内置的 `ALLOW_ALL_HOSTNAME_VERIFIER`），直接判「完全未做校验」；若握手失败（logcat 出现 `SSLHandshakeException` / `Trust anchor for certification path not found`），装代理 CA 再抓——成功则判「仅校验系统信任库、无固定」；装了 CA 仍失败才是 pinning。**关键纪律**：装 CA 这一步必须单独做，一上来就装永远区分不出「无校验」与「有校验无固定」；反过来「什么都没装就能看到」永远是校验缺陷，不是代理配好了。此外还要查双向认证——Burp Alerts 出现 "client failed to negotiate" 即提示需要客户端证书，从 bundle/数据目录/Keychain 提取装入 Burp。第二块是**区分校验缺陷与 pinning 的意义**：两者误判方向会浪费大量时间——校验缺陷直接读代码定位即可，pinning 才需要上 patch/hook。第三块是**pinning 突破的两条路线与顺序**：静态 patch（apktool 反编译 → 改 smali → 回编译 → 重签名）一次性可复现，但需看懂 smali，遇混淆/加固会「改一处崩一处」，且改签名会触发签名校验；运行时 hook（Xposed / Cydia Substrate）不动 APK，直接改内存中的方法实现，适合 pinning 复杂/混淆严重的情况。作者判断 Cydia Substrate 更优（能 hook native，Xposed 只能 hook 从 Zygote fork 的 Java 代码）。顺序原则是先判断代价：pinning 只是几行 `TrustManager` 时 patch 最快；在 native / 被加固包住时直接上 hook。

为什么放一个能力：用户的一句话需求通常是「抓不到包，帮我搞定」，而正确做法必须先判定档位再选突破手段——把「判定」和「突破」拆成两个能力会导致用户拿错工具（对校验缺陷上 hook、对 pinning 反复重装 CA）。三档判定与两条突破路线共用一个观测量和一套环境前提（同网段、可控代理、能改信任库、root 用于 hook）。读完应该能跑：配代理 → 不装 CA 抓 → 装 CA 抓 → 判三档 → 查双向认证 → 按档选 patch/hook → 确认流量可见且业务不报错。

**抓包工程分支**（Bug Bounty Bootcamp + 泰阿手册 + burpsuite 手册 + Android 渗透手册补充）：三档判定之外，"抓不到包"还有一类是环境/工具配置问题，必须先排除才不会误判为 pinning。①**物理前提**——Burp 默认只绑 loopback，须把监听器绑 All interfaces、手机连同一 Wi-Fi 把代理指向电脑 IP:端口、浏览器访问 `http://burp/cert` 装 CA 并选"VPN and apps"用途；绑定全接口后同网段任何设备都能连，故只在受信任 Wi-Fi 用，且用备用机（改包/root 会损坏主力机/失去保修），设备组合 = 常规机 + root 机 + 双端模拟器。②**判 pinning 的排除法**——先用浏览器/其他 App 证明"代理 + CA 链路可用"，若唯独目标 App 流量为空才判 pinning；跳过这步会把 Wi-Fi 代理未生效、CA 用途选错误判为固定。③**绕过按实现分层**——标准实现用自动化（Frida Universal Android SSL Pinning Bypass、Objection `android sslpinning disable`），自定义校验才手工（覆盖打包证书、改/禁校验代码，高度依赖目标）；静态侧可 `apktool d` 后 grep `pinning|checkClientTrusted|X509TrustManager|SHA256` 等标志确认实现。④**"不走系统代理"与"特定证书"的替代路径**——富客户端不读系统代理时用隐形代理（hosts 把域名指向 127.0.0.1 + Burp 80/443 监听 + Hostname Resolution 指回真实服务器，只做劫持不配回环会形成回环）；App 要求特定序列号/证书链时用 Burp 的 Use a custom certificate 加载 PKCS#12；客户端不信任 Burp CA 导致 SSL 协商失败时用 SSL 直连/自动加白名单（**代价是放弃该主机可见性，不能用来解决 pinning 解密**）。⑤**平台特例**——iOS 13 上 Burp 抓不到是 TLSv1.3 兼容性问题，启动加 `-Djdk.tls.server.protocols=TLSv1,TLSv1.1,TLSv1.2` 禁用，不要误判为 pinning。⑥**分析方式选型**——只需"看"用被动分析（tcpdump 存 pcap + Wireshark 离线搜），需要"改"用主动分析（Burp 代理即时改包）；装 CA 后仍证书不匹配则转逆向改包。

## A1 — 应用示例 (Application Example)

### 示例 1: Sieve 空 TrustManager（校验缺陷档）
- **类型与来源**: 【亲历】《Mobile App Hackers Handbook》Chapter 7 "SSL Validation Flaws"
- **问题/输入**: Sieve 的 `NetBackupHandler.getNewHttpConnection` 用了空实现的 `X509TrustManager`，要验证是否未装 CA 即可抓到备份流量。
- **方法论的使用**: (1) 起 Burp 监听（绑 0.0.0.0，`netstat -an | grep 8080` 确认），设备 WiFi 高级选项填代理（模拟器改 APN proxy 为 `10.0.2.2`）；(2) **先不装 CA** 跑一遍业务 → 直接看到明文备份请求体（含密码库）；(3) 判定校验缺陷，转源码定位 `X509TrustManager` / `setHostnameVerifier` / `onReceivedSslError` 确认缺陷位置。
- **结论**: 没装 CA 就能看到明文 = 校验根本没做，不是代理配错；这类代码常来自开发期连自签证书「从论坛抄来」的写法，后果是任何中间人位置都能替换证书读写流量。
- **结果**: 原书交代未装 Burp CA 即可读到备份请求体（含密码库）。

### 示例 2: Twitter 的 pinning 绕过（hook 档）
- **类型与来源**: 【亲历】《Mobile App Hackers Handbook》Chapter 7 "Manipulating the Runtime"
- **问题/输入**: Twitter 应用装了 Burp CA 仍无法代理，只弹 "Cannot retrieve Tweets at this time."（不泄露原因），要判定并绕过。
- **方法论的使用**: (1) 装了 CA 仍失败 → 判 pinning；(2) 路线 B（hook）：root 设备装 Cydia Substrate → 装现成扩展 Android SSL TrustKiller（全放行 SSL 校验）、RootCloak Plus（隐藏 root）→ `Restart System (Soft)`；(3) 用 logcat 确认扩展生效（`SSLTrusKiller: init() override in javax.net.ssl.SSLContext`）；(4) 判据：Burp 中能看到原先被 pin 的 Twitter API 流量，且业务功能未报错。
- **结论**: pinning 在装 CA 仍失败时才成立；hook 不改 APK、不动签名，适合混淆/复杂校验；Xposed 不能 hook native 代码（"anything that has not been forked from Zygote is not possible to hook using Xposed, including native code"）。
- **结果**: 原书交代加载 SSL TrustKiller 后成功代理。

### 示例 3: 【合成演练】"抓不到包"的排除法定位
- **类型与来源**: 【合成演练】按《Bug Bounty Bootcamp》第 23 章 CU-4-03/05 的 E 段规则推演，不引用现实测试结果。
- **问题/输入**: 手机已按步骤连上 Burp 代理并装了 CA，浏览器能抓到 HTTPS，但目标 App 打开后 Burp 里完全没有它的流量。
- **方法论的使用**: (1) 用浏览器验证代理与 CA 链路可用 → Burp 能看到明文；(2) 只启动目标 App 并操作敏感功能 → 该 App 流量仍为空；(3) 由"其他能抓、唯独它不能"的排除法判定为证书固定，而非配置问题；(4) 转 CU-4-06：先试 Frida/Objection 自动化脚本，失败则反编译 grep `pinning|X509TrustManager` 确认是否自定义校验，再决定手工路径。
- **结论**: "其他 App 能抓、只有目标不能"是把模糊故障收敛为 pinning 判定的关键；跳过"其他 App 能抓"这步会把代理未生效/CA 用途选错误判为固定。
- **结果**: 合成演练不产生现实结果；按此流程预期是收敛到 pinning 判定并选择对应绕过手段。

### 示例 4: 【合成演练】隐形代理抓不走系统代理的富客户端
- **类型与来源**: 【合成演练】按《burpsuite使用手册》第四章隐形代理节的 E 段规则推演，不引用现实测试结果。
- **问题/输入**: 一个 App 的请求完全不读系统代理设置，常规代理抓不到。
- **方法论的使用**: (1) 修改 hosts 把目标域名指向 `127.0.0.1`；(2) 新增 Burp 监听跑在 80（HTTP）或 443（HTTPS）；(3) HTTPS 准备目标域名 CA 证书；(4) Options→Connections→Hostname Resolution 把域名指回真实服务器。
- **结论**: 客户端毫无代理感知，流量被 hosts 劫持到本机 Burp 再转发；只做 hosts 劫持不配 Hostname Resolution 会把流量又发回 127.0.0.1 形成回环。
- **结果**: 合成演练不产生现实结果；按此流程预期是让不走代理的富客户端流量进入 Burp。

### 示例 5: 【合成演练】iOS 三阶 TLS 判定与双向认证分支
- **类型与来源**: 【合成演练】严格按 MSTG iOS Network APIs "Server certificate validation" 的 E 段规则推演，不引用现实测试结果。
- **问题/输入**: 一个 IPA、可控 Burp、一台可改信任库的测试机，需求是「判定它的证书防护属于哪一档」。
- **方法论的使用**: (1) 设备不装代理 CA、关闭 SSL Kill Switch 等工具，抓包 → 假设看到明文 → 判「完全未做证书校验」（失败）；(2) 若失败则装代理 CA 再抓 → 假设成功 → 判「仅校验系统信任库、无固定」（中等）；(3) 装 CA 后仍失败 → 判「存在固定」，进入 hook 绕过流程，绕过后重跑第 2 步确认；(4) 另查双向认证：Burp Alerts 出现 "client failed to negotiate" → 从 Keychain/包内提取客户端证书装入 Burp。
- **结论**: 单一观测量（代理可见性）+ 单变量（是否信任代理 CA）即可稳定映射到三档；装 CA 仍失败还需排除双向认证，不能直接判固定。
- **结果**: 合成演练不产生现实结果；若出现 client certificate 提示，按原文所给三种存放位置（bundle 硬编码、数据目录、Keychain）逐一排查。

## A2 — 触发场景 (Future Trigger)

### 用户会在什么情境下需要它
1. 抓包卡住：「抓不到包怎么办」「HTTPS 看不到内容」「装了证书还是不行」「Burp 里没有流量」。
2. 判定需求：「证书固定怎么判断有没有」「SSL pinning bypass」「是校验缺陷还是 pinning」。
3. 突破需求：「pinning 怎么绕」「patch 还是 hook」「Frida/Xposed 能不能过 SSL」。
4. 特殊分支：「双向认证怎么测」「客户端证书放哪」「装了 CA 还是 client failed to negotiate」。
5. 抓包工程：「手机怎么连 Burp」「其他应用能抓就这个不行」「App 不走系统代理怎么办」「隐形代理怎么配」「iOS 13 抓不到包」「App 校验证书序列号」。

### 语言信号（出现这些就该激活）
- 中文：「抓不到包」「HTTPS 看不到」「证书固定」「SSL pinning」「装证书」「patch smali」「Xposed hook」「双向认证」「客户端证书」「Burp 绑定」「隐形代理」「Hostname Resolution」「Objection」「TLSv1.3」。
- English: "Burp not intercepting Android app", "SSL pinning or broken validation", "bypass SSL pinning Android", "SSL Kill Switch", "client certificate authentication mobile", "set up burp with android device", "burp sees no traffic from app", "objection sslpinning disable failed", "configure invisible proxy burp", "burp not intercepting iOS 13 traffic"。

### 与相邻能力的区分
- 与 `<webview-client-injection>` 的区别：后者判 WebView 加载的内容源与 JS 能力，本能力判信道层的证书校验；WebView 的 `handler.proceed()` 会让 HTTPS 变可 MITM，属后者范畴，但 MITM 后的流量抓取用本能力。
- 与 `<unpacking-and-hook>` 的区别：两者都需要 root 且都可能被反调试拦住，但本能力 hook 的目的是看流量（改 Java 方法/SSLContext），脱壳 hook 的目的是拿 dex 代码（改 `dvmDexFileOpenPartial` 断点）；本能力 patch 改代码绕过检测，脱壳不改代码只取数据。
- 与 `<ios-platform-security-testing>` 的区别：后者覆盖 iOS 的 scheme/存储/本地认证/越狱检测，本能力专攻 TLS 那一层；三档判定在 iOS 和 Android 都适用，但装 CA 方式（7.0+ 用户 CA 默认不被信任）有平台差异。

## E — 可执行步骤 (Execution)

**必需输入**: 设备与测试机同网段；能读 logcat；能修改设备 WiFi 代理或模拟器 APN；可控代理（Burp/ZAP）；root 设备（hook 路线）；能反编译与重签（patch 路线）；缺「代理可见性观测」时不得进入 pinning 结论。

**交付物与完成标准**: 一张三档判定表（每档对应观测量与代码定位）+ 突破路线记录（patch 改了哪行 / hook 装了哪个扩展）+ 最终「原先被 pin 的 API 在 Burp 可见且业务不报错」的验证。完成标准：判定与突破分离记录，档位归属明确。

1. **配置代理与监听**
   - 做什么：起 Burp 监听（绑 0.0.0.0，`netstat -an | grep 8080` 确认），设备 WiFi 高级选项填代理；模拟器改 APN 的 proxy 为 `10.0.2.2`。
   - 完成标准：设备流量经代理，能看到 HTTP 明文（作为基线对照）。
   - 判停：Android 4.0 之前部分应用不走 WiFi 代理设置，需 Proxydroid（要 root）；模拟器用 APN 而非 WiFi 设置。

2. **不装 CA 抓一次（关键第一步）**
   - 做什么：**先不装**代理 CA 跑一遍业务。
   - 完成标准：记录是否看到明文；看到即判「完全未做证书校验」，跳到第 5 步并转源码定位。
   - 判停：把「能看到流量」当成「代理配好了」会漏报校验缺陷这个真问题；这一步不能省，否则永远区分不出无校验与有校验无固定。

3. **装 CA 再抓**
   - 做什么：握手失败时导出 Burp CA 为 **DER 格式但改名 `.crt`**（作者特别提示扩展名必须是 crt，否则系统不认）→ `adb push burp.crt /sdcard/` → 设置里从 SD 卡安装 → 重测。
   - 完成标准：成功即判「仅校验系统信任库、无固定」（中等档）。
   - 判停：失败不要直接判 pinning，先按第 4 步排除双向认证；Android 7.0+ 用户 CA 默认不被 App 信任，需按平台差异另行处理。

4. **排除双向认证并确认 pinning**
   - 做什么：查 Burp Alerts 是否出现 "client failed to negotiate" → 有则从 bundle/数据目录/Keychain 提取客户端证书装入 Burp 再重测；仍失败则判 pinning。
   - 完成标准：区分出「缺客户端证书」与「证书固定」两种失败原因。
   - 判停：把双向认证缺证书误判为固定会浪费大量时间在 hook 上。

5. **按 pinning 实现层选突破路线**
   - 做什么：判定 pinning 在 Java 层（搜 `CertificatePinner`/`TrustManager`/`HostnameVerifier`）还是 native（so 里做校验）→ Java 且逻辑简单走路线 A patch；native/混淆严重/被加固包住走路线 B hook。
   - 完成标准：路线选择与代价判断有记录。
   - 判停：先确认是 pinning 而非校验缺陷（第 2 步）；误判方向会白忙。

6. **路线 A：静态 patch**
   - 做什么：`apktool d app.apk` → 定位校验函数改成恒通过（或把 `su` 之类字符串换成不存在的值让检测失败）→ `apktool b` → 用 **JDK 1.6 的 jarsigner** 重签 → 安装验证。
   - 完成标准：Burp 可见被 pin 流量且业务不报错。
   - 判停：忘重签或用了新版 jarsigner 会安装报证书错误；patch 改变签名触发应用自身签名校验而崩溃，不要误判为「pinning 更强」。

7. **路线 B：运行时 hook**
   - 做什么：root 设备装 Cydia Substrate（能 hook native，优于只能 hook Java 的 Xposed）→ 装现成扩展（Android SSL TrustKiller 全放行 SSL 校验；RootCloak Plus 隐藏 root）→ `Restart System (Soft)` → logcat 确认扩展生效。
   - 完成标准：Burp 可见原先被 pin 的 API 流量，业务功能未报错。
   - 判停：以为 Xposed 能 hook native 是错的；hook 扩展可能与反调试冲突，按 `<unpacking-and-hook>` 的 TracerPid 处理思路应对。

8. **（抓包工程分支）环境前提与误判排除**
   - 做什么：配代理三件套——Burp 监听绑 All interfaces、手机连同一 Wi-Fi 代理指向电脑 IP:端口、装 Burp CA 选"VPN and apps"；判 pinning 前先用浏览器/其他 App 证明"代理+CA 链路可用"；判为 pinning 后先自动化（Frida Universal Android SSL Pinning Bypass / Objection `android sslpinning disable`），失败再 `apktool d` + grep `pinning|checkClientTrusted|X509TrustManager|SHA256` 确认自定义实现；富客户端不走系统代理用隐形代理（hosts 指 127.0.0.1 + Burp 80/443 监听 + Hostname Resolution 指回真实服务器）；要求特定证书用 Use a custom certificate 加载 PKCS#12；客户端不信任 CA 用 SSL 直连/自动加白名单；iOS 13 加 `-Djdk.tls.server.protocols=TLSv1,TLSv1.1,TLSv1.2` 禁 TLSv1.3。
   - 完成标准：每条"抓不到"的故障都能归到配置/pinning/隐形代理/平台特例之一；只在受信任 Wi-Fi 绑全接口、用备用机。
   - 判停：跳过"其他 App 能抓"就判 pinning 会把配置错误当固定；只做 hosts 劫持不配 Hostname Resolution 会回环；SSL 直连/加白名单放弃该主机可见性，不能用来"解决"pinning 解密；把 iOS13 的 TLSv1.3 不兼容误判为 pinning 会走错绕过方向。

## B — 边界 (Boundary)

### 不要用的情况
- 应用已确认「不装 CA 就能看明文」（校验缺陷档）时：不需要 patch/hook，直接读代码定位缺陷即可。
- 目标是 WebView 自身的 `handler.proceed()` 放行：转 `<webview-client-injection>`，本能力处理的是网络栈证书校验。
- 目标是非 HTTP 的私有协议（不经过系统证书栈）：本能力的三档观测量不成立。
- 双向认证已排除、pinning 在 native 且加固严重：本能力只给「上 hook」的方向，具体脱壳转 `<unpacking-and-hook>`。

### 已知失败模式
- Android 4.0 之前部分应用不走 WiFi 代理设置，需 Proxydroid（要 root）；证书用 DER 扩展名保存系统安装时直接不识别；把「能看到流量」当成「代理配好了」反而漏报校验缺陷（《Mobile App Hackers Handbook》Ch7 SSL Validation Flaws）。
- 直接上 hook 却不确认到底是 pinning 还是校验缺陷；patch 后忘记重签或用了新版 jarsigner 安装报证书错误；以为 Xposed 能 hook native 代码；patch 改变签名触发签名校验崩溃误判为「pinning 更强」（同书 Ch7 Patching/Manipulating Runtime）。
- 一上来就装 CA，永远区分不出「无校验」与「有校验无固定」；把「装了 CA 仍失败」直接判为固定，而实际是双向认证缺客户端证书（《mobile-security-testing-guide》iOS Network APIs）。
- 把 bundle + 硬编码口令的客户端证书当安全做法——原文指出这是最常见且几乎无安全收益的做法（同书）。
- 绑定 All interfaces 后在公共 Wi-Fi 操作，把代理暴露给同网段陌生人；在主力机上直接改包/root 导致设备损坏或保修失效（《Bug Bounty Bootcamp》Ch23）。
- 跳过"其他 App 能抓"就断定 pinning，把 Wi-Fi 代理未生效、CA 用途未选 VPN and apps 误判为固定；把手工绕过当通用配方照搬、或只会点按钮遇自定义固定卡住（同书）。
- 只做 hosts 劫持不配 Hostname Resolution 造成回环；把 SSL 直连/自动加白名单当作"解决"证书固定（实则放弃该主机可见性）（《burpsuite使用手册》Ch4）。
- 把 iOS 13 的 TLSv1.3 兼容性问题误判为 pinning 去做绕过（《泰阿手册》条目 88）；静态只 grep `http:`/`https:` 不搜证书锁定关键字，导致抓包失败时不知原因（条目 3）。

### 作者与时代的局限
- jarsigner/JDK 1.6、Cydia Substrate、Xposed、SSL TrustKiller 等是 MAHH 写作时的工具生态；现代 Android 已普遍转向 Frida + frida-multiple-unpinning / objection，工具名与版本需更新，但「先判档再突破」的方法论不变。
- Android 7.0+ 用户 CA 默认不被 App 信任，是原书之后的网络安全配置变化；iOS 的 ATS 与应用传输安全策略也应一并核对。
- Twitter 弹 "Cannot retrieve Tweets at this time." 的具体表现是历史案例，用于说明「应用不泄露 pinning 失败原因」的现象。

### 容易混淆的方法
- 「校验缺陷」与「pinning」：前者是校验根本没做（不装 CA 就能看明文），后者是校验做了且做得对需要对抗（装 CA 仍失败）；误判方向浪费时间。
- 「patch」与「hook」：patch 改 APK 字节码并重签（一次性、可复现、改签名），hook 改运行时内存（不动 APK、适合复杂/混淆）；先判代价再选。
- 「证书固定失败」与「双向认证缺证书」：都表现为装 CA 仍握手失败，靠 Burp Alerts 的 "client failed to negotiate" 区分。

### 授权与合规边界
> 待补充（用户自行填写）
