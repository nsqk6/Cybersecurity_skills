# iOS 平台入口与本地认证测试

## R — 原文 (Reading)

> Security issues arise when an app processes calls to its URL scheme without properly validating the URL and its parameters and when users aren't prompted for confirmation before triggering an important action.

> — 《mobile-security-testing-guide》iOS Platform APIs / "Testing Custom URL Schemes (MSTG-PLATFORM-3)"

> Please be aware that using either the LocalAuthentication.framework or the Security.framework, will be a control that can be bypassed by an attacker as it does only return a boolean and no data to proceed with.

> — 《mobile-security-testing-guide》Local Authentication on iOS / "Testing Local Authentication (MSTG-AUTH-8)"

> If the sensitive data is stored in plaintext, the app fails this test. / The encryption must be implemented so that the secret key is stored in the Keychain with secure settings, ideally kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly.

> — 《mobile-security-testing-guide》Data Storage on iOS / "Testing Local Data Storage"

> 1.脱壳 2.cycript 3.class-dump 4.Hopper 5.Theos：五步对应五个不同的信息层级，顺序不可大幅颠倒，不脱壳后面全是无意义数据，不先用cycript定位类就会在海量类里盲找。

> — 《01-iOS逆向之抢红包以外的那些事儿》以红包为名浅谈破解插件

> 反调试的原理，一句话概述，就是通过一些可用的系统函数如sysctl、ptrace、syscall等，检测到调试器对其的附加后做出相应的处理措施。

> — 《01-iOS逆向之抢红包以外的那些事儿》渗透测试·反调试

## I — 方法论骨架 (Interpretation)

这个能力回答的是 iOS 侧一组高频需求：**「iOS 的跨 App 入口（URL scheme）怎么测」「本地存储/生物识别到底算不算安全」「越狱检测怎么绕、启动即退出是不是检测导致的」「这个越狱够不够用来做测试」**。它把四块共享「iOS 平台机制 + Frida/越狱工具链」底座的工作放一起：URL Scheme 五步测试、Keychain 与明文存储判定、生物识别门禁判定、越狱检测绕过与越狱能力评估。

核心机制四块。第一块是 **URL Scheme 五步**：自定义 scheme 是全系统可调用入口，任何 App、任何网页都能投递任意参数，且 iOS 对同名 scheme 无归属仲裁（后装者可能截获）。测试要把「暴露面」与「处理逻辑」分开：静态提取 `CFBundleURLSchemes`/`LSApplicationQueriesSchemes` 和 `://` 字符串 → `frida-trace` 定位 handler（`application:openURL:options:`）→ hook `-[NSString isEqualToString:]` 等比较函数判断来源是否校验 → 直接打开空 scheme 和畸形参数探测隐藏界面 → FuzzDB 字典批量投递查 `.ips` 崩溃。判据是参数是否校验、来源是否校验、敏感动作是否要求用户确认。第二块是**存储判定线**：iOS 默认存储 API（NSUserDefaults、CoreData、Realm、SQLite、文件）都不加密，真正保护来自「数据分类 + 类密钥」——文件靠 Data Protection class，短凭据靠 Keychain 的 `kSecAttrAccessible*`/`SecAccessControl`。判定不是「有没有用 Keychain」而是「保护属性是否与数据敏感度匹配」：`Always`/`AfterFirstUnlock` 且非 ThisDeviceOnly 会让凭据随备份离开设备，`WhenPasscodeSetThisDeviceOnly` 才绑定硬件与口令。先 grep 应用容器找明文，再 dump Keychain 逐条读 Protection/Access Group，再查卸载重装残留与备份面。第三块是**生物识别门禁**：`evaluatePolicy` 返回值只是给 UI 的布尔，hook 一次即恒 true，业务照常继续——因为后续逻辑不依赖任何「只有认证通过才拿得到」的数据。真门禁必须让认证成为获取密钥的必要条件：secret 存 Keychain 并设 `SecAccessControl`（`.touchIDCurrentSet` / `kSecAccessControlUserPresence` + `kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly`），认证失败时 `SecItemCopyMatching` 返回 nil，业务自然中断。动态验证用 Needle/Swizzler2 让 evaluatePolicy 返回 true 后点 Cancel，看业务流是否继续。第四块是**越狱检测绕过与越狱能力**：绕过手段取决于检测执行时机与进程是否活着——点击时才跑可用 Cycript 进程内替换，启动即退出必须用 Frida `-f`（spawn 挂起注入再放行）做早期 hook；且「启动即退出」不必然是检测，先用非越狱设备对照排除崩溃 bug。越狱能力由漏洞在启动链的位置决定——Bootrom 级无法通过软件更新修复、能力最强；iBoot 级几乎同等但可被系统更新修掉；Userland 级至少需两个漏洞、不改内核时能力有限。持久性上 tethered 重启失效、untethered 重启仍有效。

为什么放一起：这四块都是 iOS 平台特有机制（Android 无直接对应），用户面对一台越狱/真机做 iOS 评估时会连续遇到——先测 scheme 入口、再查存储、再看认证、遇闪退要判检测、最后确认越狱工具够不够用。共享越狱设备 + Frida/Cycript/Needle 工具链。读完应能跑：列 scheme → 定位 handler 判三项校验 → 查明文与 Keychain 属性 → hook evaluatePolicy 判门禁 → 遇闪退先对照再选绕过时机 → 评估越狱能力层级。

**iOS 逆向工具链分支**（3 篇 163 实战 + Mac 手册）：当"测入口/存储/认证"需要下到运行时时，这条分支给出工具与推理骨架。①**插件逆向五步流水线**——脱壳（frida-dump/Clutch，运行时内存 dump）→ cycript 打印 UI 层级定目标类 → class-dump 导出 .h → Hopper 反汇编候选方法 → Theos 打包注入；顺序不可大幅颠倒，不脱壳后面全是加密数据，不先定位类就在海量类里盲找。②**反注入识别**——iOS10 以下看 Mach-O 的 `__RESTRICT` 段（dyld 据此拒绝第三方 dylib），用 010editor 改段名任一字母即可绕过；iOS13+ 改用 `DYLD_INSERT_LIBRARIES` 等环境变量判加载状态，判据随系统版本迁移，不能用同一招。③**越狱检测的识别与绕过**——运行时 API 特征是 `_dyld_image_count`/`_dyld_get_image_name` 遍历已加载镜像匹配 `MobileSubstrate.dylib` 等特征库名，绕过统一 patch 为 `return 0`；函数名常含 Jail/JailBroken/Jb/Break 关键字，用 `frida-trace` 验调用再 hook；**hook 未生效时的排障**——用副作用反推真正判定点（弹窗提示说明结果已传到 UI 层，把目标从 BLYDevice 换到 `-[UIDevice isJailbroken]` 用 `retval.replace(ptr("0x0"))`）。④**反调试**——识别特征是 sysctl/ptrace/syscall；两条绕过路径：LLDB 在 ptrace 入口下断点把 R0（request）从 0x1f 改成别的值，或持久化 hook ptrace（request==31 返回 0）**并 hook dlsym**（符号为 "ptrace" 返回假实现），只 hook ptrace 会被 dlsym 取原始地址绕过。⑤**代理检测**——判据函数 `CFNetworkCopySystemProxySettings`，按反编译定位→LLDB 看调用栈/寄存器确认判定点→Theos 插件 return 0 三段走，动态调试不可省。⑥**hook 选型**——Mobile Substrate 的 `MSHookMessageEx` 处理 Objective-C 方法、`MSHookFunction` 处理 C/C++ 函数，对 OC 方法用 Function 会绕过 objc_msgSend 失效；符号被 strip 时用 `objc_getClass`→`sel_getUid`→`class_getInstanceMethod` 取 Method 结构第三个指针（IMP）下断点。⑦**加解密定位与篡改**——先查系统统一库（CCCrypt/libcommonCrypto，一层 hook 拿全量 key/IV/in/out），只看部分明文才转厂商自定义类（*Encryptor）；RSA 请求包无私钥无法本地解密时，把篡改前移到数据进入 RSAEncrypt 之前的明文 arg 阶段，再转给 Burp。⑧**设备指纹推理**——参数（xxid/deviceid/fingerprint）→沙盒落盘文件（FP_IP.txt）→重启对比值稳定性→首次启动时机下断点，判据是"重启后是否变化""是否只在首次启动生成"。

## A1 — 应用示例 (Application Example)

### 示例 1: Skype `skype://` 未确认拨号
- **类型与来源**: 【转述】《mobile-security-testing-guide》iOS Platform APIs / Testing Custom URL Schemes
- **问题/输入**: Skype 2010 年的 `skype://` scheme，攻击者用不可见 iframe 触发任意拨号。
- **方法论的使用**: (1) 静态提取 `CFBundleURLSchemes` 得到 scheme 与参数模板；(2) `frida-trace -U <App> -m "*[* *openURL*]"` 定位处理函数；(3) 校验判定：hook 比较函数，判断是否有用户确认步骤——原文指出问题在于「未请求用户确认即可拨打任意号码」；(4) 功能探测：直接打开带号码的 scheme 看是否静默拨号。
- **结论**: scheme 是跨 App 入口，处理敏感动作必须要求用户确认；只验证「scheme 能打开 App」远远不够，必须测参数与来源。
- **结果**: 原书记载攻击者用不可见 iframe 触发 `skype://` 拨打任意号码；另引 iGoat-Swift 的 `iGoat://?contactNumber={0}&message={0}` 模糊测试全程无崩溃的【例题】。

### 示例 2: Needle keychain_dump 发现明文口令
- **类型与来源**: 【转述】《mobile-security-testing-guide》Data Storage on iOS
- **问题/输入**: 一个 iOS App，要判断其 Keychain 存储是否达标。
- **方法论的使用**: (1) 触发全部功能生成数据，grep 应用容器 `/var/mobile/Containers/Data/Application/$APP_ID/` → 找明文；(2) dump Keychain（越狱用 keychain_dumper，非越狱用 objection），逐条读 `Protection` 与 `Access Group`；Needle `storage/data/keychain_dump` 输出示例 `"Protection": "kSecAttrAccessibleWhenUnlocked"`, `"Data": "rosebud"`；(3) 卸载重装看 Keychain 是否残留；(4) 查备份面属性是否 `ThisDeviceOnly`。
- **结论**: 可备份类属性（`Always`/`AfterFirstUnlock` 非 ThisDeviceOnly）会让凭据随 iCloud/iTunes 备份离开设备；「Keystore 里有记录」不等于保护到位，必须看 accessibility 属性是否匹配敏感度。
- **结果**: 原文以 `"Data": "rosebud"` 例说明口令在 Keychain 中明文可见；iMazing 之类工具只能读备份拿不到全部容器（原文明确此限制）。

### 示例 4: 越狱检测 hook 未生效时转 UIDevice
- **类型与来源**: 【亲历】《06-当frida来敲门》越狱检测绕过
- **问题/输入**: hook `BLYDevice isJailBreak` 改返回值后 App 仍退出，要找真正的判定点。
- **方法论的使用**: (1) 用 brida/frida 搜函数名中 Jail/JailBroken/Jb/Break 关键字，列出 16 个含 Jail 的 OBJC 函数，锁定 BLYDevice 与 UIDevice 的 isJailbroken；(2) hook BLYDevice 改返回值 → 仍退出，判定未生效；(3) 从"弹窗提示"这一副作用推断判定已传到 UI 层 → 把目标换成 `-[UIDevice isJailbroken]`，用 `retval.replace(ptr("0x0"))` 替换返回值 → 成功绕过。
- **结论**: hook 未生效时不能继续在原函数上加码，要用可观察副作用反推真正的判定点；`frida-trace` 先验调用再下 hook 可避免盲改系统 UI 函数（如 `_isConstrainedByScreenJail`）。
- **结果**: 原书记载改用 UIDevice 后"成功绕过"。

### 示例 5: 【合成演练】枚举反注入与反调试特征
- **类型与来源**: 【合成演练】按《01-iOS逆向之抢红包以外的那些事儿》各检测节的 E 段规则推演，不引用现实测试结果。
- **问题/输入**: 一个 App 注入 dylib 后闪退，且 debugserver 附加时报 Segmentation fault: 11，要分别判反注入与反调试。
- **方法论的使用**: (1) 反注入：先判系统版本——低版本查 Mach-O `__RESTRICT` 段用 010editor 改段名字母；高版本查 `getenv("DYLD_INSERT_LIBRARIES")` 路径 patch；(2) 反调试：现象 Segmentation fault → 判存在反调试；LLDB 在 ptrace 下断点把 R0 从 0x1f 改成别的值临时附加，持久化则同时 hook ptrace（request==31 return 0）与 dlsym（"ptrace" 返回 my_ptrace）；(3) 代理检测另按 CFNetworkCopySystemProxySettings 三段定位。
- **结论**: 反注入拦"动态库能否加载"、反调试针对"调试器附加"、代理检测针对"网络中间人环境"，三者识别特征与绕过点都不同；低版本 `__RESTRICT` 招式不能套到 iOS13 的高版本检测。
- **结果**: 合成演练不产生现实结果；按此流程预期是分别定位到对应检测函数再选 patch 手段。

### 示例 6: DVIA 越狱检测绕过（时机选择）
- **类型与来源**: 【亲历】《mobile-security-testing-guide》iOS Anti-Reversing Defenses / Bypassing Jailbreak Detection
- **问题/输入**: DVIA 的 `SFAntiPiracy`/`JailbreakDetectionVC`，检测越狱即退出，要选绕过手段。
- **方法论的使用**: (1) 复现现象：记录是「点按钮后退出」还是「启动即退出」；(2) Hopper/IDA 搜 "jail" 定位 `+[... isTheDeviceJailbroken]` 与 `-[... isJailbroken]`；(3) 运行中介入：`cycript -p <PID>`，`choose(Class)` 返回空数组 `[]`，点击按钮实例化后才拿到实例，`isJailbroken` 由 true 改 false 成功；(4) 若启动即检测则用 `frida-trace -U -f <binary> -m "-[JailbreakDetectionVC isJailbroken]"` 在 handler 改返回值；(5) 文件类检测 hook `-[NSFileManager fileExistsAtPath:]` 对 `/Applications/Cydia.app` 返回 0，必要时下沉到 `open/stat/fopen/openat/faccessat`。
- **结论**: 绕过手段取决于检测执行时机——进程内替换只适用于点击时检测，启动即退出必须用早期 hook；替换实现而非仅替换返回值可能带来副作用。
- **结果**: 原书记载 choose 后点击按钮实例化成功改值；另给「启动即退出先用非越狱设备对照排除崩溃 bug」的前置判别（CU-2-10）。

## A2 — 触发场景 (Future Trigger)

### 用户会在什么情境下需要它
1. 跨 App 入口：「URL scheme 怎么测」「deep link 有没有越权」「can another app trigger actions in my app」。
2. 存储认证：「iOS 本地存储怎么测」「Keychain 里的数据算安全吗」「指纹/面容登录能不能绕过」「biometric auth bypass」。
3. 越狱检测：「App 检测越狱直接闪退」「越狱检测怎么绕过」「app exits immediately on jailbroken device」「crash or anti-tamper」。
4. 环境能力：「这个越狱够不够用」「越狱后能做哪些测试」「tethered vs untethered jailbreak 区别」。
5. iOS 逆向与检测对抗：「iOS 逆向从哪开始」「怎么定位要 hook 的类」「一注入就闪退」「一附加就崩」「改了返回值还是没用」「流量是加密的看不懂」「设备指纹怎么来的」。

### 语言信号（出现这些就该激活）
- 中文：「URL scheme」「deep link」「越权触发」「Keychain」「明文存储」「kSecAttrAccessible」「生物识别」「Touch ID 绕过」「evaluatePolicy」「越狱检测」「启动即闪退」「tethered 越狱」「脱壳」「cycript」「class-dump」「Theos」「__RESTRICT」「MobileSubstrate」「ptrace」「dlsym」「CFNetworkCopySystemProxySettings」「MSHookMessageEx」「CCCrypt」「RSA 加密改不了」。
- English: "URL scheme testing iOS", "plaintext credentials in app container", "Keychain protection class", "biometric auth bypass", "bypass jailbreak detection", "crash or anti-tamper", "tethered vs untethered jailbreak", "iOS tweak workflow", "anti injection crash", "PT_DENY_ATTACH", "proxy detection bypass", "MSHookFunction vs MSHookMessageEx", "hook crypto", "RSA no private key"。

### 与相邻能力的区分
- 与 `<component-exposure-and-exploitation>` 的区别：iOS 无直接 IPC，scheme 是主要跨 App 入口；Android 的 exported Activity/Intent 判据不适用于 iOS，不要混用。
- 与 `<attack-surface-scoping>` 的区别：六项未校验清单负责「列全攻击面」，本能力负责 iOS 侧具体入口的实测手法（scheme 五步、存储、认证、越狱检测）。
- 与 `<unpacking-and-hook>` 的区别：iOS 越狱检测绕过用 Cycript/Frida 改方法返回值，Android 脱壳反调试用 IDA 改内存数据；平台与手段不同，但都共享「逆向是手段」的判断（`<attack-surface-scoping>`）。
- 与 `<transport-security-testing>` 的区别：后者专攻 TLS 证书层（三档判定），本能力覆盖 iOS 平台其他机制；iOS 装 CA 方式差异在两者都会涉及。

## E — 可执行步骤 (Execution)

**必需输入**: IPA 或越狱设备 + Frida/IDB/Needle 任一；scheme 测试需能投递 URL 的入口（Safari/其他 App）；存储测试需越狱或可注入 Frida 的重打包包；认证测试需能触发受保护动作；越狱检测绕过需知道目标类/方法名；缺「非越狱对照设备」时不得判定「闪退 = 检测」。

**交付物与完成标准**: scheme 测试产出「scheme 清单 × 三项校验结论 × fuzz 崩溃记录」；存储测试产出「明文命中表 + Keychain Protection 表 + 残留结论」；认证测试产出「hook evaluatePolicy 后是否继续」的对照；越狱测试产出「检测时机 + 绕过手段 + 越狱能力层级」。完成标准：每条结论有具体命令、hook 点或对照实验支撑。

1. **（URL Scheme）静态提取与 handler 定位**
   - 做什么：`grep -A 5 -nri urlsch Info.plist` 或 `rabin2 -zzq` 找 `CFBundleURLSchemes` 与 `://` 字符串 → `frida-trace -U <App> -m "*[* *openURL*]"` 定位处理函数，确认是否废弃 API。
   - 完成标准：得到 scheme 与参数模板清单，确认处理入口。
   - 判停：只验证「scheme 能打开 App」就收工不成立；只测 universal links（有 AASA 校验）而漏掉遗留自定义 scheme（无校验）会漏报；别把非公开 API（如 `LSApplicationWorkspace.openSensitiveURL:`）当成被测 App 行为。

2. **（URL Scheme）三项校验判定与 fuzz**
   - 做什么：hook `-[NSString isEqualToString:]` 投递伪造来源 URL，若比较链从未出现调用方 bundle id 判「未校验来源」；直接打开空 scheme 与畸形参数（如 `myapp://testpayload'`）看是否出现隐藏调试界面/绕过本地认证；FuzzDB 字典批量投递查 `/private/var/mobile/Library/Logs/CrashReporter` 的 `.ips`。
   - 完成标准：参数校验、来源校验、用户确认三项各有结论；崩溃对应到具体 payload。
   - 判停：出现隐藏调试界面/绕过本地认证即高危；有 `.ips` 即内存破坏候选，转可达性筛选。

3. **（存储）明文与 Keychain 属性判定**
   - 做什么：触发全部功能生成数据 → grep 应用容器找明文 → dump Keychain 逐条读 Protection/Access Group → 卸载重装查残留 → 查 ThisDeviceOnly 备份面。
   - 完成标准：敏感项落在 `Always`/`AfterFirstUnlock` 或无 AccessControl 判不达标；明文命中即失败。
   - 判停：只 dump Keychain 漏掉 NSUserDefaults/CoreData 明文 token；把「Keystore 有记录」等同于保护到位。

4. **（认证）生物识别门禁判定**
   - 做什么：`otool -L` 看是否链接 LocalAuthentication.framework → 读 `SecAccessControlCreateWithFlags` 的保护类与 flag（无 SecAccessControl 或仅 evaluatePolicy 判不达标）→ Needle `hooking/frida/script_touch-id-bypass` 或 Swizzler2 让 evaluatePolicy 返回 true → 点 Cancel → 看业务流是否继续。
   - 完成标准：Cancel 后业务流继续 = 绕过成功、认证不达标；需重新认证或数据取不到 = 达标。
   - 判停：看到用了 LocalAuthentication 就判「有生物识别」不成立；忽略 `kSecAttrAccessControl` 与 `kSecAttrAccessible` 互斥会导致配置未生效。

5. **（越狱检测）先判现象再选绕过时机**
   - 做什么：在非越狱设备/模拟器复跑同一路径 → 看 `.ips` 崩溃日志（EXC_BAD_ACCESS 与主动 exit() 不同）→ 仅「非越狱正常、越狱必退」才进入绕过；搜 "jail" 定位类方法/实例方法 → 点击时检测用 Cycript 替换（实例方法先 `choose(Class)` 并让 App 实例化）；启动即检测用 `frida-trace -U -f` 在 handler 改返回值 → 文件类检测 hook NSFileManager 或下沉到 open/stat/fopen。
   - 完成标准：检测时机明确；绕过手段与时机匹配；`isJailbroken` 由 true 改 false。
   - 判停：用 Cycript 绕「启动即退出」必然失败；只 hook 高层 fileExistsAtPath 而检测走 stat/faccessat 会漏；替换实现注意副作用。

6. **（iOS 逆向工具链）插件逆向、检测对抗与加解密定位**
   - 做什么：按五步流水线走——脱壳（frida-dump/Clutch）→ cycript 定目标类 → class-dump 出 .h → Hopper 反汇编 → Theos 注入；遇反注入按版本选 `__RESTRICT` 改段名或 `DYLD_INSERT_LIBRARIES` 环境变量 patch；越狱检测搜 dyld image API/Jail 关键字、统一 return 0、hook 未生效则从 UI 副作用转移到 UIDevice 候选；反调试在 ptrace 下断点改 R0 并同时 hook ptrace 与 dlsym；代理检测按反编译→LLDB→Theos 三段定位；hook 选型按 OC/C 分别用 MSHookMessageEx/MSHookFunction，符号 stripped 则从运行时反查 IMP；加解密先查 CCCrypt 系统库再看自定义 *Encryptor，RSA 请求无私钥则在 RSAEncrypt 前改明文 arg；设备指纹按参数→沙盒→重启对比→首启时机推理。
   - 完成标准：每个检测点有识别特征与对应 patch；hook 目标能在运行时稳定生效；加密流量的明文入口被定位。
   - 判停：跳过脱壳直接反编译得到加密数据；低版本反注入招式套到 iOS13 仍闪退；只 hook ptrace 不 hook dlsym 会被绕过；对 OC 方法用 MSHookFunction 失效；只看厂商类忽略系统统一库；执着找 RSA 私钥白费功夫。

7. **（越狱能力）评估漏洞层级与持久性**
   - 做什么：查越狱针对的漏洞层级（bootrom/iBoot/userland）与漏洞数量 → 判持久性（tethered/untethered）→ 映射到测试能力（改内核/读全盘需 bootrom/iBoot；仅注入进程读容器 userland 够）。
   - 完成标准：明确该越狱工具能否支撑当前测试项。
   - 判停：认为「越狱了就有 root」是错的（userland 级不改内核能力有限）；把 tethered 机当可随意重启的测试机会导致用例中断；别期待软件更新修掉 bootrom 漏洞。

## B — 边界 (Boundary)

### 不要用的情况
- 目标是 Android 平台：本能力全是 iOS 机制，不适用。
- App 没有自定义 scheme（只用 universal links 且 AASA 校验完善）：scheme 分支不适用。
- 单机无越狱又无重打包条件：存储/认证/越狱检测的多数动态手法不成立，转 `<attack-surface-scoping>` 选模拟器做有源码的存储检查。
- 目标是服务端认证逻辑：本能力的本地认证判定不替代服务端校验（本地门禁永远不能替代服务端校验）。

### 已知失败模式
- 只验证「scheme 能打开 App」就收工，不测参数与来源；只测 universal links 漏掉遗留 scheme；把非公开 API 当成被测 App 行为（`mobile-security-testing-guide` iOS Platform APIs）。
- 只 dump Keychain 就下结论，漏掉 NSUserDefaults/CoreData 里的明文 token；把「Keystore 里有记录」等同于保护到位，忽略 accessibility 属性（同书 Data Storage on iOS）。
- 看到用了 LocalAuthentication 就判「有生物识别」；忽略 `kSecAttrAccessControl` 与 `kSecAttrAccessible` 互斥；在 iOS 12 之前假设 ThisDeviceOnly 提供「临时可用性」（原文指出 iOS 不支持条目访问的临时性）（同书 Local Authentication）。
- 见「启动即退出」即下结论是越狱检测，不做非越狱对照；把真实越狱检测当成 bug 向开发报不存在的缺陷（同书 Anti-Reversing）。
- 用 Cycript 绕「启动即退出」必然失败；只 hook 高层 fileExistsAtPath 而检测走 stat/faccessat 时漏；替换实现带来副作用（同书）。
- 认为「越狱了就有 root」；把 tethered 越狱机当可随意重启的测试机；期待用软件更新修掉 bootrom 漏洞（`iOS Hacker's Handbook` Ch10）。
- 跳过脱壳直接反编译得到加密数据；遇到反注入时把 iOS13 环境变量检测当 `__RESTRICT` 处理改段名仍闪退；hook ptrace 不 hook dlsym 被绕过；插件代码里 `newptrace` 在 `return 0` 之后才判断 request 导致逻辑不可达；代理检测盲改第一个命中点改到无关配置读取函数（《01-iOS逆向之抢红包以外的那些事儿》）。
- hook 未生效时反复篡改同一非判定函数；搜到系统 UI 函数（如 `_isConstrainedByScreenJail`）就盲改；只 hook 高层检测忽略底层特征；对 OC 方法用 MSHookFunction 绕过 objc_msgSend 失效；符号 stripped 直接按名字下断点报 Function not defined；一上来翻厂商类忽略 CCCrypt 系统库捷径；只看方法名断定用途（如发现 RSADecrypt 但从未调用）；不验证重启行为就假定第一个参数是唯一标识（《06-当frida来敲门》/《The Mac Hackers Handbook》Ch11）。

### 作者与时代的局限
- scheme 测试中的 Skype 2010 案例、Needle 工具、Cycript、Pangu9 越狱、limera1n bootrom 漏洞都是写作时的历史案例；现代 iOS 的 universal links、Frida、checkra1n/palera1n 等已演进，方法论（列入口→判校验→实测）不变。
- Keychain 的 `kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly`、SecAccessControl 的 flag 在后续 iOS 版本有变化，判定按目标版本核对。
- 越狱漏洞层级（bootrom/iBoot/userland）与持久性分类是原理性框架，仍适用于理解越狱能力，但具体漏洞与工具需更新。

### 容易混淆的方法
- 「URL Scheme」与「Universal Links」：前者自定义、无归属仲裁、需重点测参数与来源；后者有 AASA 文件校验；只测后者会漏掉遗留 scheme。
- 「静态存储加密」与「本地认证门禁」：前者要求落盘加密（CU-2-07），后者要求每次访问都认证（本能力）；两者都靠 Keychain 的 SecAccessControl，但保护时机不同。
- 「越狱检测」与「反调试检测」：前者针对文件/权限/URL handler，后者针对调试器存在性（`<static-reverse-and-tampering>` 的 ptrace/sysctl）；绕过点常不在同一函数。
- 「越狱能力层级」与「环境三档」：`<attack-surface-scoping>` 说「越狱机能做四件事」，本能力进一步说「不同越狱的能力上限不同」。

### 授权与合规边界
> 待补充（用户自行填写）
