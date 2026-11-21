# 静态逆向与重打包插桩

## R — 原文 (Reading)

> 1）首先看这个类有没有静态方法和静态代码块，因为这类的代码会在对象初始化之前运行，可能在这里加载so文件，或者是加密校验等操作。2）再看看这个类的构造方法。3）最后再看生命周期方法。

> — 《Android应用安全防护和逆向分析》第 20 章 20.5.1

> If you don't have access to a jailbroken device, you can patch and repackage the target app to load a dynamic library at startup… However, this technique works only if the app binary isn't FairPlay-encrypted (i.e., obtained from the App Store).

> — 《mobile-security-testing-guide》Tampering and Reverse Engineering on iOS / "Dynamic Analysis on Non-Jailbroken Devices → Manual Repackaging"

> A few steps are involved when fuzzing an application. The first one is figuring out exactly what application you want to fuzz. Next, you need to generate the fuzzed inputs. After that, you need to find a way to get these inputs to the application. Finally, you need a way to monitor the application being tested for any faults that might occur.

> — 《iOS Hacker's Handbook》Chapter 6 "The Recipe for Fuzzing"

## I — 方法论骨架 (Interpretation)

这个能力回答的是工具链层面的需求：**「代码拿到了但跑不起来怎么定位校验点」「没有越狱机怎么做动态插桩」「二进制的免费防护开了没」「怎么系统地对一个解析器做模糊测试」**。它把四件共享「静态分析 + 重打包/重签」底座的工作放在一起：按执行时机定位校验点、非越狱重打包注入、编译期防护符号检查、模糊测试配方。

核心机制四块。第一块是**按执行时机定位校验点**（Android）：重打包后「点图标没反应、logcat 无异常」说明应用在极早期主动退出，通常是 dex 校验（防改代码）或签名校验（防重打包）。定位依赖执行时机而非代码位置：静态代码块 → 构造方法 → 生命周期方法，越靠前越可能是校验点（先于任何 UI）。辅助手段是**代码注入打点**——往每个可疑方法后插一条 log，跑一次看哪条 log 之后进程退出，就锁定那个方法；插 log 有讲究：返回类型 V 时在 `invoke-*` 之后插，非 V 时必须在 `move-result-object` 之后插；`MyLog.smali` 放 smali 根目录且**删掉包名声明**。第二块是**非越狱重打包注入 Gadget**（iOS）：向 Mach-O 主程序插一条 load command 指向 `FridaGadget.dylib`，用自己的开发者证书重签，App 启动时加载 gadget 实现无越狱插桩。前提是二进制可读可改——App Store 包带 FairPlay 加密，`cryptid` 非 0 时无法插桩，必须先脱壳；profile 用成 distribution 类型会导致 `get-task-allow=false` 调试器无法 attach；漏签内嵌 dylib 会启动即崩。第三块是**编译期免费防护检查**（iOS）：三项各有可观测符号——PIE 在 Mach-O header 的 `PIE` flag（缺失则 ASLR 失效，ROP 变容易）、Stack Canary 在 `___stack_chk_fail`/`___stack_chk_guard`、ARC 在 `_objc_release`/`_objc_autorelease*`。用符号存在性判断比读 Xcode 工程设置更可靠（可作用于只有 IPA 的黑盒）。第四块是**模糊测试四步配方**：选目标（冷门解析器 × 代码年龄 × 漏洞历史排序）→ 生成（变异改合法样本 vs 规范驱动生成，改动控制在「足以触发问题但不足以被立刻拒绝」的甜点区）→ 投递（解决如何重复送入，iOS 上 MobileSafari 不能命令行启动需另找入口）→ 监控（attach 调试器捕获异常，保存触发崩溃的样本）。产出率由最弱一环决定，"if you can't tell when something has gone wrong, it does no good to perform the testing"。

为什么放一起：这四件事都需要「静态分析二进制 + 必要时修改/重签 + 在设备上验证」这套工具链能力，用户往往在同一阶段连续做——先查防护开了没（otool），再想动态分析（重打包插桩），跑不起来先定位校验点（smali 打点），对解析器再上 fuzz。读完应能跑：判断手上是 dex 还是 Mach-O → 选对应手法 → 重签验证 → 对结果保持「符号存在≠每函数受保护」「变异式≠无漏洞」的警惕。

**逆向工具选型补充**（Android 渗透手册补充）：静态逆向第一条分岔是"只读理解"还是"要改并重编译"——`dex2jar + JD-GUI` 把 dex 转成 .jar 显示**近似** Java 源码，适合快速读逻辑但不可回写；`Apktool` 把 dex 转成 smali 是**双向**的，改完能 `apktool b` 重打包成可安装 APK，适合需要修改的场景。判据就是是否需要回编译，用 JD-GUI 试图回编译会得到无法使用的近似代码；proguard 等保护会让反编译结果失真，不要期待精确源码。这一分岔是本节 smali 打点、重打包插桩的前置选型动作。

## A1 — 应用示例 (Application Example)

### 示例 1: 重打包后闪退的校验点定位
- **类型与来源**: 【亲历】《Android应用安全防护和逆向分析》第 20 章 20.5.1
- **问题/输入**: 某 App 重打包后点图标没反应、logcat 无异常，要找到导致退出的校验点。
- **方法论的使用**: (1) `apktool d` 反编译，看 Manifest 找自定义 Application；(2) 按执行时机读：静态字段/静态代码块 → 构造方法 → `onCreate`/`attachBaseContext` → 其它生命周期，定位到 `vr.h(this)` 做签名校验；(3) 插 log 确认：在 `invoke-*` 之后插自定义 `MyLog` 调用（返回非 V 时在 `move-result-object` 之后插），`MyLog.smali` 放 smali 根目录并删包名；(4) 回编译、重签、安装，抓 log 看最后一条落在哪个方法；(5) 注释对应 smali 行后正常运行。
- **结论**: 定位依赖执行时机而非全局搜索（动态拼接/加密字符串会让搜索失效）；校验只有两大类——对 dex 做校验、对 apk 签名做校验；只改一处校验若还有第二处会表现为「还是闪退」。
- **结果**: 原书交代注释 `vr.h(this)` 后正常运行；另引 native 取数据库密码 `libpsProcess.so` 的 `getDbPassword` 与 Java 层返回值一致佐证静态分析有效。

### 示例 2: OWASP UnCrackable iOS Level 1 的重打包插桩
- **类型与来源**: 【例题】《mobile-security-testing-guide》Tampering and Reverse Engineering on iOS
- **问题/输入**: 没有越狱机，要对一个 IPA 做动态分析。
- **方法论的使用**: (1) `otool -l <binary> | grep -A4 LC_ENCRYPTION_INFO` 看 `cryptid` 确认未加密；(2) 取得开发者证书与 provisioning profile，`security cms -D -i <profile>.mobileprovision > profile.plist` 导出 entitlements；(3) 用 optool 插入 load command 指向 `FridaGadget.dylib`，把 dylib 拷入 Frameworks；(4) 重签主程序与 dylib（`codesign`/ldid），重新打包安装；(5) 启动 App 后 `frida-ps -U` 能看到目标进程并 attach。
- **结论**: 非越狱插桩的前提是二进制未加密（FairPlay）；profile 必须是 development 类型（distribution 会导致 get-task-allow=false）；漏签内嵌组件会启动即崩；能力上限受沙箱限制（"you can't break out of the sandbox this way"）。
- **结果**: 原文以该例题演示全流程，并用 Telegram X 演示 entitlements 提取。

### 示例 3: Preview 与 iOS 的模糊测试命中率对比
- **类型与来源**: 【例题】《iOS Hacker's Handbook》Chapter 6 "The Recipe for Fuzzing"
- **问题/输入**: 用 `fuzz_buffer()` 随机改字节函数对 PDF 解析器做模糊测试，对比 macOS Preview 与 iOS 的命中率。
- **方法论的使用**: (1) 选目标：PDF header atoms 解析（冷门、年代久、有漏洞历史）；(2) 生成：用多个不同特性的合法样本做变异，Simple 样本测不到多少解析路径；(3) 投递：解决重复送入（MobileSafari 不能命令行启动需另找入口）；(4) 监控：attach 调试器捕获异常，保存触发崩溃的样本 → 每个崩溃对应到具体输入文件。
- **结论**: 只做变异式就断言「没有漏洞」不成立（TRACE 等方法分支永远不会被生成）；改动幅度过大导致输入全被拒，必须找 "sweet spot"；无监控或无样本留存等于没测。
- **结果**: 原书以此对比在 Preview 与 iOS 上的命中率差异（Preview 上百次崩溃、iOS 约 7%），并说明模糊结果需按可达性（`<attack-surface-scoping>`）筛选后才算有效漏洞。

## A2 — 触发场景 (Future Trigger)

### 用户会在什么情境下需要它
1. Android 重打包后异常：「重打包后闪退」「怎么找签名校验」「反编译后从哪看起」「点了图标没反应」。
2. iOS 插桩：「没有越狱机怎么动态分析」「frida 注入非越狱 iPhone」「repackaging IPA with FridaGadget」。
3. 编译防护检查：「这个 App 有没有开 PIE/ASLR」「二进制加固怎么检查」「check stack canary / ARC in IPA」。
4. 模糊测试：「怎么对一个文件解析器做 fuzz」「模糊测试跑不出结果」「mutation vs generation fuzzing」。
5. 反调试补丁：「下断点就被踢」「anti-debugging 怎么绕」「PT_DENY_ATTACH bypass」。

### 语言信号（出现这些就该激活）
- 中文：「重打包闪退」「签名校验」「静态代码块」「smali 打点」「非越狱注入」「FridaGadget」「重签」「PIE」「栈保护」「otool」「fuzz 模糊测试」。
- English: "apk crashes after repack", "find signature check in smali", "repackaging IPA with FridaGadget", "dynamic analysis on non-jailbroken iOS", "check stack canary / ARC in IPA", "PT_DENY_ATTACH bypass", "mutation vs generation fuzzing"。

### 与相邻能力的区分
- 与 `<unpacking-and-hook>` 的区别：后者处理「拿不到 dex / so 被加密」的加固场景（动态 dump 内存），本能力处理「已拿到 dex 但跑不起来 / 重打包插桩 / 免费防护检查 / fuzz」的静态工具链场景。
- 与 `<transport-security-testing>` 的区别：后者 patch 的目的是绕过 pinning 看流量，本能力的 patch 目的是定位校验点/注入 Gadget/打 log；两者共用 apktool/重签工具但目标不同。
- 与 `<attack-surface-scoping>` 的区别：fuzz 产出的是「崩溃候选」，需回攻击面能力做可达性筛选后才算有效漏洞；本能力不负责漏洞定级。

## E — 可执行步骤 (Execution)

**必需输入**: 视分支而定——Android 校验定位需未加固的 APK + 重打包重签环境 + logcat；iOS 插桩需 macOS + Xcode 命令行 + 开发者 profile + 未加密 IPA；防护检查需解包 IPA + otool/IDB；fuzz 需一个可用样本 + 能重复触发的入口（生成式还需协议规范）。缺关键前提时不得给出「无漏洞/防护到位」结论。

**交付物与完成标准**: Android 分支产出「校验点定位记录 + 注释/改写后的 smali」；iOS 分支产出「重签可运行的 IPA + frida-ps 可见进程」；防护检查产出「PIE/Canary/ARC 三态表」；fuzz 产出「样本-崩溃对应清单」。完成标准：每条结论有可复现命令或对照证据。

1. **判断手上的二进制类型和目标**
   - 做什么：确认是 Android dex（APK）还是 iOS Mach-O（IPA）；明确本次要回答的问题（校验点 / 插桩 / 防护检查 / fuzz）。
   - 完成标准：分支选择明确。
   - 判停：加固包先转 `<unpacking-and-hook>`；目标是看流量转 `<transport-security-testing>`。

2. **（Android 分支）按执行时机定位校验点**
   - 做什么：apktool d → Manifest 找自定义 Application → 按顺序读静态代码块/构造方法/生命周期 → 搜 `signature`/`getPackageInfo(..., GET_SIGNATURES)`/`MessageDigest`/读自身 dex。
   - 完成标准：定位到疑似校验方法。
   - 判停：全局搜字符串作为唯一手段遇动态拼接会失效；只改一处校验还有第二处会「还是闪退」，需全局搜 `signature` 提前发现。

3. **（Android 分支）代码注入打点定位**
   - 做什么：在 `invoke-*` 之后（返回 V）或 `move-result-object` 之后（返回非 V）插 `MyLog` 调用，`MyLog.smali` 放根目录删包名 → 回编译、重签、安装 → 抓 log 看最后一条落点。
   - 完成标准：最后一条 log 指向校验方法。
   - 判停：没避开 `move-result-object` 会拿不到返回值；MyLog.smali 忘删包名回编译报错。

4. **（iOS 插桩分支）确认未加密并重签注入**
   - 做什么：`otool -l | grep LC_ENCRYPTION_INFO` 看 cryptid（非 0 先脱壳）→ 导出 entitlements → optool 插 load command 指向 FridaGadget.dylib → 拷入 Frameworks → codesign/ldid 重签主程序与 dylib → 打包安装 → `frida-ps -U` 验证。
   - 完成标准：目标进程可见并可 attach。
   - 判停：cryptid 非 0 直接插桩会失败；profile 用成 distribution（get-task-allow=false）调试器无法 attach；漏签内嵌 dylib 启动即崩；bundle id 需与 profile App ID 匹配。

5. **（iOS 防护检查分支）otool 三项符号检查**
   - 做什么：解包 IPA → `otool -hv` 看 flags 是否含 `PIE` → `otool -Iv | grep stack` 看 `___stack_chk_fail`/`___stack_chk_guard` → `otool -Iv | grep release` 看 `_objc_release` → IDB "Analyze Binary…" 交叉验证。
   - 完成标准：三项三态表齐全。
   - 判停：有源码时只读 Build Settings 不看产物会与工程设置不一致；有符号不等于每个函数受保护（`-fstack-protector-all` 才覆盖全部函数）；加密二进制需先脱壳才看得到真实段。

6. **（反调试补丁分支）指令级 patch**
   - 做什么：iOS ptrace 路线——搜 `dlsym(RTLD_SELF, "ptrace")` 参数 31，找到 `BLX R6`（字节 `B0 47`）改为 `NOP`（`00 BF`）；sysctl 路线——改 `P_TRACED` 判断分支的 `MOVNE R0,#1` 为 `#0`；重签后 lldb attach 验证。
   - 完成标准：能正常下断点。
   - 判停：实际样本多用 dlsym 动态取址，按符号名搜函数常搜不到；只改一处而样本有冗余检测仍会退出。

7. **（fuzz 分支）四步配方**
   - 做什么：选目标（冷门×年龄×漏洞历史）→ 生成（变异 vs 生成，找 sweet spot）→ 投递（解决重复送入）→ 监控（捕获异常、保存样本）。
   - 完成标准：每个崩溃对应到具体输入文件。
   - 判停：只做变异式就断言无漏洞不成立；改动过大输入全被拒；无监控或无样本留存等于没测；结果需回攻击面能力做可达性筛选。

## B — 边界 (Boundary)

### 不要用的情况
- APK 已加固（dex 被抽空/so 加密）：转 `<unpacking-and-hook>`，本能力的 smali 打点不适用。
- 目标是看 HTTPS 流量：转 `<transport-security-testing>`。
- 纯黑盒且无样本输入、无重复入口时：fuzz 分支不成立，不要空跑。
- 有源码且能直接改代码时：不必走重打包 smali 打点，直接源码加 log 更高效。

### 已知失败模式
- 用「全局搜字符串」作为定位校验的唯一手段，遇动态拼接/加密字符串失效；插 log 没避开 `move-result-object`；MyLog.smali 忘删包名回编译报错；只改一处校验还有第二处（`Android应用安全防护和逆向分析` Ch20.5.1）。
- 拿 App Store 包直接插桩，FairPlay 未脱壳导致 gadget 不加载；profile 用 distribution 类型致 get-task-allow=false；重签漏签内嵌 dylib/framework 导致启动即崩（`mobile-security-testing-guide` Tampering and Reverse Engineering on iOS）。
- 有源码时只读 Build Settings 不看产物；把「存在符号」当作「每个函数都受保护」（同书 MSTG-CODE-9）。
- 实际样本用 dlsym 动态取址，按符号名搜 ptrace 搜不到；只改一处而样本放多处冗余检测仍退出（同书 iOS Anti-Debugging）。
- 只做变异式就断言「没有漏洞」（TRACE 等方法分支永远不会被生成）；改动幅度过大输入全被拒；无监控或无样本留存（iOSHH Ch6）。
- 用 dex2jar/JD-GUI 试图回编译，得到无法直接使用的近似代码；遇到 proguard 保护仍期待看到精确源码（《Android 渗透测试学习手册》3.2/3.3）。

### 作者与时代的局限
- apktool  smali 打点、jarsigner 重签、optool 插 load command、FridaGadget.dylib、otool 三项符号检查都是写作时的工具生态；现代工具（jadx、apksigner、objection、Frida 直注入）已演进，方法论不变。
- otool 检查的 PIE/Canary/ARC 是编译期免费防护，不等于运行中全部生效（如 `-fstack-protector-all` 才全覆盖）。
- fuzz 配方来自 iOSHH 写作时对 PDF 解析器的研究，现代 fuzzing 已有 AFL/libFuzzer 等覆盖率引导工具，但「选目标/生成/投递/监控」四环框架仍适用。

### 容易混淆的方法
- 「静态校验定位」与「动态脱壳」：前者 dex 已拿到但跑不起来（smali 打点），后者 dex 拿不到（dump 内存）；两者都属于逆向但前提不同。
- 「重打包注入 Gadget」与「越狱后直接注入」：前者用于无越狱机（能力受沙箱限制），后者用于越狱机（可读写全盘/运行时）；选哪种取决于环境，不是能力高低。
- 「变异式 fuzz」与「生成式 fuzz」：前者改合法样本、快但难深入，后者依规范构造、成本高但覆盖分支；只做一种就下结论会漏。
- 「有符号」与「全函数受保护」：otool 看到 Canary 符号不代表每个函数都有栈保护。

### 授权与合规边界
> 待补充（用户自行填写）
