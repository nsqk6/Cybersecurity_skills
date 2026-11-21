# 脱壳与动态 Hook

## R — 原文 (Reading)

> 不管之前的源程序如何加固，放到哪了，最终都是需要被加载到内存中然后运行，而且是没有加密的内容，那么只要找到dex的内存位置，把这部分数据弄出来就可以了

> — 《Android应用安全防护和逆向分析》第 23 章 23.2

> 这里只有一个Application类，这个apk可能被加固了，为什么这么说呢？因为一个apk加固，外面肯定得套一个壳，这个壳必须是自定义的Application类，它需要做一些初始化操作

> — 《Android应用安全防护和逆向分析》第 23 章 23.1

> Ultimately, the reverse engineer always wins.

> — 《mobile-security-testing-guide》Tampering and Reverse Engineering / "Why You Need It"

> 优点：因为是Frida启动的进程，在启动的同时注入frida代码，所以Hook的时机很早。适用于在进程启动前的一些hook，如hook RegisterNative、较早进行的加解密等。

> — 《075-Hook梦幻旅途之Frida》1.1.2 混合运行 Frida

> 这个时候Hook动态注册函数就能一把尖刀，直刺So中函数所在的位置。

> — 《075-Hook梦幻旅途之Frida》3.2 寻找关键函数

## I — 方法论骨架 (Interpretation)

这个能力回答的是加固场景的核心需求：**「APK 反编译出来什么都没有，怎么把里面的真实代码拿出来，以及被反调试挡住时怎么继续」**。它把「识别加固 → 定位源 APK 藏身点 → dump 内存 dex → 过反调试 → 把逆向定位成手段而非目的」串成一条链，核心洞见是：**不必逆向任何一家的解密算法，只需在 Dalvik 加载 dex 的收口处取一次内存快照**。

核心机制五块。第一块是**加固识别**：壳必须抢在真实代码前运行，所以壳的 Application 必须是 dex 里唯一/最先被执行的东西（常见命名 `StubApplication`/`SuperApplication`），用 dex2jar + jd-gui 打开会看到「只有一个 Application 类，连入口 Activity 都没有」。同时有不变量——四大组件必须在 Manifest 声明，于是「Manifest 里有 MainActivity，代码里却找不到」这对矛盾就是判定证据，不需要知道是哪家壳。第二块是**三个藏身点**：源 APK 必在本地，APK 里能藏二进制大文件的位置只有三处——`assets/`（多出打不开的 `.dat`/`.jar`）、壳 dex 尾部（导致 dex2jar 解析失败，这个失败本身就是判据）、`libs/` 里未被 load 的 so（so 数量多于 Application 实际 load 的数量）。排查顺序是「dex2jar 试解析 → 看 assets → 看 libs」，三步都不必逆向解密算法，因为下一步一律改成 dump 内存。第三块是**dump 定式**：所有 dex 加固最终都要把解密后的 dex 交给 Dalvik 加载，收口函数是 `libdvm.so` 的 `dvmDexFileOpenPartial(void* addr, int len, ...)`——第一个参数是 dex 内存起始地址，第二个是大小，此刻内容明文且连续。断点地址 = 函数在 so 内相对地址（静态分析得）+ so 内存基址（运行时 Modules View 得）；断下后单步到 `PUSH` 之后（不越过后面的 `BL`），此时 R0=起始地址、R1=size，用 IDA 脚本把 `[R0, R0+R1)` 写到本地 `dump.dex`。dump 后若 dex2jar 失败而 baksmali 成功，属正常，改走 smali 路线不要重 dump。第四块是**反调试处置**：IDA attach 后进程立即退出的原因是加固在 `JNI_OnLoad` 或早期线程轮询 `/proc/<pid>/status` 的 `TracerPid`，>0 即自杀；在 so 加密无法静态分析时，常规「nop 掉检测指令」失效，改为在系统库层拦截——给 `libc.so` 未被加固的 `fopen`/`fgets` 下断点，在读到 `TracerPid:` 那行时把内存值改成 0（或改 R0 指向内容）。因为检测在子线程轮询，需重复改多次直到主线程走到 `dvmDexFileOpenPartial`。第五块是**定位逆向为手段**：逆向只有三个用途——解除阻碍动态分析的防护、无源码时理解逻辑找硬编码、评估 MASVS-R 韧性；「逆向必然成功」决定了韧性评估的结论口径应写「提高了多少成本」而非「是否安全」。

为什么放一个能力：用户的一句需求「加固了怎么逆向」天然需要这条完整链——不先识别就不知道要不要脱壳，不定位藏身点就不知道去哪找，不 dump 内存就拿不到代码，被反调试挡住就得先过检测，最后还要有「够用即停」的判断避免为了逆向而逆向。所有环节共享 root/可调试设备这一前提。读完应该能跑：dex2jar 看类列表 + Manifest 交叉验证 → 三处找 payload → 改 debuggable 重签 → attach + 下 dvmDexFileOpenPartial 断点 → 遇反调试改 TracerPid → dump + baksmali → 够用即停。

**动态 Hook 工具链分支**（Frida 实战三篇 + Mac 手册补充）：dump 解决「拿到代码」，而拿代码之后的运行时观察与篡改靠另一套工具链，二者共享「先定位再动手、够用即停」的纪律。这一分支的骨架是六条：①**注入时机**——Attach 与 Spawn 不是等价启动方式而是两个时机窗口，越早发生的逻辑（RegisterNatives、init 里的解密）越必须用 Spawn（`device.spawn` 挂起→注入→resume），代价是噪声大易卡死，稳定界面的逻辑用 Attach；②**调试迭代速度**——优先 CLI（`frida -U --no-pause -f pkg -l script`）而非 Python+JS 混合脚本，CLI 与原脚本保持同步、保存即生效，把反馈环从「重启 App」压缩到「保存文件」，逆向瓶颈往往是迭代速度；③**so 函数地址 API 选型**——`findExportByName` 找不到返回 null（探测分支）、`getExportByName` 抛异常（断言场景）、`enumerateExportsSync` 遍历（名字未知），按容错需求选，避免枚举阶段就崩；④**JNI 函数 Hook**——JNIEnv 指向函数指针数组，按「JNI.h 序号 × 指针大小」算偏移读地址（`Java.vm.getEnv().handle.readPointer()` + `Memory.readPointer(env.add(offset))`），把 200 多个函数名存数组用 `indexOf×pointerSize` 自动算偏移；⑤**Hook RegisterNatives 定位动态注册函数**——遍历 JNINativeMethod 三元组的「名字/签名/函数指针」，追加 Hook FindClass 关联 jclass 与类名，得到能在 IDA 用 G 跳转的地址；⑥**地址空间换算**——运行时地址 fnPtr 减 so 基址（`Process.findModuleByAddress(fnPtr).base`）得 IDA 虚拟地址，或用 `DebugSymbol.fromAddress(fnPtr).name`，直接把运行时地址输进 IDA 会跳错位置。Mac 手册再补两点：`mach_override` 的 hook/island 机制通过保留 real 函数指针在原函数前后加逻辑（单向、无 mach_unoverride 不可卸载，适用于 C/C++ 函数），以及符号被 strip 时从 Objective-C 运行时反查 IMP（`objc_getClass`→`sel_getUid`→`class_getInstanceMethod` 的 Method 结构第三个指针就是实现地址）。

## A1 — 应用示例 (Application Example)

### 示例 1: 阿里 CTF 题的脱壳全程
- **类型与来源**: 【亲历】《Android应用安全防护和逆向分析》第 23 章 23.1/23.2、第 24 章 24.2
- **问题/输入**: 一个加固 APK，dex 里只剩一个 Application，Manifest 里却声明了 MainActivity，要拿到真实代码。
- **方法论的使用**: (1) 识别：dex2jar + jd-gui 看类列表只有 Application、无入口 Activity；apktool 拿 Manifest 找到 MainActivity 全名但 dex 里无对应类；(2) 定位藏身：`assets/` 下两个 jar（jd-gui 打不开）+ `libs/` 下三个 so，而 Application 只 load 了 `libmobisec.so`；(3) 脱壳：`adb pull /system/lib/libdvm.so` 用 IDA 静态分析取 `dvmDexFileOpenPartial` 相对地址 43308 → 设备跑 android_server、`adb forward tcp:23946` → `am start -D` debug 启动 → jdb attach → 双开 IDA 取 libdvm.so 基址 41579000，G 跳到 415BC308 下断点 → 断下后单步到 PUSH 之后，R0=dex 起始、R1=size → IDA 脚本 dump 到 `dump.dex`；(4) 验证：baksmali 反编译成功，读到 `@JavascriptInterface` 的 `showToast("\u7965\u9f99\uff01")`。
- **结论**: 相对地址 + 基址 = 断点地址；单步不要越过 BL 否则寄存器被覆盖；dex2jar 失败而 baksmali 成功属正常。
- **结果**: 原书交代 dump 后 baksmali 成功并读到真实代码。

### 示例 2: 某加固平台的 TracerPid 反调试绕过
- **类型与来源**: 【亲历】《Android应用安全防护和逆向分析》第 24 章 24.2 第七步
- **问题/输入**: IDA attach 后进程立即退出，jdb 也断开，怀疑加固反调试。
- **方法论的使用**: (1) 确认现象：attach 成功瞬间看 `/proc/<pid>/status` 的 `TracerPid` 非 0（值 24336 = android_server 的 pid）；(2) so 被加密无法静态分析，常规 nop 检测指令失效；(3) 在 IDA 里给 `fopen`、`fgets` 下断点（可直接输函数名）→ 逐个过 fopen，跳过 `/proc/self/cmdline` 等干扰（中间还遇到读 `/proc/self/cmdline.debug.atrace.app_cmdlines` 的干扰项），直到命中 `/proc/<pid>/status`；(4) fgets 断点后 F8 单步，数到第 6 次读到 `TracerPid`；(5) 在 Hex View 用 `G` 跳到 R0 指向的数据地址（注意调试视图的 G 跳指令、Hex View 的 G 跳数据），把数字改成 0 → Edit → Apply changes；(6) F9 继续，重复修改 3 次直到主线程命中 dvmDexFileOpenPartial，再执行 dump。
- **结论**: 检测是子线程轮询，必须持续改到目标断点；改一次就放行会被下一轮杀掉；检测若不用 fopen/fgets 读 status，这两个断点不命中，需换关键点函数多次尝试。
- **结果**: 原书交代共修改 3 次后成功到达 dump 断点。

### 示例 4: Hook RegisterNatives 定位动态注册 native 函数
- **类型与来源**: 【亲历】《075-Hook梦幻旅途之Frida》3.2/3.3（作者以 libm4399.so 的 tokenDecrypt 为例）
- **问题/输入**: 一个 native 方法在 JNI_OnLoad 里动态注册，IDA 因防护无法反编译，要定位它在 so 里的地址。
- **方法论的使用**: (1) 选 Spawn 注入（RegisterNatives 发生极早，Attach 会错过）；(2) Hook JNIEnv 第 215 位取得 RegisterNatives，遍历 `args[3]` 指向的数量与 JNINativeMethod 三元组 → 拿到 fnPtr 与 signature；(3) 用 `DebugSymbol.fromAddress(fnPtr).name` 与 `Process.findModuleByAddress(fnPtr).base` 补全定位；(4) 追加 Hook FindClass 用 `jclassAddress2NameMap[args[0]] = args[1].readCString()` 关联类名。
- **结论**: 必须输出 IDA 可跳转地址（运行时绝对地址无效）；作者实测 fnPtr `0x8a339267` 减基址 `0x8a322000` 得 `0x17267`，与 `DebugSymbol.name` 的 `0x17266+1` 一致。
- **结果**: 原书记载定位到 tokenDecrypt 的签名 `(Ljava/lang/String;)Ljava/lang/String;`，IDA 虚拟地址 `0x17267`。

### 示例 5: 【合成演练】逆向到「够用」即停
- **类型与来源**: 【合成演练】按《mobile-security-testing-guide》"Why You Need It" 的 E 段规则推演，不引用现实测试结果。
- **问题/输入**: 一个无源码 App 有证书固定挡住动态分析，目标是测它的业务逻辑漏洞而非还原全部代码。
- **方法论的使用**: (1) 明确卡点属于三类中的「解除阻碍动态分析的防护」；(2) 只做到能 hook 到目标函数即停，不追求完整反编译；(3) 若目标是第 3 类「评估 MASVS-R 韧性」，按项给「绕过耗时/所需技能」的定性结论，而非二元通过。
- **结论**: 逆向必然成功——防护只能提高成本不能提供保证，报告应写「提高了多少成本」而非「是否安全」；「我没绕过」属于「未评估」而非「通过」。
- **结果**: 合成演练不产生现实结果；按此流程，预期是只在必要时脱壳/hook，不把时间耗在与安全问题无关的还原上。

## A2 — 触发场景 (Future Trigger)

### 用户会在什么情境下需要它
1. 反编译受阻：「反编译出来什么都没有」「只有一个 Application 类」「是不是加壳了」。
2. 脱壳操作：「脱壳怎么脱」「dump dex 用什么函数」「加固了怎么逆向」「assets 里的 dat 是什么」。
3. 反调试卡住：「IDA 一 attach 就退出」「加固有反调试怎么办」「TracerPid 怎么过」。
4. 策略判断：「要不要脱壳/反编译」「逆向到什么程度够了」「有混淆是不是就安全了」。
5. 动态 Hook：「hook 不到函数/脚本没反应」「怎么一启动就 hook」「IDA 里找不到 native 函数」「hook 到的地址 IDA 对不上」「JNI_OnLoad 反编译失败」。

### 语言信号（出现这些就该激活）
- 中文：「加壳」「加固」「脱壳」「dump dex」「dvmDexFileOpenPartial」「反调试」「TracerPid」「StubApplication」「只有一个 Application 类」「逆向到什么程度」「Attach 还是 Spawn」「RegisterNatives」「JNIEnv 偏移」「运行时地址换算」。
- English: "APK is packed", "how to tell if app is hardened", "dump dex from memory", "dvmDexFileOpenPartial breakpoint", "anti-debug bypass IDA Android", "TracerPid patch", "unpacking hardened APK", "how deep should reverse engineering go", "frida attach not catching RegisterNatives", "runtime address to IDA offset", "findExportByName returns null"。

### 与相邻能力的区分
- 与 `<static-reverse-and-tampering>` 的区别：本能力处理「拿不到 dex / so 被加密」的加固场景（动态 dump 内存），后者处理「已拿到 dex 但跑不起来 / 重打包插桩」的静态场景；两者共享 root/重签前提但目的不同。
- 与 `<sandbox-data-acquisition>` 的区别：都可能需要 debuggable，但本能力目标是取 dex 代码，后者目标是取私有数据。
- 与 `<transport-security-testing>` 的区别：都可能需要 root + hook，都可能被反调试拦住；本能力 hook 取代码，后者 hook 看流量。
- 与 `<ios-platform-security-testing>` 的越狱检测绕过区别：iOS 侧用 Cycript/Frida 改方法返回值，本能力用 IDA 改内存数据/下系统库断点，平台与手段不同。

## E — 可执行步骤 (Execution)

**必需输入**: root 设备或可调试设备；目标已被改成 `debuggable=true`（需重打包重签）；IDA + android_server（需匹配架构）；能列 zip 内容；对反调试分支需已知检测是读 status 文件这一实现。缺 debuggable 时先转 `<static-reverse-and-tampering>` 改 Manifest，缺 root 时本能力不成立。

**交付物与完成标准**: 一份加固判定记录（dex 类列表 + Manifest 组件对照）+ 藏身点清单 + dump 出的 `dump.dex` 及 baksmali 结果 + 反调试处置记录。完成标准：dump 出的 dex 能被 baksmali 反编译出业务类；报告明确「逆向做到哪一步、为什么停」。

1. **识别加固**
   - 做什么：解压 APK → dex2jar + jd-gui 看类列表 → 判据「只有 Application（及内部类），无业务类、无入口 Activity」；apktool 拿 Manifest 找 MAIN/LAUNCHER activity 全名 → 判据「Manifest 有该组件但 dex 无对应类」；看壳 Application 的 `attachBaseContext()` 加载了什么。
   - 完成标准：两条证据交叉验证成立。
   - 判停：见类少就断「空壳/demo」不成立；dex2jar 解析失败要区分「dex 尾部被追加」与「工具不支持」，前者直接转 dump 内存。

2. **定位源 APK 藏身点**
   - 做什么：dex2jar 试解析失败 → 怀疑 dex 尾部追加；列 `assets/` 大文件试 unzip -l / jd-gui，打不开记候选；列 `libs/<abi>/` 的 so 与壳 loadLibrary 名字比对，多出的记候选。
   - 完成标准：三处候选清单齐全，记录壳的初始化路径（copy 到 files 再 System.load）。
   - 判停：只在 assets 里找遇到 so 承载会卡死（作者评语「这就比较难了」）；不要花时间逆向 so 解密算法——跳过算法直接 dump 内存。

3. **准备调试环境**
   - 做什么：改 Manifest 使 debuggable=true → 重打包重签 → `adb pull /system/lib/libdvm.so` 用 IDA 静态分析取 `dvmDexFileOpenPartial` 相对地址 → 设备跑 android_server、`adb forward tcp:23946` → `am start -D -n <pkg>/<launchActivity>` → `jdb -attach`（端口从 DDMS 看，可能不是 8700）。
   - 完成标准：进程处于可调试挂起状态，相对地址已记录。
   - 判停：加固包常 debuggable=false，必须先改 Manifest；attach 后进程立即退出说明有反调试，转第 5 步。

4. **下断点并 dump**
   - 做什么：双开 IDA（一个静态、一个 attach）→ attach 侧取 libdvm.so 基址，G 跳「相对地址 + 基址」下断点 → 运行 → 断下后单步到 `PUSH` 之后（不越过 BL）→ 此时 R0=起始、R1=size → IDA 脚本把 `[R0, R0+R1)` 写到 `dump.dex`。
   - 完成标准：dump.dex 落盘，baksmali 反编译成功。
   - 判停：只 dump 一次就收工不够——壳会先用 `dvmLoadNativeCode` 加载自己的 so、再建反调试线程，中间多次停留，需反复运行到 dvmDexFileOpenPartial；dex2jar 失败就用 baksmali 验证，不要重 dump。

5. **反调试处置（按需）**
   - 做什么：给 `fopen`/`fgets` 下断点 → 逐个过 fopen 跳过无关读取直到命中 `/proc/<pid>/status` → fgets 断点后 F8 单步数清第几次读 `TracerPid` → Hex View 的 G 跳 R0 数据地址改值为 0 → Apply changes → F9 继续，重复到主线程命中目标断点。
   - 完成标准：能稳定到达 dump 断点。
   - 判停：调试视图的 G 跳指令地址、Hex View 的 G 才跳数据地址，别跳错；改一次就放行会被子线程下一轮杀掉；检测不走 fopen/fgets 时这两个断点不命中，换关键点函数多次尝试。

6. **（动态 Hook 分支）注入时机与地址定位**
   - 做什么：按目标函数触发时机选注入模式——极早调用（RegisterNatives/init 解密）用 Spawn（`spawn`→注入→`resume`），稳定界面逻辑用 Attach；调试一律用 CLI（`frida -U --no-pause [-f] pkg -l script`）而非 Python+JS 混合脚本，保存即生效；so 函数用 `findExportByName`（探测，返回 null）/ `getExportByName`（断言，抛异常）/ `enumerateExportsSync`（批量）按容错选；JNI 函数在 `Java.perform` 内按 `indexOf×pointerSize` 算偏移 Hook；Hook RegisterNatives 遍历三元组拿 fnPtr 与 signature，Hook FindClass 关联类名；运行时地址用 `DebugSymbol.fromAddress(fnPtr).name` 或 `fnPtr - module.base` 换算成 IDA 虚拟地址。
   - 完成标准：目标函数被稳定 hook，输出带 IDA 可跳转地址，迭代反馈环压缩到「保存脚本」。
   - 判停：极早调用用 Attach 会「毫无收获」；稳定逻辑用 Spawn 会被噪声淹没且易卡死；在 `Java.perform` 外取 JNIEnv 失败；直接把运行时地址输入 IDA 跳到错误位置；多架构 so 选错架构（优先 armv7a）任何 API 都找不到。

7. **结果验证与够用即停**
   - 做什么：baksmali 反编译 dump.dex 得到 smali → 只读需要的逻辑/硬编码 → 明确当前逆向属于三用途中的哪一类并决定停止点。
   - 完成标准：回答了具体的测试问题（找到硬编码/打通动态分析/给出韧性结论）。
   - 判停：无源码时试图完整还原业务逻辑成本极高且常无必要；把「我没绕过」当成「防护有效」是错的，应记为「未评估」。

## B — 边界 (Boundary)

### 不要用的情况
- unattempted dex 加固（如仅做资源混淆、类仍在 dex 里）：转 `<static-reverse-and-tampering>` 的静态分析，不必 dump 内存。
- ART/OAT 环境：本书脱壳定式基于 Dalvik 的 `dvmDexFileOpenPartial`，ART 下的路径不在本书范围（MAHH 只在 "Dealing with ART" 节提到 `oat2dex` 与「APK 仍在设备上、OAT 内嵌原始 DEX」两个事实，未给流程）。
- iOS 平台：本能力是 Android dex 加固语境，iOS 的越狱检测/反调试绕过转 `<ios-platform-security-testing>`。
- 目标是看 HTTPS 流量而非拿代码：转 `<transport-security-testing>`。

### 已知失败模式
- 见到类很少就断定「是空壳/是 demo」，未与 Manifest 交叉验证；只看反编译工具报错就断定加固，没区分「dex 尾部被追加」与「工具不支持」；只记「已加固」不继续找 payload，结论停在「无法评估」（《Android应用安全防护和逆向分析》Ch23.1）。
- 只在 assets 里找，遇到 so 承载的加固就卡死；把「多出来的 so」当普通第三方库放过；花时间逆向 so 解密算法（同书 Ch23.1）。
- 单步越过 BL 导致寄存器被覆盖；只 dump 一次就收工；用 dex2jar 失败就以为 dump 坏了；加固包带反调试 attach 后进程立刻退出未先处置（同书 Ch23.2/24.2）。
- 反调试只改一次就放行；在调试视图用 G 跳数据地址跳错到指令区；期望「改完就永久生效」（同书 Ch24.2）。
- 无源码时试图完整还原业务逻辑；把「我没绕过」当成「防护有效」——最有效的保护是专有方案，标准技巧打不动，属于「未评估」而非「通过」（《mobile-security-testing-guide》Why You Need It）。
- 对极早调用用 Attach 毫无收获、对稳定逻辑用 Spawn 被噪声淹没且卡死；坚持 Python+JS 混合脚本逐次重启拖慢迭代；把 find 当断言用、返回 null 后直接 attach 崩溃；在 `Java.perform` 外取 JNIEnv 失败；直接把运行时地址输进 IDA 跳错位置；多架构 so 选错架构任何 API 都找不到（《075-Hook梦幻旅途之Frida》1.1/2.3/3.3）。
- 以为 mach_override 注入后可热卸载（无 mach_unoverride）；对 Objective-C 方法用函数 hook（调用经 objc_msgSend 会失效，应改 swizzling）；符号 stripped 时直接 `break -[Class method:]` 报 Function not defined，须从运行时反查 IMP（《The Mac Hackers Handbook》Ch11）。全量 JNI hook 库「理论上可行但实操未顺利打印全部调用」，不要指望开箱即用（Frida 书 2.3）。

### 作者与时代的局限
- `dvmDexFileOpenPartial` 是 Dalvik（Android 4.4 及以前）的收口函数；ART 时代该函数不存在，定式失效，需换 OAT 脱壳工具，本书未给流程。
- IDA + android_server、Cydia Substrate、jdb 等是写作时工具生态；现代常用 Frida + frida-dexdump，但「在 Dalvik 加载收口处取内存快照」的思想一致。
- 加固厂商的具体藏身手法（assets/ijm_lib、libmobisec.so 等）是历史样本，当前加固方案已演进；判定结构（Manifest 与 dex 矛盾）仍成立。

### 容易混淆的方法
- 「混淆」与「加固」：混淆后类仍在、只是名字乱；加固后类不在 dex 里。前者转静态分析，后者才需脱壳。
- 「dump 内存」与「逆向解密算法」：本能力跳过算法，在收口处取明文快照；不要陷入对某家 so 算法的分析。
- 「反调试 nop 指令」与「改 TracerPid 内存值」：前者是 so 可读时的静态做法，后者是 so 加密时的动态替代，属 `<static-reverse-and-tampering>` 与本能力的分工。
- 「hook 改方法」与「下断点改内存数据」：pinning 绕过 hook 改 Java 方法实现，本能力反调试改的是 status 文件在内存里的数值；两者平台层不同。

### 授权与合规边界
> 待补充（用户自行填写）
