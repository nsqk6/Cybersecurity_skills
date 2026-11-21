# 移动安全 · OCR 增补：方法论框架与判据

> 本卡由扫描件 OCR 后提取的 **3 个候选单元**按类型聚合而成，逐字引用、执行步骤、失败模式、书内案例均原样保留自 `candidates/ocr-batch-*.md`。这一批是「已提取、按类型归集」的增补材料，与同目录其他能力卡的三重验证 + 人工聚类流程不同，故单独标注，不冒充正式聚类卡。

## R — 原文 (Reading)

> android:protectionLevel: 这个属性的值用来表示该权限所对应的风险等级 … "signature"和"signatureOrSystem"保护等级在 app 安装之前是不会被提示给用户的。这就是说，即便 app 将会使用一个安全风险很大的权限，但只要声明的是"signature"或"signatureOrSystem"的保护等级，用户就不会收到相应的警告。 … 如果 app 中的"android:minSdkVersion"或"android:targetSdkVersion"的值小于或等于 16,"android:exported"的默认值就是 true。如果 app 中把"android:minSdkVersion"或"android:targetSdkVersion"设为大于或等于 17的值，它默认值就是 false。
>
> — 《Android安全攻防实战》· 第 2 章「2.5 探索 AndroidManifest.xml 文件」

> Drozer 可以分成两个部分: 其一是"console"一一它运行在你的本地计算机上，其二是"server"一一它基本上就是一个安装在目标 Android 设备上的 app。当你使用 console 与 Android 设备交互时，基本上就是把 Java 代码输入到运行在实际设备上的 drozer 代理 (agent) 中 … 它本质上是一个不需要任何权限的 Android app一一这实际上是它的一个组件。这也就是说: 你管理的任何 exploit，装入 Android 设备之后，能够相当好地自动适应当前设备，只需要很低的权限就能成功运行。
>
> — 《Android安全攻防实战》· 第 3 章「3.1 简介」

> [SDK path] /sdk/platform-tools/dx --dex --output=Example.dex Example.class … struct DexHeader { ul magic[8]; u4 checksum; ul signature[kSHA1DigestLen]; u4 fileSize; u4 headerSize; u4 endianTag; ... u4 stringIdsSize; u4 stringIdsOff; u4 typelIdsSize; u4 typelIdsOff; ... } … DEX 文件的约数是 dex\n035, 或者用十六进制表示: 64 65 78 0a 30 33 35 00。 … endianTag 字段中存放的是个固定值 ... 12345678。 … [SDK-path] /build-tools/android-[version]/dexdump classes.dex … dx -dex -verbose-dump -dump-to=[output-file].txt [input-file] .class
>
> — 《Android安全攻防实战》· 第 6 章「6.2 把 Java 源码编译成 DEX 文件」+「6.3 解析 DEX 文件的格式」

## I — 方法论骨架 (Interpretation)

**评估 AndroidManifest 权限保护等级与组件 exported 默认值** — protectionLevel 决定权限在安装前是否向用户展示——`dangerous` 必展示，`normal` 仅主动查看时展示，`signature`/`signatureOrSystem` 完全不展示。开发者把高风险权限标成 `signature` 就能绕过用户感知。`exported` 决定组件能否被其他 app 调起——SDK ≤16 默认 true，≥17 默认 false，但有 intent-filter 且未显式设 exported 时系统推断为 true。审计时同时核对 `minSdkVersion`/`targetSdkVersion`、intent-filter 是否存在、`exported` 是否显式声明三个变量。另：组件级 `android:permission` 会覆盖 `<application>` 级权限——「如果一个正常的 app 中的某个组件重载了一个危险的权限，那就将会引入可观的安全风险」。

**drozer agent/console 双端架构与部署** — drozer 把漏洞利用代码的执行点从"重新编译一个攻击 app"转移到"console 下发字节码给 agent 代执行"。agent 是个无权限 app——证明导出组件的风险不需要危险权限即可触发，一个什么都不申请的 app 就能黑掉有漏洞的 app。这与传统 PC 端 Metasploit 思路一致，作者直接类比"专用移动安全评估的 Metasploit"。理解这一架构是写自定义 drozer 模块（CU-05）的前提。

**解析 DEX 文件格式与用 dexdump/dx 提取元数据** — DEX 文件由 9 个区段组成——`DexHeader`（magic + checksum + SHA1 + 各区段偏移）、`StringIds`（指向 data 区字符串的偏移数组）、`TypeIds`（指向 StringIds 的索引）、`ProtoIds`（方法原型）、`FieldIds`、`MethodIds`、`ClassDefs`（类定义含 accessFlags + codeOff 指向字节码）、`Data`、`LinkData`。所有 size/off 字段都是 4 字节小端无符号整型。`magic` = `dex\n035\0`，`endianTag` = `0x12345678` 用来校验字节序。`dx --dex` 编译 .class → .dex；`dexdump` 解析 DEX 输出人类可读结构；`dx -dex -verbose-dump -dump-to=` 输出逐字节语义。掌握格式是写 DEX fuzzer、找隐藏字符串、分析恶意软件混淆的前提。

## A1 — 应用示例 (Application Example)

### 示例 1: 评估 AndroidManifest 权限保护等级与组件 exported 默认值
- **类型与来源**: 【principle】《Android安全攻防实战_ocr.txt》· 第 2 章「2.5 探索 AndroidManifest.xml 文件」（Page 60–64）
- **问题/输入**: apktool；待审计 APK；理解 Android 权限风险分级
- **方法论的使用**: protectionLevel 决定权限在安装前是否向用户展示——`dangerous` 必展示，`normal` 仅主动查看时展示，`signature`/`signatureOrSystem` 完全不展示。开发者把高风险权限标成 `signature` 就能绕过用户感知。`exported` 决定组件能否被其他 app 调起——SDK ≤16 默认 true，≥17 默认 false，但有 intent-filter 且未显式设 exported 时系统推断为 true。审计时同时核对 `minSdkVersion`/`targetSdkVersion`、intent-filter 是否存在、`exported` 是否显式声明三个变量。另：组件级 `android:permission` 会覆盖 `<application>` 级权限——「如果一个正常的 app 中的某个组件重载了一个危险的权限，那就将会引入可观的安全风险」。
- **结果**: 未提供具体 case，作者将其定位为"评判安全评估人员是否优秀的准绳"

### 示例 2: drozer agent/console 双端架构与部署
- **类型与来源**: 【principle】《Android安全攻防实战_ocr.txt》· 第 3 章「3.1 简介」（Page 75–76）
- **问题/输入**: PC 装 Java / Python 2.7；设备开启调试；agent 已部署
- **方法论的使用**: drozer 把漏洞利用代码的执行点从"重新编译一个攻击 app"转移到"console 下发字节码给 agent 代执行"。agent 是个无权限 app——证明导出组件的风险不需要危险权限即可触发，一个什么都不申请的 app 就能黑掉有漏洞的 app。这与传统 PC 端 Metasploit 思路一致，作者直接类比"专用移动安全评估的 Metasploit"。理解这一架构是写自定义 drozer 模块（CU-05）的前提。
- **结果**: 【亲历】作者完整演示 Windows / Linux 两条路径的安装与排错

### 示例 3: 解析 DEX 文件格式与用 dexdump/dx 提取元数据
- **类型与来源**: 【framework】《Android安全攻防实战_ocr.txt》· 第 6 章「6.2 把 Java 源码编译成 DEX 文件」+「6.3 解析 DEX 文件的格式」（Page 175–193）
- **问题/输入**: Android SDK（含 dx 与 dexdump）；Java JDK；理解 ELF/DEX 等二进制格式基础
- **方法论的使用**: DEX 文件由 9 个区段组成——`DexHeader`（magic + checksum + SHA1 + 各区段偏移）、`StringIds`（指向 data 区字符串的偏移数组）、`TypeIds`（指向 StringIds 的索引）、`ProtoIds`（方法原型）、`FieldIds`、`MethodIds`、`ClassDefs`（类定义含 accessFlags + codeOff 指向字节码）、`Data`、`LinkData`。所有 size/off 字段都是 4 字节小端无符号整型。`magic` = `dex\n035\0`，`endianTag` = `0x12345678` 用来校验字节序。`dx --dex` 编译 .class → .dex；`dexdump` 解析 DEX 输出人类可读结构；`dx -dex -verbose-dump -dump-to=` 输出逐字节语义。掌握格式是写 DEX fuzzer、找隐藏字符串、分析恶意软件混淆的前提。
- **结果**: 【亲历】作者完整解析 Example.dex 头部字段：magic `dex\n035\0`、checksum `3567e33f`、fileSize `0x310`、endianTag `12345678`、stringIdsSize `0x10`（16 个字符串）（Page 182–183）

## A2 — 相邻能力 (Adjacency)

1. 出现「protectionLevel signature」这类信号时，回到本卡查对应单元的方法与判据。
2. 出现「权限风险等级」这类信号时，回到本卡查对应单元的方法与判据。
3. 出现「exported 默认值」这类信号时，回到本卡查对应单元的方法与判据。
4. 出现「targetSdkVersion 16 17」这类信号时，回到本卡查对应单元的方法与判据。
5. 出现「组件攻击面 评估」这类信号时，回到本卡查对应单元的方法与判据。
6. 出现「drozer 架构」这类信号时，回到本卡查对应单元的方法与判据。

语言信号：「protectionLevel signature」、「权限风险等级」、「exported 默认值」、「targetSdkVersion 16 17」、「组件攻击面 评估」、「drozer 架构」

本卡为增补材料，正式能力卡请优先读：`attack-surface-scoping`、`component-exposure-and-exploitation`。

**相邻区分（原文）**：

- 与 CU-12「保护组件」区分——本单元是审计判据，CU-12 是加固配方
- 与 CU-05 区分——本单元讲架构与部署，CU-05 讲具体枚举模块使用
- 与 CU-17 区分——本单元讲文件结构，CU-17 讲字节码语义

## E — 执行步骤 (Execution)

### 评估 AndroidManifest 权限保护等级与组件 exported 默认值

1. `apktool d -f -s Contacts.apk decoded/` 解出 `AndroidManifest.xml`
  2. 提取所有 `<permission>` 元素的 `android:name` 与 `android:protectionLevel`，逐条核对保护等级与权限实际行为是否匹配
  3. 提取 `<uses-sdk>` 的 `minSdkVersion` / `targetSdkVersion`，对每个 `<activity>`/`<service>`/`<receiver>`/`<provider>` 检查 `android:exported` 是否显式声明
  4. 比对 `<application android:permission="X">` 与子组件 `android:permission="Y"`，标记组件权限弱于基线的降级情况

### drozer agent/console 双端架构与部署

1. PC 装 drozer console（Windows 走 installer，Linux 走 deb / 源码 `easy_install drozer-[version]-py2.7.egg`）
  2. 设备装 `drozer.apk`：`adb install drozer.apk`（需开启"未知来源"和"USB 调试"）
  3. 设备 drozer agent 界面拖亮"Embedded Server → Enabled"
  4. PC 端 `adb forward tcp:31415 tcp:31415` 后 `drozer console connect`

### 解析 DEX 文件格式与用 dexdump/dx 提取元数据

1. `javac -source 1.6 -target 1.6 Example.java` 编译 Java
  2. `[SDK]/sdk/platform-tools/dx --dex --output=Example.dex Example.class` 转 DEX
  3. `hexdump -C Example.dex` 查 magic / checksum / SHA1 / endianTag
  4. `[SDK]/build-tools/android-[version]/dexdump Example.dex` 拿类列表与方法签名
  5. `dx -dex -verbose-dump -dump-to=dump.txt Example.class` 拿逐字段语义
  6. 解析 `StringIds` 区段：每个 `DexStringId` 是 4 字节偏移，指向 data 区 `uleb128 length + UTF-8 字符串`

### 统一判停条件

- 单元「失败模式」里列出的任一条件成立时停止该路径，换维度重查；
- OCR 文本不可读、引用无法核对时，只作线索，不写入结论；
- 连续三次同类验证无结果时回到攻击面/问题定义重排优先级。

## B — 失效与边界 (Boundary)

- **评估 AndroidManifest 权限保护等级与组件 exported 默认值**：OCR 文本指出 `signatureOrSystem` 的官方定义作者表述不完整（译者注补充了"系统镜像内的 app"这一条件）；仅看 `exported="false"` 字面值不够——若组件有 intent-filter 且未显式设 exported，运行时仍可能被调起
- **drozer agent/console 双端架构与部署**：drozer console 启动报错"找不到 Java"——需将 `C:\Program Files\Java\jre7` 加到 PATH；deb 安装失败时备用方案需 `apt-get install python-dev python-setuptools ia32-libs-i386` + `easy_install protobuf==2.4.1 twisted==10.2.0`
- **解析 DEX 文件格式与用 dexdump/dx 提取元数据**：OCR 文本指出原文「21 个字节」SHA 签名实为 20 字节（译者注已纠正）；不同 Android 版本 DEX magic 版本号会变（035/036/037/038/039）；Android 8+ 引入 DEX v2/v3 增加了快速解析区段

### 授权与合规边界

> 待补充（用户自行填写）
