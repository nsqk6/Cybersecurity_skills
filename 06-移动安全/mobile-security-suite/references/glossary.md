# 移动安全域 · 术语表

只收"读能力卡时会卡住"的术语，不收通用词。按主题分组，共 35 条。

## 攻击面与定级

| 术语 | 英文 | 在本域语境下的含义 |
|---|---|---|
| 攻击面 | attack surface | 处理攻击者提供输入的代码；移动端大量代码路径外部不可达，"漏洞 = 缺陷 × 输入可达"，先证可达再谈危害。端点发现可用运行时 Burp 流量差分 + 静态 `apkurlgrep` 取差集找 App 独有接口。 |
| 可达性 | reachability | 输入能否从外部经过各组件到达缺陷代码；任一跳不成立即降级为不可利用。 |
| 权限成本 / 上下文等级 | privilege cost / context level | 危害由"做成所需权限"与"所需身份"决定：最小权限载体（如 drozer 仅 INTERNET）即可做成则危害高；root/system 可绕过 exported，其下成立的问题不算应用缺陷。 |
| 五轴模型 | five axes / DREAD | Damage/Reproducibility/Exploitability/Affected users/Discoverability，给扫描器告警加的人工闸门；取最弱轴而非打总分，也是剔除假阳性（按浏览器模型误报的 CSRF/XSS）后的定级工具。 |
| 多端认证差分 | cross-endpoint auth diff | 同一功能多端实现不一致：App vs Web 的令牌/IDOR 对比、2FA 常缺于 API/旧客户端、翻转客户端 `mfa` 标志绕过、会话缺陷 + XSS 组合接管。 |

## Android 组件与 IPC

| 术语 | 英文 | 在本域语境下的含义 |
|---|---|---|
| 导出 / 隐式导出 | exported / implicit export | 组件可被同设备其他应用调用。三种来源：默认行为（仅 provider API<17 默认 true）、显式 `exported="true"`、带 `<intent-filter>` 隐式导出；只 grep 显式属性会整片漏判。 |
| targetSdkVersion | targetSdkVersion | 决定兼容性行为而非设备版本；老 APK 装新机仍按老行为运行，是 provider 默认导出与 JS Bridge 判据的关键变量。 |
| content provider | content provider | Android IPC 数据共享组件；query 把 projection/sortOrder 拼进 SQL（可注入），实现 `openFile()` 的 file-backed provider 以应用 uid 打开文件（可用 `/system/etc/hosts` 探针测任意文件读）。 |
| path-permission | path-permission | provider 按 URI 文本字面匹配的权限；只保护 `/Keys` 不保护 `/Keys/`，是"保护字符串而非数据"的典型。 |
| projection | projection | query 的字段参数，被拼进 SQL 且未参数化，是 provider SQLi 最稳的注入点（selection 走 selectionArgs 时不可注）。 |
| Messenger / handleMessage | Messenger / handleMessage | bound service 的消息分发开关表；`switch(msg.what)` + `arg1` 常量是协议文档，可据以构造消息、找 PIN 爆破 oracle。 |
| 广播嗅探 / 伪造 | intent sniffing / broadcast spoofing | 广播一对多：泄露向是第三方注册同名 action 收凭证，伪造向是发"登录成功"广播让接收器执行敏感动作；动态注册的 receiver drozer 列不出，只能读代码。 |
| BROWSABLE Activity | BROWSABLE activity | 声明 `android.intent.category.BROWSABLE` 的 Activity，可被外部以 VIEW intent 调起打开任意 URL；关键升级点是检查打开请求是否带 auth 令牌（带则账户接管）。 |

## 客户端与 WebView

| 术语 | 英文 | 在本域语境下的含义 |
|---|---|---|
| WebSettings | WebSettings | WebView 的配置集合；多个危险项默认开（file/content 访问、savePassword），判危害先定加载源再查开关。 |
| JS Bridge / addJavascriptInterface | JavaScript bridge | 把 Java 对象挂到 JS 全局变量；API <17 可反射调任意 public 方法即 RCE，≥17 只有 @JavascriptInterface 方法可见；`allowUniversalAccessFromFileURLs`（file:// 跨源读）API ≤15 默认开，配合 JS 与外部可控 URL 可成任意代码执行。 |
| ZipSlip | ZipSlip | 解压时 ZipEntry 名未校验含 `../`，以应用自身权限覆盖自身沙盒文件；危害是篡改而非"远程任意文件写"。 |
| allowBackup | allowBackup | manifest 属性，默认 true（缺失即 true）；允许 adb backup 导出沙盒为 .ab（24 字节头 + zlib tar），价值在能写回篡改。 |
| debuggable / run-as | debuggable / run-as | debuggable=true 允许 run-as 切 uid 并以应用身份执行命令，等于把私有目录权限交给 shell 用户。 |
| 目录 x 位 / umask | directory execute bit / umask | 访问文件要求路径每级目录都有 x，文件 777 可能被目录 770 挡住，须沿路径逐级看；umask 决定新文件默认权限（4.0+ 为 0077、2.3 为 666），同一代码在不同版本暴露面不同。 |

## 传输、证书与抓包工程

| 术语 | 英文 | 在本域语境下的含义 |
|---|---|---|
| 校验缺陷 | broken certificate validation | 未装代理 CA 就能看到 HTTPS 明文，说明 TrustManager 空实现或 HostnameVerifier 恒真；直接读代码定位，无需 hook。 |
| pinning / 双向认证 | certificate pinning / mutual TLS | 装了 CA 仍握手失败才可能是 pinning，须先排除双向认证（Burp Alerts "client failed to negotiate"）与 iOS 13 的 TLSv1.3 不兼容；代理侧可用自定义证书（PKCS#12）应对要求特定序列号的 App。 |
| patch / hook | static patch / runtime hook | patch 改 smali 并重签（一次性、改签名），hook 改运行时内存（不动 APK、适合混淆）；标准 pinning 用 Frida/Objection 自动化，自定义实现才手工改校验代码。 |
| 隐形代理 | invisible proxy | App 不读系统代理时，用 hosts 把域名指向 127.0.0.1 + Burp 80/443 监听 + Hostname Resolution 指回真实服务器，让客户端无代理感知地进入 Burp；只做劫持不配回环会形成回环。 |

## 逆向、脱壳与 Hook

| 术语 | 英文 | 在本域语境下的含义 |
|---|---|---|
| 加固 / 壳 | packing / packer | 真实 dex 被加密/隐藏，dex 里只剩壳 Application；判据是 dex 类列表与 Manifest 组件声明的矛盾。 |
| dvmDexFileOpenPartial | dvmDexFileOpenPartial | Dalvik 加载 dex 的收口函数，R0=dex 起始地址、R1=size；在此下断点即可 dump 明文 dex，跳过各家解密算法（ART/OAT 不适用）。 |
| TracerPid | TracerPid | /proc/<pid>/status 中表示被调试的字段；加固轮询它 >0 即自杀，可在 libc 的 fopen/fgets 断点改内存值为 0 绕过。 |
| Attach / Spawn | attach / spawn | Frida 的两种注入时机窗口：越早发生的逻辑（RegisterNatives、init 解密）越必须 Spawn（挂起→注入→resume），稳定界面逻辑用 Attach；CLI 模式保存脚本即生效，迭代快于 Python+JS 混合脚本。 |
| RegisterNatives / JNIEnv | RegisterNatives / JNIEnv | JNIEnv 指向函数指针数组，按"JNI.h 序号 × 指针大小"算偏移可 Hook 任意 JNI 函数；Hook RegisterNatives 遍历 JNINativeMethod 三元组可在运行时定位动态注册的 native 函数地址，再减 so 基址换算成 IDA 虚拟地址。 |
| 重打包插桩 / mach_override | repackaging / mach_override | 向 IPA 插 load command 指向 FridaGadget.dylib 并重签（前提未 FairPlay 加密）；mach_override 的 hook/island 保留 real 指针在前/后加逻辑、不可卸载（单向）；OC 方法须 swizzling 而非函数 hook，符号 stripped 时从运行时反查 IMP。 |

## iOS 平台

| 术语 | 英文 | 在本域语境下的含义 |
|---|---|---|
| URL Scheme | custom URL scheme | 全系统可调用的跨 App 入口，iOS 对同名 scheme 无归属仲裁；测参数校验、来源校验、敏感动作是否需用户确认（universal links 有 AASA 校验，遗留 scheme 无）。 |
| kSecAttrAccessible | kSecAttrAccessible* | Keychain 保护属性；`Always`/`AfterFirstUnlock` 非 ThisDeviceOnly 会随备份离开设备，`WhenPasscodeSetThisDeviceOnly` 才绑定硬件与口令。 |
| evaluatePolicy | evaluatePolicy | LocalAuthentication 只返回布尔给 UI，hook 即恒 true；真门禁须让认证成为从 Keychain 取密钥的必要条件。 |
| tethered / untethered | tethered / untethered jailbreak | 重启后是否仍有效；能力由漏洞层级决定（bootrom 最强且无法软件修复、iBoot 次之、userland 至少需两漏洞且能力有限）。 |
| __RESTRICT / 反注入 | __RESTRICT / anti-injection | iOS10 以下 Mach-O 的 `__RESTRICT` 段让 dyld 拒绝第三方 dylib（改段名字母绕过）；iOS13+ 改用 `DYLD_INSERT_LIBRARIES` 等环境变量判加载状态。反调试另用 sysctl/ptrace/syscall，绕过须同时 hook ptrace 与 dlsym。 |
| iOS 插件逆向五步 | iOS tweak workflow | 脱壳（frida-dump/Clutch）→ cycript 定目标类 → class-dump 出 .h → Hopper 反汇编 → Theos 注入；顺序不可颠倒。加解密定位先查 CCCrypt 系统库再看自定义 *Encryptor，RSA 请求无私钥则在 RSAEncrypt 前改明文 arg。 |
