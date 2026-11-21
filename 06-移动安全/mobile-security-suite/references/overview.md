# 移动安全域 · 总览

## 这个域在真实工作中解决什么问题

移动安全评估的核心不是"会不会用某个工具"，而是"面对一个 App，测什么、按什么顺序测、哪些问题算数、该定什么级"。本域把 49 个候选单元合成 10 个能力，覆盖从项目规划到报告收口的完整链条：先用信任边界切分攻击面并锁定范围/构建变体/测试环境/敏感数据清单，再逐层做组件导出判定、provider 取数、WebView 注入、传输校验、沙盒取数、脱壳逆向、iOS 平台入口测试，最后用量化线与五轴闸门把工具输出转成可复算的发现。域里反复强调一条纪律：**移动端的假阳性主要来自"把桌面/Web 模型套到移动端"和"把平台性质当成应用缺陷"**——所以每个能力都带"可达性/权限成本/上下文等级"的收敛动作。

## 能力地图

| 二级分类 | 能力（slug） | 中文标题 | promoted | 一句话决策规则 |
|---|---|---|---|---|
| 工程化 | `attack-surface-scoping` | 攻击面切分与测试面规划 | 是 | 先按信任边界分层列全、锁范围/变体/环境/敏感数据、再用可达性与五阶段收敛 |
| 工程化 | `auth-and-findings-triage` | 认证量化与发现定级闸门 | 否 | 认证套四条量化线与口令分档，扫描告警先核攻击链可达性，保留项五轴取最弱轴 |
| 客户端 | `component-exposure-and-exploitation` | 组件导出判定与利用 | 是 | 三条路径取并集判导出，再用最小权限载体与上下文等级双闸门定级 |
| 客户端 | `sandbox-data-acquisition` | 沙盒数据获取 | 否 | 沿路径逐级看 x 位并在普通上下文实测，allowBackup 三步导出解包再写回验证 |
| 客户端 | `webview-client-injection` | WebView 与客户端注入链 | 否 | 先定加载源再查 WebSettings 默认值，Bridge 按 targetSdk 17 分界，ZipSlip 须有替换 zip 前提 |
| 客户端 | `ios-platform-security-testing` | iOS 平台入口与本地认证测试 | 否 | scheme 五步测、存储看属性匹配敏感度、生物识别须解锁密钥、越狱检测先排除崩溃 |
| 漏洞定位 | `provider-data-extraction` | Content Provider 数据抽取 | 否 | 先证原路径被拒再变形绕权限，projection 单引号经 sqlite_master 拖表，hosts 探针加 ../ |
| 漏洞定位 | `transport-security-testing` | 传输校验与 pinning 对抗 | 否 | 先不装 CA 抓一次定档，装 CA 再抓分中档，仍失败先排双向认证再判 pinning |
| 逆向分析 | `unpacking-and-hook` | 脱壳与动态 Hook | 是 | dex 与 Manifest 交叉识别加固，dvmDexFileOpenPartial 断点 dump，反调试改 TracerPid |
| 工具链 | `static-reverse-and-tampering` | 静态逆向与重打包插桩 | 否 | dex 按执行时机定位校验点，iOS 非越狱需未加密二进制插 Gadget，fuzz 按四环最弱项定产出 |

对外暴露 3 个 promoted 入口（攻击面切分、组件导出与利用、脱壳与 Hook），其余 7 个作为路由内的能力卡，由入口能力按场景调度。

## 域的共性失败模式

1. **把扫描器告警直接当发现**：扫描器按浏览器/Web 模型报 CSRF/XSS，但移动端 Cookie 仓独立、恶意链接跳出系统浏览器，攻击链断在第一步；照抄 DAST 报告会塞满假阳性。
2. **把平台性质当应用缺陷**：root/system 能给任何组件发 intent、查任何 provider，`exported=false` 对它们无效；"root 下能打开未导出页"证明的是平台性质，不是应用问题，必须换普通上下文对照。
3. **只看单个开关/单个字符串下结论**：见 `setJavaScriptEnabled(true)` 就报 WebView 漏洞、见 `exported="true"` 才认导出、见 `../` 就报 ZipSlip、只测 selection 就断言无注入——正确判据都要求"输入可控 + 权限/能力暴露 + 防护缺失"同时成立。
4. **把"已加固/有混淆"当成"风险已消除"或"无法评估"**：混淆、签名校验、反调试只增加读的成本，不改变可达性；"我没绕过"属于未评估而非通过（逆向必然成功）。
5. **忽略版本前提**：Content provider 默认导出随 API/targetSdk 变化、umask 随 Android 版本变化、JS Bridge 由 targetSdk 而非设备版本决定、ART 下 dvmDexFileOpenPartial 定式失效——同一份 APK 在不同版本上结论不同。
6. **混淆"能拿到"与"能用/能篡改"**：导出成功不等于普通上下文可达、备份能导出不等于能写回、取到 provider 数据可能是密文、能装 CA 不等于区分了 pinning 与双向认证。
7. **过度逆向/过度依赖单一环境**：为了逆向而逆向、无源码时试图完整还原业务逻辑；用 iOS 模拟器做黑盒逆向（x86 架构不符）、只拿生产包硬刚防护耗光时间、只拿 debug 包得出"无防护问题"的错误结论。
8. **只算单一危害维度定级**：只算 Damage potential 把所有"能读本地文件"报成高危；忽略 Discoverability 把需逆向才能发现的缺陷当成随时可利用；忘记锁号测试时序把账号第一天锁死。
9. **"抓不到包"不分成因就上绕过**：跳过"其他 App 能抓"的排除就把 Wi-Fi 代理未生效/CA 用途选错/iOS 13 的 TLSv1.3 不兼容误判为 pinning；对不走系统代理的富客户端仍死磕系统代理配置而非改隐形代理；把 SSL 直连/加白名单当作解决固定（实则放弃该主机可见性）。
10. **Hook/detection 对抗中的时机与版本错配**：对极早调用用 Attach、对稳定逻辑用 Spawn；只 hook ptrace 不 hook dlsym 被绕过；hook 未生效时反复改同一非判定函数而不从 UI 副作用反推；把 iOS10 的 `__RESTRICT` 招式套到 iOS13 的环境变量检测；只测单端认证就下"权限没问题"结论，漏掉 API/旧客户端缺失的 2FA。
11. **迷信自动化工具**：在不懂解包/代理/pinning 判定的前提下把 MobSF 当"一键出洞"；只会点按钮遇自定义固定/校验就卡住，既无法验证结果也无法应对自动化之外的实现。

## 覆盖说明：哪些书贡献了哪些能力

| 来源书 | 侧重 | 贡献的能力 |
|---|---|---|
| Mobile App Hackers Handbook（MAHH） | Android 组件/provider/WebView/传输/沙盒取证，Sieve 贯穿案例 | `attack-surface-scoping`、`component-exposure-and-exploitation`、`provider-data-extraction`、`sandbox-data-acquisition`、`webview-client-injection`、`transport-security-testing` |
| mobile-security-testing-guide（MSTG） | 项目级五阶段流程、假阳性、认证量化、iOS 平台与反逆向 | `attack-surface-scoping`、`auth-and-findings-triage`、`transport-security-testing`、`unpacking-and-hook`、`static-reverse-and-tampering`、`ios-platform-security-testing` |
| Android应用安全防护和逆向分析（逆向书） | 加固识别、脱壳 dump、反调试、smali 打点、ZipSlip | `unpacking-and-hook`、`static-reverse-and-tampering`、`webview-client-injection`、`sandbox-data-acquisition` |
| iOS Hacker's Handbook（iOSHH） | 攻击面可达性、纵深防御、设备口令、模糊测试、越狱分层 | `attack-surface-scoping`、`static-reverse-and-tampering`、`auth-and-findings-triage`、`ios-platform-security-testing` |
| 163 酒仙桥六号部队实战三篇 | Frida 注入时机/JNI Hook/RegisterNatives/地址换算、iOS 插件逆向五步、反注入/越狱/反调试/代理检测、加解密定位与篡改 | `unpacking-and-hook`、`ios-platform-security-testing` |
| Bug Bounty Bootcamp | 先 Web 后 App 的差分策略、端点发现、pinning 判定与绕过、Auth 差分、会话+XSS 组合、设备实验室 | `attack-surface-scoping`、`transport-security-testing`、`auth-and-findings-triage`、`sandbox-data-acquisition` |
| 泰阿手册 / burpsuite 手册 / Android 渗透手册 / Mac 手册 / 黑客秘笈与 playbook | grep 锁定关键字、隐形代理与自定义证书、TLSv1.3 排障、BROWSABLE 任意 URL、dex2jar/Apktool 选型、mach_override/OC IMP 反查、2FA 多端覆盖与 mfa 翻转 | `transport-security-testing`、`component-exposure-and-exploitation`、`static-reverse-and-tampering`、`unpacking-and-hook`、`auth-and-findings-triage` |

**无产出登记**：`iOS_Application_Security_index.txt` 为纯索引/目录文件，无可引用正文与判定标准，未产出单元；iOS 越狱内核/沙箱实现/堆利用/ROP/基带攻击等章节属二进制利用而非 App 测试方法论，未产出单元；burpsuite 手册第二十章为「暂时没有写的计划」空章，the-hacker-playbook-3 与黑客秘笈除 2FA 一致性条目外全文为内网横向移动，均无移动 App 方法。共 94 个候选单元（batch-1~4），全部通过三重验证并并入上述 10 个能力。
