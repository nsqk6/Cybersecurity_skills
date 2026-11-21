# 反序列化利用：先证明「字节流会被 readObject」，再决定用哪条链

## R — 原文 (Reading)

> "整个解密过程，可以看到在进行反序列化之前没有任何过滤，导致外界传什么值，就反序列化什么。"
>
> — 《163酒仙桥六号部队__061-Apache_Shiro_反序列化之殇》

> "URLDNS 通过 URL 构造函数传递 SilentURLStreamHandler 类对象，该类重写了 getHostAddress 方法，将方法体置为空实现，旨在执行 HashMap.put 时，不会触发 DNSLOG 请求，降低对目标漏洞的误判率。"
>
> — 《163酒仙桥六号部队__109-Java反序列化之ysoserial_URLDNS模块分析》

> "这里我们分两种情况，漏洞机器能出网的检测，以及漏洞机器不能出网的检测。"
>
> — 《163酒仙桥六号部队__061-Apache_Shiro_反序列化之殇》

## I — 方法论骨架 (Interpretation)

反序列化利用有一条严格的推进顺序，跳步会导致两类误判：把「入口不通」当「没有漏洞」，或把「探测成功」当「能执行命令」。

**第一步：找入口（sink）**。能触发 `readObject` 的位置有四类：应用自己反序列化的参数/Cookie（Shiro `rememberMe`、PHP `unserialize($_COOKIE)`）、协议层（RMI Registry 的 bind/lookup、JNDI 的 `lookup`）、解析库的隐式反序列化（Fastjson 的 `@type` → setter、XMLDecoder）、以及「加密的序列化 Cookie」这类凭据载体。每一类的入口条件不同，工具也不同。

**第二步：证明入口可达（探测）**。不要直接把命令执行 payload 打上去。`URLDNS` 是最低风险的存在性证明：它只用 JDK 自带类（`HashMap.readObject` → `hash` → `URL.hashCode` → `InetAddress.getByName`），不含任何命令执行，只发一次 DNS 查询。收到解析 = 这个入口确实把字节流反序列化了；收不到 = 入口根本没走到 `readObject`。两个构造细节决定成败：必须用 `SilentURLStreamHandler` 把 `getHostAddress` 置空（否则生成 payload 时就先发一次 DNS，自己污染自己），必须把 `hashCode` 反射重置回 -1（否则序列化时把改写后的值写进去，反序列化时不再走 handler）。

**第三步：按「能否出网」分叉**。这是第一个真正的决策点，也决定整条利用链的形状：

- 能出网 → 远程类加载（RMI `codebase`/JNDI `javaCodeBase`/Fastjson `lookup`）或 JRMP 回连，不需要本地 gadget。
- 不能出网 → 只能用本地 gadget 链（CommonsCollections 等），或改用「回显」（把命令结果写回当前 HTTP 响应），或盲写文件后读取。

**第四步：选链并验证前置条件**。gadget 链依赖目标 classpath 有对应库；远程加载依赖版本窗口（RMI 的 `useCodebaseOnly` 在 6u45/7u21 后默认 true；JNDI 的 `trustURLCodebase` 在 6u141/7u131/8u121 后默认 false）。版本对了但配置手工放开的也存在，所以「版本 + 配置」两查。

**第五步：取结果**。出网则反弹/下载；不出网则回显（需要拿到当前线程的 request/response，见 A1 示例 4），或盲写文件。

**第六步：受限环境绕过**。拿到 PHP 执行但命令跑不了时，转 `disable_functions` 的替代通道（本域放在 `waf-bypass-encoding` 卡）。

## A1 — 应用示例 (Application Example)

### 示例 1: 逆推 rememberMe 三段结构
- **类型与来源**: 【亲历】《163酒仙桥六号部队__061-Apache_Shiro_反序列化之殇》
- **问题/输入**: 登录后下发 `rememberMe` Cookie，值为 Base64 串。
- **方法论的使用**: ① Base64 解码看长度是否为 16 的整数倍 + 16（16 字节 IV + 密文）；② 取前 16 字节当 IV、余下当密文，用候选密钥解，能解出 `aced0005` 开头的 Java 序列化头即密钥命中；③ 命中后不再研究加密，直接构造 `iv + AES(serialized_payload)` 再 Base64；④ 同时确认版本（1.2.4 及以前）与是否存在自定义 key。
- **结论**: 不要一上来打 payload，先把「服务端怎么造这个 Cookie」走一遍——IV 可自选、key 是常量、反序列化前无类型校验，三个事实合起来等于「能造就能执行」。
- **结果**: 作者在 `shiro-shiro-root-1.2.4` 上断点跟完 `convertPrincipalsToBytes → encrypt`，给出完整加解密链并成功利用。

### 示例 2: URLDNS 的两处构造坑
- **类型与来源**: 【亲历】《163酒仙桥六号部队__109-Java反序列化之ysoserial_URLDNS模块分析》
- **问题/输入**: 一个可疑的反序列化入口，先要确认它是否真的会 `readObject`。
- **方法论的使用**: ① 只发 URLDNS，观察 dnslog 是否有解析记录；② 记录响应码/耗时变化，排除「DNS 是别的组件发的」；③ 换真实 gadget 前先确认目标 classpath 是否有对应库，否则会出现「探测成功但利用打不动」；④ 目标不出网时此步必失败，直接转回显方案。
- **结论**: 探测与利用必须分开——URLDNS 证明的是「入口可达」，不是「能执行命令」。
- **结果**: 作者逐行跟 `GeneratePayload → getObject → serialize` 与 `HashMap.readObject`，并用该模块给 Shiro 做初判。

### 示例 3: Fastjson 从 `@type` 到 `lookup`
- **类型与来源**: 【亲历】《163酒仙桥六号部队__029-从Fastjson绕WAF到打穿网闸》
- **问题/输入**: 一个 JSON 参数，版本未知，页面报错被隐藏。
- **方法论的使用**: ① 抓包确认参数是 JSON 且能被 `@type` 解析（用无害类探是否有回显/报错差异）；② 版本未知时按「从新到旧」逐代试绕过：1.2.24 无校验 → 1.2.25 加 `checkAutoType` → 1.2.41/42/43 用 `L...;` 前缀后缀截断 → 1.2.45 用 ibatis 类 → 1.2.47–1.49 用双 JSON 嵌套；③ 命中后把 `dataSourceName` 指向自建 LDAP/RMI（marshalsec），VPS 收到回连即证明链路通；④ 收到回连后再编译落地类、反弹。
- **结论**: 「JSON 字段 → setter → lookup → 远程类」是一条不需要反序列化字节流的链，因此能穿过只查二进制特征的设备。
- **结果**: 作者完成「外网发现 JSON 参数 → 盲打 Fastjson → 绕 WAF → 反弹 → 内网横向 → 打穿网闸」的完整链。

### 示例 4: 不出网时的回显
- **类型与来源**: 【亲历】《163酒仙桥六号部队__067-JAVA反序列化基于常见框架_中间件回显方案》
- **问题/输入**: 反序列化触发点不在 Servlet 方法里，拿不到方法参数级的 req/res。
- **方法论的使用**: ① 判断容器/框架：Tomcat 走 `Registry → RequestInfo → req`，Spring MVC 走 `RequestContextHolder.getRequestAttributes()`；② Tomcat 路径：`Registry.getMBeanServer()` → `JmxMBeanServer.mbsInterceptor`（实现为 `DefaultMBeanServerInterceptor`）→ `Repository.query` 取所有 `Http11Processor`；③ 用自定义请求头（原文用 `admin`）在当前 Processor 的 `req` 里认出自己那条请求，避免把结果写到别人响应里；④ 执行命令 → `request.getResponse().doWrite(ByteBuffer)` 写回。
- **结论**: 回显的全部工作是「沿调用栈往上找到容器存 req 的存储点，反射取出，结果写回 response」；框架越上层越好找。
- **结果**: 作者分别在 Tomcat webapp 与 Spring MVC 上打断点跟栈，给出两段完整代码。

## A2 — 触发场景 (Future Trigger) ★

### 用户会在什么情境下需要它
1. 看到 Base64/hex 的 Cookie 或参数，长度像序列化数据，想知道能否打。
2. 目标是 Shiro/Fastjson/WebLogic/JBoss/RMI/JNDI 之一，需要判断走哪条链。
3. 已经确认有反序列化点，但目标不出网，需要选回显或盲写方案。
4. 有一个 URLDNS 探测成功但真实 gadget 打不动，需要判断是 classpath 缺库还是版本问题。
5. 需要给「为什么这个洞打不通」一个结论（补丁 / 拦截 / 环境差异）。
6. 拿到 PHP 代码执行但命令跑不了（转 `waf-bypass-encoding`）。

### 语言信号（出现这些就该激活）
- 中文：「rememberMe 这个 Cookie 能不能打」「Shiro 默认 key 是多少」「@type 被过滤了怎么办」「Fastjson 版本怎么绕」「怎么确认这个点能反序列化」「目标不出网怎么打」「反序列化怎么回显」「JNDI 注入怎么打」
- English: "shiro rememberMe deserialization", "fastjson autotype bypass", "JdbcRowSetImpl JNDI", "URLDNS detection", "is this deserialization sink reachable", "RMI registry exploit", "JRMP listener vs client", "deserialization echo Tomcat", "no outbound access deserialization"

### 与相邻能力的区分
- 与 `command-file-injection` 的区别：那张卡从「输入直接进解释器」进入，本卡从「字节流被 readObject」进入；两者常在同一个 getshell 目标上接力。
- 与 `server-request-injection` 的区别：JNDI/SSRF 都涉及「让服务器发请求」，但本卡的触发点是反序列化而非 URL 参数；Fastjson 的 `lookup` 是「解析库替我发请求」。
- 与 `waf-bypass-encoding` 的区别：本卡假设 payload 能到达 `readObject`；被设备拦住（如 `@type` 被拦）时转那张卡的 `\u` 转义与分层绕过。
- 与 `auth-session-bypass` 的区别：Shiro 的 `rememberMe` 在本卡是「攻击载体」，在那张卡只是「会话机制」。

## E — 可执行步骤 (Execution)

**必需输入**: 一个可疑入口（Cookie/参数/协议端口/JSON 字段）；目标的技术栈与版本线索；一个可控的出网观测点（dnslog + 自建 HTTP）；本地 gadget 环境（ysoserial/marshalsec 等）。缺「出网观测点」时只能走盲写/回显，结论强度下降。

**交付物与完成标准**: 一条「入口 → 探测证据 → 分叉（出网/不出网）→ 链 → 结果取回」的记录；完成标准是存在可重复的副作用（DNS 解析 / 回连 / 命令输出 / 文件落地）。

1. **判入口类型**
   - 做什么：按载体分类——加密 Cookie（Shiro 类）→ 逆推加密结构；业务参数/JSON → 看是否 `@type`/XMLDecoder；协议端口（1099/7001/8080 的 invoker）→ RMI/JNDI/中间件组件；PHP 的 `unserialize($_COOKIE)` → 看 `__wakeup`/`__destruct`。
   - 完成标准：能写出「入口 → 触发函数 → 需要的编码形式」。
   - 判停：入口是纯文本且无解析库参与时，本卡不适用，转 `injection-channel-selection` 或 `command-file-injection`。

2. **存在性探测（最低风险）**
   - 做什么：发 URLDNS（注意 SilentURLStreamHandler 与 hashCode 重置两个构造细节），观察 dnslog；记录响应码/耗时排除误判。
   - 完成标准：收到解析 = 入口可达；收不到 = 换入口或判「不出网」。
   - 判停：目标不出网时 URLDNS 必失败，直接进第 4 步的回显/盲写分支，不要反复重试。

3. **测出网能力**
   - 做什么：DNS 回连之外再试 HTTP 回连（访问自建 VPS 的 80/443）；排除「只是 DNS 被禁」。
   - 完成标准：能明确回答「目标能不能主动外联」。
   - 判停：完全不出网 → 第 4 步；能出网 → 第 5 步。

4. **不出网：回显或盲写**
   - 做什么：回显——判断容器（Tomcat/Spring），沿调用栈反射取 req/res，用自定义头认出自己的请求，把命令结果 `doWrite` 回去；盲写——把结果写到可被 HTTP 访问的路径，或写临时表再 union 读出。
   - 完成标准：拿到命令输出（回显）或文件内容（盲写）。
   - 判停：反序列化触发点在非 Web 线程（定时任务）时，回显必失败（拿不到当前 request），转盲写。

5. **出网：远程加载或 JRMP**
   - 做什么：RMI 先判「目标端口是 Registry 还是 JRMP 监听」——Registry 用 `RMIRegistryExploit`（bind）或 `JRMPClient`（DGC 注册），只有 JRMP 监听口时只能用 `JRMPClient` 且需要目标主动连回；JNDI 伪装成目录服务，按「能否出网 + 有无本地链」选 `javaCodeBase`（远程加载，最省事）、`javaSerializedData`（本地链）、`javaReferenceAddress`（前两条被过滤时的备选，注意互斥前提）。
   - 完成标准：VPS 收到回连或类加载请求。
   - 判停：先查版本窗口——RMI `useCodebaseOnly`（6u45/7u21 后默认 true）、JNDI `trustURLCodebase`（6u141/7u131/8u121 后默认 false）；命中旧版本再走远程加载，否则直接转本地 gadget。

6. **本地 gadget 与版本绕过**
   - 做什么：确认目标 classpath 有对应库（CommonsCollections 等）；Fastjson 按「从新到旧」逐代试绕过（`L...;` 只适用 1.2.41/42/43）；Shiro 确认版本与自定义 key。
   - 完成标准：链能执行到可见副作用（DNS/回连/命令）。
   - 判停：报错被隐藏（盲打）时不能靠报错判版本，改用「逐代试 + 看回连」；照抄别人 payload 会得到随机成功/失败。

7. **取结果并收敛**
   - 做什么：优先回显；其次反弹/下载；再次盲写；最后写文件后读取。`whoami`/`id` 确认权限再决定是否提权。
   - 完成标准：拿到一条可复现的命令输出或文件内容。
   - 判停：所有链都打不动时回到第 2 步确认「入口真的可达」——很多「打不通」其实是入口判断错误。

## B — 边界 (Boundary) ★

### 不要用的情况
- 目标 classpath 干净（无 CommonsCollections 等）、版本又在 `trustURLCodebase` 默认关闭之后、且不出网：本地与远程两条路同时封死，不要耗。
- 反序列化点做了类型白名单（`ObjectInputFilter`、`resolveClass` 校验）：非白名单类直接被拒，链基本不成立。
- Shiro 使用自定义随机 key 且登录入口不暴露版本：先要拿到 key，否则 AES 解不开，后续全部无效。

### 已知失败模式
- **不装 `SilentURLStreamHandler`**：生成 payload 时 `HashMap.put` 就发一次 DNS，导致误判「目标有反序列化」。
- **不重置 `hashCode`**：序列化时把改写后的值写进去，反序列化时 `URL.hashCode` 不再走 handler，收不到 DNS。
- **把 URLDNS 成功当「能 RCE」**：它只证明入口可达，gadget 是否存在要单独确认。
- **只看版本不看配置**：高版本可能被手工放开 `useCodebaseOnly=false`/`trustURLCodebase=true`；反过来在低版本上堆 gadget 也是浪费。
- **混用两套版本线**：RMI 看 `useCodebaseOnly`，JNDI 看 `trustURLCodebase`，别把 6u45 与 8u121 混着记。
- **`L...;` 截断用在 1.2.45+**：会得到「明明版本对但打不动」。
- **`javaReferenceAddress` 忽略互斥前提**：同 Entry 内 `javaSerializedData`/`javaRemoteLocation` 非空时根本不进 `decodeReference`。
- **在非 Web 线程用回显**：拿不到当前 request，必失败。
- **本地环境缺依赖就判漏洞不存在**：原书提醒不指定 jstl 1.2/不加 commons-collections4 时环境报错，会误判。

### 作者与时代的局限
- Fastjson 的绕过史写到 1.2.49；此后 `safeMode` 与 autoType 白名单普及，书中的逐代绕过多数失效，但「版本决定缝隙」的方法仍适用。
- Shiro 默认 key 已被官方在新版本移除，实战中更常见的是「自定义 key 泄露」（源码/配置文件/硬编码）。
- JNDI 在 8u191+ 默认关闭远程加载，主流利用已转向「本地 gadget + JNDI」组合，书中对这条组合的描述较少。
- 反序列化回显方案依赖容器内部字段名（`mbsInterceptor`、`RequestInfo.req`），换大版本即失效。

### 容易混淆的方法
- **反序列化 vs 表达式注入**：前者是「对象图被还原时触发 gadget」，后者是「表达式被求值」；Fastjson 两者都能走到（`@type` vs `$ref`/SpEL）。
- **URLDNS 探测 vs Fastjson dnslog 探测**：前者证明「字节流被反序列化」，后者证明「目标能出网且 JNDI 注入生效」；证明对象不同。
- **JRMPListener vs JRMPClient**：前者是「等别人连我」，本身不能主动打；后者才能主动连目标。
- **回显 vs 带外**：前者把结果写回当前响应（要求触发点在 Web 线程），后者让目标主动外连（要求能出网）。

### 授权与合规边界
> 待补充（用户自行填写）
