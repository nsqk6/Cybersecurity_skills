# Web安全与代码审计 — 术语词典

| 术语 | 英文 | 含义（在本域语境下） |
|---|---|---|
| 攻击面 | attack surface | 目标暴露给外部、可被输入影响的功能与资产的集合。测绘的产出是一张「功能 → 参数 → 角色」的表，不是 URL 列表 |
| 站点图 | site map | 用真实点击喂代理抓出来的功能关系图，比爬虫更接近真实入口 |
| 软 404 | soft 404 | 返回 200 但内容是「不存在」的页面。目录爆破时它会让所有请求都「成功」，必须先标定 |
| 入口点 | entry point | 任何能把用户输入带进应用的位置：URL 路径/查询串、body、cookie、header、带外（如 `X-Forwarded-For`） |
| 参数污染 | HPP, HTTP Parameter Pollution | 同名参数出现多次，不同层（WAF/框架/业务）取值不一致导致的绕过与判定分歧 |
| 注入通道 | extraction channel | 从注入点把数据取回来的路径：回显 → 布尔 → 报错 → 时间 → 带外。选择顺序由「能观测到什么副作用」决定 |
| 带外 | OOB, out-of-band | 通过目标主动发起的连接（DNS/HTTP/SMB）把结果送到攻击端。适用于目标能出网但应用无任何回显的情况 |
| 布尔盲注 | boolean-based blind | 只靠「真/假两种响应状态」逐位推数据。前提是两种状态稳定可区分 |
| 时间盲注 | time-based blind | 靠响应延迟推断。判据不是「延迟了 5 秒」，而是「改变延迟量，延迟随之变化」 |
| 二次解码 | double decoding | 输入被解码两次（如 `%2527` → `%27` → `'`）。绕过过滤的常见成因 |
| 宽字节注入 | GBK/wide-byte injection | 多字节编码下转义字符被吃掉一个字节，导致引号逃逸 |
| 模拟预处理 | emulated prepares | PDO 的 `ATTR_EMULATE_PREPARES=true`，参数在客户端拼接，防不住注入 |
| 输出语境 | output context | 注入点所在的语法环境：HTML 正文/属性/URL/JS 字符串/CSS。向量必须匹配语境 |
| 存储型 XSS | stored XSS | 载荷落库、由他人浏览时触发。危害看「谁会被触发」而非「能不能弹窗」 |
| DOM XSS | DOM-based XSS | 污染源与 sink 都在客户端，服务端响应里看不到载荷 |
| CSRF | cross-site request forgery | 借用户已认证的身份发出请求。成立三条件：相关动作、基于 cookie 的会话、无不可预测参数 |
| 点击劫持 | clickjacking | 用 iframe 叠加诱导点击。与 CSRF 的区别是它需要用户真实点击 |
| IDOR | insecure direct object reference | 直接改对象标识就能访问他人资源。判定必须用「两个身份 × 同一请求」 |
| 水平/垂直越权 | horizontal / vertical | 同级用户之间 vs 低权限访问高权限功能 |
| 业务逻辑缺陷 | business logic flaw | 代码按设计正常运行，但设计隐含假设被打破（负数、跳步、并发） |
| 竞态 | race condition | 检查与使用之间存在时间窗。典型在「仅一次」类操作（领券、提现、注册） |
| SSTI | server-side template injection | 用户输入进入模板引擎并被求值。判定靠模板语法的回显差异 |
| SSRF | server-side request forgery | 服务端替攻击者发请求。危害分「能读什么」与「能打什么」两层 |
| XXE | XML external entity | XML 解析器处理外部实体导致文件读取/SSRF。前提是解析器未禁用 DTD |
| 反序列化 | deserialization | 字节流还原对象时触发 `readObject`／魔术方法。判定先证明「会被反序列化」，再谈链 |
| gadget 链 | gadget chain | 反序列化时能被串联调用到危险操作的类组合 |
| JNDI 注入 | JNDI injection | 通过 `lookup` 加载远程对象（LDAP/RMI）。受 JDK 版本与 `trustURLCodebase` 限制 |
| WAF 失效层 | WAF failure layer | 绕过前先判断拦截发生在哪一层：语法层/语义层/会话层/速率层。不同层对应不同手法 |
| 分块传输绕过 | chunked transfer bypass | 用 `Transfer-Encoding: chunked` 让 WAF 与后端的解析产生分歧 |
| 危险函数 | dangerous sink | 审计时的定位锚点：`eval`、`system`、`unserialize`、`include`、`extract` 等 |
| 数据流追踪 | taint analysis | 从入口（source）追到危险操作（sink），中间记录过滤与净化 |
| 模糊测试 | fuzzing | 用变异输入批量探测异常。Web 场景下看响应差异而非崩溃 |
| 危害定级 | severity rating | 由「影响面 × 可利用性 × 前置条件」决定，不由漏洞类型决定 |

## 用法

- 读能力卡时遇到不熟的术语，回这张表查定义，再回到卡里的 E 段看它在具体步骤里怎么用。
- 术语定义与具体书目的对应关系见各能力卡 R 段引文。
