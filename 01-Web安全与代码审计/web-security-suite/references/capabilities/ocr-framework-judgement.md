# Web安全与代码审计 · OCR 增补：方法论框架与判据

> 本卡由扫描件 OCR 后提取的 **26 个候选单元**按类型聚合而成，逐字引用、执行步骤、失败模式、书内案例均原样保留自 `candidates/ocr-batch-*.md`。这一批是「已提取、按类型归集」的增补材料，与同目录其他能力卡的三重验证 + 人工聚类流程不同，故单独标注，不冒充正式聚类卡。

## R — 原文 (Reading)

> 根据敏感本[OCR]数来逆向追踪参数的传递过程，是目前使用得最多的一种方式，因为大多数漏洞是由于函数的使用不当造成的。另外非函数使用不当的漏洞，如 SQL FE[OCR]入，也有一些特征，比如 Select、Insert 等，再结合 From 和 Where 等关键字，我们就可以判断这是和[OCR]否是一条 SQL 语句……这种方式的优点是只需搜索相应敏感关键字，即可以快速地挖掘想要的漏洞，具有可定向挖掘和高效、高质量的优点。其缺点为由于没有通读代码，对程序的整体框架了解不够深入，在挖掘漏洞时定位利用点会花费一点时间，另外对逻辑漏洞挖掘覆盖不到。
>
> — 《代码审计：企业级Web代码安全架构》· 第 3 章 通用代码审计思路 / 3.1 敏感畏[OCR]数回溯参数过程

> 还可以先找出哪些文件在接收外部传人的参数，然后跟踪变量的传递过程 ，观察是否有变量传人到高危函数里面，或者传递的过程中是否有代码逻辑漏洞，这是一种正向追踪的方式，这样的挖掘方式比逆向追踪挖掘得更全。
>
> — 《代码审计：企业级Web代码安全架构》· 前言「代码审计思路」

> 通读全文代码也有一定的技巧，并不是随便找文件逐个读完就可以了……首先我们要看程序的大体代码结构……在看程序目录结构的时候，我们要特别注意以下几个文件: 1) 函数集文件，通常命名中包含 functions 或者 common 等关键字……2) 配置文件，通常命名中包括 config 关键字……3) 安全过滤文件……通常命名中有 filter, safe, check 等关键字……4) index 文件，index 是一个程序的人口[OCR]文件。
>
> — 《代码审计：企业级Web代码安全架构》· 第 3 章 3.2 通读全文代码

> 在有了一定的代码审计经验之后，一定会知道哪些功能点通常会有哪些漏洞……首先安装好并且运行程序，到处点点，浏览一下，看下程序有哪些功能……然后寻找经常会出问题的功能点，简单黑盒测试一下，如果没有发现很普通、很常见的漏洞，再去读这个功能的代码……1) 文件上传功能……2 ) 文件管理功能……3) 登录认证功能……4) 找回密码功能。
>
> — 《代码审计：企业级Web代码安全架构》· 第 3 章 3.3 根据功能点定向审计

> magic_quotes_gpc 在安全方面做了很大的贡献，只要它被开启，在不存在编码或者其他特殊绕过的情况下，可以使得很多漏洞无法被利用……但是[OCR]在PHP 5 中 magic_quotes_gpc 并不会过滤 $_ SERVER 变量，导致很多类似 client-ip、referer 一类的漏洞能够利用。在 PHP 5.3 之后的不推荐使用 magic_quotes_gpc, PHP 5.4 之后干脆被取消。
>
> — 《代码审计：企业级Web代码安全架构》· 第 1 章 PHP 核心配置详解 / magic_quotes_gpc

> 在正式的生产环境中，为了更安全地运行PHP，也可以使用 disable_functions 指令来禁止一些敏感函数的使用。当你想用本指令禁止一些危险函数时，切记要把 dl0[OCR] 函数也加到禁止列表，因为攻击者可以利用 dl0 函数来加载自定义的 PHP 扩展以突破 disable_functions 指令的限制。本指令配置范围为php.ini only. fic[OCR] Ft AS FA pm Bc My fo FG Sp ew[OCR], A: disable_functions=phpinfo,eval,passthru,exec,system.
>
> — 《代码审计：企业级Web代码安全架构》· 第 1 章 disable_functions

> open_basedir 指令用来限制 PHP Es[OCR] fa) HE oe[OCR], AS HR AT] te BE Web 3c[OCR]件目录即可……PEA[OCR] open_basedir 需要注意的一点是，指定的限ii[OCR] Sc ATA[OCR], MANE AEM[OCR]. BU[OCR], URAC[OCR] open_basedir =/www/a，那么目录 /www/a 和 /www/ab 都是可以访问的。所以如果要将访问仅限制在指定的目录内，请用斜线结束路径名。例如设置成: open_basedir = /www/a/。
>
> — 《代码审计：企业级Web代码安全架构》· 第 1 章 open_basedir

> 另外看这个文件的时候注意观察配置文件中参数值是用单引号还是用双引号括起来，如果是双引号，则很可能会存在代码执行漏洞，例如下面 Kuwebs 的代码，只要我们在修改配置的时候利用 PHP 可变变量的特性即可执行代码。
>
> — 《代码审计：企业级Web代码安全架构》· 第 3 章 3.2.1.2 查看关键文件代码

> SQL 注入漏洞虽然是目前最泛滥的漏洞，不过要解决 SQL 注入漏洞其实还比较简单。在 PHP 中可以利用魔术引号来解决，不过魔术引号在 PHP 5.4 后被取消，并且 gpc 在遇到 int 型的注入时也会显得不那么给力了，所以通常用得多的还是过滤函数和类……像 discuz、dedecms、phpcms 等程序里面都使用过滤类，不过如果单纯的过滤函数写得不够严谨，也会出现绕过的情况……当然最好的解决方案还是利用预编译的方式。
>
> — 《代码审计：企业级Web代码安全架构》· 第 4 章 4.1.2 漏洞防范

> 一般的XSS 漏洞都是因为没过滤特殊字符，导致可以通过注入单双引号以及尖括号等字符利用漏洞……防御这类的 XSS 漏洞只需要过滤掉相关的特殊字符即可，特殊字符列表如下 : 1) 单引号 (")2) 双引号 (")3 ) 尖括号 (<>)4) SORT[OCR] (\)5) AS[OCR] (:)6) and符(&)7)#号 (#)……还有两个问题，这些字符应该怎么过滤，什么时候过滤? 为了保证数据原始性，最好的过滤方式是在输出和二次调用的时候进行如 HTML 实体一类的转码，防止脚本注入的问题。
>
> — 《代码审计：企业级Web代码安全架构》· 第 4 章 4.2.2.1 特殊字符 HTML 实体转码

> 上面我们提到过滤特殊字符来防止 XSS 漏洞，实际上即使过滤了也同样可能会被绕过，比如利用跟宽字节注入一样的方式来吃掉反斜枉[OCR]，再利用标签的事件来执行js 代码，面对这样的情况，我们还得加标签事件的黑名单或者白名单，这里更推荐用和白[OCR]名单的方式，实现规则可以直接用正则表达式来匹配，如果匹配到的事件不在白名单列表，就直接拦截掉，而不是替换为空。
>
> — 《代码审计：企业级Web代码安全架构》· 第 4 章 4.2.2.2 标签事件属性黑白名单

> 目前的认证方式大多是基于 Cookie 和 Session ，不少程序会把当前登录的用户账号等认证信息放到 Cookie 中,或许是加密方式，是为了保持用户可以长时间登录，不会一退出浏览器或者 Session 超时就退出账户，进行操作的时候直接从 Cookie 中读取出当前用户信息，这里就存在一个算法可信的问题，如果这段 Cookie 信息没有加 salt 一类的东西 ，就可以导致任意用户登录漏洞，只要知道用户的部分信息，即可生成认证令牌，甚至有的程序会直接把用户名明文放到 Cookie 中，操作的时候直接取这个用户名的数据，这也是常说的越权漏洞。
>
> — 《代码审计：企业级Web代码安全架构》· 第 3 章 3.3 登录认证功能

> 找回密码功能的漏洞有很多利用场景，最常见的是验证码爆破，目前特别是 APP 应用，请求后端验证码的时候大多是4位，并且没有限制验证码错误次数和有效时间，于是就出现了爆破的漏洞。除此之外，还有验证凭证的算法，这需要在代码中才能看到，所以我们做代码审计的时候可以看看这个算法是否可信。
>
> — 《代码审计：企业级Web代码安全架构》· 第 3 章 3.3 找回密码功能

> 根据对 RDBMS 岂[OCR]的指令种类的不同, SQL 语句可以分为以下三类...DDL (Data Definition Language，数据定义语言用来创建或者除存储[OCR]数据用的数据库以及数据库中的表等对象...DML (Data Manipulation Language, 数据操作语言)用来查询或者变更表中的记录。DML ALLELES[OCR]. SELECT 查询表中的数据 INSERT , 向表中插入新数据 ‘UPDATE 变更表中的数据 DELETE ; 删除表中的数据...实际使用的 SQL 语句当中有 90% 属于 DML，本书同样会以 DML 为中心进行讲解。
>
> — 《SQL基础教程》· 第 1 章 1-3 SQL 语句及其种类

## I — 方法论骨架 (Interpretation)

**敏感关键字回溯参数（逆向追踪审计法）** — 漏洞的根因是「危险函数 + 可控输入」。从危险函数（sink）这一端出发，反向沿着赋值链回溯到输入源（source），判断中间是否经过有效过滤。比正向通读效率高，因为 sink 关键字有限且稳定（`mysql_query`、`eval`、`include`、`unlink` 等），而 source 路径多变。但回溯法天然偏科——它看的是「单条数据流」，对跨请求、跨存储的二次逻辑漏洞和业务越权漏洞失效。

**正向追踪变量传递审计法** — 从 source 端（`$_GET/$_POST/$_COOKIE/$_SERVER` 入口文件）出发，沿着变量赋值/传参链正向走到 sink。比逆向追踪更全面的原因是：一个 source 可能流向多个 sink，正向跟踪能一次看完所有 sink；而逆向一次只看一个 sink。代价是要先把所有「接收外部参数的文件」找出来，前置工作量大。

**通读全文代码审计法（四类关键文件优先）** — 通读不是线性读，而是「结构 → 关键文件 → 业务」三段式。先看目录拿到模块图；再精读四类关键文件——函数集（看可复用的过滤逻辑）、配置文件（看编码/双引号）、过滤文件（看全局过滤的盲区）、index（看路由和包含关系）。这四类文件决定了「全局过滤水位」，先建立水位线，后续读业务代码时只需寻找「绕过水位线的低洼地」。

**功能点定向审计法（四大高危功能点）** — 漏洞分布不是均匀的，而是高度集中在少数功能点上。先用黑盒快速过一遍，把「明显漏洞」扫掉；剩下的「未触发但可疑」的功能点直接精读代码。比通读全文快，比关键字回溯全——因为先验地知道「每个功能点的漏洞模式」，可以一次抓多个 sink。作者给出的四个功能点覆盖了 OWASP Top 10 中注入、文件操作、认证失败、业务逻辑四类。

**`magic_quotes_gpc` 不保护 `$_SERVER` 的判据** — GPC 只对 GET/POST/COOKIE 三个超全局做转义，`$_SERVER` 不在列表内。`HTTP_CLIENT_IP`、`HTTP_X_FORWARDED_FOR`、`HTTP_REFERER`、`HTTP_USER_AGENT` 这些头字段都落到 `$_SERVER`，开发者若直接拼到 SQL，GPC 拦不住。这是一条「配置水位线有缝」的判据——只要看到代码取 `$_SERVER['HTTP_X_FORWARDED_FOR']` 拼 SQL，无论是否开启 GPC 都判为可注入。

**`disable_functions` 必须连带禁用 `dl()`** — `disable_functions` 是 PHP 解释器层面的黑名单，但 `dl()` 是个特例——它能动态加载 `.so`/`.dll` 扩展，扩展内的函数以 C 实现运行在 PHP 进程内，不受 `disable_functions` 约束。攻击者上传一个恶意扩展（如重新实现 `system` 的 `evil.so`），用 `dl('evil.so')` 加载后即可绕过整个黑名单。这是「黑名单 + 后门入口」的经典反例——黑名单的强度等于其最弱入口的强度。

**`open_basedir` 路径必须以斜杠结尾** — `open_basedir` 的匹配规则是「前缀匹配」而非「目录精确匹配」。设 `/www/a` 时，`/www/ab`、`/www/abc`、`/www/attachments` 都命中前缀，等于「限制在 /www/a 下」退化为「限制在 /www/a* 下」。攻击者可在同分区布置恶意目录 `/www/attachments/evil.php` 突破预期。加尾斜杠 `/www/a/` 让前缀多一个 `/`，要求路径分隔符精确出现，才能把限制收敛到单目录。

**双引号包裹配置值引发代码执行的判据** — PHP 双引号字符串会做变量解析（`"$var"` 展开为变量值），单引号不会。配置文件里若用 `"$kuWebsiteURL"` 形式存值，且该值在后台可被用户修改，那么写入 `$kuWebsiteURL = "${@eval($_GET['cmd'])}"` 这类可变变量语法就能在配置被 include 时代码执行。判据非常简单：配置值用双引号 → 触发可变变量特性 → 代码执行隐患。

**SQL 注入分层防御路径（gpc → addslashes → mysql_real_escape_string → intval → PDO prepare）** — 单点防御都有盲区，作者把防御分成五层并指出每层边界：①GPC/addslashes 防 string 型但有编码绕过和 int 型盲区；②`mysql_real_escape_string` 感知字符集但仍是字符串转义；③`intval` 专治 int 型但只适用于数值参数；④过滤类（Discuz 的 `addslashes_deep` 等）覆盖入口但易漏 `$_SERVER` 和数组；⑤PDO prepare 把「字符串转义」升级为「SQL 语法结构分离」，是唯一从根本上消除注入的方案。从 ① 到 ⑤ 是「点 → 线 → 面 → 结构」的递进。

**XSS 防御：输出与二次调用时 HTML 实体转码** — 输入阶段就转码会破坏数据原始性（用户输入 `<3` 变成 `&lt;3` 存库，后续导出 CSV/JSON 时格式错乱）。正确时机是「输出到浏览器时」和「二次调用前」（如把数据库读出的字符串再拼到 JS 上下文）。这要求开发者不能在入口统一转码，而要在每个输出点单独转码，对工程纪律要求高，所以很多项目偷懒在入口转，要么破坏数据要么漏掉某些输出点。

**XSS 标签事件白名单优于黑名单** — 黑名单（如 `remove_xss` 把 `onerror` 替换为空）的问题是「替换为空」可被字符拆解绕过（`oneronerrorr` 删除中间 `onerror` 后剩余 `onerror`）。白名单（只允许 `<a><b><img>` 等少数标签和 `onclick` 等少数事件，不在名单直接拦截）不存在「替换绕过」。拦截而非替换是关键——替换是字符串操作，拦截是逻辑拒绝，前者总有边 case，后者无歧义。

**Cookie 无 salt 任意用户登录判据** — 「长时间登录」需求让开发者把认证信息存到 Cookie（客户端可控），但 Cookie 内容若只是 `base64(username)` 或 `md5(username + password)` 而无服务端独有秘密（salt），就退化成「知道用户名即可伪造 Cookie」。salt 必须是服务端独有且不变的随机串（如 `config.php` 里的 `pwdhash`），否则用已知用户名 + 字典攻击仍可还原。判据：Cookie 中含认证信息 + 无 salt → 任意用户登录。

**找回密码验证码爆破判据（4 位 + 无次数限制 + 无时效）** — 4 位数字验证码空间 = 10000，无错误次数限制时爆破成本 = 平均 5000 次请求；无时效限制时甚至可离线字典攻击。三个条件叠加使「找回密码」从安全机制退化为「按用户名重置任意账号密码」接口。判据是三个条件的合取——只要三个同时成立，爆破必然可行。修复时任意打破一个（加次数限制 / 提高到 6 位 / 加 5 分钟时效）即可。

**区分 DDL/DML/DCL 三类 SQL 语句以定位注入影响面** — SQL 语句按对 RDBMS 的指令种类三分：DDL（CREATE/DROP/ALTER，改库表结构）、DML（SELECT/INSERT/UPDATE/DELETE，改表内记录）、DCL（COMMIT/ROLLBACK/GRANT/REVOKE，控制事务与权限）。作者指出实际使用中 90% 是 DML——这意味着注入点的「常态 sink」在 DML，但若应用拼接了 DDL（如动态建表、`DROP TABLE`）或 DCL（`GRANT`），危害会跨边界放大。安全工程师读源码找注入 sink 时，应先按这三类对应用中拼接的 SQL 语句分类：DML 注入影响数据机密性/完整性，DDL 注入影响结构（删库删表），DCL 注入影响权限授予。三类注入的危害量级、修复优先级、回滚可能性都不同。

**用 WHERE 子句构造行级筛选条件（SQL 注入的核心 sink）** — WHERE 子句是 SQL 中行级筛选的唯一入口，其条件表达式由「列名 + 比较运算符 + 字面量」构成。这是 SQL 注入最核心的 sink——应用把用户输入直接拼进 WHERE 条件表达式的字面量位置时，攻击者可以通过闭合字面量、注入 `OR 1=1`、追加 `UNION SELECT` 等方式改变条件语义。理解 WHERE 子句的合法结构（列名/运算符/字面量）是判断「用户输入是否被正确隔离为字面量」的前提——只要用户输入没有走参数化绑定，它就会被 SQL 解析器当成 SQL 语法的一部分而非字面量。

**AND 运算优先于 OR 运算（注入逻辑绕过的语法基础）** — SQL 逻辑运算符 `AND` 优先级高于 `OR`——即 `A AND B OR C` 会被解析为 `(A AND B) OR C`，而非 `A AND (B OR C)`。本书指出这是初学者常错之处：原意是「A 且 (B 或 C)」，实际被解析成「(A 且 B) 或 C」，导致 `C` 单独为真就让整式为真。这一运算优先级是 SQL 注入中 `' OR 1=1 --` 类 payload 的语法基础——攻击者注入 `OR <恒真条件>`，由于 `OR` 优先级低于 `AND`，注入的 `OR` 会与原查询的所有 `AND` 条件组合，最终整个 WHERE 因 `OR <恒真>` 而全表命中。理解优先级才能解释为什么 `OR 1=1` 能绕过 `AND` 串联的多重条件。

**SQL 三值逻辑 TRUE/FALSE/UNKNOWN（boolean blind injection 的语义基础）** — SQL 与绝大多数编程语言不同，逻辑运算不是二值而是三值——TRUE/FALSE 之外还有 UNKNOWN（不确定），由 NULL 参与比较产生。UNKNOWN 在 AND 中接近 FALSE（任一 UNKNOWN 让 AND 不一定为真），在 OR 中接近 TRUE（任一 UNKNOWN 让 OR 不一定为假）。这一三值逻辑是 boolean-based blind SQL 注入的语义基础：攻击者构造 `AND <boolean condition>` 让查询在条件为 TRUE 时返回正常结果，在 FALSE 时返回空或异常，UNKNOWN 时表现接近 FALSE。理解三值逻辑才能解释为什么 `WHERE col = NULL` 永远不返回行（结果是 UNKNOWN），以及为什么 `OR col = NULL` 不能当作恒真使用。

**字符串字面量必须单引号括起，数字字面量无需引号（注入形态区分）** — SQL 字面量分两类——字符串/日期必须用单引号 `'...'` 括起，数字直接写。这决定了 SQL 注入的两种基本形态：(1) 字符串型注入——注入点在引号内，需先用 `'` 闭合原字面量，再注入 SQL，最后用 `--` 注释掉尾部引号（典型 `' OR 1=1 --`）；(2) 数字型注入——注入点无引号，直接拼数字，注入无需闭合引号（典型 `1 OR 1=1`）。安全工程师在源码审计时，区分这两类是判断 payload 形态的第一步：字符串型要看是否转义了引号，数字型要看是否做了整数化。本书还特别强调「插入到表中的数据是区分大小写的」——SQL 关键字大小写不敏感（见 CU-2-20），但字符串数据大小写敏感，这影响 WAF 绕过中关键字大小写变换的可用性。

**子查询先内层后外层执行（subquery injection 的执行模型）** — SQL 子查询是嵌套结构，执行顺序是「先内层后外层」——内层子查询先执行产生临时结果，外层查询把临时结果当表使用。子查询分两类：(1) 普通子查询（返回多行多列，可作 FROM/IN 的参数）；(2) 标量子查询（返回 1 行 1 列，可用于 `=`/`<>` 比较运算符）。这一执行模型是 subquery-based SQL injection 的基础——攻击者在 WHERE 子句中注入 `(SELECT ...)` 子查询，子查询会先于外层执行。基于此可构造：error-based 注入（子查询中触发类型转换错误外带数据）、time-based 盲注（子查询中 `SLEEP`/`WAITFOR DELAY`）、UNION 注入外的子查询外带（`AND (SELECT password FROM users WHERE id=1) = 'x'` 逐字符比较）。

**UNION 集合运算要求列数与类型对齐（UNION-based injection 的硬约束）** — UNION/INTERSECT/EXCEPT 集合运算要求两侧 SELECT 的列数相同、对应位置列类型一致。这是 UNION-based SQL injection 的硬约束——攻击者注入 `UNION SELECT ...` 时必须让注入侧的列数与原查询一致，类型可隐式转换。本书还指出 `ORDER BY` 只能在最后用一次。这一约束决定了 UNION 注入的常规流程：(1) 先用 `ORDER BY N` 试探列数（逐步增加 N 直到报错）；(2) 用 `UNION SELECT 1,2,3,...` 确定回显位；(3) 在回显位替换 `(SELECT col FROM ...)` 外带数据。若两侧类型不兼容会报错，注入失败但暴露存在性。

**HAVING 子句指定组条件，WHERE 子句指定行条件** — WHERE 和 HAVING 都指定条件，但作用阶段不同：WHERE 在 GROUP BY 之前过滤行（行级），HAVING 在 GROUP BY 之后过滤组（组级）。本书指出这是初学者常错之处——想筛 `COUNT(*) = 2` 的组，用 WHERE 会报错（WHERE 不能用聚合函数），必须用 HAVING。这一区分对安全工程师的意义：(1) 注入点在 HAVING 子句时，注入条件作用于聚合后的组，行为与 WHERE 注入不同；(2) HAVING 子句可使用聚合函数，意味着注入 payload 可包含 `COUNT/SUM/AVG`——这是构造基于聚合的盲注的入口；(3) 应用代码若把用户输入同时拼到 WHERE 和 HAVING，需分别审计。

**区分 DROP TABLE 与 DELETE FROM（破坏性注入的两种量级）** — DROP TABLE 删除表本身（结构 + 数据），DELETE FROM 删除表内数据但保留表结构。本书指出二者破坏量级不同——DROP 后必须重建表才能恢复，DELETE 后只需重新 INSERT。这一区分对安全工程师评估注入危害至关重要：(1) 若应用拼接了 `DROP TABLE` 且输入可控，注入可达「删库」级别——数据完全丢失且结构不存；(2) 若仅 `DELETE FROM` 可达，表结构保留，可从备份恢复；(3) 多数应用业务不需要 DDL，应在 DB 用户权限层面禁止 DROP，把破坏上限锁在 DELETE。审计时优先找 DDL 拼接点。

**用 INSERT ... SELECT 从其他表复制数据（注入数据外带的合法路径）** — INSERT ... SELECT 把 SELECT 结果直接插入目标表，是 SQL 标准的「表间数据复制」语法。执行流程：(1) SELECT 子句先执行产生结果集；(2) 结果集逐行 INSERT 到目标表。本书指出这可用于数据备份。对安全工程师的意义：(1) 这是 SQL 注入数据外带的合法路径——攻击者若可达 INSERT sink 且目标表可控，可注入 `INSERT INTO attacker_table SELECT * FROM users` 直接把敏感数据复制到攻击者可控表；(2) 在 UNION 注入受限（无回显位）时，INSERT sink 比 SELECT sink 更危险，因为可主动写数据；(3) 应用若动态拼 INSERT 表名或列名，注入可达 schema 修改级别。

**用事务（COMMIT/ROLLBACK/ACID）管理数据更新的原子性** — 事务把多个 DML 操作封装为原子单元，COMMIT 提交全部、ROLLBACK 全部取消。ACID 四特性：原子性（全或无）、一致性（约束满足）、隔离性（并发事务互不干扰）、持久性（提交后永久）。本书指出事务必须显式结束（COMMIT/ROLLBACK），无显式结束时 DBMS 行为依模式而定。对安全工程师的意义：(1) 注入若触发 ROLLBACK，所有注入产生的写入被取消——这是「检测即回滚」防护的理论基础；(2) 自动提交模式下（见 CU-2-21），每条语句独立提交，注入写入无法回滚；(3) 评估注入危害时需确认应用是否在事务中执行拼接 SQL——若是，注入写入可被 ROLLBACK 取消，危害降级。

**SQL 关键字大小写不敏感（WAF 绕过的基础语法特性）** — SQL 关键字（SELECT/FROM/WHERE 等）和表名/列名大小写不敏感，但字符串字面量大小写敏感。本书明确区分这两类——`SELECT` 和 `select` 等价，但 `'Computer'`、`'COMPUTER'`、`'computer'` 是三个不同的字符串。这一区分是 WAF 绕过的语法基础：(1) WAF 规则若按大小写匹配关键字（如只拦 `UNION SELECT`），用 `UnIoN sElEcT` 可绕过；(2) WAF 规则若按字符串匹配值（如拦 `'admin'`），不能用大小写变换绕过——因为字符串大小写敏感；(3) 注入 payload 中关键字大小写变换是最低成本的 WAF 绕过手段之一。安全工程师设计 WAF 规则时，关键字匹配必须大小写不敏感，值匹配按业务需求决定。

**SQL 语句子句执行顺序（FROM→WHERE→GROUP BY→HAVING→SELECT→ORDER BY）** — SQL 语句的「书写顺序」与「DBMS 内部执行顺序」不同。书写顺序：SELECT → FROM → WHERE → GROUP BY → HAVING → ORDER BY。执行顺序：FROM → WHERE → GROUP BY → HAVING → SELECT → ORDER BY。本书指出这是「SQL 难以理解的原因之一」。这一执行模型对安全工程师的意义：(1) 注入点在 WHERE 时，条件作用于 FROM 后的原始行集；(2) 注入点在 HAVING 时，条件作用于 GROUP BY 后的组；(3) SELECT 别名不能用于 WHERE/HAVING（因为 SELECT 在它们之后执行，别名还未生成）——这是反例 CU-2-16 的根因；(4) ORDER BY 注入时，SELECT 已执行，可用 SELECT 别名做 ORDER BY 注入条件。

## A1 — 应用示例 (Application Example)

### 示例 1: 敏感关键字回溯参数（逆向追踪审计法）
- **类型与来源**: 【framework】《代码审计：企业级Web代码安全架构_ocr.txt》· 第 3 章 通用代码审计思路 / 3.1 敏感畏[OCR]数回溯参数过程（Page 61–65）
- **问题/输入**: 一份可索引的源码（Seay 项目或 grep 可达）；熟悉 PHP 危险函数清单；对常见过滤函数（`addslashes`、`intval`、`htmlspecialchars`）的绕过条件有先验。
- **方法论的使用**: 漏洞的根因是「危险函数 + 可控输入」。从危险函数（sink）这一端出发，反向沿着赋值链回溯到输入源（source），判断中间是否经过有效过滤。比正向通读效率高，因为 sink 关键字有限且稳定（`mysql_query`、`eval`、`include`、`unlink` 等），而 source 路径多变。但回溯法天然偏科——它看的是「单条数据流」，对跨请求、跨存储的二次逻辑漏洞和业务越权漏洞失效。
- **结果**: 【亲历】espcms `adminsoft/control/citylist.php` 的 `oncitylist()`，`$parentid` 经 `accept('parentid','R')` → `daddslashes()` 过滤，但 SQL 语句 `select * from $db_table where parentid=$parentid` 不需要单引号闭合，int 型注入直接利用（Page 64–65）。

### 示例 2: 正向追踪变量传递审计法
- **类型与来源**: 【framework】《代码审计：企业级Web代码安全架构_ocr.txt》· 前言「代码审计思路」（Page 7–8）+ 第 3 章 3.1 引言（Page 61）
- **问题/输入**: 全文可读；能识别「接收外部参数」的入口模式；对赋值链跨文件传递（函数调用、`include`）的追踪能力（Seay 全局搜索 / RIPS 跨文件追踪）。
- **方法论的使用**: 从 source 端（`$_GET/$_POST/$_COOKIE/$_SERVER` 入口文件）出发，沿着变量赋值/传参链正向走到 sink。比逆向追踪更全面的原因是：一个 source 可能流向多个 sink，正向跟踪能一次看完所有 sink；而逆向一次只看一个 sink。代价是要先把所有「接收外部参数的文件」找出来，前置工作量大。
- **结果**: 未提供独立案例，前言中作为三种思路之一提出，与逆向追踪配对出现。

### 示例 3: 通读全文代码审计法（四类关键文件优先）
- **类型与来源**: 【framework】《代码审计：企业级Web代码安全架构_ocr.txt》· 第 3 章 3.2 通读全文代码（Page 66–73）
- **问题/输入**: 完整源码；可识别 PHP 框架（Discuz/DedeCMS/PHPCMS 等）的命名惯例；时间预算充足（作者承认「花费的时间比较多」）。
- **方法论的使用**: 通读不是线性读，而是「结构 → 关键文件 → 业务」三段式。先看目录拿到模块图；再精读四类关键文件——函数集（看可复用的过滤逻辑）、配置文件（看编码/双引号）、过滤文件（看全局过滤的盲区）、index（看路由和包含关系）。这四类文件决定了「全局过滤水位」，先建立水位线，后续读业务代码时只需寻找「绕过水位线的低洼地」。
- **结果**: 【亲历】骑士 cms 3.5.1 完整审计（Page 68–73）：从 include 目录的 `common.fun.php` 读到 `addslashes_deep`/`mystrip_tags`/`remove_xss`/`getip`/`inserttable`/`wheresql`/`asyn_userkey` 七个关键函数；从 `/data/config.php` 看到 `QISHI_DBCHARSET='GBK'` 与 `mysql_query("SET NAMES gbk")`，定位到宽字节注入隐患。

### 示例 4: 功能点定向审计法（四大高危功能点）
- **类型与来源**: 【framework】《代码审计：企业级Web代码安全架构_ocr.txt》· 第 3 章 3.3 根据功能点定向审计（Page 79–82）
- **问题/输入**: 有一定经验积累（知道每个功能点的典型漏洞模式）；可运行环境；黑盒工具配合。
- **方法论的使用**: 漏洞分布不是均匀的，而是高度集中在少数功能点上。先用黑盒快速过一遍，把「明显漏洞」扫掉；剩下的「未触发但可疑」的功能点直接精读代码。比通读全文快，比关键字回溯全——因为先验地知道「每个功能点的漏洞模式」，可以一次抓多个 sink。作者给出的四个功能点覆盖了 OWASP Top 10 中注入、文件操作、认证失败、业务逻辑四类。
- **结果**: 【亲历】BugFree 重装漏洞（Page 81–82）：`install/index.php` 的 `install.lock` 检查后用 `header("location: ../index.php")` 跳转但未 `exit`，下方代码继续执行，可直接重装覆盖配置。

### 示例 5: `magic_quotes_gpc` 不保护 `$_SERVER` 的判据
- **类型与来源**: 【principle】《代码审计：企业级Web代码安全架构_ocr.txt》· 第 1 章 PHP 核心配置详解 / magic_quotes_gpc（Page 22）
- **问题/输入**: PHP 5.x 项目（5.4 前）或虽有自实现入口过滤但过滤范围只覆盖 `$_GET/$_POST/$_COOKIE` 的项目。
- **方法论的使用**: GPC 只对 GET/POST/COOKIE 三个超全局做转义，`$_SERVER` 不在列表内。`HTTP_CLIENT_IP`、`HTTP_X_FORWARDED_FOR`、`HTTP_REFERER`、`HTTP_USER_AGENT` 这些头字段都落到 `$_SERVER`，开发者若直接拼到 SQL，GPC 拦不住。这是一条「配置水位线有缝」的判据——只要看到代码取 `$_SERVER['HTTP_X_FORWARDED_FOR']` 拼 SQL，无论是否开启 GPC 都判为可注入。
- **结果**: 【亲历】骑士 cms `common.fun.php` 的 `getip()` 函数取 `HTTP_CLIENT_IP`/`HTTP_X_FORWARDED_FOR`/`REMOTE_ADDR`，虽做了 `\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}` 正则约束，作者评论「是可以伪造 IP 地址的」（Page 73）。

### 示例 6: `disable_functions` 必须连带禁用 `dl()`
- **类型与来源**: 【principle】《代码审计：企业级Web代码安全架构_ocr.txt》· 第 1 章 disable_functions（Page 27）
- **问题/输入**: PHP 5.2/5.3 项目（`dl` 在 5.3+ 受 `enable_dl=Off` 限制，但旧版本仍可用）；对服务器有上传通道（攻击者需能放扩展文件）。
- **方法论的使用**: `disable_functions` 是 PHP 解释器层面的黑名单，但 `dl()` 是个特例——它能动态加载 `.so`/`.dll` 扩展，扩展内的函数以 C 实现运行在 PHP 进程内，不受 `disable_functions` 约束。攻击者上传一个恶意扩展（如重新实现 `system` 的 `evil.so`），用 `dl('evil.so')` 加载后即可绕过整个黑名单。这是「黑名单 + 后门入口」的经典反例——黑名单的强度等于其最弱入口的强度。
- **结果**: 未提供独立案例，作为配置原则提出。

### 示例 7: `open_basedir` 路径必须以斜杠结尾
- **类型与来源**: 【principle】《代码审计：企业级Web代码安全架构_ocr.txt》· 第 1 章 open_basedir（Page 26–27）
- **问题/输入**: 对 PHP 配置可读；目标有 `open_basedir` 配置。
- **方法论的使用**: `open_basedir` 的匹配规则是「前缀匹配」而非「目录精确匹配」。设 `/www/a` 时，`/www/ab`、`/www/abc`、`/www/attachments` 都命中前缀，等于「限制在 /www/a 下」退化为「限制在 /www/a* 下」。攻击者可在同分区布置恶意目录 `/www/attachments/evil.php` 突破预期。加尾斜杠 `/www/a/` 让前缀多一个 `/`，要求路径分隔符精确出现，才能把限制收敛到单目录。
- **结果**: 未提供独立案例，作为配置原则提出。

### 示例 8: 双引号包裹配置值引发代码执行的判据
- **类型与来源**: 【principle】《代码审计：企业级Web代码安全架构_ocr.txt》· 第 3 章 3.2.1.2 查看关键文件代码（Page 67）+ 3.2.1.3 查看配置文件（Page 75）
- **问题/输入**: 配置文件可读；能识别后台「网站基本信息配置」一类的写入入口。
- **方法论的使用**: PHP 双引号字符串会做变量解析（`"$var"` 展开为变量值），单引号不会。配置文件里若用 `"$kuWebsiteURL"` 形式存值，且该值在后台可被用户修改，那么写入 `$kuWebsiteURL = "${@eval($_GET['cmd'])}"` 这类可变变量语法就能在配置被 include 时代码执行。判据非常简单：配置值用双引号 → 触发可变变量特性 → 代码执行隐患。
- **结果**: 【转述】Kuwebs 的 `/data/config.php` 用 `$kuWebsiteURL = "http://www.kuwebs.com"` 双引号包裹，作者明确说可利用 PHP 可变变量特性执行代码（Page 67）；【亲历】骑士 cms `/data/config.php` 同样用双引号，作者评论「很明显看到，很有可能存在我们之前说过的双引号解析代码执行的问题」（Page 75）。

## A2 — 相邻能力 (Adjacency)

1. 出现「这个 PHP 站点怎么快速找漏洞」这类信号时，回到本卡查对应单元的方法与判据。
2. 出现「按危险函数反查输入」这类信号时，回到本卡查对应单元的方法与判据。
3. 出现「逆向追踪审计」这类信号时，回到本卡查对应单元的方法与判据。
4. 出现「trace parameter backwards」这类信号时，回到本卡查对应单元的方法与判据。
5. 出现「sink to source audit」这类信号时，回到本卡查对应单元的方法与判据。
6. 出现「全面排查某个参数流到哪」这类信号时，回到本卡查对应单元的方法与判据。

语言信号：「这个 PHP 站点怎么快速找漏洞」、「按危险函数反查输入」、「逆向追踪审计」、「trace parameter backwards」、「sink to source audit」、「全面排查某个参数流到哪」

本卡为增补材料，正式能力卡请优先读：`recon-asset-surface`、`injection-channel-selection`。

**相邻区分（原文）**：

- 与 CU-1-02「正向追踪」方向相反；与 CU-1-03「通读全文」粒度不同——本单元是「点到点」，通读全文是「面到点」。

---
- 与 CU-1-01 方向相反；粒度比 CU-1-03「通读全文」更窄，专注单条数据流。

---
- 与 CU-1-01/02 是粒度差异——本单元产出整体业务逻辑图，回溯/正向只看单条数据流；与 CU-1-04「功能点定向」是广度差异——本单元全覆盖，功能点定向只看高危点。

---
- 与 CU-1-03「通读全文」是广度差异——本单元只看高危点；与 CU-1-01「关键字回溯」是切入点差异——本单元从功能切入，回溯从 sink 切入。

---
- 与 CU-1-11「HTTP 头 IP 字段注入挖掘」是「判据 vs 操作配方」的关系——本单元给判据，CU-1-11 给挖掘步骤。

---
- 与 CU-1-08「open_basedir 路径斜杠」是同章配置原则，但本单元讲黑名单完整性，后者讲路径约束粒度。

---
- 与 CU-1-07 同属配置原则，但本单元讲路径约束粒度，前者讲黑名单完整性。

---
- 与 CU-1-06「GPC 不保护 $_SERVER」是「配置水位线有缝」的同构判据——都是从「全局防御的盲区」找切入点。

---

## E — 执行步骤 (Execution)

### 敏感关键字回溯参数（逆向追踪审计法）

1. 用 Seay/RIPS/grep 搜索 sink 关键字（如 `select`、`eval`、`include`、`unlink`、`exec`）→ 得到候选代码行清单
  2. 双击候选行定位到源码，选中变量后在工具的「变量传递过程」面板反向查看赋值来源
  3. 沿着 accept / `$_GET` / `$_POST` / `$_REQUEST` / `$_SERVER` 一路回溯到 source，标记每一跳的过滤函数
  4. 判断「是否所有路径都过滤」+「过滤函数是否可绕过」；只要存在一条不过滤或可绕过的路径，即认定漏洞成立

### 正向追踪变量传递审计法

1. 全局搜索 `$_GET`、`$_POST`、`$_REQUEST`、`$_COOKIE`、`$_SERVER`、`$_FILES`、`accept(`、`indexget(` 等 source 接收点 → 列出所有入口文件
  2. 对每个 source 变量建立赋值链：`$a = $_GET['x']; $b = foo($a); $c = bar($b); ... sink($c)`
  3. 沿链标出每一跳的处理函数（过滤/编码/拼接/序列化）
  4. 终点若落到 sink（`mysql_query`/`eval`/`include`/`unlink`/`exec`）且链路中存在「未过滤跳」，则漏洞成立

### 通读全文代码审计法（四类关键文件优先）

1. 列主目录、模块目录、插件目录的文件清单（含大小、创建时间），按命名识别 api/admin/manage/include 等关键字目录
  2. 找函数集文件：打开 `index.php` 头部的 `include`/`require` 链，定位 `functions.php`/`common.fun.php`/`common.inc.php`，读完全部公共函数
  3. 找配置文件：搜 `config` 关键字，结合所在目录（`/data/config.php` 比模板缓存里的 `config` 更可信），看 DB 编码、双引号/单引号使用、`DBCHARSET` 常量
  4. 找过滤文件：搜 `filter/safe/check` 关键字，确认入口是否统一 `addslashes`、是否覆盖 `$_SERVER`
  5. 跟读 `index.php` 及几个核心目录的 index 文件，画出「请求 → 路由 → 控制器 → 视图」骨架
  6. 在已知「全局过滤水位」下，去业务模块里找「未走统一过滤」或「过滤后被解码」的低洼点

### 功能点定向审计法（四大高危功能点）

1. 安装运行程序，黑盒浏览全部功能，列出功能清单与对应程序文件（独立模块 / 插件 / 通用类）
  2. 按四大高危点优先级精读：
     - **文件上传**：看 `move_uploaded_file` 的格式白名单是否可绕过、文件名是否入库（SQLi 隐患）
     - **文件管理**：看文件名/路径参数是否走 `../` 跳目录（任意文件读取/删除）、文件名是否输出到页面（XSS）
     - **登录认证**：看 Cookie 中是否明文存用户名、是否带 salt、认证算法是否可预测（任意用户登录/越权）
     - **找回密码**：看验证码长度、错误次数限制、有效时间、验证凭证算法可信度（爆破/重置）
  3. 黑盒已确认无常见漏洞的点可跳过精读，节省时间

### `magic_quotes_gpc` 不保护 `$_SERVER` 的判据

1. 全局搜索 `$_SERVER`、`getenv('HTTP_`、`HTTP_CLIENT_IP`、`HTTP_X_FORWARDED_FOR`、`HTTP_REFERER`、`HTTP_USER_AGENT`
  2. 命中处看变量是否拼接到 SQL/命令/文件路径
  3. 即使开启 GPC 也判定为漏洞，因为 GPC 不覆盖 `$_SERVER`
  4. PHP 5.4+ 项目无 GPC，但代码里若有自实现的 `addslashes($_GET)` 入口过滤，也常常漏掉 `$_SERVER`，同样适用本判据

### `disable_functions` 必须连带禁用 `dl()`

1. 看 `php.ini` 的 `disable_functions` 是否包含 `dl`
  2. 若不含 `dl`，判定 `disable_functions` 整体可被 `dl()` 突破，黑名单失效
  3. 修复时把 `dl` 加入禁用列表（`disable_functions=phpinfo,eval,passthru,exec,system,dl,...`）
  4. 同时检查 `enable_dl` 是否为 `Off`（PHP 5.3+ 默认 Off，但旧版默认 On）

### `open_basedir` 路径必须以斜杠结尾

1. 读 `php.ini` 或 `.htaccess` 或 `ini_set('open_basedir', ...)` 的路径值
  2. 检查路径末尾是否有 `/`（Windows 下 `\` 或 `/` 均可）
  3. 若无尾斜杠，标记为「限制范围过宽」缺陷，可能允许同前缀目录访问
  4. 修复：统一以 `目录 + DIRECTORY_SEPARATOR` 形式设置

### 双引号包裹配置值引发代码执行的判据

1. 找配置文件（命名含 `config`，目录多为 `/data/`、`/include/`、根目录）
  2. 看配置项的赋值是用单引号还是双引号包裹
  3. 若是双引号，看该配置项是否在后台可被用户修改（写入数据库后生成配置文件）
  4. 若可写，构造 payload `${@eval($_GET['cmd'])}` 或 `${${@print(phpinfo())}}` 写入配置项，触发 include 时执行

### SQL 注入分层防御路径（gpc → addslashes → mysql_real_escape_string → intval → PDO prepare）

1. 入口层：在全局公共文件里对 `$_GET/$_POST/$_COOKIE` 统一 `addslashes_deep`（递归处理数组）
  2. 字符集层：连接 MySQL 后 `SET NAMES 'gbk', character_set_client=binary` 或用 `mysql_set_charset('gbk')` + `mysql_real_escape_string`
  3. 类型层：int 参数一律 `intval`，float 参数一律 `floatval`
  4. 业务层：在 SQL 拼接前对来源不明变量再过一遍业务相关过滤（如订单号 `\d+` 校验）
  5. 终端层：能用 PDO prepare 的地方一律用 `?` 占位 + `execute(array($var))`，并强制 `setAttribute(PDO::ATTR_EMULATE_PREPARES, false)`
  6. 漏洞响应：发现绕过时，不要只补当前 payload，要回头检查 ①～⑤ 哪一层失守

### XSS 防御：输出与二次调用时 HTML 实体转码

1. 检查每个输出点（`echo`/`print`/模板变量）是否在输出前 `htmlspecialchars($var, ENT_QUOTES, 'UTF-8')`
  2. 数据库读出的数据若需拼到 JS 上下文，用 `json_encode($var)`（自动转 `<`、`>`、`/`）
  3. 富文本场景用白名单 HTML 净化器（如 HTMLPurifier），而非 `htmlspecialchars`
  4. 输入阶段只做长度/格式校验，不做 HTML 转码；让数据库存原始数据

### XSS 标签事件白名单优于黑名单

1. 列出业务必需的标签白名单（如 `<p><br><strong><em><a><img><ul><ol><li>`）
  2. 列出业务必需的属性白名单（如 `href`、`src`、`alt`、`title`、`class`）
  3. 列出业务必需的事件白名单（通常为空；若必须用，限定到 `onclick` 且强制 `sanitize`）
  4. 用 HTMLPurifier 或自实现正则解析 HTML，遇到不在白名单的标签/属性/事件直接删除整节点，而非替换字符串
  5. 测试用 `oneronerrorr`、`<scr<script>ipt>`、`<img src=x onerror=...>` 等绕过 payload 验证

### Cookie 无 salt 任意用户登录判据

1. 全局搜 `setcookie`、`$_COOKIE`、`setcookie`、`C::cookie`、`dsetcookie`
  2. 看 Cookie 值的构造：是 `base64(username)`、`md5(password)`、`username:hash` 还是 `encrypt(username, key)`
  3. 若 hash 部分只用 `username + password` 或 `username + 时间戳`，无服务端 salt，判定为可伪造
  4. 若 Cookie 中明文存 username 且服务端直接信任 `$_COOKIE['username']` 取数据，判定为越权
  5. 修复：Cookie 值 = `hmac(username + expiry, server_secret)`，服务端验签

### 找回密码验证码爆破判据（4 位 + 无次数限制 + 无时效）

1. 找「找回密码」功能代码（搜 `resetpassword`、`findpwd`、`forget`、`verify_code`、`sms_code`）
  2. 看验证码长度（4 位 / 6 位 / 8 位）和字符集（数字 / 字母数字）
  3. 看错误次数是否有上限（`if ($error_count > N) lock()`）
  4. 看时效（生成时间戳 + 有效期检查）
  5. 看验证凭证算法：是 `rand()` / `time()` 派生（可预测）还是 `random_bytes(16)`（不可预测）
  6. 三个条件（4 位 / 无次数 / 无时效）任一成立且算法可预测 → 判定爆破可行

### 区分 DDL/DML/DCL 三类 SQL 语句以定位注入影响面

1. 在源码中全局搜 `SELECT|INSERT|UPDATE|DELETE|CREATE|DROP|ALTER|GRANT|REVOKE|COMMIT|ROLLBACK` 关键字 → 拿到候选拼接点清单
  2. 按三类标签分类每个候选点：DML/DDL/DCL
  3. 对每类分别评估：DML 点看可读取/可改写的表范围；DDL 点看是否可达 `DROP TABLE`/`ALTER TABLE ... ADD`；DCL 点看是否可达 `GRANT` 提权
  4. 按危害量级排序：DCL（权限）> DDL（结构）> DML（数据）

### 用 WHERE 子句构造行级筛选条件（SQL 注入的核心 sink）

1. 在应用源码中找到形如 `WHERE col = '${user_input}'` 或 `WHERE col = ${user_input}` 的拼接点 → 标记为注入 sink
  2. 检查用户输入是否走参数化绑定（`?` 占位、`$1` 占位、Prepared statement） → 是则跳过
  3. 若为字符串字面量拼接（带引号）：检查输入是否经过引号转义 + 编码处理
  4. 若为数字字面量拼接（无引号）：检查输入是否经过整数化（`intval`）处理
  5. 检查输入中是否存在 `'`、`"`、`--`、`/*`、`;`、`UNION` 等元字符 → 若存在且未转义，注入成立

### AND 运算优先于 OR 运算（注入逻辑绕过的语法基础）

1. 阅读应用原查询的 WHERE 条件结构，识别 AND 与 OR 的组合
  2. 模拟 SQL 解析器按 AND 优先分组：`A AND B OR C` → `(A AND B) OR C`
  3. 设计注入 payload：在 WHERE 末尾注入 `OR <恒真条件>`，使其与原条件 OR 组合 → 整式恒真
  4. 若原查询已用括号显式分组，注入点需在括号外或先闭合括号

### SQL 三值逻辑 TRUE/FALSE/UNKNOWN（boolean blind injection 的语义基础）

1. 构造盲注条件 `AND (<注入条件>)`，其中 `<注入条件>` 返回 TRUE/FALSE
  2. 观察页面响应：有数据 = TRUE，无数据 = FALSE/UNKNOWN
  3. 若怀疑列含 NULL，先用 `IS NULL` 排除 NULL 行，再注入 boolean 条件以避免 UNKNOWN 干扰
  4. 对二值布尔映射做 binary search：`AND ASCII(SUBSTRING(col,1,1)) > 64` 之类

### 字符串字面量必须单引号括起，数字字面量无需引号（注入形态区分）

1. 阅读应用源码，识别注入点的字面量类型：`WHERE col = '${input}'` 是字符串型，`WHERE col = ${input}` 是数字型
  2. 字符串型：构造 payload 需先闭合引号 `'`，再注入，再用 `--` 或 `#` 截断尾部引号
  3. 数字型：直接注入 SQL 元素，无需闭合引号（如 `1 UNION SELECT ...`）
  4. 修复侧：字符串型用参数化或引号转义（注意多字节编码宽字节问题）；数字型用 `intval` 或参数化

### 子查询先内层后外层执行（subquery injection 的执行模型）

1. 在注入点构造标量子查询 `(SELECT col FROM table WHERE cond)`，验证子查询执行
  2. 标量子查询返回单值，可用于 `=`/`<>` 比较：`AND (SELECT password FROM users WHERE id=1) > 'M'`
  3. 多行子查询用 IN/EXISTS 包装：`AND id IN (SELECT id FROM ...)`
  4. 错误注入：构造会触发类型转换错误的子查询，让错误消息外带数据
  5. 时间注入：子查询内嵌 `SLEEP(N)` 或 `CASE WHEN ... THEN ... ELSE ... END` 配合延迟函数

### UNION 集合运算要求列数与类型对齐（UNION-based injection 的硬约束）

1. 探测列数：`?id=1 ORDER BY 1--`、`?id=1 ORDER BY 2--`...直到报错，确定列数 N
  2. 探测回显位：`?id=-1 UNION SELECT 1,2,...,N--`，观察页面哪些位置出现数字
  3. 在回显位替换为子查询：`?id=-1 UNION SELECT 1,(SELECT user()),3,...--`
  4. 若类型不匹配报错：在回显位用 `NULL` 占位，逐步替换为具体类型值
  5. 若原查询有 `ORDER BY`，注入需用 `--` 截断避免语法冲突

### HAVING 子句指定组条件，WHERE 子句指定行条件

1. 在源码中分别找 `WHERE ${input}` 和 `HAVING ${input}` 拼接点 → 标记不同 sink
  2. WHERE 注入：用 `OR 1=1` 绕过行级筛选
  3. HAVING 注入：用 `OR COUNT(*) > 0` 或 `OR SUM(col) > 0` 绕过组级筛选
  4. 跨子句联合：若 WHERE 与 HAVING 都有拼接点，可联合构造跨子句 payload

### 区分 DROP TABLE 与 DELETE FROM（破坏性注入的两种量级）

1. 在源码中搜 `DROP TABLE`、`DROP DATABASE`、`TRUNCATE` → 标记为高危 DDL sink
  2. 搜 `DELETE FROM` → 标记为中危 DML sink
  3. 评估每个 sink 的输入可控性：参数化 → 低风险；拼接 → 高风险
  4. 评估 DB 用户权限：是否 granting 了 DROP 权限给应用用户；最小权限原则应只授 DML

### 用 INSERT ... SELECT 从其他表复制数据（注入数据外带的合法路径）

1. 在源码中搜 `INSERT INTO ${table}` 拼接点 → 标记为可写 sink
  2. 评估表名/列名是否来自用户输入：若是，注入可达 INSERT...SELECT 数据外带
  3. PoC 构造：`INSERT INTO logs (msg) VALUES ('${input}')` → 输入 `'); INSERT INTO attacker_table SELECT username, password FROM users;--`
  4. 修复侧：表名/列名白名单校验；值用参数化；DB 用户对 INSERT 目标表权限收紧

### 用事务（COMMIT/ROLLBACK/ACID）管理数据更新的原子性

1. 在源码中找事务边界：`BEGIN`/`START TRANSACTION` 与 `COMMIT`/`ROLLBACK` 之间的 DML 是事务内
  2. 注入 sink 在事务内：注入写入可被 ROLLBACK 取消，但需应用检测异常并回滚
  3. 注入 sink 在自动提交模式：注入写入立即生效，无法回滚
  4. 评估 DB 用户对 COMMIT/ROLLBACK 的权限：部分只读账号无 COMMIT 权限

### SQL 关键字大小写不敏感（WAF 绕过的基础语法特性）

1. 测试 WAF 关键字匹配是否大小写敏感：用 `union select` vs `UNION SELECT` vs `UnIoN SeLeCt` 对比
  2. 若 WAF 大小写敏感：用大小写混合绕过，如 `UnIoN SeLeCt 1,2,3--`
  3. 若 WAF 大小写不敏感：改用注释内联绕过（`UN/**/ION SELECT`）或编码绕过
  4. 字符串值匹配场景：WAF 拦 `'admin'` 时，可试 `'ADMIN'`（若 DB 列校对规则大小写不敏感，查询仍命中）

### SQL 语句子句执行顺序（FROM→WHERE→GROUP BY→HAVING→SELECT→ORDER BY）

1. 拆解原查询的子句结构：标记每个子句是否存在
  2. 按执行顺序推演注入 payload 的生效阶段：WHERE 注入在 GROUP BY 前生效，HAVING 注入在 GROUP BY 后
  3. 推断别名可用性：SELECT 别名在 ORDER BY 可用，在 WHERE/HAVING 不可用
  4. 设计跨子句 payload：利用子查询绕过别名限制（如 WHERE 中用 `(SELECT avg...)` 替代 SELECT 别名）

### 统一判停条件

- 单元「失败模式」里列出的任一条件成立时停止该路径，换维度重查；
- OCR 文本不可读、引用无法核对时，只作线索，不写入结论；
- 连续三次同类验证无结果时回到攻击面/问题定义重排优先级。

## B — 失效与边界 (Boundary)

- **敏感关键字回溯参数（逆向追踪审计法）**：作者明确警告「对逻辑漏洞挖掘覆盖不到」——回溯法只看数据流，不看状态机；订单多步交互、积分扣减等逻辑漏洞会被漏掉。此外回溯到 `accept` 这类包装函数后还需继续穿透到 `$_GET/$_POST`，否则会误判过滤已生效。
- **正向追踪变量传递审计法**：框架类应用会把 source 接收集中到路由器/控制器，链路经多层层封装后跨文件跳转，追踪成本陡增，作者建议「学习代码审计的前期建议不要去读开源框架」（Page 53）。
- **通读全文代码审计法（四类关键文件优先）**：框架代码会把审计师「搞得早头[OCR]转向」，作者建议「学习代码审计的前期建议不要去读开源框架或者使用开源框架的应用」（Page 53）——通读法对框架抽象层级敏感，越复杂的框架越需要先学框架本身。
- **功能点定向审计法（四大高危功能点）**：「在使用这种方式审计之前建议先了解整个程序的架构设计和和[OCR]运行流程」（Page 81）——跳过架构了解直接功能点定向，会漏掉跨功能点的链式漏洞（如订单→支付→积分的多步逻辑漏洞）。
- **`magic_quotes_gpc` 不保护 `$_SERVER` 的判据**：PHP 5.4+ 已取消 GPC，本判据的历史版本前提不再适用，但「入口过滤未覆盖 `$_SERVER`」的现代变体依然成立——需结合项目自实现过滤函数的实际覆盖范围判断。
- **`disable_functions` 必须连带禁用 `dl()`**：在 PHP 已编译为 `--enable-maintainer-zts` 或 `dl()` 被禁的 SAPI（如 `mod_php` 在某些发行版）下，`dl()` 本身不可用，本判据不适用；需先确认 SAPI 支持。
- **`open_basedir` 路径必须以斜杠结尾**：多目录配置时（`open_basedir = /www/a/:/tmp/`），易在某个目录上漏掉斜杠；`ini_set` 在运行时设置 `open_basedir` 时，PHP 会把路径缩窄到当前脚本所在目录的父级，行为与 `php.ini` 设置不同，需分别验证。
- **双引号包裹配置值引发代码执行的判据**：PHP 5.5+ 对可变变量在双引号中的解析做了限制，部分 payload 失效；单引号配置不受影响。
- **SQL 注入分层防御路径（gpc → addslashes → mysql_real_escape_string → intval → PDO prepare）**：任何一层单独使用都有绕过——见 CU-1-12（宽字节绕 ①②）、CU-1-13（二次解码绕 ①）、CU-1-16（数组遍历绕 ①）、CU-1-15（PHP<5.3.6 PDO 仿真绕 ⑤）。必须多层叠加。
- **XSS 防御：输出与二次调用时 HTML 实体转码**：在入口统一 `htmlspecialchars` 会导致存储数据被双重转义（`<` → `&lt;` → `&amp;lt;`）；漏掉某个输出点会单点失守；模板引擎的自动转义需在每个模板单独开启，易遗漏。
- **XSS 标签事件白名单优于黑名单**：纯正则做白名单仍可能被 HTML 容错（浏览器会把 `<scr<script>ipt>` 解析成 `<script>`）绕过——必须用真实 HTML 解析器；白名单太宽（允许 `<iframe>`）等于没白名单。
- **Cookie 无 salt 任意用户登录判据**：salt 太短或可预测（如用 `md5(site_name)` 当 salt）仍可被字典攻击；salt 写在源码里泄露后失效（需结合密钥管理）。
- **找回密码验证码爆破判据（4 位 + 无次数限制 + 无时效）**：4 位 + 限制 3 次 + 5 分钟时效的项目，单次爆破不可行，但若验证码重用（同一会话内多次请求不刷新）或验证后不失效，仍可被绕过；需检查「验证码重置时机」。
- **区分 DDL/DML/DCL 三类 SQL 语句以定位注入影响面**：本书未提及安全相关失败模式。读者常见误区是把注入只当成 DML 注入，忽略应用中的 DDL/DCL 拼接点——DDL 拼接点虽少但一旦可达通常是 RCE 级危害（如 `COPY ... TO PROGRAM` in PostgreSQL）。
- **用 WHERE 子句构造行级筛选条件（SQL 注入的核心 sink）**：本书未提及安全失败模式。常见误判：把 `addslashes` 当成充分防护——它在 GBK 等多字节编码下会被宽字节绕过；只检查 `'` 不检查数字拼接点（数字型注入不需要引号闭合）。
- **AND 运算优先于 OR 运算（注入逻辑绕过的语法基础）**：本书明确警告：「想要优先执行 OR 运算时，可以像代码清单 2-36 那样使用半角括号将 OR 部分括起来」（Page 77–78）。应用层若用括号显式分组且输入在括号内，简单 `OR 1=1` 不一定生效；需先闭合括号再注入。
- **SQL 三值逻辑 TRUE/FALSE/UNKNOWN（boolean blind injection 的语义基础）**：本书明确警告：「这就是为什么在创建 shohin 表时，要纵某些列设定 OT MOLL A[OCR]（NOT NULL 约束）」（Page 81）——NULL 列在三值逻辑下会让 boolean 注入结果不稳定。NULL 干扰下，攻击者难以区分 FALSE 与 UNKNOWN，盲注推断会出错。
- **字符串字面量必须单引号括起，数字字面量无需引号（注入形态区分）**：本书未提及安全失败模式。常见错误：把数字型注入当字符串型处理，payload 多加引号导致语法错误；或在 GBK 编码下用 `addslashes` 转义引号被宽字节绕过（`\` 被 GBK 高字节吞掉）。
- **子查询先内层后外层执行（subquery injection 的执行模型）**：本书明确警告：「使用标量子查询时的注意事项...该子查询绝对不能返回多行结果」（Page 171）——标量子查询返回多行会报错。注入时若把多行子查询当作标量子查询使用，会触发「子查询返回多行」错误，注入失败但暴露存在性。
- **UNION 集合运算要求列数与类型对齐（UNION-based injection 的硬约束）**：本书明确警告：「列数必须相同」「类型必须一致」（Page 232）。注入侧若列数不符，会报「UNION 查询的列数不一致」错误；类型不符会报「类型不兼容」错误。两者都暴露注入存在但不直接外带数据。本书还指出 `UNION ALL` 保留重复行，可用于绕过去重过滤。
- **HAVING 子句指定组条件，WHERE 子句指定行条件**：本书明确警告：「WHERE 子名只能指定记录 (行) 的条件，而不能用来指定组的条件」（Page 105）。开发者误把聚合条件写到 WHERE 是常见 bug——SQL 报错，但若应用捕获错误并继续，可能跳过本应过滤的组。
- **区分 DROP TABLE 与 DELETE FROM（破坏性注入的两种量级）**：本书明确警告：「不管使用哪种方法，删除数据时都要慎重，一旦误删，想要恢复数据就会变得十分困难」（Page 133）。注入侧若可达 DROP，无备份则数据永久丢失；DELETE 在自动提交模式下（见 CU-2-21）也无法回滚。
- **用 INSERT ... SELECT 从其他表复制数据（注入数据外带的合法路径）**：本书未提及安全失败模式。常见防护失败：应用只对 INSERT 值参数化，但表名/列名仍拼接——注入点转移；多语句执行被驱动禁用，注入需用子查询而非多语句。
- **用事务（COMMIT/ROLLBACK/ACID）管理数据更新的原子性**：本书明确警告：「在提交之前一定要确认是否真的需要进行这些更新」「万一由于误操作提交了包含错误更新的事务，就只能重新回到重新寻表、重新插入数据这样繁珊的老路上了」（Page 145）。注入侧若误触发 COMMIT，写入永久生效，无法回滚。
- **SQL 关键字大小写不敏感（WAF 绕过的基础语法特性）**：本书未提及安全失败模式。常见误判：以为整个 SQL 都大小写不敏感——实际上字符串字面量大小写敏感，注入字符串值时大小写变换会改变匹配结果。
- **SQL 语句子句执行顺序（FROM→WHERE→GROUP BY→HAVING→SELECT→ORDER BY）**：本书明确警告：「书写顺序和 DBMS 内部的执行顺序并不相同造成的。这也是 SQL 难以理解的原因之一」（Page 99）。开发者误以为按书写顺序执行，导致 WHERE 中误用 SELECT 别名——SQL 报错。

### 授权与合规边界

> 待补充（用户自行填写）
