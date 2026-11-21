# Web安全与代码审计 · OCR 增补：可执行配方与排障

> 本卡由扫描件 OCR 后提取的 **13 个候选单元**按类型聚合而成，逐字引用、执行步骤、失败模式、书内案例均原样保留自 `candidates/ocr-batch-*.md`。这一批是「已提取、按类型归集」的增补材料，与同目录其他能力卡的三重验证 + 人工聚类流程不同，故单独标注，不冒充正式聚类卡。

## R — 原文 (Reading)

> 漏洞的利用依赖PHP 版本、Web 中间件版本与类型、操作系统类型和版本以及这些软件的配置等多因素，所以我们在代码审计前需要做不少的准备工作……对于 PHP, MySQL, Apache 等服务软件版本，尽量使用目前使用最多的版本，比如 PHP 5.2.X、MySQL 5.0 以上，在针对特殊的漏洞测试时可能还需要安装不同的版本进行测试，还需要在不同的操作系统下测试……不同的操作系统下，漏洞的测试结果也可能会不一样。简单举例，像文件包含[OCR]这种漏洞在不同操作系统下路径表示方式不一样，利用方式也会不一样。
>
> — 《代码审计：企业级Web代码安全架构》· 第 1 章 代码审计环境搭建

> 从上面的测试代码中可以发现，数据库操作存在一些关键字，比如 select from、mysql_connect, mysql_query, mysql fetch[OCR] row 等，数据库的查询方式还有update、insert、delete，我们在做白盒审计时，只需要查找这些关键字，即可定向挖掘 SQL 注入漏洞。
>
> — 《代码审计：企业级Web代码安全架构》· 第 4 章 4.1.1.1 普通注入

> 像 HTTP 头里面的HTTP_CLIENT_IP 和HTTP X[OCR] FORWORDFOR 等获取到的 IP 地址经常没有安全过滤就直接拼接到 SQL 语句中,并且由于它们是在 $_ SERVER 变量中不受 GPC 的影响，那我们就可以去查找 HTTP_CLIENT_IP 和HTTP _X_ FORWORDFOR 关键字来快速寻找漏洞……SQL 注入经常出现在登录页面、获取 HTTP 头〈user-agent/client-ip 等)、订单处理等地方……登录页面的注入现在来说大多是发生在 HTTP 头里面的 client-ip 和 x-forward-for，一般用来记录登录的也[OCR]地址。
>
> — 《代码审计：企业级Web代码安全架构》· 第 3 章 3.1

> 在使用PHP 连接 MySQL 的时候，当设置“set character_set_client=gbk”时会导致一个编码转换的注入问题，也就是我们所熟悉的宽字节注和人[OCR]，当存在宽字节注和人[OCR]漏洞时，注和人[OCR]参数里带入 %df%27，即可把程序中过滤的\(%5c) 吃掉……对宽字节注入的挖掘方法也比较简单，只要搜索如下几个关键字即可 : SET NAMES、character _set_client=gbk、mysql _set_charset ('gbk')……关于这个漏洞的解决方法推荐如下几种方法: 1) 在执行查询之前先执行SET NAMES 'gbk',character_set_client=binary 设置 character_set_client 为 binary。 2) 使用mysql_set_charset('gbk) 设置编码，然后使用mysql_real escape _string()函数被[OCR]参数过滤。 3) 使用 pdo 方式，在 PHP5.3.6 及以下版本需要设置 setAttribute(PDO::ATTR_EMULATE_PREPARES, false); 来禁用 prepared statements 的仿真效果。
>
> — 《代码审计：企业级Web代码安全架构》· 第 4 章 4.1.1.2 编码注入

> 只要字符被进行转换就有可能产生漏洞……如果某处使用了 urldecode 或者 rawurldecode 函数，则会导致二次解码生成单引号而引发注入。原理是我们提交参数到 WebServer 时，WebServer 会自动解码一次，假设目标程序开启了 GPC，我们提交 /1.php?id=1%2527，因为我们提交的参数里面没有单引号，所以第一次解码后的结果是 1d[OCR]=1%27, %25 解码的结果是 %，如果程序里面使用了 urldecode 或者 rawurldecode 函数来解码 id参数，则解码后的结果是 id=1"单引号成功出现引发注入……那我们就可以通过搜索 urldecode 和 rawurldecode 函数来挖掘二次 urldecode 注入漏洞。
>
> — 《代码审计：企业级Web代码安全架构》· 第 4 章 4.1.1.2 编码注入

> 挖掘 XSS 漏洞的关键在于寻找没有被过滤的参数，且这些参数传人到输出函数，常用的输出函数列表如下: print、print r、echo 、printf、sprintf、die 、var_dump var_export，所以我们只要寻找带有变量的这些函数即可。另外在代码审计中，XSS 漏洞在浏览器环境对利用的影响非常大，所以最重要的还要掌握各种浏览器容错、编码等特性和数据协议……XSS 漏洞经常出现在文章发表、评论回复、留言以及资料设置等地方，特别是在发文章的时候，因为这里大多都是富文本，有各种图片引用、文字格式设置等，所以经常出现对标签事件过滤不严格导致的XSS。
>
> — 《代码审计：企业级Web代码安全架构》· 第 4 章 4.2.1 挖掘经验

> CSRF 主要是用于越权操作，所有漏洞自然在有权限控制的地方，像管理后台、会员中心、论坛帖子以及交易管理等，这几个场景里面，管理后台又是最高危的地方……我们在挖掘 CSRF 的时候可以先搭建好环境，打开几个有非静态操作的页面，抓包看看有没有 token，如果没有 token 的话，再直接请求这个页面，不带 referer。如果返回的数据还是一样的话[OCR]，那说明很有可能有 CSREF[OCR] 漏洞了。
>
> — 《代码审计：企业级Web代码安全架构》· 第 4 章 4.3.1 挖掘经验

> 从白盒角度来说的话[OCR]，只要读代码的时候看看几个核心文件里面有没有验证 token Ail[OCR] referer 相关的代码，这里的核心文件指的是被大量文件引用的基础文件，或者直接搜 "token" 这个关键字也能找，如果在核心文件没有，再去看看你比较关心的功能点的代码有没有验证。
>
> — 《代码审计：企业级Web代码安全架构》· 第 4 章 4.3.1 挖掘经验

> 注释是 SQL 语句中用来标识说明或者注意事项的部分。注释对 SQL 的执行没有任何影响。因此，无论是英文字母还是汉字都可以随意使用- 注释的书写方法有如下两种-
> 1行注和[OCR] = 书写在"--"之后，只能写在同一行...多行注和[OCR] ... /* ... */  (Page 60，原文规则部分 OCR 残缺，由代码清单 2-13 `-- 本SELECT语句用来除去结果中的重复数据。` 与代码清单 2-14 `/* xSELECTBO, FRR OME, + /` 印证)
>
> — 《SQL基础教程》· 第 2 章 2-1 注释的书写方法

> 截至目前，我们使用字符串作为查询条件的例子中，使用的都是=. 这里的 = 只有在字符串完全一致时才为真。与之相反，LIKE 谓词更加模[OCR]...部分一臻[OCR]大体可以分为前方一致、 中辐一致[OCR]有后方一致三种类型。
> 其中的"$"是代表"0 字符以上的任意字符串"的特殊符号。本例中代表"以 aaa 开头的所有字符串"...此外，我们还可以使用 _〈下划线) 来代替$，与不同的是其代表了"任意 1个字符"。
>
> — 《SQL基础教程》· 第 6 章 6-2 LIKE 谓词一一字符串的部分一致查询

> IN 谓词 (NoT IN 谓词》 具有其他谓词所没有的使用方法。那就是可以使用子查询作为其参数来使用。我们已经在 5-2 节中学习过了，子查询就是 SQL 内部生成的表。因此也可以说"能够将表作为 IN 的参数"。同理，我们还可以说"能够将视图作为 IN 的参数"。
> 但需要注意的是，在使用 IN 和 NOT IN 时是无法选取出 NULL 数据的。实际结果也是如此，上述两组结果中都不包含进货单价为 NOLL[OCR] 的叉子和圆 BRAG[OCR]。NULL 终究还是需要使用 TS NULL[OCR] 和 IS NOT NULL 来进行判断。
>
> — 《SQL基础教程》· 第 6 章 6-2 使用子查询作为IN谓词的参数

> 一言以蔽之，谓词的作用就是"判断是否存在满足某种条件的记录". 如果存在这样的记录就反回真 (TRUE)，如果不存在就返回假 (FALSE). EXIST (存在) 谓词的主语是"记录"。
> 理由@和@都说明 EXIST 是使用方法特殊而难以理解的调[OCR]词.特别是使用否定形式 NOT EXIST 的 SELECT 语句，即使是 DB 工程师也常常无法迅速理解。
>
> — 《SQL基础教程》· 第 6 章 6-2 EXIST谓词

> 使用 BETWEEN 可以进行范围查询。该谓词与其他谓词或者函数的不同之处在于它使用了 3 PR[OCR]. lin[OCR]. Ah shohin 《商品)表中读取出销售单价 (hanbai_tanka) 为 100 日元到 1000 日元之间的商品时，可以使用代码清单 6-27 中的 SQL 语句...BETWEEN 的特点就是结果中会包含 100 和 1000 这两个临界值。
>
> — 《SQL基础教程》· 第 6 章 6-2 BETWEEN谓词一一范围查询

## I — 方法论骨架 (Interpretation)

**企业级代码审计环境准备（多版本+多系统）** — 漏洞的「可利用性」是代码 + PHP 版本 + Web 中间件 + OS + 配置五元组共同决定的，不是代码单变量函数。一个 `include $_GET['a']` 在 PHP 5.2 + `allow_url_include=on` 是远程文件包含，在 PHP 5.4 默认配置下就只是本地包含。审计环境必须能复现目标五元组，否则会大量「审计到漏洞但 PoC 不成立」。多版本切换用 phpStudy 这类集成包，比手动编译快一个量级。

**SQL 注入关键字定向挖掘** — SQL 注入的 sink 是「执行 SQL 的函数」，source 是「外部参数」。 sink 集合在 PHP + MySQL 技术栈下是闭集：`mysql_query`、`mysql_db_query`、`mysqli_query`、`PDO::query`、`PDO::exec`、`$db->query`（封装后）、`execute`。SQL 字符串构造常用 `select`/`from`/`where`/`update`/`insert`/`delete` 关键字与变量拼接。先搜 sink 再看上下文，比通读全文快一个量级。

**HTTP 头 IP 字段 SQL 注入挖掘** — 登录页常把客户端 IP 记到登录日志表，开发者直接把 `$_SERVER['HTTP_CLIENT_IP']`/`$_SERVER['HTTP_X_FORWARDED_FOR']` 拼 SQL。这两个字段由客户端在 HTTP 头里发送，完全可控，且不受 GPC 保护（见 CU-1-06）。挖掘时搜这两个关键字比搜 `mysql_query` 更精准——直接锁定「IP 入库」的业务场景。

**MySQL 宽字节注入挖掘与三种修复** — GBK 编码下 `%df%5c` 合成一个汉字「运」，吃掉 `addslashes` 加的反斜杠 `%5c`，使原本被转义的单引号 `%27` 重新裸露。根因是「PHP 端按字节转义，MySQL 端按 GBK 解码」的编码不对称。挖掘靠搜三个关键字定位「GBK 连接」，靠 `%df'` 验证。修复要打破不对称——把 client 编码设为 `binary` 让 MySQL 不做 GBK 解码，或用 `mysql_real_escape_string` 它会感知当前字符集，或用 PDO 强制服务端预编译。

**二次 urldecode 注入挖掘** — WebServer 接收参数时做了一次 URL 解码（`%27` → `'`），此时 GPC 会转义这个 `'`。但若代码里又显式调用 `urldecode($var)`，相当于做第二次解码。攻击者提交 `%2527`：第一次解码变成 `%27`（无单引号，GPC 不动），第二次解码变成 `'`（绕过 GPC）。根因是「WebServer 解码 + 代码显式解码」的次数不对称。搜 `urldecode`/`rawurldecode` 即可定位。

**XSS 输出函数关键字定向挖掘** — XSS 的 sink 是「输出到浏览器的函数」，比 SQLi 的 sink 更分散（7 个常用函数）。source 同样是外部参数。挖掘逻辑与 SQLi 同构——搜 sink、回溯 source、看过滤。但 XSS 多一个变量：输出上下文（HTML 标签内 / 属性内 / JS 内 / URL 内）决定所需绕过方式不同，富文本场景更复杂。富文本场景必须用白名单而非黑名单。

**CSRF 黑盒三步判据（抓包看 token → 去 referer 复请求 → 对比响应）** — CSRF 的判据是「服务器不验证请求来源」。三步法对应三个判别信号：①请求里有没有 token（无 → 可能漏洞）；②不带 referer 服务器是否仍接受（接受 → 跨站请求可被构造）；③响应是否一致（一致 → 操作完成）。三步全过即可判定漏洞。黑盒三步法适用于快速过一遍管理后台所有非静态操作。

**CSRF 白盒 token 关键字搜索（核心基础文件优先）** — CSRF 防御代码要么集中在「全局基础文件」（每个请求都过一遍），要么分散在「各功能点」。集中式一处即可判定全局水位；分散式只能逐功能点查。先搜 `token` 定位集中式实现——若核心文件有，CSRF 大面积被防住，剩余只查「未走核心文件的特殊入口」；若核心文件没有，所有功能点都需逐个检查。搜索路径优先级：`common.php`/`common.inc.php`/`init.php`/`index.php` 头部 → 各 `admin/*.php` 入口 → 具体功能文件。

**用 `--` 和 `/* */` 书写 SQL 注释（注入截断的标准工具）** — SQL 标准注释有 `--`（单行，到行尾）和 `/* ... */`（多行，可跨行）两种。注释对执行无影响——这意味着用户输入中如果包含 `--` 或 `/* */`，应用拼接的 SQL 后半段会被数据库当成注释丢弃。这是 SQL 注入中「截断原查询后半段」的标准手段：典型 payload `' OR 1=1 --` 用 `--` 注释掉原查询尾部的 `'` 或 `ORDER BY` 子句。本书只讲注释的合法用途，但注释语法的存在性本身即是注入可用工具——安全工程师必须知道目标 RDBMS 支持哪些注释符（标准 `--` 与 `/* */`、MySQL 额外有 `#`）。

**用 LIKE 谓词和 `%`/`_` 通配符做模式匹配** — LIKE 谓词用 `%`（0 个或多个任意字符）和 `_`（恰好 1 个任意字符）做模式匹配，支持前方一致（`'abc%'`）、中间一致（`'%abc%'`）、后方一致（`'%abc'`）。本书指出 `=` 只匹配完全一致，LIKE 才支持部分一致。LIKE 是注入 sink 的常见类型——应用搜索框若直接拼 `WHERE col LIKE '%${input}%'`，用户输入中的 `'`、`%`、`_` 都会改变查询语义：(1) `'` 闭合字面量触发常规注入；(2) `%` 和 `_` 是通配符，可构造通配符注入（如输入 `%` 让条件变成 `LIKE '%%%'` 匹配所有）；(3) 通配符本身可用于 blind injection 枚举数据（`AND password LIKE 'a%'` 逐字符推断）。

**用 IN/NOT IN 谓词接受子查询作为参数（blind 注入的枚举工具）** — IN/NOT IN 谓词的特殊性在于可接受子查询作为参数（其他谓词只能接受值列表）。子查询参数会先执行，结果作为 IN 的值列表。这一特性让 IN 成为盲注枚举的核心工具：(1) 用 `IN (SELECT ...)` 把外带数据嵌入子查询，通过 IN 匹配结果反映到外层条件；(2) `NOT IN (SELECT ...)` 反向枚举。本书还警告「IN 和 NOT IN 无法选取 NULL 数据」——这是注入侧的失败模式：若子查询结果含 NULL，`NOT IN` 会返回空（因为 `x NOT IN (a, NULL)` 等价于 `x <> a AND x <> NULL`，后者是 UNKNOWN，AND 中 UNKNOWN 接近 FALSE），导致盲注误判。

**用 EXISTS/NOT EXISTS 谓词判断子查询是否返回行** — EXISTS 谓词接受子查询，子查询返回至少 1 行则 TRUE，否则 FALSE。本书指出 EXISTS 难点在「NOT EXISTS」——双重否定。EXISTS 的安全性在于：(1) 不关心子查询返回什么列，只关心是否有行——这让 EXISTS 注入比 IN 注入更隐蔽（不需要列对齐）；(2) 关联子查询中的 EXISTS 会对外层每一行执行一次子查询，是行级判断；(3) EXISTS 注入是盲注的理想工具——`AND EXISTS (SELECT 1 FROM users WHERE password LIKE 'a%')` 在条件成立时返回正常页面，不成立时返回空，构造二分搜索可逐字符推断数据。

**用 BETWEEN 谓词做范围查询（盲注二分搜索的工具）** — BETWEEN 是三参数谓词（值 + 下界 + 上界），返回值在 [下界, 上界] 闭区间内为 TRUE。本书特别强调「结果中会包含临界值」——这是 BETWEEN 与 `> AND <` 的关键区别（后者开区间）。BETWEEN 是盲注二分搜索的理想工具：(1) 用 `AND ascii(SUBSTRING(col,1,1)) BETWEEN 97 AND 122` 快速锁定字符范围；(2) 二分缩窄：`BETWEEN 97 AND 109`、`BETWEEN 97 AND 103`...；(3) 用 BETWEEN 比较多个字段值时需保证类型一致。闭区间特性意味着二分逻辑需调整：mid 计算后下界或上界要 +1/-1，否则死循环。

## A1 — 应用示例 (Application Example)

### 示例 1: 企业级代码审计环境准备（多版本+多系统）
- **类型与来源**: 【recipe】《代码审计：企业级Web代码安全架构_ocr.txt》· 第 1 章 代码审计环境搭建（Page 17–18）+ 前言（Page 7）
- **问题/输入**: 目标环境的 phpinfo 截图或 `php -i` 输出；目标 Web 中间件类型；目标 OS 类型。
- **方法论的使用**: 漏洞的「可利用性」是代码 + PHP 版本 + Web 中间件 + OS + 配置五元组共同决定的，不是代码单变量函数。一个 `include $_GET['a']` 在 PHP 5.2 + `allow_url_include=on` 是远程文件包含，在 PHP 5.4 默认配置下就只是本地包含。审计环境必须能复现目标五元组，否则会大量「审计到漏洞但 PoC 不成立」。多版本切换用 phpStudy 这类集成包，比手动编译快一个量级。
- **结果**: 未提供独立案例，作为第 1 章总论贯穿全书。

### 示例 2: SQL 注入关键字定向挖掘
- **类型与来源**: 【recipe】《代码审计：企业级Web代码安全架构_ocr.txt》· 第 4 章 4.1.1.1 普通注入（Page 84–85）
- **问题/输入**: PHP + MySQL 技术栈；源码可索引。
- **方法论的使用**: SQL 注入的 sink 是「执行 SQL 的函数」，source 是「外部参数」。 sink 集合在 PHP + MySQL 技术栈下是闭集：`mysql_query`、`mysql_db_query`、`mysqli_query`、`PDO::query`、`PDO::exec`、`$db->query`（封装后）、`execute`。SQL 字符串构造常用 `select`/`from`/`where`/`update`/`insert`/`delete` 关键字与变量拼接。先搜 sink 再看上下文，比通读全文快一个量级。
- **结果**: 【亲历】espcms `$sql = "select * from $db_table where parentid=$parentid"`，`$parentid` 经 `daddslashes` 过滤但 SQL 不需单引号闭合，int 型注入成立（Page 64–65）；【例题】`$uid=$_GET['id']; $sql="SELECT * FROM userinfo where id=$uid"`（Page 85）。

### 示例 3: HTTP 头 IP 字段 SQL 注入挖掘
- **类型与来源**: 【recipe】《代码审计：企业级Web代码安全架构_ocr.txt》· 第 3 章 3.1（Page 62）+ 第 4 章 4.1.1（Page 84）
- **问题/输入**: PHP 项目有登录日志/操作日志功能；可 Burp 抓包改 HTTP 头。
- **方法论的使用**: 登录页常把客户端 IP 记到登录日志表，开发者直接把 `$_SERVER['HTTP_CLIENT_IP']`/`$_SERVER['HTTP_X_FORWARDED_FOR']` 拼 SQL。这两个字段由客户端在 HTTP 头里发送，完全可控，且不受 GPC 保护（见 CU-1-06）。挖掘时搜这两个关键字比搜 `mysql_query` 更精准——直接锁定「IP 入库」的业务场景。
- **结果**: 【转述】作者明确说「登录页面的注入现在来说大多是发生在 HTTP 头里面的 client-ip 和 x-forward-for」（Page 84）；骑士 cms 的 `getip()` 虽做了正则但作者仍评论「是可以伪造 IP 地址的」（Page 73）。

### 示例 4: MySQL 宽字节注入挖掘与三种修复
- **类型与来源**: 【recipe】《代码审计：企业级Web代码安全架构_ocr.txt》· 第 4 章 4.1.1.2 编码注入（Page 85–87）
- **问题/输入**: PHP + MySQL 项目；连接编码为 GBK/GB2312（`config.php` 里 `DBCHARSET='GBK'` 是强信号）。
- **方法论的使用**: GBK 编码下 `%df%5c` 合成一个汉字「运」，吃掉 `addslashes` 加的反斜杠 `%5c`，使原本被转义的单引号 `%27` 重新裸露。根因是「PHP 端按字节转义，MySQL 端按 GBK 解码」的编码不对称。挖掘靠搜三个关键字定位「GBK 连接」，靠 `%df'` 验证。修复要打破不对称——把 client 编码设为 `binary` 让 MySQL 不做 GBK 解码，或用 `mysql_real_escape_string` 它会感知当前字符集，或用 PDO 强制服务端预编译。
- **结果**: 【亲历】骑士 cms `/data/config.php` 设 `QISHI_DBCHARSET='GBK'`，`mysql.class.php` 的 `connect()` 执行 `mysql_query("SET NAMES gbk")`，作者判定「在 MySQL 版本大于 4.1 小于 5 的情况下，基本所有跟数据库有关的操作都存在[宽字节注入]」（Page 76）；【例题】测试代码 `mysql_query("SET NAMES 'gbk'", $conn); $uid=addslashes($_GET['id']);` 提交 `?id=%df' union select 1,2,3,4%23` 成功注入（Page 86）。

### 示例 5: 二次 urldecode 注入挖掘
- **类型与来源**: 【recipe】《代码审计：企业级Web代码安全架构_ocr.txt》· 第 4 章 4.1.1.2 编码注入（Page 87–88）
- **问题/输入**: PHP 项目；代码中存在 `urldecode`/`rawurldecode` 调用且参数来自外部输入。
- **方法论的使用**: WebServer 接收参数时做了一次 URL 解码（`%27` → `'`），此时 GPC 会转义这个 `'`。但若代码里又显式调用 `urldecode($var)`，相当于做第二次解码。攻击者提交 `%2527`：第一次解码变成 `%27`（无单引号，GPC 不动），第二次解码变成 `'`（绕过 GPC）。根因是「WebServer 解码 + 代码显式解码」的次数不对称。搜 `urldecode`/`rawurldecode` 即可定位。
- **结果**: 【亲历】espcms `interface/search.php` 的 `in_taglist()` 函数：`$tagkey = urldecode($this->fun->accept('tagkey', 'R'));` 经 `urldecode` 绕过 GPC，拼到 `AND FIND_IN_SET('$tagkey', tags)` 引发注入（Page 88–89）；【例题】`$a=addslashes($_GET['p']); $b=urldecode($a);` 提交 `?p=1%2527` 输出 `$b=1'`（Page 88）。

### 示例 6: XSS 输出函数关键字定向挖掘
- **类型与来源**: 【recipe】《代码审计：企业级Web代码安全架构_ocr.txt》· 第 4 章 4.2.1 挖掘经验（Page 92–93）
- **问题/输入**: PHP 项目；源码可索引；熟悉 HTML/JS 上下文所需的不同 payload。
- **方法论的使用**: XSS 的 sink 是「输出到浏览器的函数」，比 SQLi 的 sink 更分散（7 个常用函数）。source 同样是外部参数。挖掘逻辑与 SQLi 同构——搜 sink、回溯 source、看过滤。但 XSS 多一个变量：输出上下文（HTML 标签内 / 属性内 / JS 内 / URL 内）决定所需绕过方式不同，富文本场景更复杂。富文本场景必须用白名单而非黑名单。
- **结果**: 【例题】反射型 XSS：`echo "Sig:".$_GET["oauth_signature"]."\n";` 直接输出 GET 参数（Page 93）；【亲历】骑士 cms 存储型 XSS：友情链接申请页 logo 字段输入 `1 oner&#114;or=ale&#114;t (1)`，HTML 实体编码绕过 `remove_xss`，后台管理员查看时触发（Page 95–96）。

### 示例 7: CSRF 黑盒三步判据（抓包看 token → 去 referer 复请求 → 对比响应）
- **类型与来源**: 【recipe】《代码审计：企业级Web代码安全架构_ocr.txt》· 第 4 章 4.3.1 挖掘经验（Page 99）
- **问题/输入**: 测试环境；管理后台账号；Burp Suite。
- **方法论的使用**: CSRF 的判据是「服务器不验证请求来源」。三步法对应三个判别信号：①请求里有没有 token（无 → 可能漏洞）；②不带 referer 服务器是否仍接受（接受 → 跨站请求可被构造）；③响应是否一致（一致 → 操作完成）。三步全过即可判定漏洞。黑盒三步法适用于快速过一遍管理后台所有非静态操作。
- **结果**: 【转述】作者明确说「管理后台又是最高危的地方」（Page 99）；【亲历】Discuz CSRF 备份拖库（Page 99–100）：`source/admincp/admincp_db.php` 第 30 行起未做 `formhash` 验证，表名和文件名从 `$_GET` 直接提交，构造 `<img src="http://127.0.0.1/discuz/admin.php?action=db&operation=export&...">` 嵌入论坛帖子即可让管理员访问时触发拖库。

### 示例 8: CSRF 白盒 token 关键字搜索（核心基础文件优先）
- **类型与来源**: 【recipe】《代码审计：企业级Web代码安全架构_ocr.txt》· 第 4 章 4.3.1 挖掘经验（Page 99）
- **问题/输入**: 源码可索引；能识别项目的「核心基础文件」（通常是入口 include 链的终点）。
- **方法论的使用**: CSRF 防御代码要么集中在「全局基础文件」（每个请求都过一遍），要么分散在「各功能点」。集中式一处即可判定全局水位；分散式只能逐功能点查。先搜 `token` 定位集中式实现——若核心文件有，CSRF 大面积被防住，剩余只查「未走核心文件的特殊入口」；若核心文件没有，所有功能点都需逐个检查。搜索路径优先级：`common.php`/`common.inc.php`/`init.php`/`index.php` 头部 → 各 `admin/*.php` 入口 → 具体功能文件。
- **结果**: 未提供独立案例，与 CU-1-20 的 Discuz 案例对照（该案例就是因为核心文件 `admincp_db.php` 没有 `formhash` 验证才被拖库）。

## A2 — 相邻能力 (Adjacency)

1. 出现「审计环境怎么搭」这类信号时，回到本卡查对应单元的方法与判据。
2. 出现「不同 PHP 版本切换」这类信号时，回到本卡查对应单元的方法与判据。
3. 出现「这个漏洞在我环境复现不了」这类信号时，回到本卡查对应单元的方法与判据。
4. 出现「php audit environment」这类信号时，回到本卡查对应单元的方法与判据。
5. 出现「multi-version php setup」这类信号时，回到本卡查对应单元的方法与判据。
6. 出现「SQL 注入怎么挖」这类信号时，回到本卡查对应单元的方法与判据。

语言信号：「审计环境怎么搭」、「不同 PHP 版本切换」、「这个漏洞在我环境复现不了」、「php audit environment」、「multi-version php setup」、「SQL 注入怎么挖」

本卡为增补材料，正式能力卡请优先读：`recon-asset-surface`、`injection-channel-selection`。

**相邻区分（原文）**：

- 与 CU-1-06～CU-1-09 是「环境 vs 配置项」差异——本单元讲环境编排，后四个讲具体配置项的安全判据。

---
- 与 CU-1-11/12/13 是「定向配方」细分——本单元给总框架，后三个给具体变体（HTTP 头/宽字节/二次解码）。

---
- 与 CU-1-10 是「场景特化」——本单元针对登录 IP 记录场景，CU-1-10 给通用 SQL sink 搜法。

---
- 与 CU-1-13「二次 urldecode 注入」同属「编码不对称类」注入，但根因不同——本单元是 PHP/MySQL 字符集不对称，CU-1-13 是 WebServer/PHP 解码次数不对称。

---
- 与 CU-1-12「宽字节」是「编码不对称类」姐妹篇——宽字节是字符集不对称，本单元是解码次数不对称。

---
- 与 CU-1-18/19 是「挖掘 vs 防御」关系——本单元给挖掘配方，后两个给防御原则。

---
- 与 CU-1-21 是「黑盒 vs 白盒」同题姐妹——本单元黑盒三步，CU-1-21 白盒关键字搜。

---
- 与 CU-1-20 是「黑盒 vs 白盒」同题姐妹——本单元白盒搜索，CU-1-20 黑盒三步。

---

## E — 执行步骤 (Execution)

### 企业级代码审计环境准备（多版本+多系统）

1. 装一套 phpStudy（Win）或 lamp/lnmp 集成包（Linux），覆盖 PHP 5.2/5.3/5.4/5.5/5.6 + Apache/Nginx + MySQL 五个组合
  2. 对照目标 phpinfo 拉齐 `magic_quotes_gpc`、`magic_quotes_runtime`、`safe_mode`、`open_basedir`、`disable_functions`、`display_errors`、`allow_url_include`、`allow_url_fopen`、`short_open_tag` 等关键配置
  3. 对特殊漏洞（宽字节、文件包含、`%00` 截断）单独切换到对应 PHP 版本测试
  4. 跨 OS 验证路径相关漏洞：Windows 用 `\` 和 `..\\`，Linux 用 `/` 和 `../`，验证 PoC 是否依赖路径分隔符

### SQL 注入关键字定向挖掘

1. 全局搜索 sink：`mysql_query`、`mysqli_query`、`->query(`、`->execute(`、`PDO::query`、`->exec(`
  2. 命中处向上看 SQL 字符串构造，定位拼接变量（`"...$var..."` / `"...".$var."..."` / `sprintf("...%s...", $var)`）
  3. 回溯变量来源，确认是否外部可控
  4. 检查拼接前是否经过 `addslashes`/`mysql_real_escape_string`/`intval`/`PDO prepare` 过滤
  5. 若是 string 型拼接且仅有 `addslashes`，看是否宽字节可绕过；若是 int 型拼接且无 `intval`，直接判为注入

### HTTP 头 IP 字段 SQL 注入挖掘

1. 全局搜 `HTTP_CLIENT_IP`、`HTTP_X_FORWARDED_FOR`、`HTTP_X_FORWORDFOR`（注意作者拼错的变体）、`getenv('HTTP_CLIENT_IP')`、`getenv('HTTP_X_FORWARDED_FOR')`
  2. 命中处看变量是否拼到 `INSERT INTO ... login_log` 或 `UPDATE ... SET last_ip = ...`
  3. 检查是否做 IP 格式校验（`\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}`）；若只取第一段正则匹配但不限制整体，仍可注入
  4. Burp 抓登录请求，在 `X-Forwarded-For` 头注入 `1' union select 1,2,3#` 验证

### MySQL 宽字节注入挖掘与三种修复

1. 搜 `SET NAMES`、`character_set_client=gbk`、`mysql_set_charset('gbk')`、`mysql_query("SET NAMES gbk"`
  2. 命中处向上确认数据库连接代码，看编码设置后是否补 `character_set_client=binary`
  3. 若未补，构造 payload `?id=%df' union select 1,2,3#` 验证
  4. 修复三选一：
     - 执行 `SET NAMES 'gbk', character_set_client=binary`
     - `mysql_set_charset('gbk')` + `mysql_real_escape_string($var, $conn)`
     - PDO + `setAttribute(PDO::ATTR_EMULATE_PREPARES, false)`

### 二次 urldecode 注入挖掘

1. 全局搜 `urldecode(`、`rawurldecode(`
  2. 命中处看变量是否来自 `$_GET/$_POST/$_REQUEST` 且最终拼到 SQL
  3. 构造 payload `%2527`（即 `%27` 的二次 URL 编码）测试
  4. 修复：去掉多余的 `urldecode`（WebServer 已解码一次），或显式对二次解码结果再次 `addslashes`

### XSS 输出函数关键字定向挖掘

1. 全局搜 `echo`、`print`、`printf`、`sprintf`、`die`、`var_dump`、`var_export`、`print_r`
  2. 命中处看变量来源（`$_GET` 直接输出 → 反射型；从数据库/文件读出 → 存储型）
  3. 检查输出前是否 `htmlspecialchars` / `strip_tags` / `remove_xss`
  4. 看输出上下文：标签内（需 `<` `>`）、属性内（需 `"` 或 `'` 闭合）、JS 内（需 `</script>` 或 `\` 转义）、URL 内（需 `javascript:`）
  5. 富文本场景搜 `strip_tags`、`remove_xss` 等过滤函数，看是黑名单还是白名单
  6. 重点检查文章发表、评论、留言、资料设置（昵称/签名）四个功能点

### CSRF 黑盒三步判据（抓包看 token → 去 referer 复请求 → 对比响应）

1. 搭建测试环境，登录管理后台/会员中心
  2. 对每个非静态操作（增删改、配置修改）Burp 抓包，看请求里是否有 `token=` / `csrf_token` / `__hash__` 等字段
  3. 若无 token，把请求复制到 Burp Repeater，删除 `Referer` 头重新发送
  4. 对比带/不带 Referer 的响应，若状态码与响应体一致 → 判定 CSRF 成立
  5. 构造 PoC：`<img src="http://target/admin.php?action=del&id=1">` 嵌入跨站页面

### CSRF 白盒 token 关键字搜索（核心基础文件优先）

1. 全局搜 `token`、`csrf`、`formhash`、`_hash`、`verify_token`、`check_token`
  2. 命中处看是否在核心基础文件（`common.inc.php`、`admin/common.php`）中且对每个请求强制校验
  3. 若核心文件无，逐个看关心的功能点（增删改、配置修改、用户管理）的代码
  4. 检查 token 校验逻辑：是否比较 `$_POST['token']` 与 `$_SESSION['token']`，是否一次性（用后失效），是否绑用户（防跨用户借用）
  5. 同时搜 `Referer`、`HTTP_REFERER`，看是否做来源校验

### 用 `--` 和 `/* */` 书写 SQL 注释（注入截断的标准工具）

1. 在用户输入中检测 `--`、`/*`、`*/`、`#`（MySQL）→ 出现任一即标记为潜在注释截断 payload
  2. 用注释截断法构造 PoC：在注入点插入 `' OR 1=1 -- `，验证是否能注释掉原查询尾部
  3. 若原查询尾部有 `ORDER BY` 等子句导致 UNION 注入难以对齐，用 `/* ... */` 包裹尾部子句以跳过
  4. 修复侧：在应用层对用户输入中的 `--`、`/*`、`*/` 做转义或拒绝——但根本解法仍是参数化绑定

### 用 LIKE 谓词和 `%`/`_` 通配符做模式匹配

1. 在 LIKE 注入点先用 `'` 闭合字面量，验证是否走字符串字面量拼接
  2. 通配符枚举：`AND password LIKE 'a%'` → TRUE 时首位是 a；继续 `AND password LIKE 'ab%'` 缩窄
  3. 通配符注入 DoS：输入超长 `%` 串让 LIKE 退化为全表扫描，消耗 DB 资源
  4. 修复侧：对用户输入中的 `%`、`_` 做转义（`ESCAPE '\'` 子句），但根本解法是参数化

### 用 IN/NOT IN 谓词接受子查询作为参数（blind 注入的枚举工具）

1. 在注入点构造 `AND id IN (SELECT id FROM ...)`，子查询先执行产生值列表，外层 IN 匹配
  2. 用 `NOT IN` 反向枚举：`AND id NOT IN (SELECT id FROM ...)` 选出不匹配的
  3. 若子查询可能返回 NULL，用 `AND id IN (SELECT id FROM ... WHERE id IS NOT NULL)` 排除 NULL 干扰
  4. 二分枚举：`AND ascii(SUBSTRING((SELECT ...),1,1)) IN (97,98,99,...)` 缩窄字符集

### 用 EXISTS/NOT EXISTS 谓词判断子查询是否返回行

1. 在注入点构造 `AND EXISTS (SELECT 1 FROM target_table WHERE <condition>)`
  2. 二分搜索：`AND EXISTS (SELECT 1 FROM users WHERE password LIKE 'a%')` → TRUE 时密码首位是 a 类字符
  3. 缩窄：`AND EXISTS (SELECT 1 FROM users WHERE password LIKE 'ab%')` → TRUE 时前两位是 ab
  4. 反向：`AND NOT EXISTS (SELECT 1 FROM ...)` 验证不存在性

### 用 BETWEEN 谓词做范围查询（盲注二分搜索的工具）

1. 用 `BETWEEN 0 AND 255` 锁定字符 ASCII 范围
  2. 二分：`BETWEEN 0 AND 127` → TRUE 时缩窄到 [0,127]，FALSE 时缩窄到 [128,255]
  3. 注意闭区间：缩窄时 `BETWEEN 0 AND 127` TRUE 后，下次用 `BETWEEN 0 AND 63`，避免重复测试 mid
  4. 排除临界值场景：用 `> AND <` 开区间替代 BETWEEN

### 统一判停条件

- 单元「失败模式」里列出的任一条件成立时停止该路径，换维度重查；
- OCR 文本不可读、引用无法核对时，只作线索，不写入结论；
- 连续三次同类验证无结果时回到攻击面/问题定义重排优先级。

## B — 失效与边界 (Boundary)

- **企业级代码审计环境准备（多版本+多系统）**：只装一个 PHP 最新版就开审，会把所有「PHP 5.4 之前才存在」的漏洞漏掉（如 `magic_quotes_gpc`、`%00` 截断、`safe_mode` 绕过）；反之只装旧版会把「新版本已修复」的漏洞误报为可利用。
- **SQL 注入关键字定向挖掘**：框架的 ORM 层（如 ThinkPHP 的 `M()->where()->select()`）会把 sink 隐藏到链式调用里，单纯搜关键字会漏；需配合搜 `where(`、`find(`、`select(` 等链式 sink。
- **HTTP 头 IP 字段 SQL 注入挖掘**：部分框架（如 Discuz 的 `getip()`）做了完整 IP 正则约束 + `intval` 段验证，注入不成立；需先确认正则约束是否够严。
- **MySQL 宽字节注入挖掘与三种修复**：`mysql_set_charset('gbk')` 看似安全，但作者明确说「不幸的是它也只是调用了 SET NAMES ，所以效果也是一样的」——只有配合 `mysql_real_escape_string` 才能真正生效，单用仍可绕过。PHP 5.3.6 以下的 PDO 默认本地仿真 prepare，仍存在宽字节，必须显式 `ATTR_EMULATE_PREPARES=false`。
- **二次 urldecode 注入挖掘**：若代码用 `urldecode` 解码后立即用 `intval` 转 int，注入不成立；需确认解码后是否直接拼 SQL。
- **XSS 输出函数关键字定向挖掘**：富文本场景的黑名单几乎总被绕过（作者明确推荐白名单）；模板引擎的自动转义（如 Twig 的 `autoescape`）会让 `echo $var` 看似无过滤实则安全，需先确认模板配置。
- **CSRF 黑盒三步判据（抓包看 token → 去 referer 复请求 → 对比响应）**：部分操作虽无 token 但检查 `Referer`，三步法的「不带 Referer」会触发拦截；需先单独验证「Referer 是否被检查」再做判定。一些操作需要 CSRF token 但放在 cookie 里，请求里看不到 `token=` 字段，需特别检查 cookie。
- **CSRF 白盒 token 关键字搜索（核心基础文件优先）**：token 在核心文件里但仅 `if (isset($_POST['token']))` 检查存在性而不校验值等于 session 中的 token；或 token 不一次性、不过期，可被预测/复用——校验存在 ≠ 校验有效，需读完整逻辑。
- **用 `--` 和 `/* */` 书写 SQL 注释（注入截断的标准工具）**：本书未提及安全失败模式。`--` 后必须有空格或换行（SQL 标准要求），某些场景下 `--x` 不被识别为注释；`/* */` 未闭合会导致整个查询语法错误，注入反而失败。
- **用 LIKE 谓词和 `%`/`_` 通配符做模式匹配**：本书未提及安全失败模式。常见误判：LIKE 注入点认为 `%` 是无害字符——实际上 `%` 在 LIKE 上下文中是通配符，会改变匹配范围；MySQL 默认大小写不敏感的 LIKE 在 PostgreSQL/Oracle 中大小写敏感，跨 DBMS 注入需调整。
- **用 IN/NOT IN 谓词接受子查询作为参数（blind 注入的枚举工具）**：本书明确警告：「在使用 IN 和 NOT IN 时是无法选取出 NULL 数据的...NULL 终究还是需要使用 IS NULL 和 IS NOT NULL 来进行判断」（Page 209）。`NOT IN` 子查询含 NULL 时全表不匹配——这是 SQL 的反直觉行为，注入侧会因此误判列空。
- **用 EXISTS/NOT EXISTS 谓词判断子查询是否返回行**：本书明确警告：「使用否定形式 NOT EXIST 的 SELECT 语句，即使是 DB 工程师也常常无法迅速理解」（Page 214）。注入侧用 NOT EXISTS 时逻辑容易反，调试时需用 EXISTS 验证正向。
- **用 BETWEEN 谓词做范围查询（盲注二分搜索的工具）**：本书明确警告：「BETWEEN 的特点就是结果中会包含 100 和 1000 这两个临界值。如果不想让结果中包含临界值，那就必须使用 < 和 >」（Page 207）。注入侧若把 BETWEEN 当开区间用，二分逻辑会卡在临界值上。

### 授权与合规边界

> 待补充（用户自行填写）
