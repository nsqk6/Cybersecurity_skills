# Web安全与代码审计 · OCR 增补：反例与失效边界

> 本卡由扫描件 OCR 后提取的 **8 个候选单元**按类型聚合而成，逐字引用、执行步骤、失败模式、书内案例均原样保留自 `candidates/ocr-batch-*.md`。这一批是「已提取、按类型归集」的增补材料，与同目录其他能力卡的三重验证 + 人工聚类流程不同，故单独标注，不冒充正式聚类卡。

## R — 原文 (Reading)

> 上面这段代码虽然使用了 pdo 的 prepare 方式来处理 sql 查询，但是当PHP 版本<5.3.6 之前还是存在宽字节 SQL 注和[OCR]漏洞，原因在于这样的查询方式是使用了 PHP 本地模拟 prepare，再把完整的 SQL 语句发送给 MySQL 服务器，并且有使用 set names 'gbk 语句，所以会有PHP 和 MySQL 编码不一致的原因导致 SQL 注入，正确的写法应该[OCR]是使用 ATTR_EMULATE_PREPARES 来禁用 PHP 本地模拟 prepare。
>
> — 《代码审计：企业级Web代码安全架构》· 第 4 章 4.1.2.3 PDO prepare 预编译

> addslashes 函数过滤的值范围和 GPC 是一样的，即单引号 (7)[OCR]、双引号 OC)[OCR], BR[OCR]杠〈\) 及空字符NULL，它只是一个简单的检查参数的函数，大多数程序使用它是在程序的入口，进行判断如果没有开启 GPC，则使用它对 $_POST/S_GET[OCR] 等变量进行过滤，不过它的参数必须是 string 类型，所以曾经某些程序使用这种方式对输入进行过滤时出现了绕过，比如只遍历$_GET 的值，当时并没有考虑到$_GET 的值也是一个数组。
>
> — 《代码审计：企业级Web代码安全架构》· 第 4 章 4.1.2.2 过滤函数和类

> $action = isset($_REQUEST['action']) ? $_REQUEST['action'] : CHECK[OCR]; if(is_file("install.lock") && $action != UPGRADED[OCR] && $action != INSTALLED[OCR]) { header ("location: ../index.php") ; } 这段代码存在一个逻辑漏洞，首先判断 install lock[OCR] 文件是否存在以及 action 参数值是否升级完成和安装完成，如果是，则跳转到程序首页，这里仅仅使用了 header ("location: ../index.php"); 并没有使用 die() 或者 exit() 等函数退出程序流程，这个跳转只是 HTTP 头的跳转，下方代码依然会继续执行，这时候如果使用浏览器请求 instaly[OCR]index.php 文件则会跳转到首页，我们用 burp 试试……可以看到程序又可以再次安装。
>
> — 《代码审计：企业级Web代码安全架构》· 第 3 章 3.3 BugFree 重装漏洞案例

> 但时至今日，全自动化的代码审计仍然存在很多困难，主要难点在于理解编程语言的语法、路[OCR]文件之间的关联调用、理解开发框架、业务逻辑等地方。因为这些困难在短期内难以克服，所以通过代码审计来挖掘漏洞，仍然是一种极具技巧性和需要丰富经验的工作……使用一款好的代码安全审计软件可以极大地降低审计成本，可以帮助审计师快速发现问题所在，同时也能降低审计门槛，但也不能过分依赖审计软件。
>
> — 《代码审计：企业级Web代码安全架构》· 序言

> 那如果想选取进货单价为 NULL 的记录的话，条件表达式该怎么写 982[OCR] 历经一看苦思揽想后，用"shire_tanka ~ NULL"试了试，还是一条记录也取不出来。
> 即使使用 <> 运算符也还是无法选取出 NULL 的记录日[OCR]，因此，SQL 提供了专门用来庆断[OCR]是天为 NOLL[OCR] 的运算符 TS NULL[OCR]。想要选取 NULL, SREMSTORSISRE 的记录时，可以像代码清单 2-28 那样来书写条件表达式。
>
> — 《SQL基础教程》· 第 2 章 2-2 不能对NULL使用比较运算符

> 大家是不是觉得应该选取出比 2 大的 3、10、11 和 222 这4条记录 WE[OCR]? ...大家之所以这样想是因为混淆了数字和字符串的缘故。也就是说2 和 '27[OCR] 并不一样。BRE[OCR], chr 列被定为字符品[OCR]类型，并且对字符车[OCR]类型的数据进行大小比较时，使用的是和数字比较不同的规则。典型的规则就是按照字典顺序进行比较
>
> — 《SQL基础教程》· 第 2 章 2-2 对字符串使用不等号时的注意事项

> 在使用 COUNT 这样的聚合函数时，SELECT 子句中的元素有严格的限制。实际上, 使用聚合函数时，SELECT 子句中只能存在以下三种元素。常数...聚合函数...GROUP BY子句中指定的列名( 也就是聚合键 )
> 这里经常会出现的错误就是把聚合键之外的列名书写在 SELECT 子句之中...列名 shohin_mei 并没有包含在 GROUP BY 子句当中。因此，该列名也不能书写在 SELECT 子名之中...将表进行分组之后，一行就代表了一个进货单价。问题就出在这里，聚合键和商品名并不一定是一对一的。
>
> — 《SQL基础教程》· 第 3 章 3-2 与聚合函数和GROUP BY子句有关的常见错误

> 自动提交的情况需要特别注间[OCR]的是 DELETE 语句。如果不是自动提交，即全 用 DELETE OMT RGM[OCR], 也可以通过ROLLBACK 命令取清该事务的处理，亿复表中的数据。但这仅有于明示开妈事务，或者关闭自动提交的情况。如果不小心在自动提交模式下执行了 DELETE 所作[OCR]。即使由当地天济于事了[OCR]。这是一个很严重的问题,初学者难免全碰到这样的麻烦。一旦误几了数据，如果抱法和新插 A, 是不是起器的心都有了? 所以一定要特别小心。
>
> — 《SQL基础教程》· 第 4 章 4-4 事务处理何时开始

## I — 方法论骨架 (Interpretation)

**PDO prepare 在 PHP<5.3.6 仍存在宽字节注入反例** — PDO prepare 有两种实现：①本地仿真（PHP 端拼接 SQL 发给 MySQL，等于没预编译）；②服务端预编译（MySQL 端用 `?` 占位语法分离）。PHP < 5.3.6 默认走 ①，开发者写了 `prepare(...)->execute(array($var))` 看似用了预编译，实际仍是字符串拼接后发送，遇到 `SET NAMES 'gbk'` 仍有宽字节。这是「看似安全实际不安全」的典型反例——只看 API 形态会误判已防护。

**`addslashes` 只遍历 `$_GET` 不考虑数组的绕过反例** — `addslashes` 的签名是 `addslashes(string $str): string`，要求参数是字符串。入口过滤代码常写成 `foreach ($_GET as $k => $v) $_GET[$k] = addslashes($v);`。但 `$_GET['ids']` 可以是数组（`?ids[]=1&ids[]=2`），此时 `$v` 是 array，`addslashes(array)` 在 PHP 5.3+ 返回 NULL 并报警告，原始数组未被过滤保留下来，后续代码取 `$_GET['ids'][0]` 拼到 SQL 时绕过成立。根因是「过滤代码假设输入是 string，但 HTTP 协议允许数组」。

**`header()` 跳转后未 `exit/die` 导致重装漏洞反例** — `header("Location: ...")` 只发送一个 HTTP 302 响应头，不终止 PHP 解释器执行后续语句。浏览器会跟随跳转，但攻击者用 curl/Burp 直接看响应体，能拿到「跳转后的下方代码执行结果」。BugFree 的 `install/index.php` 用 `header()` 跳转后继续执行安装逻辑，导致 `install.lock` 形同虚设。这是 PHP 最经典的逻辑漏洞模式之一，作者把它放在「功能点定向审计」章节作为典型反例。

**全自动化代码审计的能力边界（作者明确警告）** — 全自动化审计的瓶颈是「程序理解」而非「模式匹配」——能搜 `mysql_query` 不等于能判断这个 `mysql_query` 是否真的可控，因为变量经过 N 层封装、跨文件传递、框架路由后才到达 sink。Seay/RIPS/Fortify 都只能给出「候选可疑点」，最终仍需人工判断可控性。作者明确警告「不能过分依赖审计软件」，把工具定位为「放大镜」而非「判官」。

**用 = NULL 比较选取 NULL 行（反例：永远选不出）** — 对 NULL 用 `=`、`<>`、`<`、`>` 等比较运算符都得不到 TRUE 结果，而是得到 UNKNOWN（三值逻辑，见 CU-2-05）。这意味着 `WHERE col = NULL` 永远选不出 NULL 行，`WHERE col <> NULL` 也选不出非 NULL 行——因为 UNKNOWN 在 WHERE 中被当作 FALSE 处理。SQL 必须用 `IS NULL` / `IS NOT NULL` 谓词才能正确判断 NULL。这一反例对安全工程师有两层意义：(1) 应用代码若用 `= NULL` 做权限检查是逻辑漏洞——查询永远返回空，可能被攻击者利用绕过某些「必须为空才能通过」的检查；(2) 注入 payload 中若用 `= NULL` 做条件，结果永远是 UNKNOWN，注入逻辑会被静默吞掉，调试盲注时会误判为「注入点不存在」。

**字符串按字典序比较（反例：'10' < '2'）** — SQL 中字符串类型（CHAR/VARCHAR）的比较按字典序，不是按数值大小。即 `'10' < '2'` 为 TRUE，因为字典序逐字符比较，`'1'` < `'2'` 就直接判定。本书明确指出「混淆了数字和字符串」是初学者常错之处。这一反例对安全工程师有三层意义：(1) 应用代码若用字符串列存数字（如商品编号 `'0001'`、手机号），按字符串比较时 `'10' < '2'`——这是注入条件构造的常见误判；(2) WAF 规则若按字符串匹配数字 payload，需考虑字典序而非数值序；(3) 注入 payload 中 `>` 比较若用于字符串列，结果与数字列完全不同——盲注二分搜索时需要先确认列类型。

**使用聚合函数时 SELECT 子句只能写常数/聚合函数/聚合键（反例）** — 使用聚合函数 + GROUP BY 时，SELECT 子句中只能出现三种元素：常数、聚合函数、GROUP BY 指定的聚合键。本书指出这是「严格限制」，原因是分组后每行代表一组，聚合键外的列在该组内可能有多值，无法确定显示哪个。这一反例对注入的意义：(1) 注入 UNION SELECT 时若原查询是聚合查询，注入侧需遵守同样约束（SELECT 列要对齐聚合语义）；(2) 注入额外列到 SELECT 会让查询报错——这是 error-based 注入的触发点，错误信息可能泄露 schema 信息；(3) 应用代码若动态拼 SELECT 列名且未校验是否在聚合键中，可被注入触发报错。

**自动提交模式下 DELETE 不可回滚（反例：误删不可恢复）** — 自动提交模式下，每条 SQL 语句独立构成事务，执行后立即 COMMIT——无法 ROLLBACK。本书特别警告 DELETE 在自动提交下的不可恢复性：明示事务模式下 `DELETE FROM table` 可用 ROLLBACK 撤销，自动提交模式下不行。这一反例对安全工程师有两层意义：(1) 注入若触发 DELETE 且应用连接为自动提交模式，删除立即生效，无法靠 ROLLBACK 挽救——危害评估时需确认连接模式；(2) 应用代码若在自动提交模式下用 DELETE 做敏感操作，是设计缺陷——应改为显式事务 + 异常处理 + ROLLBACK。常见 RDBMS 默认模式：PostgreSQL/MySQL/SQL Server 默认自动提交，Oracle/DB2 默认显式事务。

## A1 — 应用示例 (Application Example)

### 示例 1: PDO prepare 在 PHP<5.3.6 仍存在宽字节注入反例
- **类型与来源**: 【counter-example】《代码审计：企业级Web代码安全架构_ocr.txt》· 第 4 章 4.1.2.3 PDO prepare 预编译（Page 91–92）
- **问题/输入**: PHP < 5.3.6 项目；用 PDO 但未显式禁用仿真。
- **方法论的使用**: PDO prepare 有两种实现：①本地仿真（PHP 端拼接 SQL 发给 MySQL，等于没预编译）；②服务端预编译（MySQL 端用 `?` 占位语法分离）。PHP < 5.3.6 默认走 ①，开发者写了 `prepare(...)->execute(array($var))` 看似用了预编译，实际仍是字符串拼接后发送，遇到 `SET NAMES 'gbk'` 仍有宽字节。这是「看似安全实际不安全」的典型反例——只看 API 形态会误判已防护。
- **结果**: 【例题】作者给出错误写法 `$dbh->exec("set names 'gbk'"); $stmt = $dbh->prepare($sql); $stmt->execute(array($name, $pass));` 与正确写法 `$dbh->setAttribute(PDO::ATTR_EMULATE_PREPARES, false); $dbh->exec("set names 'utf8'");` 的对照（Page 91–92）。

### 示例 2: `addslashes` 只遍历 `$_GET` 不考虑数组的绕过反例
- **类型与来源**: 【counter-example】《代码审计：企业级Web代码安全架构_ocr.txt》· 第 4 章 4.1.2.2 过滤函数和类（Page 90）
- **问题/输入**: PHP 入口过滤代码用 `foreach + addslashes` 而非递归；攻击者可发数组参数。
- **方法论的使用**: `addslashes` 的签名是 `addslashes(string $str): string`，要求参数是字符串。入口过滤代码常写成 `foreach ($_GET as $k => $v) $_GET[$k] = addslashes($v);`。但 `$_GET['ids']` 可以是数组（`?ids[]=1&ids[]=2`），此时 `$v` 是 array，`addslashes(array)` 在 PHP 5.3+ 返回 NULL 并报警告，原始数组未被过滤保留下来，后续代码取 `$_GET['ids'][0]` 拼到 SQL 时绕过成立。根因是「过滤代码假设输入是 string，但 HTTP 协议允许数组」。
- **结果**: 未提供独立案例，作为反例提出（Page 90）；骑士 cms 的 `addslashes_deep` 给出了正确递归写法（Page 70–71）。

### 示例 3: `header()` 跳转后未 `exit/die` 导致重装漏洞反例
- **类型与来源**: 【counter-example】《代码审计：企业级Web代码安全架构_ocr.txt》· 第 3 章 3.3 BugFree 重装漏洞案例（Page 81–82）
- **问题/输入**: PHP 项目；源码可索引；能用 Burp/curl 绕过浏览器自动跟随。
- **方法论的使用**: `header("Location: ...")` 只发送一个 HTTP 302 响应头，不终止 PHP 解释器执行后续语句。浏览器会跟随跳转，但攻击者用 curl/Burp 直接看响应体，能拿到「跳转后的下方代码执行结果」。BugFree 的 `install/index.php` 用 `header()` 跳转后继续执行安装逻辑，导致 `install.lock` 形同虚设。这是 PHP 最经典的逻辑漏洞模式之一，作者把它放在「功能点定向审计」章节作为典型反例。
- **结果**: 【亲历】BugFree `install/index.php` 的 `install.lock` 检查后用 `header("location: ../index.php")` 跳转但未 `exit`，作者用 Burp 重放请求，看到 `phpinfo()` 信息泄露，程序可再次安装覆盖配置（Page 81–82）。

### 示例 4: 全自动化代码审计的能力边界（作者明确警告）
- **类型与来源**: 【counter-example】《代码审计：企业级Web代码安全架构_ocr.txt》· 序言（吴翰清，Page 6）+ 前言（作者，Page 7）+ 第 2 章 2.2 代码审计工具（Page 36）
- **问题/输入**: 已运行 Seay/RIPS/Fortify 拿到候选清单；能识别人工复核点。
- **方法论的使用**: 全自动化审计的瓶颈是「程序理解」而非「模式匹配」——能搜 `mysql_query` 不等于能判断这个 `mysql_query` 是否真的可控，因为变量经过 N 层封装、跨文件传递、框架路由后才到达 sink。Seay/RIPS/Fortify 都只能给出「候选可疑点」，最终仍需人工判断可控性。作者明确警告「不能过分依赖审计软件」，把工具定位为「放大镜」而非「判官」。
- **结果**: 【转述】吴翰清在序言中明确警告「全自动化的代码审计仍然存在很多困难，主要难点在于理解编程语言的语法、路[OCR]文件之间的关联调用、理解开发框架、业务逻辑等地方」（Page 6）；作者在第 2 章说「不能过分依赖审计软件」（Page 36）。

### 示例 5: 用 = NULL 比较选取 NULL 行（反例：永远选不出）
- **类型与来源**: 【counter-example】《SQL基础教程_ocr.txt》· 第 2 章 2-2 不能对NULL使用比较运算符（Page 69–71）
- **问题/输入**: 知道目标列是否允许 NULL；理解三值逻辑（见 CU-2-05）。
- **方法论的使用**: 对 NULL 用 `=`、`<>`、`<`、`>` 等比较运算符都得不到 TRUE 结果，而是得到 UNKNOWN（三值逻辑，见 CU-2-05）。这意味着 `WHERE col = NULL` 永远选不出 NULL 行，`WHERE col <> NULL` 也选不出非 NULL 行——因为 UNKNOWN 在 WHERE 中被当作 FALSE 处理。SQL 必须用 `IS NULL` / `IS NOT NULL` 谓词才能正确判断 NULL。这一反例对安全工程师有两层意义：(1) 应用代码若用 `= NULL` 做权限检查是逻辑漏洞——查询永远返回空，可能被攻击者利用绕过某些「必须为空才能通过」的检查；(2) 注入 payload 中若用 `= NULL` 做条件，结果永远是 UNKNOWN，注入逻辑会被静默吞掉，调试盲注时会误判为「注入点不存在」。
- **结果**: 【例题】代码清单 2-27 错误的 SELECT 语句 `WHERE shiire_tanka = NULL` 一条记录也取不出来；代码清单 2-28 正确写法 `WHERE shiire_tanka IS NULL`（Page 70–71）。

### 示例 6: 字符串按字典序比较（反例：'10' < '2'）
- **类型与来源**: 【counter-example】《SQL基础教程_ocr.txt》· 第 2 章 2-2 对字符串使用不等号时的注意事项（Page 67–68）
- **问题/输入**: 已知目标列的数据类型；理解字典序规则（首字符优先，相同则比较下一位）。
- **方法论的使用**: SQL 中字符串类型（CHAR/VARCHAR）的比较按字典序，不是按数值大小。即 `'10' < '2'` 为 TRUE，因为字典序逐字符比较，`'1'` < `'2'` 就直接判定。本书明确指出「混淆了数字和字符串」是初学者常错之处。这一反例对安全工程师有三层意义：(1) 应用代码若用字符串列存数字（如商品编号 `'0001'`、手机号），按字符串比较时 `'10' < '2'`——这是注入条件构造的常见误判；(2) WAF 规则若按字符串匹配数字 payload，需考虑字典序而非数值序；(3) 注入 payload 中 `>` 比较若用于字符串列，结果与数字列完全不同——盲注二分搜索时需要先确认列类型。
- **结果**: 【例题】Chars 表 chr 列存 '1','2','3','10','11','222'，查询 `WHERE chr > '2'` 只返回 '3' 和 '222'，不返回 '10' 和 '11'——因为 '10' 首字符 '1' 在字典序中小于 '2'（Page 67–68）。

### 示例 7: 使用聚合函数时 SELECT 子句只能写常数/聚合函数/聚合键（反例）
- **类型与来源**: 【counter-example】《SQL基础教程_ocr.txt》· 第 3 章 3-2 与聚合函数和GROUP BY子句有关的常见错误（Page 100–101）
- **问题/输入**: 已知原查询是否含 GROUP BY；理解聚合键语义。
- **方法论的使用**: 使用聚合函数 + GROUP BY 时，SELECT 子句中只能出现三种元素：常数、聚合函数、GROUP BY 指定的聚合键。本书指出这是「严格限制」，原因是分组后每行代表一组，聚合键外的列在该组内可能有多值，无法确定显示哪个。这一反例对注入的意义：(1) 注入 UNION SELECT 时若原查询是聚合查询，注入侧需遵守同样约束（SELECT 列要对齐聚合语义）；(2) 注入额外列到 SELECT 会让查询报错——这是 error-based 注入的触发点，错误信息可能泄露 schema 信息；(3) 应用代码若动态拼 SELECT 列名且未校验是否在聚合键中，可被注入触发报错。
- **结果**: 【例题】代码清单 3-16 `SELECT shohin_mei, shiire_tanka, COUNT(*) FROM Shohin GROUP BY shiire_tanka` 在 PostgreSQL 报错，因 `shohin_mei` 不在 GROUP BY 中（Page 100）。

### 示例 8: 自动提交模式下 DELETE 不可回滚（反例：误删不可恢复）
- **类型与来源**: 【counter-example】《SQL基础教程_ocr.txt》· 第 4 章 4-4 事务处理何时开始（Page 147）
- **问题/输入**: 应用 DB 连接配置可读；知道目标 RDBMS 的默认事务模式。
- **方法论的使用**: 自动提交模式下，每条 SQL 语句独立构成事务，执行后立即 COMMIT——无法 ROLLBACK。本书特别警告 DELETE 在自动提交下的不可恢复性：明示事务模式下 `DELETE FROM table` 可用 ROLLBACK 撤销，自动提交模式下不行。这一反例对安全工程师有两层意义：(1) 注入若触发 DELETE 且应用连接为自动提交模式，删除立即生效，无法靠 ROLLBACK 挽救——危害评估时需确认连接模式；(2) 应用代码若在自动提交模式下用 DELETE 做敏感操作，是设计缺陷——应改为显式事务 + 异常处理 + ROLLBACK。常见 RDBMS 默认模式：PostgreSQL/MySQL/SQL Server 默认自动提交，Oracle/DB2 默认显式事务。
- **结果**: 【例题】作者举自动提交模式下误删数据的场景：明示事务模式下 DELETE 可 ROLLBACK 恢复，自动提交模式下不可恢复（Page 147）。

## A2 — 相邻能力 (Adjacency)

1. 出现「PDO prepare 还能注入吗」这类信号时，回到本卡查对应单元的方法与判据。
2. 出现「PHP 5.3 宽字节」这类信号时，回到本卡查对应单元的方法与判据。
3. 出现「ATTR_EMULATE_PREPARES 是什么」这类信号时，回到本卡查对应单元的方法与判据。
4. 出现「PDO prepare wide byte」这类信号时，回到本卡查对应单元的方法与判据。
5. 出现「PHP 5.3 SQLi bypass」这类信号时，回到本卡查对应单元的方法与判据。
6. 出现「addslashes 数组绕过」这类信号时，回到本卡查对应单元的方法与判据。

语言信号：「PDO prepare 还能注入吗」、「PHP 5.3 宽字节」、「ATTR_EMULATE_PREPARES 是什么」、「PDO prepare wide byte」、「PHP 5.3 SQLi bypass」、「addslashes 数组绕过」

本卡为增补材料，正式能力卡请优先读：`recon-asset-surface`、`injection-channel-selection`。

**相邻区分（原文）**：

- 与 CU-1-12 是「修复 vs 反例」关系——CU-1-12 给宽字节修复三选一，本单元警告其中第三种在旧 PHP 上的反例。

---
- 与 CU-1-06「GPC 不保护 $_SERVER」是「全局过滤盲区」同构反例——前者是「类型盲区」，后者是「超全局盲区」。

---
- 与 CU-1-04「功能点定向」是「方法 vs 案例」关系——本单元是 CU-1-04 在「登录认证功能」上挖到的具体反例。

---
- 与 CU-1-01「关键字回溯」是「工具 vs 人工」配合——工具给出候选，人工用本单元的方法判断；本单元警告「工具不是判官」。
- 与 CU-2-05「三值逻辑」是反例与原理关系——本单元是 NULL 比较的具体反例，CU-2-05 是三值逻辑的全局规则；与 CU-2-13「EXISTS」是粒度差异——EXISTS 是判断记录存在性，IS NULL 是判断值是否为 NULL。

---
- 与 CU-2-07「字面量引号」是规则差异——本单元是字符串比较规则，CU-2-07 是字面量写法规则；与 CU-2-05「三值逻辑」是反例类型差异——本单元是类型混淆，CU-2-05 是 NULL 处理。

---
- 与 CU-2-15「HAVING vs WHERE」是约束对象差异——本单元约束 SELECT 列，CU-2-15 约束条件子句；与 CU-2-10「UNION 列对齐」是约束场景差异——本单元是单查询聚合约束，CU-2-10 是多查询集合并集约束。

---
- 与 CU-2-19「事务 ACID」是模式差异——本单元是自动提交反例，CU-2-19 是事务概念；与 CU-2-17「DROP vs DELETE」是恢复机制差异——本单元讨论可回滚性，CU-2-17 讨论破坏量级。

---

## E — 执行步骤 (Execution)

### PDO prepare 在 PHP<5.3.6 仍存在宽字节注入反例

1. 看 PDO 连接代码，确认 PHP 版本
  2. 若 PHP < 5.3.6，检查是否显式 `setAttribute(PDO::ATTR_EMULATE_PREPARES, false)`
  3. 若未设置，即使代码用了 `prepare`+`execute`，仍判定为宽字节注入可绕过
  4. 修复：补 `setAttribute(PDO::ATTR_EMULATE_PREPARES, false)`，并把 `set names 'gbk'` 改为 `set names 'utf8'` 或不设字符集让 PDO 默认处理

### `addslashes` 只遍历 `$_GET` 不考虑数组的绕过反例

1. 看入口过滤代码，确认是否对 `$_GET/$_POST/$_COOKIE` 做 `foreach + addslashes`
  2. 检查是否用 `is_array($v)` 分流，或直接用 `array_map('addslashes_deep', $v)` 递归
  3. 若未处理数组分支，构造 `?ids[]=1'&ids[]=2` 测试
  4. 修复：用 `addslashes_deep` 这类递归函数（`is_array($value) ? array_map('addslashes_deep', $value) : addslashes($value)`）

### `header()` 跳转后未 `exit/die` 导致重装漏洞反例

1. 全局搜 `header("Location`、`header('Location`、`header("location`
  2. 命中处看后续是否紧跟 `exit()` / `die()` / `return`
  3. 若无退出语句，标记为「跳转不终止」缺陷，下方代码可被强制执行
  4. 重点检查 `install/index.php`、`upgrade.php`、`admin/login.php`、`api.php` 等「权限跳转」场景
  5. 修复：每个 `header("Location: ...")` 后立即 `exit();` 或 `die();`

### 全自动化代码审计的能力边界（作者明确警告）

1. 用 Seay/RIPS 跑自动审计，拿到候选清单（sink 命中行）
  2. 把候选清单按 sink 类型分流（SQLi / XSS / 文件操作 / 代码执行）
  3. 对每个候选用 CU-1-01「关键字回溯」法人工判断变量可控性
  4. 对框架项目，先学框架的 source/sink 抽象（如 ThinkPHP 的 `I()` 函数是 source，`M()->where()->select()` 是 sink），再让人工判断对齐框架语义
  5. 业务逻辑漏洞、越权漏洞、CSRF 不依赖 sink 函数，自动化工具几乎无能为力，必须走 CU-1-03「通读全文」或 CU-1-04「功能点定向」

### 用 = NULL 比较选取 NULL 行（反例：永远选不出）

1. 在源码中搜 `= NULL`、`<> NULL`、`!= NULL` → 标记为可疑逻辑点（功能 bug 或注入 payload 错误）
  2. 用 `IS NULL` / `IS NOT NULL` 替换测试，验证是否是 NULL 判断错误
  3. 注入侧：避免在 payload 中用 `= NULL` 做恒真条件（结果 UNKNOWN 不是 TRUE），改用 `IS NULL` 在允许 NULL 的列上构造恒真

### 字符串按字典序比较（反例：'10' < '2'）

1. 在源码或 schema 中确认比较列的数据类型（CHAR/VARCHAR vs INT/NUMERIC）
  2. 字符串列：盲注条件用字典序比较，如 `col > 'M'` 而非 `col > 13`
  3. 数字列：盲注条件用数值比较，如 `col > 64`
  4. 跨类型比较：用 CAST 转换类型后比较，避免字典序与数值序混淆

### 使用聚合函数时 SELECT 子句只能写常数/聚合函数/聚合键（反例）

1. 检测原查询是否含 GROUP BY → 是则注入侧 SELECT 必须遵守聚合约束
  2. 注入额外列触发报错：` UNION SELECT 1, extra_col, 3 FROM ...--` → 报错信息可能泄露列名
  3. 修复侧：应用若动态拼 SELECT 列，校验列名是否在 GROUP BY 聚合键集合内

### 自动提交模式下 DELETE 不可回滚（反例：误删不可恢复）

1. 确认应用 DB 连接的事务模式：搜 `SET autocommit`、连接字符串参数、ORM 配置
  2. 自动提交模式下的 DELETE sink：标记为「不可回滚」高危
  3. 显式事务模式下的 DELETE sink：标记为「可回滚」中危（需应用异常处理正确）
  4. 修复侧：把 DELETE 改为显式事务 `BEGIN; DELETE...; COMMIT;`，并加异常捕获 + ROLLBACK

### 统一判停条件

- 单元「失败模式」里列出的任一条件成立时停止该路径，换维度重查；
- OCR 文本不可读、引用无法核对时，只作线索，不写入结论；
- 连续三次同类验证无结果时回到攻击面/问题定义重排优先级。

## B — 失效与边界 (Boundary)

- **PDO prepare 在 PHP<5.3.6 仍存在宽字节注入反例**：PHP 5.3.6+ 默认 `ATTR_EMULATE_PREPARES=false`，本反例不适用；但有些旧代码或框架会在连接时显式开仿真，仍需检查。
- **`addslashes` 只遍历 `$_GET` 不考虑数组的绕过反例**：PHP 7+ 对 `addslashes(array)` 直接返回 NULL 并报 TypeError，过滤完全失效；PHP 5.x 行为不一致，需结合版本验证。
- **`header()` 跳转后未 `exit/die` 导致重装漏洞反例**：某些框架（如 Laravel 的 `redirect()->away()`）封装了 `header + exit`，本反例不适用；需先确认项目是否裸用 PHP 原生 `header()`。
- **全自动化代码审计的能力边界（作者明确警告）**：直接把工具报告当结论，会同时产生大量误报（工具不理解的过滤函数被当作无过滤）和漏报（跨文件追踪失败、框架 sink 不识别、业务逻辑漏洞不命中任何规则）；商业工具 Fortify 用五大分析器（数据流/控制流/语义/结构/配置）也只能缓解不能消除。
- **用 = NULL 比较选取 NULL 行（反例：永远选不出）**：本书明确警告：「即使使用 <> 运算符也还是无法选取出 NULL 的记录」（Page 70）。开发者常误以为 `<> NULL` 能选非 NULL 行——结果连 NULL 行都选不出，逻辑错误但不会报错。
- **字符串按字典序比较（反例：'10' < '2'）**：本书明确警告：「大家之所以这样想是因为混淆了数字和字符串的缘故」（Page 68）。注入侧若把字符串列当数字列做二分盲注，结果会乱序——'10' 在 '2' 之前出现，二分逻辑失效。
- **使用聚合函数时 SELECT 子句只能写常数/聚合函数/聚合键（反例）**：本书明确警告：「聚合键和商品名并不一定是一对一的」（Page 101）。PostgreSQL 严格按此规则，MySQL 默认宽松（允许 SELECT 聚合键外列，取任意值）——跨 DBMS 注入行为不同。
- **自动提交模式下 DELETE 不可回滚（反例：误删不可恢复）**：本书明确警告：「一旦误几了数据，如果抱法和新插 A, 是不是起器的心都有了? 所以一定要特别小心」（Page 147）。注入侧若误触发自动提交 DELETE，数据立即丢失，只能靠备份恢复。

### 授权与合规边界

> 待补充（用户自行填写）
