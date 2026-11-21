# Content Provider 数据抽取

## R — 原文 (Reading)

> This specific path including the appended slash was not protected by that permission. This is because a literal comparison was used when there were other valid forms that reached the same data.

> — 《Mobile App Hackers Handbook》Chapter 7 "Pattern-Matching Flaws"

> Injecting a single quote into the projection causes an error in the structure of the query that SQLite received.

> — 《Mobile App Hackers Handbook》Chapter 7 "Exploiting Insecure Content Providers → SQL Injection"

> An easy way to check whether a content provider allows the retrieval of any file is by requesting the /system/etc/hosts file, which always exists and is word readable on Android devices.

> — 《Mobile App Hackers Handbook》Chapter 7 "File-Backed Content Providers"

## I — 方法论骨架 (Interpretation)

这个能力回答的是一句很具体的需求：**「这个 content provider 已经能访问了，我怎么把它后面的数据真正取出来」**。它覆盖三类取数手法——path-permission 字面匹配绕过、provider SQL 注入、file-backed provider 目录穿越——并给出它们各自的前置条件与判据，避免把「路径不对」「无权限」「数据加密」混为一谈。

核心机制是三条分支，共享一个前置：provider 必须已可达（要么导出且无读权限，要么已按 path-permission 绕过）。第一条分支是 **path-permission 绕过**：`<path-permission android:path="/Keys">` 只保护字面等于 `/Keys` 的 URI，而 Content provider 的 URI 解析对尾斜杠、路径段复用、`//`、URL 编码等形式往往同样路由到同一张表，于是 `/Keys/` 绕过 `/Keys`。这是「保护的是字符串而不是数据」——权限声明按 URI 文本匹配，数据访问按解析后的路径；判据是能否找到另一种写法到达同一 `query()` 分支，而不是能否绕过校验逻辑。第二条分支是 **SQL 注入**：`query(Uri, projection, selection, selectionArgs, sortOrder)` 被拼成 `select projection from table where selection=selectionArgs order by sortOrder`，其中 `selectionArgs` 参数化，但 `projection` 和 `sortOrder` 是字符串拼接，所以 projection 是最稳的注入点。利用链固定：单引号报错确认拼接 → `* from sqlite_master where type='table'--` 列表 → 对目标表 `* from <table>--` 取数据；注释符 `--` 用来吃掉后面的 `FROM <table>`，不写就不是合法语句。第三条分支是 **file-backed provider 穿越**：实现 `openFile()` 的 provider 以**自己的 uid** 打开文件，能读到 App 私有目录里的一切；若 URI 未与白名单比对即可取任意文件。用一个「必然存在且必然可读」的文件 `/system/etc/hosts` 做零成本探针，能立刻把「路径不对」与「无穿越」区分开：拿到 `127.0.0.1 localhost` 即完全无限制，报错再试 `../` 序列。

为什么把三条放一个能力：用户面对的是「一个 provider，我要看看能拿到什么」，而不是分别带着三个工具名来。三条分支有明确的先后关系——先判权限是否挂对路径（path-permission），再在放开的路径上注入取表（SQLi），或在 file-backed provider 上取文件（穿越）；它们可叠加（先绕过路径权限，再在放开的路径上注入），也有共同失败模式（只测根路径就下结论、用 drozer 的 finduri 当结论、忘记数据被 SQLCipher 加密）。读完这段应该能跑一遍：读 provider 的 Path Permissions/权限 → 变形 URI 验证绕过 → 单引号确认注入并拖表 → hosts 探针 + `../` 取文件 → 双 scanner 交叉确认 → 落笔。

## A1 — 应用示例 (Application Example)

### 示例 1: Sieve 的 /Keys 尾斜杠绕过
- **类型与来源**: 【亲历】《Mobile App Hackers Handbook》Chapter 7 "Pattern-Matching Flaws"
- **问题/输入**: Sieve 的 provider 对 `/Keys` 设了 READ_KEYS 权限，要判断能否读到密钥。
- **方法论的使用**: `app.provider.info -a com.mwr.example.sieve` 读出 Path Permissions 的 Path=`/Keys`、Type=PATTERN_LITERAL → 对 `/Keys` 查询返回 `Permission Denial`（先证明原路径被拒）→ 对 `/Keys/` 查询 → 直接返回 `Thisismylongpassword123 / 1234`。
- **结论**: 字面比较保护的是字符串 `/Keys`，而 `/Keys/` 路由到同一张表，权限被绕过；这是「保护字符串而非数据」的典型。
- **结果**: 原书交代 `/Keys/` 成功返回主密码与 PIN。

### 示例 2: Sieve /Passwords 的 projection 注入拖库
- **类型与来源**: 【亲历 + 转述】《Mobile App Hackers Handbook》Chapter 7 "SQL Injection"
- **问题/输入**: Sieve 的 `/Passwords` provider 可达，后端是 SQLite，要取回凭据。
- **方法论的使用**: (1) `app.provider.query <uri> --projection "'"` → 返回 `unrecognized token` 之类 SQLite 报错，确认 projection 未参数化；(2) `--projection "* from sqlite_master where type='table'--"` → 拿到表名清单（含 `Key`）；(3) `--projection "* from <table>--"` 取数据；(4) 用 `scanner.provider.injection -a <uri>` 与 `scanner.provider.sqltables -a <uri>` 交叉确认，两个模块都列为可注入才写进报告。
- **结论**: projection 是独有的注入点（selection 走 selectionArgs 时不可注），`--` 注释符是关键，不写就不是合法语句。
- **结果**: 原书交代取到 `Thisismylongpassword123 / 1234`；另引三星 `content://channels` 注入 dump 出全部短信，绕过 READ_SMS 权限。

### 示例 3: Sieve FileBackupProvider 的 hosts 探针与穿越
- **类型与来源**: 【亲历 + 转述】《Mobile App Hackers Handbook》Chapter 7 "File-Backed Content Providers"
- **问题/输入**: Sieve 的 FileBackupProvider 支持 `content://` 直接读文件，要判断能否取任意文件。
- **方法论的使用**: (1) `app.provider.read <authority>/system/etc/hosts` → 返回 `127.0.0.1 localhost`，说明完全无校验；(2) 逐步加 `../`：`../../../../data/data/<pkg>/databases/database.db`，层数靠试或读源码定；(3) 优先取 `<pkg>/databases/*.db`、`shared_prefs/*.xml`、`files/` 下的配置 → `sqlite3 database.db .dump` 验证；(4) `scanner.provider.traversal -a <uri>` 复核，输出 `Vulnerable Providers:` 含该 URI 才落笔。
- **结论**: 用必然存在且可读的 hosts 做探针，能一步区分「路径不对」与「无穿越」；file-backed provider 以应用 uid 打开文件，所以能读私有目录。
- **结果**: 原书交代读到 `database.db` 并 dump 出主密码；另引 Shazam 同类问题（`AdMarvelCachedImageLocalFileContentProvider`）。

## A2 — 触发场景 (Future Trigger)

### 用户会在什么情境下需要它
1. 已有 provider 访问权：「provider 能不能注入」「content provider sql 注入怎么测」「怎么读别的 App 的数据库」。
2. 路径权限疑点：「provider 有读权限还能读吗」「path-permission 怎么绕」「为什么加个斜杠就能读」。
3. 文件读取：「provider 能读文件吗」「目录穿越怎么测」「能不能读到别的应用的数据库」。
4. 工具结果复核阶段：想确认 drozer 的 finduri / injection 扫描结果是否可信。

### 语言信号（出现这些就该激活）
- 中文：「content provider 注入」「projection 单引号」「sqlite_master 拖库」「path-permission 绕过」「尾斜杠」「目录穿越」「读私有数据库」「任意文件读」。
- English: "content provider SQL injection", "sqlite injection Android provider", "bypass content provider path permission", "path-permission bypass", "content provider directory traversal", "arbitrary file read Android provider"。

### 与相邻能力的区分
- 与 `<component-exposure-and-exploitation>` 的区别：后者判「provider 是否导出、权限成本、普通上下文是否可达」；本能力在「已可达」前提下做数据抽取。若 provider 不可达，先回后者。
- 与 `<webview-client-injection>` 的区别：path-permission 绕过打的是 URI→表的映射，WebView 的 `setAllowContentAccess`/universal access 打的是 WebView 能被诱导读 content/file；两者可串联（WebView 作为代理访问 provider）。
- 与 `<sandbox-data-acquisition>` 的区别：本能力经 IPC 接口取数（provider 的 query/openFile），后者经文件系统权限链、备份接口、调试接口取数。

## E — 可执行步骤 (Execution)

**必需输入**: 目标 provider 已可达（导出且无读权限，或已按第 1 步绕过）；已知 authority 与 URI；read 操作需确认后端是 SQLite（对 SQLi 分支）；file-backed 分支需确认 provider 实现了 `openFile()`；缺「可达性结论」时先回 `<component-exposure-and-exploitation>`。

**交付物与完成标准**: 每个可利用点一份「变形/注入/穿越记录 + scanner 交叉确认 + 取到的数据样本（脱敏）」；报告标注修复方向。完成标准：每条结论都有「原路径被拒 → 变形成功」或「单引号报错 → 拖表成功」的对照链，且通过双 scanner 复核。

1. **读 provider 权限与 Path Permissions**
   - 做什么：`app.provider.info -a <pkg>` 读出 `Path Permissions` 的 Path 与 Type（PATTERN_LITERAL / PATTERN_PREFIX），记下被保护路径与读权限要求。
   - 完成标准：每个 provider 有「根路径权限 + 子路径权限」清单。
   - 判停：若 provider 对根路径无读权限、只对某子路径设权限，是最典型配置，进入第 2 步；若本来就没设路径权限，跳过第 2 步直接测 SQLi/穿越。

2. **path-permission 变形验证**
   - 做什么：对被保护路径逐个变形——尾部加 `/`、加 `//`、追加不存在的子段、URL 编码 → 每次 `app.provider.query <变形 URI>`。
   - 完成标准：原路径返回 `Permission Denial` 而某个变形返回数据行，缺陷成立。
   - 判停：必须先证明原路径被拒；只测根路径就下「有权限保护」的结论不成立；反过来对所有 provider 一律试 `/` 会把本来没设权限的当成「绕过成功」。

3. **SQLi 单引号起手与拖库**
   - 做什么：`--projection "'"` → 看是否返回 SQLite 报错 → `* from sqlite_master where type='table'--` 列表 → 挑含 `password/key/token/user` 的表 → `--projection "* from <table>--"` 取数据。
   - 完成标准：三步链完整，且 `--` 注释符正确；取到的表/字段有样本。
   - 判停：只测 selection 就断言无注入不成立（selection 走 selectionArgs 时不可注）；忘写 `--` 导致语法错误不要误判为「不可注入」。

4. **file-backed 穿越取文件**
   - 做什么：`app.provider.read <authority>/system/etc/hosts` → 返回 `127.0.0.1 localhost` 即无校验；失败则逐步加 `../` 序列 → 取 `<pkg>/databases/*.db`、`shared_prefs/*.xml`、`files/` 下配置 → `sqlite3 database.db .dump` 验证。
   - 完成标准：能定位到是哪一级校验缺失（无校验 / 固定前缀拼接），并落盘目标文件（`> 文件名`）。
   - 判停：`../` 层数过多会被规范化后落到别的目录，靠试或读源码定；忘记 `> 文件名` 把二进制内容落盘会在终端截断。

5. **scanner 交叉确认与定级**
   - 做什么：`scanner.provider.injection -a <uri>` 与 `scanner.provider.sqltables -a <uri>` 确认注入；`scanner.provider.traversal -a <uri>` 确认穿越。
   - 完成标准：对应模块都把该 URI 列为可注入/可穿越才写进报告。
   - 判停：数据被 SQLCipher 加密时导出成功也不能直接读，需另找密钥（从 `openOrCreateDatabase()` 追密钥，或拿 `classes.dex` 里所有字符串逐个试开库）；不得因此判为「无数据」。

6. **修复建议对照**
   - 做什么：path-permission 问题用 pathPrefix/正则替代字面匹配；穿越问题用 `getCanonicalPath()` 与基目录前缀比对；SQLi 用参数化 projection/sortOrder。
   - 完成标准：每条建议对应到具体代码改动点。
   - 判停：若修复只做「过滤 `../` 字面量」这种字符串级判断，判为不彻底，要求按解析后的真实路径比对。

## B — 边界 (Boundary)

### 不要用的情况
- provider 不可达（未导出且普通上下文不可达）时：本能力不适用，先回 `<component-exposure-and-exploitation>` 判可达性。
- 后端不是 SQLite 的 provider：SQLi 分支的 `sqlite_master` 链不适用，需换数据库口径。
- 只实现 `query()` 不实现 `openFile()` 的 provider：穿越分支不适用。
- 数据已被强加密且密钥不落盘：取到密文不等于拿到数据，本能力止步于「可取密文 + 密钥需另寻」。

### 已知失败模式
- 只测根路径就下「有权限保护」结论；或反过来对所有 provider 一律试 `/`，把本来没设路径权限的当成「绕过成功」（《Mobile App Hackers Handbook》Ch7 Pattern-Matching Flaws）。
- 只测 selection 就断言无注入；忘写 `--` 导致语法错误误判为「不可注入」（同书 Ch7 SQL Injection）。
- 只试 `content://<authority>` 根路径就放弃 file-backed 穿越；`../` 层数写多或写少——层数过多会被规范化后落到别的目录（同书 Ch7 File-Backed Providers）。
- 忘记 `> 文件名` 把二进制内容落盘，直接在终端看会截断（同书 Ch7）。
- 用 drozer 的 `-a <包名>` 让工具自己找 URI，作者明确说这依赖 finduri、会漏，不推荐用于完整评估（同书 Ch7）。

### 作者与时代的局限
- 三类手法基于 MAHH 写作时的 ContentProvider 实现与 drozer 工具版本；现代 Android 对用户 CA、provider 权限与 URI 解析做了收紧，变形是否仍路由到同一表需按目标版本实测。
- SQLCipher 等加密存储的密钥追踪属于「File Encryption Practices」节的另一条线，本能力只给「另找密钥」的提示，不含完整密钥恢复流程。
- 三星 `content://channels` 等 CVE 是历史案例，用于说明危害形态，不代表当前设备仍存在。

### 容易混淆的方法
- 「path-permission 绕过」与「目录穿越」：前者是权限挂错路径（URI→表的映射被字面匹配），后者是文件路径未规范化（openFile 的 path 拼接）；修复手段不同（pathPrefix/正则 vs `getCanonicalPath()` 前缀比对）。
- 「SQLi」与「path-permission 绕过」：可叠加——先绕过路径权限，再在放开的路径上注入；但判据不同，前者看 SQLite 报错，后者看 Permission Denial 与变形成功。
- 「取到数据」与「数据可读」：SQLCipher 加密时取到的是密文，不要写成「拿到明文凭据」。

### 授权与合规边界
> 待补充（用户自行填写）
