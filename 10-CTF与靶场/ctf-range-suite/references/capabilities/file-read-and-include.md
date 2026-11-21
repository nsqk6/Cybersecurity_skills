# 文件读与包含：从确认漏洞到 getshell

## R — 原文 (Reading)

> The /etc/passwd file is a Linux system file that stores user information and their working directory, is readable by all users/groups, and is generally used as a baseline for determining the existence of file read vulnerabilities in a Linux system.

> — 《Handbook for CTFers》Ch1 · Arbitrary File Read / Common Read Paths

> If we directly pass the file name of this file containing PHP code to the include function, the PHP code cannot be leaked in the form of visual text because the PHP code is executed. However, this can be avoided by using Filter at this time.

> — 《Handbook for CTFers》Ch1 · Common Trigger Points / PHP Wrapper and Filter

> (5) 文件上传+文件包含拿shell是靶机常用的方式，遇到两个漏洞，可以熟练拿shell。

> — 《Vulnhub靶场实战指南》第二节 Billu_b0x「踩到的坑」

> 根据之前整理的文件包含漏洞笔记利用思路：结合之前信息探测的结果，靶机只开通了http 与ssh 服务。Apache的日志包含失败，尝试包含ssh的登陆日志。成功读到ssh的登陆日志。

> — 《Vulnhub靶场实战指南》第八节 The Ether「Web漏洞挖掘」

## I — 方法论骨架 (Interpretation)

这张卡把「任意文件读 / 文件包含」这一类漏洞从「确认存在」一路推进到「拿到 shell」。它把五个单元串成一条有依赖的链：先用基线文件确认漏洞真的存在（而不是在假漏洞上浪费请求），再按分层清单决定读什么，遇到「路径对但读不出明文」「参数传不进去」「读到了却没法变成代码执行」这三个卡点时分别切到对应分支，最后完成 getshell。核心纪律是：**每一步都先确认事实，再换手段，而不是反复重跑同一个动作**。

**第一段：用 `/etc/passwd` 做存在性基线**。文件读漏洞的价值不在「读到某个文件」，而在「把服务器配置、进程、历史命令等资产信息一次性摊开」。判存在用人人可读的 `/etc/passwd`——回显含 root 等系统账户即确认。之后按目标分层取：flag 名用相对/绝对路径清单 fuzz（`../../../../flag(.txt|.php|.pyc|.py)`、`/etc/flag`、`/tmp/flag`、`/root/flag`、`/home/[user]/flag`）；服务器信息读 `/etc/apache2/*`、`/etc/nginx/*`、`/etc/cron*`、`/etc/environment`、`/etc/hosts`；运行时信息读 `/proc/[pid]/cmdline`、`cwd`、`environ`——明文密码常出现在 cmdline（`mysql -uxxx -pxxxx`），secret_key 常出现在 environ。`/proc/self/` 直接指向当前进程，省去爆破 PID。失败模式：一上来就 fuzz flag 路径，漏洞其实不存在会浪费大量请求；`/etc/shadow` 只有 root 可读，普通权限读不到属正常，不要据此否定漏洞。

**第二段：`php://filter` 解决「执行而非显示」**。`include()` 解析到 `<?php ... ?>` 时会执行代码而不是输出文本，所以直接读源码文件看不到内容。PHP 的 Wrapper/Filter 机制允许在文件流上做变换：`php://filter` 配合 Base64 Filter 先把流编码成不含 PHP 标签的 Base64 文本，页面回显后本地解码。这是 PHP 特有通道，其他语言的包含漏洞没有。失败模式：把 Base64 输出当 flag 直接提交；对非 PHP 文件也套 Filter；题目禁用 filter 协议时本分支失效。

**第三段：GET 不通就改 POST**。同一个参数在 GET 与 POST 下可能经过不同校验分支；靶场常把「方法切换」设计成绕过点。现象是附加 `?file=/etc/passwd` 被跳转或拒绝，换成 POST body 提交同样参数即成功。这是成本极低的尝试，应作为文件包含类漏洞的固定第二步。注意：方法切换只对**已定位的参数**有效，仍需先找到正确参数（如 `panel.php` 的包含点不认真看源码就发现不了）。

**第四段：上传 + 包含组合拿 shell**。单独的文件上传可能因白名单被拦，单独的文件包含可能因无可控文件而无从下手；两者组合时，上传点负责把 payload 落地成「图片马」，包含点负责让服务器把它当代码执行。判据：同时看到上传功能与 `?file=` 类参数就优先尝试组合。步骤是下载正常图片、在中间或末尾插入一句话木马、上传到可写目录、用包含参数指向该路径并带 `cmd` 参数验证执行、再反弹 shell。缺任一半都走不通——Acid 节就因找不到上传点而放弃 include.php。

**第五段：LFI 读日志时用开放服务反推载体**。文件包含要 getshell 需要先让 payload 落进一个会被包含的文件，日志是最常用载体，但读哪个日志取决于目标开放了什么服务。做法是把侦察得到的开放服务清单直接映射成日志候选：有 http 试 Apache `access.log`，有 ssh 试 `auth.log`，逐一验证；然后用一句话作为 ssh 用户名/请求内容写入日志，再包含该日志 getshell。The Ether 节 Apache 日志因 www-data 无权限包含失败，转 ssh 日志成功——只试一种日志就放弃会错失机会。

**五段的关系**：第一段回答「漏洞在不在」，第二段回答「路径对了为什么读不出明文」，第三段回答「参数怎么传才生效」，第四、五段回答「读到了怎么变成代码执行」。四、五是两条并列的 getshell 路线：有上传点走组合马，无上传点走日志投毒。

## A1 — 应用示例 (Application Example)

### 示例 1: `/etc/passwd` 基线 + `/proc` 明文口令
- **类型与来源**: 【例题/转述】《Handbook for CTFers》Ch1 1.3.2.1
- **问题/输入**: 发现一个可控文件路径参数，不知道漏洞是否真实存在、之后该读什么。
- **方法论的使用**: 先读 `/etc/passwd` 确认存在；按路径族 fuzz flag；再读 Web 服务器配置与 cron 得到 web 根目录、端口、隐藏目录；最后读 `/proc/self/cmdline` 与 `/proc/self/environ`，从启动命令中取明文口令、从环境变量取 secret_key。
- **结论**: 文件读的价值是「摊开服务器资产」，要按 flag→配置→进程环境分层取，而不是只找 flag 文件。
- **结果**: 原书指出 `mysql -uxxx -pxxxx` 会在 `/proc/[pid]/cmdline` 暴露明文口令，未给具体 flag。

### 示例 2: `php://filter` Base64 读源码
- **类型与来源**: 【例题】《Handbook for CTFers》Ch1 1.3.1.1
- **问题/输入**: `include` 参数可控，但直接传源码文件名时页面不显示 `<?php` 文本。
- **方法论的使用**: 确认路径参数可控且 PHP 标签被「吞掉」（执行而非显示）；改用 `php://filter` 的 Base64 Filter 读该路径，页面回显一串 Base64；本地解码还原含 `<?php` 的原文，继续审计。
- **结论**: 路径对但表示形式不对时，Filter 是 PHP 特有的绕道；Base64 输出不是最终 flag。
- **结果**: 原书说明「读出的内容里不会有 PHP 标签」，并提示 `allow_url_include` 打开时后果更严重。

### 示例 3: Billu_b0x 的 GET 改 POST + 图片马 + panel.php
- **类型与来源**: 【亲历】《Vulnhub靶场实战指南》第二节 Billu_b0x
- **问题/输入**: `test.php` 的包含参数用 GET 带 `?file=/etc/passwd` 没反应。
- **方法论的使用**: 在 Hackbar/Burp 中 Change request method 转 POST，重新提交同一参数，成功读到 `/etc/passwd`；随后批量下载页面源码，发现 `panel.php` 的不明显包含点；制作图片马上传到可写目录，用包含参数指向它并带 `cmd` 参数验证命令执行，再反弹 shell。
- **结论**: 方法切换是低成本固定第二步；组合马需要同时有上传点与包含点，`panel.php` 这类点要靠读源码发现。
- **结果**: 原书记载成功读到 `/etc/passwd` 并通过组合拿 shell，具体 flag 值未给。

### 示例 4: The Ether 的 Apache 失败转 ssh 日志
- **类型与来源**: 【亲历】《Vulnhub靶场实战指南》第八节 The Ether
- **问题/输入**: LFI 确认存在，但读不到常规文件；需要一条 getshell 路径。
- **方法论的使用**: 回看侦察结果，靶机只开放 http 与 ssh；先试包含 Apache access.log，因 www-data 无读写权限失败；转试 ssh 登录日志 `auth.log` 成功读到；用一句话作为 ssh 用户名写入日志，再包含该日志 getshell。
- **结论**: 日志载体由开放服务清单驱动枚举，不由盲猜决定；一种失败就转下一种。
- **结果**: 原书记载成功读到 ssh 登录日志并继续 getshell。

## A2 — 触发场景 (Future Trigger) ★

### 用户会在什么情境下需要它
1. 找到可控文件路径参数，不确定漏洞是否真实存在、下一步读什么。
2. `include` 读源码文件，回显里没有 `<?php` 文本，只有空白或执行结果。
3. `?file=/etc/passwd` 加在 URL 上没反应，怀疑被过滤或走不同分支。
4. 有上传点但传不上去 shell，或有包含点但找不到可控文件。
5. LFI 确认存在，但不知道包含哪个文件才能 getshell。
6. Apache 日志包含失败，想知道还有没有别的日志可用。

### 语言信号（出现这些就该激活）
- 中文：「任意文件读怎么起手」「读到 /etc/passwd 之后干什么」「LFI 后续利用」「include 读源码不显示」「php://filter 怎么用」「包含 /etc/passwd 没反应」「LFI 怎么绕过」「文件包含怎么 getshell」「图片马怎么用」「日志包含失败」「该包含哪个日志文件」
- English: "arbitrary file read what to read next", "LFI source code not shown", "php://filter base64", "LFI returns nothing", "LFI + upload combo", "log poisoning which log", "file inclusion to shell"

### 与相邻能力的区分
- 与 `web-vuln-channel-selection` 的区别：那张卡处理 SQLi/SSRF/XSS/逻辑漏洞的判型与通道；本卡专管文件读/包含这一类的完整利用链。
- 与 `web-recon-source-leak` 的区别：`.git` 泄露是版本库文件暴露，不走文件读参数；本卡的可控路径参数是应用自身的漏洞。
- 与 `rce-egress-and-shell` 的区别：本卡负责「把包含变成命令执行」，那张卡负责「拿到命令执行后怎么反弹 shell、怎么看到结果」。
- 与 `lab-privesc` 的区别：本卡停在 getshell / 低权限 shell，提权由那张卡接手。

## E — 可执行步骤 (Execution)

**必需输入**: 可控的文件路径参数或 `include`/`require` 类函数；目标为 Linux（`/proc` 路径适用）；PHP 环境（Filter 分支）；上传功能与可写目录（组合马分支）；开放服务清单（日志分支）。缺关键前提时先回 `web-recon-source-leak` 或 `lab-workflow-and-triage` 补侦察。
**交付物与完成标准**: 一份「文件读利用报告」：漏洞存在性结论、分层读到的资产清单、卡点处置记录（Filter/POST/组合马/日志）、以及一个可重复的命令执行或 shell。判据是能稳定打印目标文件内容或执行 `id` 等命令。

1. **`/etc/passwd` 基线确认**
   - 做什么：读 `/etc/passwd`，回显含 root 等系统账户即确认漏洞存在。
   - 完成标准：明确「漏洞存在 / 不存在」，不在假漏洞上继续 fuzz。
   - 判停：读不到时不要直接 fuzz flag 路径；`/etc/shadow` 普通权限读不到属正常，不据此否定漏洞。

2. **分层读取资产**
   - 做什么：按 flag 路径族 → Web 配置与 cron → `/proc/self/cmdline`、`/proc/self/environ` 顺序读。
   - 完成标准：得到 flag 或 web 根目录/端口/隐藏目录/明文口令/secret_key 中的至少一类。
   - 判停：flag 不在常规位置时转配置与进程环境；只按固定清单读会漏掉藏在进程环境里的 secret_key。

3. **PHP Filter 通道（执行而非显示）**
   - 做什么：确认 PHP 标签被「吞掉」后，用 `php://filter` 的 Base64 Filter 读该路径，本地解码还原源码。
   - 完成标准：得到含 `<?php` 的原文。
   - 判停：Base64 输出不是 flag，继续解码；对非 PHP 文件套 Filter 无意义；题目禁用 filter 协议时本分支失效，退回其他读取原语。

4. **GET 改 POST**
   - 做什么：GET 带参数被跳转/拒绝时，在 Burp/Hackbar 中 Change request method 转 POST，重新提交同一参数。
   - 完成标准：读到目标文件，判定方法绕过有效。
   - 判停：只对已定位的参数有效；参数本身没找到时回 `web-recon-source-leak` 读源码找包含点（如 `panel.php`）。

5. **组合马 getshell（有上传点）**
   - 做什么：正常图片插入一句话木马生成图片马 → 上传到可写目录 → 包含参数指向该路径并带 `cmd` 参数 → 验证执行 → 反弹 shell（转 `rce-egress-and-shell`）。
   - 完成标准：能执行任意命令并获得持久访问。
   - 判停：缺上传点或缺包含点任一半都走不通；上传目录路径需可预测，包含点需可读上传目录。

6. **日志投毒 getshell（无上传点）**
   - 做什么：回看侦察的开放服务清单，列日志候选（http→Apache access.log，ssh→auth.log）；依次尝试包含；找到可读日志后用一句话作为 ssh 用户名/请求内容写入日志，再包含该日志。
   - 完成标准：包含日志后能执行一句话命令。
   - 判停：某服务日志因权限包含失败时转下一种，不要只试一种就放弃；日志内容必须可被攻击者影响。

## B — 边界 (Boundary) ★

### 不要用的情况
- 目标不是 Linux：`/proc/self` 与 `/etc/passwd` 路径族不适用，需换对应系统路径。
- 非 PHP 环境：`php://filter` 通道不存在，执行而非显示的问题需换其他读取原语。
- 只有文件读、没有上传点也没有可影响内容的日志：本卡第 5/6 步无法完成，停在信息泄漏。
- 漏洞是版本库泄露（`.git`/`.svn`）：转 `web-recon-source-leak`，不走本卡的参数路径。

### 已知失败模式
- 一上来就 fuzz flag 路径，漏洞其实不存在时浪费大量请求（Ch1）。
- `/etc/shadow` 读不到就否定漏洞——普通权限本就读不到（Ch1）。
- 把 Base64 输出当最终 flag 直接提交（Ch1 1.3.1.1）。
- 对非 PHP 文件套 Filter，读到无意义编码（Ch1）。
- GET 不通就判定参数无效，没试 POST（Vulnhub Billu_b0x）。
- 只依赖包含点不找上传点，或反过来——缺任一半组合马都走不通（Vulnhub Acid）。
- 只试 Apache 日志就放弃，The Ether 节因权限失败但 ssh 日志可用（Vulnhub The Ether）。
- 把 zsteg/binwalk 的随机候选当 flag（见 `misc-forensics-and-encoding` 的同类纪律）。

### 作者与时代的局限
- Filter 分支依赖 PHP 的 wrapper/filter 机制与 `allow_url_include` 等配置；现代 PHP 默认配置与题目环境差异大。
- `/proc/[pid]` 明文口令依赖旧版服务把密码写在命令行参数里；现代实践多用配置文件或环境变量，需按实际调整读取目标。
- 组合马与日志投毒针对可写目录、日志可读的靶场环境；成熟生产环境通常限制 Web 目录写权限与日志可读性。
- 两本书的靶场案例都假设「有意留下的缺陷组合」，实战中上传与包含未必共存。

### 容易混淆的方法
- **「路径选错」vs「表示形式不对」**：前者是读错文件（本卡第 2 步），后者是路径对但 PHP 代码被执行（第 3 步）。
- **GET/POST 方法绕过 vs 组合马**：前者解决参数怎么传才生效，后者解决两个漏洞怎么组合拿 shell。
- **日志投毒 vs 静态线索**：日志是「由开放服务动态选择的攻击载体」，页面注释是静态明示线索（`web-recon-source-leak`）。
- **文件读 vs SSRF**：文件读直接让应用读路径，SSRF 借服务器访问它才能到达的内网地址。

### 授权与合规边界
> 待补充（用户自行填写）
