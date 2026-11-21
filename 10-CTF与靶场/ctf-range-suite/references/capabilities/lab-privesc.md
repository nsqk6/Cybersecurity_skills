# Linux 靶场提权：路线排序与配置错误

## R — 原文 (Reading)

> Linux提权的基本思路：1. 溢出提权 2. 使用msf提权 3. 错误的SUID文件提权

> — 《Vulnhub靶场实战指南》第八节 The Ether / 第九节 zico2

> 所以用CVE-2017-1000112提权即可，但是目标机上没有gcc，这种情况，可以本地搭建和目标机一样的环境，在本地编译好提权exp后，在目标机器上运行即可。

> — 《Vulnhub靶场实战指南》第五节 LazySysAdmin「思路二」

> 3.su提权需要一个终端，没有经验只能Google解决了。

> — 《Vulnhub靶场实战指南》第四节 Acid 步骤9

> 查看cleanup文件的权限为777，可以随意修改和执行，可以将文件内容改成一个反弹shell

> — 《Vulnhub靶场实战指南》第十二节 BSides「提升权限」

## I — 方法论骨架 (Interpretation)

这张卡处理「已经拿到一个低权限 shell，怎么升到 root」这段靶场常见困境。它把八个单元按一条优先级链组织：**先修好 shell 的基础设施（tty、编译能力）→ 按成本从低到高排序提权路线 → 把「配置错误」这一类展开成具体配方 → 处理失败与持久化陷阱**。核心思想是：提权不是随手试 exp，而是有依赖顺序的搜索——通用内核 exp 命中即结束，没必要先手工翻所有文件；前一个路线失败时要能识别「是环境不对」而不是「没漏洞」。

**第一段：先修 shell 基础设施，再谈提权**。
- **tty 派生**：反弹 shell 得到的通常是无 tty 的 `/bin/sh`，而 `su`/`sudo` 会检查标准输入是否为终端，报 "must be run from a terminal" 或 "no tty present"。用 `python -c 'import pty;pty.spawn("/bin/bash")'` 起一个带伪终端的 shell 就能满足检查。这是从「拿到 shell」到「能切换用户」之间的固定门槛；不知道这个技巧时会误判为密码错误或账户被锁。
- **本地编译 exp**：提权 exp 的交付物是可执行二进制，编译只是生成手段。目标机上没有 gcc 不等于漏洞不可利用——只要在本地复刻相同发行版/架构/内核，编译出兼容二进制再上传即可。这把「编译能力」从目标环境解耦到攻击机，显著扩大可用 exp 范围。但本地与目标版本不一致会导致 ABI/内核不匹配（见位数失败），必须先确认版本，并记得上传后 `chmod +x`（见 `rce-egress-and-shell`）。

**第二段：Linux 提权路线排序**。按「成本从低到高、依赖从通用到特定」排：`uname -a`/`cat /etc/issue` 拿内核与发行版查现成溢出 exp → `use post/multi/recon/local_exploit_suggester` 让 msf 自动枚举 → 均无果则 `sudo -l`、找 SUID 文件、看异常大或异常权限的脚本找配置错误 → 借可 root 执行的程序反弹 root shell 并 `id` 验证 uid=0。The Ether 节溢出失败、msf suggester「没有发现可以利用的提权漏洞」，最后靠 SUID 配置错误成功——说明前两步不必然成功，必须保留第 3 步。

**第三段：配置错误类的两个具体配方**。
- **翻配置文件找密码**：靶场密码几乎不会只存在一处，Web 配置、数据库连接文件、用户 home 目录、history 都是高概率存放点。建立固定枚举清单（`config*.php`、`wp-config.php`、数据库连接文件、`/home/*` 下用户文件与 `.history`），成本低于内核 exp。zico2 节就因不知道真实路径 `/var/www` 而非 `/var/www/html` 导致写 shell 失败。
- **凭据横向复用**：拿到任意一组凭据后先横向试所有已知入口（Web 后台、phpmyadmin、SSH、数据库），可能直接跳过 getshell 这一整套动作。LazySysAdmin 用 Web 得到的 `togie/12345` 直接 SSH 登录。复用不保证处处成功，失败不代表凭据无效，应换服务再试。
- **777/SUID 脚本提权**：当某个由 root 定时执行或带 SUID 位的可执行文件对当前用户可写/可执行时，把它的内容替换成反弹 shell 命令，借高权限拿 root。线索是异常权限（777）或异常文件（本不该存在的大脚本）；`ls -l` 发现 root 拥有且对普通用户可写/可执行的脚本就值得优先验证。BSides 改 `/usr/local/bin/cleanup`（777）为 python 反弹拿 root；The Ether 用 root 所有、具 SUID 的 `xxxlogauditorxxx.py` 以 root 运行 msf 木马。要区分「有 SUID 位」与「777 可写」，两者利用方式不同但都源于权限配置错误。

**第四段：失败诊断与持久化陷阱**。
- **架构位数不匹配**：内核 exp 与系统架构强绑定，64 位 exp 在 32 位系统上无法运行，失败现象是编译或执行报错，容易被误读为「内核版本不对」而继续换 exp。判据是提权失败时先回看 `uname -a` 的架构（i686/i386 vs x86_64），再决定是否换 exp 或交叉编译。
- **马被清理脚本删除**：Web shell 反复消失有两个不同原因——杀软查杀或定时任务清理，处置不同。作者先误判为杀软，实际是 `tidyup.sh` 每 3 分钟清理 webapps；反弹出来的独立 shell 不依赖 webapps 目录里的文件，因此能绕过清理。判据：看到「周期性消失」就查 crontab/清理脚本，而不是直接上免杀。若清理脚本本身有 root 权限且可写，就转第三段的 777/SUID 配方让它反弹 root shell。

**四段关系**：第一段修基础设施（tty、编译），第二段给排序，第三段展开「配置错误」这一类（找密码、复用凭据、777/SUID），第四段处理失败诊断与持久化。贯穿纪律是「失败时先判原因（架构？编译工具？清理任务？路径？）再换手段」，而不是盲目试更多 exp。

## A1 — 应用示例 (Application Example)

### 示例 1: The Ether 的提权路线排序与 SUID 收尾
- **类型与来源**: 【亲历】《Vulnhub靶场实战指南》第八节 The Ether
- **问题/输入**: 已拿到低权限 shell，需要 root。
- **方法论的使用**: `uname -a` 查内核找溢出 exp（失败，后分析是 32 位靶机跑 64 位 exp）→ msf `local_exploit_suggester` 未发现可用提权漏洞 → 回到文件系统找 SUID 配置错误，用 root 所有、具 SUID 的 `xxxlogauditorxxx.py` 以 root 运行 msf 木马 → `id` 验证 uid=0。
- **结论**: 排序由成本与通用性决定；前两步失败不意味着无路，必须保留第 3 步。
- **结果**: 原书记载靠 SUID 配置错误提权成功，具体 flag 未给。

### 示例 2: LazySysAdmin 的无 gcc 本地编译
- **类型与来源**: 【亲历】《Vulnhub靶场实战指南》第五节 LazySysAdmin「思路二」
- **问题/输入**: 确认用 CVE-2017-1000112 提权，但目标机没有 gcc。
- **方法论的使用**: 确认目标发行版/内核/架构 → 不在目标上编译 → 本地搭同版本环境编译 exp 得到兼容二进制 → 上传到目标（记得 `chmod +x`）→ 运行提权。
- **结论**: 编译能力可解耦到攻击机；版本不一致会导致 ABI/内核不匹配，必须先确认版本。
- **结果**: 原书记载改用本地编译 CVE-2017-1000112 exp。

### 示例 3: pty 派生解决 su 无终端
- **类型与来源**: 【亲历】《Vulnhub靶场实战指南》第四节 Acid / 第二节 Breach / 第七节 FristiLeaks
- **问题/输入**: 反弹 shell 里执行 `su` 报 "must be run from a terminal" / "no tty present"。
- **方法论的使用**: 判定为无终端 → `python -c 'import pty;pty.spawn("/bin/bash")'` 派生带 tty 的 shell → 重新 `su - 用户` 输入密码完成切换。
- **结论**: 这是提权前的固定门槛；不知道技巧会误判为密码错误或账户被锁。
- **结果**: 原书记载 Breach1.0、Acid、FristiLeaks、LazySysAdmin 等多节都用了该技巧。

### 示例 4: 凭据复用与配置文件找密码
- **类型与来源**: 【亲历】《Vulnhub靶场实战指南》第五节 LazySysAdmin / 第二节 Billu_b0x / 第十一节 SickOs
- **问题/输入**: 拿到一些密码，不知道下一步；或提权时不知道该看哪些文件。
- **方法论的使用**: 从源码/配置/解码得到凭据后横向试 Web 后台、phpmyadmin、SSH、数据库；LazySysAdmin 用 `togie/12345` 直接 SSH 登录跳过反弹；提权时读 `config*.php`、`wp-config.php`、数据库连接文件、遍历 `/home` 与 `.history`；Billu_b0x 从 c.php 拿 mysql 密码、从 phpmyadmin 配置拿 root 密码。
- **结论**: 出题人把突破口放在「配置与复用」而非漏洞链；找到密码不等于能用，仍需验证并换服务再试。
- **结果**: 原书记载多节通过配置文件与凭据复用推进。

### 示例 5: tidyup.sh 清理与 777 cleanup 提权
- **类型与来源**: 【亲历】《Vulnhub靶场实战指南》第一节 Breach1.0 / 第十二节 BSides
- **问题/输入**: 上传的菜刀马几分钟后就没了；或发现 root 拥有的 777 脚本。
- **方法论的使用**: 记录消失周期 → 查 crontab/清理脚本确认 `tidyup.sh` 每 3 分钟清理 webapps（先误判为杀软）→ 不再依赖落地 web shell，改反弹独立 shell → BSides 节发现 `/usr/local/bin/cleanup` 权限 777，把内容改成 python 反弹命令，等待/触发执行拿 root → `id` 验证 uid=0。
- **结论**: 「周期性消失」查清理任务而非上免杀；777/SUID 脚本的线索是异常权限与异常文件，SUID 与 777 利用方式不同。
- **结果**: 原书记载两节均成功拿 root。

## A2 — 触发场景 (Future Trigger) ★

### 用户会在什么情境下需要它
1. 拿到 shell 后执行 `su` 报 "no tty present"。
2. 提权 exp 在目标上编译不了（没有 gcc）。
3. 提权 exp 编译后运行报错，不知道是内核版本还是架构问题。
4. 不知道从哪类提权路线开始，想有一个优先级排序。
5. 拿到一组密码，想知道还能登录哪些服务。
6. 提权时不知道该读哪些配置文件。
7. 上传的 shell 几分钟后消失，怀疑有杀软。
8. 看到一个 root 拥有的 777 或 SUID 脚本，不知道怎么用。

### 语言信号（出现这些就该激活）
- 中文：「拿到 shell 后怎么提权」「linux privilege escalation 思路」「内核 exp 打不进去」「su: must be run from a terminal」「no tty present」「切用户失败」「目标机没有 gcc」「exp 编译不了」「exp 编译后运行报错」「32 位 64 位 exp 区别」「拿到密码了下一步干嘛」「找到凭据怎么利用」「提权该看哪些文件」「数据库密码在哪」「菜刀马老是掉」「上传的 shell 被删」「是不是有杀软」「看到 777 文件怎么办」「SUID 提权怎么用」
- English: "how to escalate privileges", "linux privilege escalation order", "kernel exploit won't run", "su not working in reverse shell", "target has no compiler", "credential reuse", "where to find credentials on box", "webshell keeps disappearing", "world writable script privilege escalation", "SUID escalation"

### 与相邻能力的区分
- 与 `lab-workflow-and-triage` 的区别：那张卡管**阶段顺序与止损判断**，本卡管**拿到 shell 后的具体提权路线与配置错误利用**。
- 与 `rce-egress-and-shell` 的区别：那张卡负责拿到 shell 与看见结果（含反弹姿势），本卡从「已有低权限 shell」开始，处理 tty 派生之后的提权。
- 与 `web-recon-source-leak` 的区别：那张卡的源码注释是 Web 前端静态线索，本卡的配置文件是服务器端文件。
- 与 `awd-attack-defense` 的区别：AWD 的 exp 终点是非交互打印 flag，本卡追求 root shell；AWD 轮换节奏下提权未必值得。

## E — 可执行步骤 (Execution)

**必需输入**: 一个可稳定执行命令的低权限 shell；可读 `/etc/passwd`、内核版本、sudo 权限；对目标发行版/架构的识别能力；上传通道与攻击机监听。若 `su` 报无终端或目标无编译器，先执行第 1 步再继续。
**交付物与完成标准**: 一份「提权报告」：基础设施处理记录（tty/编译）、按排序试过的路线及结果、配置错误类的枚举清单与命中项、失败诊断（架构/路径/清理任务）、以及 `id` 显示 uid=0 的 root shell。判据是 `id` 验证 uid=0，而非「exp 跑完没报错」。

1. **修 shell 基础设施**
   - 做什么：`su` 报 tty 错误时 `python -c 'import pty;pty.spawn("/bin/bash")'`；目标无 gcc 时确认发行版/内核/架构，本地搭同版本环境编译 exp 后上传并 `chmod +x`。
   - 完成标准：`su` 可用；有可在目标运行的兼容 exp 二进制。
   - 判停：本地与目标版本不一致会导致 ABI/内核不匹配，必须先确认版本；上传后不赋权会 "Permission denied"（见 `rce-egress-and-shell`）。

2. **按优先级搜索提权路线**
   - 做什么：`uname -a`/`cat /etc/issue` 查内核找溢出 exp → msf `local_exploit_suggester` → `sudo -l`、找 SUID 文件、看异常大/异常权限脚本。
   - 完成标准：找到至少一条可尝试的路线，或明确前两步无果并进入配置错误搜索。
   - 判停：溢出 exp 失败先查架构位数（第 4 步），不要盲目换更多 exp；前两步无果必须保留第 3 步。

3. **配置错误类：枚举凭据与可写文件**
   - 做什么：读 `config*.php`、`wp-config.php`、数据库连接文件、`/home/*` 与 `.history` 找密码；拿到凭据横向试 Web 后台/phpmyadmin/SSH/数据库；`ls -l` 找 root 拥有且对当前用户可写/可执行的 777 或 SUID 脚本，读内容确认用途后替换成反弹 shell 命令。
   - 完成标准：拿到可用凭据或找到一个可替换的高权限可执行文件。
   - 判停：找到密码不等于能用，需验证并换服务再试；区分「有 SUID 位」与「777 可写」，利用方式不同；注意 `/var/www` 与 `/var/www/html` 这类真实路径差异。

4. **失败诊断：架构位数**
   - 做什么：exp 执行失败时记录完整报错，核对 `uname -a` 的架构（i686/i386 vs x86_64）与 exp 说明；位数不一致则换对应架构 exp 或交叉编译（回第 1 步）。
   - 完成标准：明确失败原因是架构、内核版本还是编译选项。
   - 判停：只在「版本匹配」上打转会重复试多个同样不可用的 exp；架构一致仍失败再怀疑内核版本。

5. **持久化陷阱：马被清理**
   - 做什么：上传的 shell 周期性消失时记录周期 → 查 crontab/清理脚本（如 `tidyup.sh`）→ 不再依赖落地 web shell，改反弹独立 shell → 若清理脚本本身有 root 权限且可写，把它改成反弹 root shell（回第 3 步）。
   - 完成标准：获得不被清理的持久 shell，或借清理脚本拿 root。
   - 判停：看到「周期性消失」不要直接上免杀（误判为杀软）；独立反弹 shell 不依赖 webapps 目录，能绕过清理。

6. **验证与记录**
   - 做什么：`id` 验证 uid=0；记录所用路线、配置文件命中项、失败诊断与清理机制。
   - 完成标准：uid=0 且记录完整，可供下一靶复用。
   - 判停：没验证 uid 就当作提权成功是错误；把靶场 777/SUID 经验当实战通用路径需按环境校准（见 `lab-workflow-and-triage`）。

## B — 边界 (Boundary) ★

### 不要用的情况
- 还没有低权限 shell：本卡前提不成立，先走 `rce-egress-and-shell` 或 `file-read-and-include`。
- 真实授权测试环境：777/SUID 配置错误与凭据复用仍是高频面，但「靶场老内核 exp 清单」命中率下降，需先做版本与服务识别（见 `lab-workflow-and-triage`）。
- AWD 竞赛：提权未必值得，flag 通道由 `awd-attack-defense` 决定。
- 目标是读静态 flag 而非 root：最小读取原语可能比提权更省事。

### 已知失败模式
- 不知道 pty 技巧，把 "no tty present" 误判为密码错误或账户被锁（Vulnhub Acid/Breach）。
- 目标无 gcc 就判定漏洞不可利用，没有本地编译这条路（LazySysAdmin）。
- 本地与目标版本不一致导致 ABI/内核不匹配，没先确认版本（LazySysAdmin 与 The Ether 的教训）。
- 忽略架构只在「版本匹配」上打转，重复试多个同样不可用的 exp（The Ether 32 位跑 64 位 exp）。
- 溢出 exp 失败、msf suggester 无结果就认为无路，没有保留 SUID 配置错误这一步（The Ether）。
- 只按文件名判断可疑文件，漏掉「特别大」「本不该存在」的 SUID 脚本（The Ether）。
- 把「周期性消失」误判为杀软，浪费时间做免杀（Breach1.0 tidyup.sh）。
- 只找一处密码、找到密码不验证就当可用；忽略 `/var/www` vs `/var/www/html` 路径差异（Billu_b0x / zico2）。

### 作者与时代的局限
- 内核 exp 清单基于靶机的旧内核（如 CVE-2017-1000112），现代发行版已修复，实战命中率低。
- msf `local_exploit_suggester` 的模块集与 API 随 Metasploit 版本变化。
- pty 派生与 777/SUID 配方针对本地靶机的宽松配置；成熟生产环境普遍限制 SUID、777 与 root 定时任务。
- 两本书都没有覆盖 Windows 提权、容器逃逸、sudo 令牌滥用等现代常见路径。
- 「本地编译」需要能取得匹配发行版/架构环境；交叉编译细节本书未展开。

### 容易混淆的方法
- **无终端（tty）vs 无编译器**：前者是 `su` 检查失败，用 pty 派生；后者是目标没有 gcc，本地编译 exp。
- **无编译器 vs 架构不匹配**：前者是工具链缺失，后者是 exp 与目标架构不符；判据分别是「有没有 gcc」和「uname -a 的位数」。
- **提权路线排序 vs 配置错误配方**：前者决定先试哪类，后者是「配置错误」这一类里的具体做法。
- **777 可写 vs SUID 位**：都源于权限配置错误，但前者靠改文件内容等 root 定时执行，后者靠执行时继承 root 权限。
- **马被清理 vs 马跑不起来**：前者是能跑但被周期性删除（查清理任务），后者是编码/权限导致没执行（见 `rce-egress-and-shell`）。

### 授权与合规边界
> 待补充（用户自行填写）
