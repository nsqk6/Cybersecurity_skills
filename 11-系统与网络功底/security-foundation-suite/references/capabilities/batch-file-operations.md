# 批量文件操作与不可逆动作防护

## R — 原文 (Reading)

> "• \; is slow, executes command once for each line. • | xargs may fail with filenames containing whitespace, quotes or slashes."
>
> — 《grep-find-sed-awk》· Part 1 "find" · "-exec or | xargs?"

> "The best practice is to execute the same command with ls –l to make sure you know which files will get deleted when you execute the command with rm."
>
> — 《Linux 101 Hacks》· Hack 18 Find Command

> "you may get error message: /bin/rm Argument list too long – Linux. Use xargs to avoid this problem."
>
> — 《Linux 101 Hacks》· Hack 22 Xargs Command

> "手指轻轻一敲就有可能输入chmod -R这样的命令，它将改变整个文件系统的权限，如果没有做备份的话，没有几年的时间恐怕是无法恢复了"
>
> — 《Linux与unix shell编程指南》· 第1章 1.10 小结

## I — 方法论骨架 (Interpretation)

这个能力解决的是：需要把 find 筛出来的一批文件交给下游命令批量处理（删除、改内容、改权限），而这类操作往往不可逆——删错、改错、传参方式选错，代价是数据丢失或权限面被破坏，且执行时不产生可读回执。核心判断是：**批量操作的风险不在语义难度，而在反馈缺失和传参方式选错**。先决定"怎么传"，再决定"怎么安全地执行"。

第一层是传递方式选型。find 结果交给下游有三种方式，判据不是"哪个快"，而是"下游命令是否需要每个文件独立执行一次"：`-exec {} \;` 对每个文件单起一个进程——慢，但每个文件是独立上下文，下游的累计变量（如 awk 的 NR）不会跨文件串味；`-exec {} +` 与 `| xargs` 一次传多个文件——快，但下游只跑一遍、跨文件状态会混；`xargs` 以空白分词，文件名含空格/引号会被切碎。所以做"逐文件判定"（如逐文件注释率）必须用 `\;` 保持 awk 简单和正确，用 xargs + FNR 虽可行但要额外处理状态。遇到 "Argument list too long"（超过内核单次 exec 上限），用 `find -print0 | xargs -0` 收口：`-print0` 用 NUL 分隔、`xargs -0` 用 NUL 解析，一次解决"参数过长"和"空格文件名被拆词"两个故障。

第二层是不可逆动作的对照实验。find 的匹配表达式（`-size`、`-mtime`、`-name` 通配）很容易与预期不符，而 `-exec rm` 不二次确认、不留回执。做法是把最终命令的动作整体替换成 `ls -l` 做免费 dry-run：路径、条件、数量原样验证，只有最后一个动作变了。同理，`sed -i` 是原地重写（写临时文件再改名），中途中断会留下半截文件且原内容已不存在——对策是加备份扩展名（`-ibak`）或先输出到新文件、`diff` 验证后再 `mv` 覆盖。`chmod -R` 没有"撤销"键且 `-R` 把单点错误平摊到整棵树——对策是先用同一条件列清单、变更前存档权限、不用 root 从高位目录执行、变更后抽样比对。

第三层是通用纪律：清理类操作优先 `mv` 到隔离目录而非直接删；先在受限范围（`-maxdepth`/单目录）验证列表再放全盘；`-name '*.tar.gz'` 必须加引号防 shell 提前展开；根分区上要加 `-type f` 免得把目录交给 rm。

## A1 — 应用示例 (Application Example)

### 示例 1: 逐文件判定注释率——为什么用 -exec \; 而非 xargs
- **类型与来源**: 【例题】《grep-find-sed-awk》Part 1 "find" · "-exec or | xargs?"
- **问题/输入**: 对 src 下每个 .java 文件统计以 `//` 开头的注释行占比，判断哪些文件注释过多。
- **方法论的使用**: 用 `find src -name '*.java' -exec awk '$1 == "//" {a+=1} END {...}' {} \;`。`\;` 让 awk 对每个文件独立执行一次，每个文件的 a、NR 从零开始，占比正确。作者承认"用 xargs + FNR 也可行，但为了保持 awk 简单"才用 `\;`——即用 `\;` 换正确性、牺牲速度是自觉选择。
- **结论**: 下游会输出跨文件累计值（比例、均值、总数）时用 `\;`；否则用 `+` 或 xargs 批量减少进程数。
- **结果**: 原书给出该 find 命令；若用 xargs 让多个文件进同一个 awk 进程而下游用 NR，占比会系统性偏移。

### 示例 2: 删除前用 ls -l 空跑
- **类型与来源**: 【例题】《Linux 101 Hacks》Hack 18 Find Command
- **问题/输入**: 想删除 / 下大于 100M 的 .tar.gz 文件。
- **方法论的使用**: 先完整写出含 rm 的最终命令但不执行；复制一份把 `-exec rm -f {} \;` 换成 `-exec ls -l {} \;` 执行，得到将被删除的确切清单；核对数量与路径（尤其确认没把目录/上级目录卷进来）；再执行原命令。清理类优先 `mv` 到隔离目录而非直接删。
- **结论**: "同一表达式、不同动作"的对照实验等于免费 dry-run；路径、条件、数量全部原样验证。
- **结果**: 原书命令 `find / -type f -name *.tar.gz -size +100M -exec ls -l {} \;` 之后才是 `-exec rm -f {} \;`（注意原书裸写通配符，实际执行要加引号）。

### 示例 3: Argument list too long 修法
- **类型与来源**: 【例题】《Linux 101 Hacks》Hack 22 Xargs Command
- **问题/输入**: `rm $(find ~ -name '*.log')` 报 "Argument list too long"，且日志文件名可能含空格。
- **方法论的使用**: 先确认是"参数过长"而非权限/路径问题；改成 `find ~ -name '*.log' -print0 | xargs -0 rm -f`；先用 `xargs -0 echo` 看最终拼出的命令行，核对后再换真实动作；需要控制每次处理个数加 `-n1`。
- **结论**: `-0` 让 NUL 分隔贯穿始终，同时解决参数分批和空格文件名拆词；只加 xargs 不加 `-0` 会删错对象。
- **结果**: 原书给出 `find ~ -name '*.log' -print0 | xargs -0 rm -f`。

### 示例 4: sed -i 带备份扩展名
- **类型与来源**: 【例题】《Sed & awk 101Hacks》27. Modifying the Input File Directly
- **问题/输入**: 要把 employee.txt 里的 John 改成 Johnny，担心改坏。
- **方法论的使用**: 批量修改前先 `cp` 一份，或 `sed -ibak 's/John/Johnny/' employee.txt` 让 sed 先备份原件；先不加 `-i` 跑一遍、`diff` 原文件与输出确认只改了想改的行；确认后再加 `-i`；校验行数不变、`diff` 与预期一致。
- **结论**: `-i` 是原地重写，中途中断（磁盘满、Ctrl-C）会留半截文件且原内容已不存在；备份是低成本对冲，取证场景应在副本上操作。
- **结果**: 原书示例生成 `employee.txtbak` 备份文件。

### 示例 5: chmod -R 的爆炸半径（合成演练）
- **类型与来源**: 【合成演练】按本卡 E 段规则推演，依据《Linux与unix shell编程指南》第1章 1.10 单元
- **问题/输入**: 想把某目录下属主是 root 的文件权限收敛为 644，但担心波及整棵树。
- **方法论的使用**: 先用 `find <dir> -user root -exec ls -l {} \;` 列出将被影响的文件；把变更前权限 `stat` 结果重定向存档；不用 root、只在必要子树执行（不从高位目录 `-R`）；变更后抽样 `ls -l` 与存档比对。
- **结论**: 权限变更没有撤销键，靠记忆或备份反推；风险在反馈缺失——你以为改了一个目录，实际改了整棵子树。
- **结果**: 按规则推演得到受控的权限变更；原书未提供此具体案例的真实执行结果，只以"千万不要在手指上贴膏药"比喻手滑。

## A2 — 触发场景 (Future Trigger) ★

### 用户会在什么情境下需要它
1. find 筛出一批文件后要批量处理（删除、改内容、改权限），需要决定用哪种传参方式、会不会踩到空格文件名或参数过长。
2. 需要执行批量删除/清理，担心匹配表达式与预期不符、删错对象，希望执行前先看到确切清单。
3. 命令报 "Argument list too long" 或 "No such file"，怀疑是参数传递方式的问题。
4. 需要批量替换文件内容或修改权限，担心改坏且无法恢复。
5. 在写会移动全局文件、改权限、删文件的脚本，需要在启动前把爆炸半径约束住。

### 语言信号（出现这些就该激活）
- 中文：「find 出来的文件怎么批量处理」「xargs 报 No such file」「find -exec 太慢」「批量删除老文件」「Argument list too long」「文件太多删不完/拷不动」「sed -i 改坏了」「批量替换文件内容」「批量改权限」「chmod 改错了怎么恢复」「确认成功再删除」
- English: "mass delete with find", "find -exec too slow", "xargs argument line too long", "in-place edit without backup", "recursive chmod gone wrong", "only delete if copy succeeded"

### 与相邻能力的区分
- 与 `text-processing-pipeline` 的区别：本卡处理**一批文件**（传参、删除、改权限），相邻卡处理**一个文本流**（选行→整形→聚合）。对象从"几百个文件"变成"一份日志"时切换。
- 与 `shell-script-reliability` 的区别：本卡是命令行上一次性批量操作的现场防护（空跑、备份、传参），相邻卡是把防护固化进脚本结构（守卫、&&/|| 闸门、trap、临时文件）。两者可叠加：脚本里的删除动作既用本卡的空跑验证，也用相邻卡的 `&&` 闸门。
- 与 `account-privilege-audit` 的区别：本卡的 chmod/suid 讲的是"自己别制造风险面"（操作安全），相邻卡讲的是"发现系统里已有的风险面"（审计排查）。

## E — 可执行步骤 (Execution)

**必需输入**: find 的筛选条件（路径/名称/大小/时间/属主）；下游动作（删除/替换/改权限）；对文件名的初步判断（是否含空格/引号/换行）；是否不可逆。缺"下游动作"或"筛选范围"必须先问清。

**交付物与完成标准**: 一条可复跑、先空跑验证过、传参方式正确的批量命令 + 一份"将被影响文件"的清单/快照；完成标准是对照实验的清单与预期一致，且不可逆动作有备份或隔离 fallback。

1. **明确筛选条件与不可逆性**
   - 做什么：写出 find 的完整表达式；标出下游动作是否不可逆（rm、覆盖、chmod -R）。
   - 完成标准：能回答"匹配哪些文件、动作能不能撤销"。
   - 判停：筛选范围过大（根分区/高位目录）→ 先加 `-maxdepth`/`-type f` 收窄，不要直接放全盘。

2. **选择传递方式**
   - 做什么：下游会输出跨文件累计值（比例、均值、总数）→ 用 `-exec {} \;`；否则用 `-exec {} +` 或 `| xargs` 批量；文件名可能含特殊字符 → `find -print0 | xargs -0`。
   - 完成标准：传参方式与下游语义匹配，不会串味、不会拆词。
   - 判停：报 "Argument list too long" → 改 `-print0 | xargs -0` 分批；报 "No such file" → 检查是否空格文件名被拆词、是否缺 `-0`。

3. **空跑验证（不可逆动作必做）**
   - 做什么：复制最终命令，把动作整体换成 `ls -l`（或 `echo`）；执行得到将被影响的确切清单。
   - 完成标准：数量与路径符合预期，没有意外把目录/上级目录卷进来。
   - 判停：清单不符 → 回去改筛选条件，不要执行真实动作。

4. **做备份/隔离，再执行**
   - 做什么：清理类优先 `mv` 到隔离目录而非直接删；`sed -i` 用 `-ibak` 或先输出到新文件、`diff` 后再 `mv`；权限变更先 `stat`/`ls -l` 存档快照。
   - 完成标准：有可恢复的原件或快照；不用 root 从高位目录执行。
   - 判停：没有备份/快照 → 不要执行不可逆动作，先补齐。

5. **变更后抽样复核**
   - 做什么：抽样 `ls -l`/`diff` 与清单/存档比对；确认改动范围与预期一致。
   - 完成标准：改动范围可控、结果符合预期。
   - 判停：发现越界改动 → 用存档快照回滚，不要试图"再改回来"。

## B — 边界 (Boundary) ★

### 不要用的情况
- 对象是单个文本流而非一批文件——转 `text-processing-pipeline`。
- 需要把防护长期固化成可复用脚本——转 `shell-script-reliability`。
- 需要审计系统里已存在的 suid/capabilities 风险面（而非自己操作权限）——转 `account-privilege-audit`。
- 文件名跨 NFS/特殊文件系统且 NUL 分隔行为异常——需先验证 `-print0` 在该文件系统上可用。

### 已知失败模式
- **传参方式选错**：《grep-find-sed-awk》Part 1 `\;` 逐文件但慢，`+`/xargs 批量但跨文件状态混；用 xargs 做逐文件判定而下游用 NR，结论系统性偏移。
- **xargs 不认特殊文件名**：同书 "`| xargs may fail with filenames containing whitespace, quotes or slashes`"；缺 `-0` 时空格文件名被拆成两个参数，删错对象。
- **跳过空跑**：《Linux 101 Hacks》Hack 18 `-exec rm` 不二次确认、不留回执，跳过 `ls -l` 对照就不知道会删什么。
- **`Argument list too long`**：同书 Hack 22 超过内核单次 exec 上限；只加 xargs 不加 `-0` 会拆词。
- **裸写通配符**：同书 Hack 18 原文 `-name *.tar.gz` 未加引号，实际执行时被 shell 提前展开；根分区不加 `-type f` 会把目录交给 rm。
- **`chmod -R` 不可逆**：《Linux与unix shell编程指南》1.10 "-R 把单点错误平摊到整棵树"且无回执；无备份时"没有几年的时间恐怕无法恢复"。
- **`sed -i` 中途中断**：《Sed & awk 101Hacks》#27 原地重写（写临时文件再改名），磁盘满或 Ctrl-C 留半截文件、原内容已不存在。
- **批量 xargs sed -i 一步到位**：同书表达式错则全部文件一起错；取证场景应在副本上操作，不动原件。

### 作者与时代的局限
- 示例基于 GNU findutils/coreutils（`-print0`、`-exec +`），BSD/macOS find 的选项写法有别，需核对。
- "优先 mv 到隔离目录""不用 root"是作者的稳健建议，具体合规要求用户自行补充（见授权占位）。
- 2000 年前后的文件系统与内核参数（ARG_MAX）与现代系统量级不同，但传参原理一致。

### 容易混淆的方法
- `-exec \;` vs `-exec +` vs `xargs`：判据是"下游是否需要每文件独立执行"，不是速度。
- `-print0` vs `-print`：前者 NUL 分隔配 `xargs -0`，后者换行分隔遇空格/换行文件名会出错。
- 本卡的"操作安全"与 `account-privilege-audit` 的"风险面审计"：一个管"别制造"，一个管"去发现"。

### 授权与合规边界
> 待补充（用户自行填写）
