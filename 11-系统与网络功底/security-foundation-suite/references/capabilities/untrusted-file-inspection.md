# 可疑文件安全检视：只读、禁 shell、残留恢复

## R — 原文 (Reading)

> "Restricted mode (-Z): All commands that make use of an external shell are disabled."
>
> — 《Vim 101 Hacks》· Hack 63 Restricted Mode

> "avoid making any unintentional modifications"（`-R`/`view` 只读模式的用意）
>
> — 《Vim 101 Hacks》· Hack 58 Read-Only Mode

> "When you have a very long line without any newline, Vim treats it as single line."
>
> — 《Vim 101 Hacks》· Hack 13 Navigate Within a Very Long Line

> "In this example, there are three swap files associated with the previous edits on file1.c, file2.txt and change-password.sql in the current directory."
>
> — 《Vim 101 Hacks》· Hack 59 Recover Swap File Explicitly

## I — 方法论骨架 (Interpretation)

这个能力解决的是：需要在终端里检视一个来路不明、超大或可能是证据的文件，同时满足三个约束——不改动原件、不被文件内容诱导执行外部命令、不因文件的特殊形态（无换行、二进制）而误判内容。核心判断是：**打开文件的"姿势"本身就是一个安全决策**，普通 `vim <file>` 同时暴露了手滑改动、内容诱导执行、二进制损坏三个风险面。

机制分三块。第一块是三个独立开关，对应三个独立风险：`-R`/`view` 只读模式防手滑改动（作者原话是为了 "avoid making any unintentional modifications"）；`-Z`/`rvim` 受限模式关闭一切调用外部 shell 的出口——`CTRL-Z` 挂起、`:sh`、过滤（`:!`）、`system()`、反引号展开，对付"内容不可信、可能诱导执行"的文件；`-b` 二进制模式把内容按字节处理，避免二进制/无换行大文件被当文本损坏。三者可按需叠加，先确认文件信息与状态栏再决定是否深入。

第二块是超长行的误判。没有换行的超长行在屏幕上折成多行显示，按 `j` 会直接跳到下一物理行，看起来像"一下子掠过很多内容"，实际是同一行。压缩 JS、被拼接成单行的日志、未格式化的 payload 都属此类——误判会导致"这段日志缺失/被截断"的错误结论，进而去查日志轮转/采集链路，方向完全错。对策：先 `wc -l` 数行数（行数与视觉不符即超长行），按显示行导航用 `gj`/`gk`/`g^`/`g$`/`gm`，大文件直接 `vim +/pattern <file>` 跳首个匹配或 `vim +143 <file>` 跳指定行，需要结构时用外部工具格式化而非在编辑器里硬读。

第三块是 swap 残留的取证价值。vim 编辑期间把缓冲区写到同目录的 `.<name>.swp`；进程崩溃、会话断开、强制重启后 swap 残留，保存的是"尚未写回磁盘的编辑内容"——可能包含当前版本已删除或改写的片段。`vim -r` 列出所有 swap 及归属信息（owner、时间、主机名、process ID），这些元数据本身可与 history、auth 等其他日志对齐构造时间线。取证时先复制 `.swp` 原件再操作，不要在原位置恢复。直接 `vim` 打开原文件会弹 `[O]pen Read-Only, (E)dit anyway, (R)ecover` 选择，选错会覆盖 swap 或丢掉恢复机会。

## A1 — 应用示例 (Application Example)

### 示例 1: 用 -Z 打开不可信文件
- **类型与来源**: 【例题】《Vim 101 Hacks》Hack 63 Restricted Mode
- **问题/输入**: 收到一份来路不明的文本，怀疑内容里埋了诱导执行外部命令的指令（如模型/脚本片段里写 `:!curl ...`）。
- **方法论的使用**: 用 `vim -Z <file>`（或 `rvim <file>`）打开——受限模式禁用所有调用外部 shell 的操作：`CTRL-Z` 挂起、`:sh`、过滤、`:system()`、反引号展开全部失效。打开后先确认文件信息与状态栏，再决定是否深入。若只是查看且内容可信度稍高，用 `vim -R <file>` 只读即可。
- **结论**: 对不可信内容用普通模式打开，`:!cmd` 一类操作会把分析环境暴露给文件内容；三个风险（改动/诱导执行/二进制损坏）各有独立开关。
- **结果**: 原书给出 `vim -Z filename`、`vim -R filename.txt`、`vim -b binaryfile` 三个命令；未提供真实攻防结果。

### 示例 2: wc -l 戳穿"日志缺了一段"的错觉
- **类型与来源**: 【例题】《Vim 101 Hacks》Hack 13 Navigate Within a Very Long Line
- **问题/输入**: 打开一份日志，视觉上只看到两行，怀疑中间"缺了很多内容"，准备去查日志采集链路。
- **方法论的使用**: 先 `wc -l <file>` 数物理行数——若行数与视觉严重不符，说明存在无换行的超长行。按显示行导航：`gj`/`gk` 上下、`g$` 行尾、`g^` 行首、`gm` 中间；大文件用 `vim +/pattern <file>` 直接跳首个匹配、`vim +143 <file>` 跳指定行。需要结构时用外部工具格式化。
- **结论**: 压缩 JS、拼接成单行的日志、未格式化 payload 都表现为超长行；"视觉跳行"不等于数据缺失，误判会让排查方向完全错。
- **结果**: 原书给出 `gj`/`gk`/`g^`/`g$`/`gm` 五个键位表与 `vim +/search-term <filename>` 定位法。

### 示例 3: 从 .swp 找回已删除的配置段
- **类型与来源**: 【例题】《Vim 101 Hacks》Hack 59 Recover Swap File Explicitly
- **问题/输入**: 编辑器崩溃后怀疑某段配置在"已保存版本"中被删掉，想从 swap 里找回来。
- **方法论的使用**: `vim -r` 列出当前目录、`~/tmp`、`/var/tmp`、`/tmp` 下的 swap，记录 `owned by`/`dated`/`user name`/`host name`/`process ID`；定位到目标 swap（如 `change-password.sql`，标注 `modified: YES`）后，先复制 `.swp` 原件，再用 `vim -r <file>` 恢复查看内容。
- **结论**: swap 保存的是未写回磁盘的缓冲区片段，可能含当前版本已删除/改写的片段；元数据本身可与 history、auth 对齐构造时间线。
- **结果**: 原书示例列出三个 swap，其中 `change-password.sql` 的 swap 标注 `modified: YES`；swap 不是完整文件，不能当完整版本使用。

### 示例 4: 二进制文件用 -b 检视（合成演练）
- **类型与来源**: 【合成演练】按本卡 E 段规则推演，依据《Vim 101 Hacks》Bonus Hack 14 二进制单元
- **问题/输入**: 有一个可疑的二进制文件，想在终端里看它的可打印字符串，避免被当文本处理而损坏显示。
- **方法论的使用**: 用 `vim -b <file>` 以二进制模式打开（作者列出 Bonus 14 处理二进制文件的方法），先确认状态栏信息，不写入；如需提取字符串用外部 `strings` 工具而非在编辑器里改。
- **结论**: 二进制内容被当文本处理会损坏显示/误判；`-b` 是对付无换行大文件和二进制的开关。
- **结果**: 按规则推演得到安全的检视方式；原书未提供此具体案例的真实结果。

## A2 — 触发场景 (Future Trigger) ★

### 用户会在什么情境下需要它
1. 需要打开一个来路不明的文件（别人给的、从取证镜像里提取的、从可疑目录发现的），担心手滑改动原件或被内容诱导执行。
2. 文件超大、无换行、疑似压缩/拼接内容，在编辑器里看起来"只有几行"，怀疑丢数据。
3. 编辑器崩溃、会话断开或机器被强制重启后，想找回未保存的编辑内容，或从 swap 元数据追溯谁在何时编辑过什么。
4. 怀疑某文件是二进制/含大量控制字符，想安全检视其可打印部分。

### 语言信号（出现这些就该激活）
- 中文：「看一个可疑文件」「别改到原文件」「打开文件只看到两行」「日志好像缺了一段」「minified js hard to read」「vim 崩溃了内容丢了」「找被删掉的那段配置」「二进制文件怎么看」
- English: "open untrusted file safely", "read-only vim", "restricted mode rvim", "very long line vim", "recover unsaved vim changes", "swap file forensics", "binary file in vim"

### 与相邻能力的区分
- 与 `text-processing-pipeline` 的区别：相邻卡在命令行对文本做聚合出结论，本卡在编辑器里安全检视单个可疑/超大文件的形态与状态。
- 与 `text-field-and-regex` 的区别：两者都处理"不可见字符"，但相邻卡用 `sed -n l` 在命令行显形以便修正匹配，本卡用 vim `-b` 二进制模式检视文件内容整体。
- 与 `host-timeline-forensics` 的区别：swap 元数据可作为时间线证据，但本卡负责"怎么安全打开与恢复 swap"，相邻卡负责"怎么把 history/文件时间/认证日志交叉成时间线"。

## E — 可执行步骤 (Execution)

**必需输入**: 文件路径与来源可信度（可信/来路不明/明确恶意）；文件形态线索（大小、是否有换行、是否二进制）；目的是"只看不改"还是"恢复未保存内容"。缺"来源可信度"必须先问。

**交付物与完成标准**: 一次不改动原件的检视 + 一份关于文件形态/内容的结论（或恢复出的片段）；完成标准是原件未被写入，且对"是否缺数据""是否含诱导内容"有明确判断。

1. **先问来源与目的**
   - 做什么：确认文件是否来路不明、是否可能是证据、目的是查看还是恢复。
   - 完成标准：明确用只读还是需要恢复模式。
   - 判停：若文件明确是证据且需保全 → 先复制原件，全程在副本上操作。

2. **选打开开关**
   - 做什么：只是查看 → `vim -R <file>`/`view <file>`；内容不可信、可能诱导执行 → `vim -Z <file>`/`rvim <file>`；二进制/无换行大文件 → `vim -b <file>`。三者可叠加。
   - 完成标准：打开姿势覆盖了来源对应的风险面。
   - 判停：若仍需写入文件 → 不要在可疑文件上直接写，转副本。

3. **核对文件形态，防超长行误判**
   - 做什么：`wc -l <file>` 数物理行数，与屏幕视觉行数对比；不符即超长行。用 `gj`/`gk`/`g^`/`g$`/`gm` 按显示行导航，或 `vim +/pattern`/`vim +N` 直接定位。
   - 完成标准：能区分"真的缺数据"和"超长行折叠显示"。
   - 判停：怀疑真缺数据 → 再去查日志轮转/采集链路；不要因视觉跳行就下结论。

4. **恢复 swap（按需）**
   - 做什么：`vim -r` 列出所有 swap 及 owner/dated/hostname/PID；复制目标 `.swp` 原件；`vim -r <file>` 恢复查看；把 swap 元数据与其他日志对齐。
   - 完成标准：恢复内容在副本上查看，原件与 swap 均未被覆盖。
   - 判停：直接打开原文件弹出 `[O]/(E)/(R)` 选择时 → 不要选覆盖 swap 的选项，避免丢掉恢复机会。

5. **形成结论**
   - 做什么：记录文件形态（行数/是否二进制/是否含不可见字符）、是否含诱导执行内容、是否有 swap 残留。
   - 完成标准：结论能回答打开前的问题，且原件未被改动。
   - 判停：若发现内容诱导执行 → 全程用 `-Z` 复核，不要在普通模式里实验。

## B — 边界 (Boundary) ★

### 不要用的情况
- 需要对文本做批量检索/聚合——转 `text-processing-pipeline`，编辑器不是聚合工具。
- 需要修正文本匹配的静默错误——转 `text-field-and-regex`，用命令行工具验证。
- 文件是结构化数据需要程序化解析——用专用解析器，vim 只做肉眼检视。
- 已经确认文件完全可信且需要编辑——普通 vim 即可，不必叠加限制开关。

### 已知失败模式
- **手滑改动证据文件**：《Vim 101 Hacks》Hack 58 用普通 vim 打开证据文件，误按 `dd` 或 `:wq` 就改了原件；`-R`/`view` 用 "avoid making any unintentional modifications" 对冲。
- **内容诱导执行**：同书 Hack 63 对不可信内容用普通模式打开，`:!cmd`/`system()`/反引号会把分析环境暴露给文件内容；`-Z` 关闭一切外部 shell 出口。
- **二进制被当文本损坏**：同书 Bonus 14 用普通模式处理二进制/无换行大文件会损坏显示，需 `-b`。
- **超长行误判数据缺失**：同书 Hack 13 "Vim treats it as single line"，`j` 直接跳物理行，误判会让人去查日志轮转/采集链路，方向完全错；`j`/`k` 在超长行上反复跳永远停在同两行之间。
- **swap 恢复选错**：同书 Hack 59 直接 vim 打开原文件弹 `[O]/(E)/(R)` 选择，选错会覆盖 swap 或丢掉恢复机会；swap 是缓冲区片段不是完整文件。
- **g 系列键位不适用时**：`l 20` 这类带宽度参数仅 GNU sed 支持；`gm` 跳中间等 g 系列在部分 vim 版本行为有别。

### 作者与时代的局限
- 基于 2000 年前后的 Vim 6.x/7.x，`-Z`/`-b`/`+N`/swap 行为在 Neovim 与新版 Vim 中有细节差异。
- 示例面向本地文件系统；网络挂载/只读介质上的 swap 行为作者未覆盖。
- `-Z` 是 vim 层的限制，不替代操作系统层的隔离；作者把合规边界留给用户自行填写。

### 容易混淆的方法
- `-R` vs `-Z`：前者防手滑改动，后者防内容诱导执行，针对不同风险，可叠加。
- `-b` vs `sed -n l`：前者在 vim 里按字节检视文件整体，后者在命令行让不可见字符显形以修正匹配。
- swap 恢复 vs history 溯源：swap 记录"编辑过什么内容"，history 记录"执行过什么命令"，取证时互补（见 `host-timeline-forensics`）。

### 授权与合规边界
> 待补充（用户自行填写）
