# 内存破坏与整数漏洞定位

## R — 原文 (Reading)

> Instead, you can reasonably estimate exploitability by answering a few questions about the resulting memory corruption. This approach is not as definitive as a proof-of-concept exploit, but it's far less time consuming, making it adequate for most assessments.
> — 《The Art of Software Security Assessment》Ch5 Assessing Memory Corruption Impact

> You want to look for situations in which a function takes a size_t or unsigned int length parameter, and the programmer passes in a signed integer that can be influenced by users.
> — 《The Art of Software Security Assessment》Ch6 Signed/Unsigned Conversions

> JL 或者JLE 跳转指令是考虑符号的，所以EAX 可以是负的，例如EAX=0xffffffff 就是-1，也是小于0x10 的。
> — 《从零开始学 IDA 逆向（上）》21.5

## I — 方法论骨架 (Interpretation)

这张卡解决两类紧密相关的问题：「这个溢出/整数问题能不能利用、严重到什么程度」以及「逆向二进制时怎么识别这些缺陷」。它把可利用性拆成可独立回答的六个问题，把整型缺陷拆成三种可枚举的机制。

内存破坏影响六问：① 缓冲区在哪（栈/堆/全局，决定可覆盖什么控制数据）；② 还覆写了什么（局部变量、堆头、SEH 会否提前崩溃）；③ 能覆写多少字节（太少可能只碰无用变量，太多必崩）；④ 用什么数据覆写（是否可控，还是只能写 NUL）；⑤ 内存块是否被共享（别名/双重分配/多线程共用）；⑥ 有哪些防护（栈 cookie、SafeSEH、ASLR、不可执行栈）。六问答案组合决定「可利用/可能可利用/仅拒绝服务」的结论。关键反直觉点：不要因为「只溢出一个字节」或「只能写 NUL」就判不可利用——off-by-one 改栈帧指针最低字节可完全接管；覆写字节过多导致必崩也不等于不可利用（可打 SEH/异常处理）。

整型缺陷三种机制必须分开验证：
- **符号转换**：`size_t`/`unsigned` 长度参数收到用户可控的有符号负值 → 被解释成巨大值（read/recvfrom/memcpy/memset/snprintf/malloc 等）。比较时还要按 C 的整型提升与寻常算术转换推出两侧真实类型，检查 `x < 0` 这类恒假条件，以及 `length - sizeof(x)`（sizeof 无符号，把整体拉成无符号）。
- **符号扩展**：`char`/`short` 默认是 signed，小有符号类型转大无符号类型时符号位复制到所有高位，负值变极大正值——即使目标是无符号也照样发生。二进制侧指纹是 `movsx`（有符号扩展），对照 `xor`+`mov` 的零扩展写法。加了 `(unsigned int)len` 强转也不一定修好——转换前的符号扩展已发生。
- **截断**：只发生在赋值、强转、带原型函数调用三种显式位置，因此可枚举。危害在「校验用大类型、使用用小类型」：检查时合法，赋给短类型后变小，绕过检查（如 66000→464 绕过 `f > sizeof(buf)-5`；65536→0 变 root）。二进制侧看有符号比较助记符：`JL/JLE/JG/JGE` 是有符号，`JB/JBE/JA/JAE` 是无符号——「有符号比较 + 无符号长度参数」组合可用负值绕过（−1 即 0xFFFFFFFF 通过 JL 检查，下游按无符号读到极大长度）。

逆向侧的判定手法：定位写入函数（gets_s/scanf_s/strcpy/recv/read）记下目标缓冲区实参与长度实参；进栈视图把缓冲区变量右键 `Array` 让 IDA 按空白自动填元素数得缓冲区字节数 N（最小值，编译器可能放大）；读长度实参——常量则与 N 比较，变量则按 `X` 回溯赋值来源（是否来自 scanf/argv/网络）；`gets_s(Buf,0x300)` 配 Buf 0x300 → 安全，配 Buf 0x10 且 Size 来自 `scanf_s` → 可控。再用栈帧偏移相减算「缓冲区到返回地址」的字节数：`距离 = |offset(目标) − offset(缓冲区)|`，32 位 EBP 帧返回地址在 `+4`、保存 EBP 在 `+0`；沿途被覆写的每个变量（指针、句柄、计数器）都必须填成「对程序有意义的值」才能让控制流活到 `ret`。全局/数据段溢出则改看「同段内缓冲区之后是否有会被 `call [ptr]` 解引用的函数指针」——没有间接调用就只是数据损坏。修补判据：类型改为无符号（JLE→JBE）或在读入处拒绝负值，而不是在使用处补救；antisniff v1.0→v1.1→v1.1.1 三版都被绕过，说明补在症状层等于没修。

## A1 — 应用示例 (Application Example)

### 示例 1: 用六问评估一处 off-by-one 的可利用性
- **类型与来源**: 【例题】《The Art of Software Security Assessment》Ch5 Listing 5-6
- **问题/输入**: 一处只能写 NUL 的 off-by-one 覆写了 `key`，是否可利用？
- **方法论的使用**: 六问逐项答——缓冲区在栈上可覆盖 `key`；覆写物是相邻变量；只能写 1 字节 NUL；数据是固定 NUL（不可控）；无共享；目标有栈 cookie 但…；综合给出评级而不是直接写 PoC。对照 Listing 5-4（覆写 ptr 后随即 free(ptr) 增加利用难度）、Listing 5-5（tokens[] 越界写入的是指向可控数据的指针）。
- **结论**: 1–2 字节覆写有时比 4 字节更好用；off-by-one 可改栈帧指针最低字节从而完全接管；不可因「只能写 NUL」直接判不可利用。
- **结果**: 原书给出评级方法与三处 Listing 例题，说明六问组合决定风险等级。

### 示例 2: 从 JLE 到 JBE 看 −1 绕过长度检查
- **类型与来源**: 【亲历】《从零开始学 IDA 逆向（上）》21.5 +《从零开始学 IDA 逆向（中）》42.3
- **问题/输入**: `VULNERABLE_o_NO.exe` 的长度检查 `if (Size < 0x10)` 为什么输入 −1 就能绕过？
- **方法论的使用**: 找到比较点读助记符为 `JLE`（有符号）；确认被比较变量 `Size` 与下游 `gets_s` 的长度实参是同一个；`0xFFFFFFFF` 在 JLE 眼里是 −1（通过），在 `size_t` 眼里是 4294967295（写爆栈）；输入 −1 实测 JL 通过、写入 2000 字节 'A' 填满整个栈；修复版把 `size` 改为 `unsigned` 后跳转变为 `JBE`，同样输入被拒绝。
- **结论**: 这不是「少写一个边界检查」，而是同一份数据在两种解释下的语义鸿沟；修复要看类型（JLE→JBE），不是改跳转本身。
- **结果**: 原书通过两种编译版本的汇编对照确认了根因与修法。

## A2 — 触发场景 (Future Trigger)

### 用户会在什么情境下需要它
1. 审计发现一处溢出/整数问题，需要在不写 PoC 的前提下给出可信的可利用性/严重性判断。
2. 看到 `signed→unsigned` 的长度参数、比较处 `x < 0`、或 `length - sizeof(x)` 这类表达式，怀疑检查被绕过。
3. 逆向二进制时发现长度检查用 `JL/JLE`、写入函数用无符号长度，想确认能否用负值打进去。
4. 需要计算「要填多少字节才能覆盖返回地址」以及沿途哪些变量必须填合法值。
5. 看到「加了一段检查」的补丁，需要判断是不是补在症状层、是否还是能绕。

### 语言信号（出现这些就该激活）
- 中文：「这个溢出能不能利用」「没有 PoC 怎么判风险」「exploitability assessment」「长度检查为什么没生效」「negative length」「signed unsigned 漏洞怎么找」「char 转 int 出问题」「movsx 是什么漏洞」「类型截断怎么找」「-1 为什么能过检查」「JLE 和 JBE 有什么区别」「要填多少字节才能覆盖返回地址」「全局变量溢出有什么用」
- English: "exploitability assessment", "negative length", "sign extension vulnerability", "integer truncation", "signed unsigned mismatch length check", "offset to EIP", "data section overflow exploitability", "patch bypass"

### 与相邻能力的区分
- 与 `source-audit-dataflow` 的区别：那张卡用 ACC 日志找「是否存在破坏」，本卡接手判「破坏后多严重 / 整型机制是什么」。
- 与 `crash-to-exploit` 的区别：本卡是静态/半静态的评级与类型识别，那张卡从运行时崩溃现场推进到可控 EIP；六问结论是那张卡的输入之一。
- 与 `mitigation-bypass-and-rop` 的区别：本卡列出「有哪些防护」这一问，那张卡专门处理如何绕过这些防护。

## E — 可执行步骤 (Execution)

**必需输入**: 漏洞点位置（源码行或反汇编地址）；目标平台类型定义与位宽；编译产物/栈帧信息（算距离必需）。缺栈帧识别时先按 `binary-analysis-toolchain` 的 `U`/`C` 修复或手工识别 EBP 帧。

**交付物与完成标准**: ① 六问评级表（缓冲区段/覆写物/字节数/可控性/共享/防护 → 结论与依据）；② 整型机制判定（符号转换/符号扩展/截断 + 具体表达式与绕过值）；③ 缓冲区→返回地址距离与「必须填合法值」清单（栈场景）或下游间接调用清单（数据段场景）；④ 补丁有效性判据。完成标准：结论写明依据，可复核。

1. **六问评估内存破坏**
   - 做什么：定位缓冲区所在段（栈/堆/静态，注意 TLS/共享库数据段）；列出覆写路径上的所有对象，找出阻碍利用的（返回前被 free 的指针、被用作长度/权限判断的整数）；量化可写字节数与可控性（任意长度可控/固定长度可控/只能写 NUL）；判断共享/别名；对照部署环境列缓解措施并评估可绕过性；综合给「可利用/可能可利用/仅拒绝服务」结论。
   - 完成标准：六问逐项有答案与依据。
   - 判停：若「只溢 1 字节/只能写 NUL」→ 不得直接判不可利用，查 off-by-one 改栈帧指针的可能；若覆写过多必崩 → 查是否能打 SEH/异常处理。

2. **识别符号转换问题**
   - 做什么：列出所有长度/计数参数为 `size_t`/`unsigned` 的调用（read/recvfrom/memcpy/memset/bcopy/snprintf/strncat/strncpy/malloc）；回溯实参类型，标出有符号且用户可控的，判定能否为负；对每个长度校验按整型提升 + 寻常算术转换推两侧类型，检查 `x < 0` 恒假；特别注意 `length - sizeof(x)`、`length + 1 >= MAX` 混合表达式。
   - 完成标准：每个可疑调用有「实参类型 / 能否为负 / 检查是否生效」三元组。
   - 判停：只看「有没有上限检查」不看是否生效 → 禁止；认为加了 `(unsigned int)` 强转就消除负值 → 转第 3 步复查符号扩展。

3. **识别符号扩展（含强转后复查）**
   - 做什么：找 `char`/`short` 被用作长度/计数/下标的点（尤其报文里读到的单字节长度）；确认类型有符号（默认 char 多数平台 signed）；追它被传入 `size_t`/`unsigned int` 的路径判负值能否到达；二进制搜 `movsx` 作候选点，对照 `xor`+`mov` 零扩展；对已有 `(unsigned int)len` 补丁复查——转换前的符号扩展已发生。
   - 完成标准：从「源字节 → char → 符号扩展 → 无巨值」的链路完整。
   - 判停：若在下游加检查但没改类型 → 判为无效修补；只在 32 位验证 → 64 位 `size_t` 更宽需重测。

4. **识别截断与计算绕过值**
   - 做什么：搜所有 `unsigned short`/`short`/`char` 接收 `size_t`/`int`/`strlen()` 结果的赋值（截断只发生在赋值/强转/带原型调用三处）；判定该变量是否参与长度校验或权限判断，是则标高危；给定小类型位宽 W，找 > 上限的输入使其 mod 2^W 落在允许区间；检查 UID/GID/端口等安全标识字段是否被截断（65536→0 变 root）。
   - 完成标准：给出具体绕过值（如 66000→464）与位宽计算。
   - 判停：只在 32 位平台验证 → 必须同时在 64 位重测；把「编译无警告」当安全 → 禁止。

5. **逆向侧：助记符 + 缓冲区/长度比对**
   - 做什么：读长度检查的比较助记符（JL/JLE/JG/JGE 有符号 vs JB/JBE/JA/JAE 无符号）；确认被比较变量与下游写入函数长度实参是同一个；「有符号比较 + 无符号长度参数」判为可用负值绕过，算所需最小值（−1 即 0xFFFFFFFF）；定位写入函数记下目标缓冲区实参与长度实参；栈视图把缓冲区 `Array` 展开得字节数 N；常量长度与 N 比较，变量长度按 `X` 回溯来源。
   - 完成标准：N 与长度实参的比较结论（安全/边界/可控）。
   - 判停：`gets_s` 带长度参数，不能只看函数名判危险；长度 == 缓冲区大小时若函数不写终止符则末字节仍越界；IDA 显示的是元素个数，算字节数要乘元素宽度。

6. **算距离与列中间变量**
   - 做什么：栈视图读缓冲区起始偏移与返回地址偏移（32 位 EBP 帧 +4、保存 EBP +0），相减得填充长度；逐个记录中间被覆写变量的偏移与宽度，列「必须填合法值」清单；需要时用脚本枚举整个栈帧打印每字段大小与到 EIP 的距离；数据段场景改看紧跟缓冲区的全局对象是否有 `call [ptr]`/`call reg` 间接调用。
   - 完成标准：填充长度 + 合法值清单（栈）或可劫持函数指针（数据段）。
   - 判停：变量被折叠成数组/只有 1 字节定义时，用相邻偏移之差而非 GetMemberSize 算宽度；ESP 基帧需考虑 push 造成的漂移；没有 `call [ptr]` 就只是数据损坏，不构成利用链。

7. **判补丁有效性**
   - 做什么：见到「加了一段检查」的补丁，先问被检查变量类型是否改变；用 desk-check 取负值逐行推演检查是否仍成立；检查该变量在后续所有使用点是否按同一类型解释；修复判据为类型改无符号或在读入处拒绝负值；在同一代码库搜同类模式一并修并回归。
   - 完成标准：补丁回到「值的类型与值域」层，所有调用路径复验通过。
   - 判停：把「代码里有 if」当已修复 → 禁止；修补后不回归 → antisniff 三版皆被绕过的教训。

## B — 边界 (Boundary)

### 不要用的情况
- 只需要「是否有漏洞」的连通性判断（不评级、不判整型机制），转 `source-audit-dataflow`。
- 已经拿到可控 EIP、要推进到 shellcode，转 `crash-to-exploit` 与 `shellcode-engineering`。
- 目标是缓解措施绕过技术本身（GS/SafeSEH/DEP/ASLR），转 `mitigation-bypass-and-rop`。
- Web 注入/过滤器类问题，转 `injection-filter-audit`。

### 已知失败模式
- 因为「只溢出一个字节」或「只能写 NUL」就判不可利用——作者明确说 1–2 字节覆写有时比 4 字节更好用，off-by-one 可改栈帧指针最低字节（Ch5）。
- 认为加了 `(unsigned int)` 强转就消除了负值——antisniff `snprintf(dst,(unsigned int)len,...)` 中 len 为负时依旧扩展成大值（Ch6）。
- 只在 32 位平台验证截断；64 位下 `size_t` 更宽导致截断更易触发（Ch6）。
- 把 `sizeof(ptr)` 当成缓冲区大小（实际返回指针宽度 4/8），与减法组合下溢成巨大值把有界函数变无界写（Ch6 Listing 6-24）。
- 按一种 snprintf 返回值语义写检查，在另一平台失效（UNIX 返回应写长度、Windows 填满返回 −1 且不保证 NUL）（Ch8 Listing 8-1）。
- 用 GetMemberSize 而不是相邻偏移之差算变量宽度；在 ESP 基帧直接套 EBP 帧偏移（IDA 权威指南 22.3.1）。
- 全局溢出只算到「缓冲区溢出」就下结论，忽略下游是否有 `call [ptr]`——没有就只是数据损坏（中 41.3/42.3）。

### 作者与时代的局限
- 六问评级是「不写 PoC 的快速估计」，作者明说不如 PoC  definitive；对新型缓解（CFG/CET/Shadow Stack）需扩展第六问。
- 整型示例基于 32 位 x86 与 C/C++ 的整型提升规则；Rust/Go 等内存安全语言的溢出语义不同。
- `movsx`/`sar` 的二进制指纹针对 Intel 汇编；ARM 的 `ldrsh`/`asr` 等需对应替换。
- NFS UID 截断为 root 一例作者注明是轶事、未经源码验证，引用时应保留这一限定。

### 容易混淆的方法
- 「符号转换」（值域不变、重新解释）、「符号扩展」（转换本身改变值）、「截断」（真的丢高位）三种机制可同时出现（先截断再当无符号用），必须分别验证。
- 「bool 型可利用性」与「六问评级」：后者给出依据与风险等级，不是简单的是/否。
- 栈溢出看「到返回地址的距离」，数据段溢出看「下游是否有间接调用」——同一缓冲区大小比对，可利用性判据不同。
- 「修补类型」与「修补症状」：antisniff 三版史说明加检查、加强转都不等于改类型。

### 授权与合规边界
> 待补充（用户自行填写）
