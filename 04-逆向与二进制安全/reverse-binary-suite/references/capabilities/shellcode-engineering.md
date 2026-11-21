# Shellcode 工程化

## R — 原文 (Reading)

> 在代码顶部执行任一个FPU（浮点）指令，然后执行“FSTENV PTR SS:[ESP-C]”
> — 《Exploit编写系列教程1-10》第九篇 Win32 Shellcode 编写入门 · GetPC

> 为了避免这个，我们用“xor eax,eax”代替。这个产生相同的结果并且机器码里不含null 字节。
> — 《Exploit编写系列教程1-10》第九篇 · 可替代指令&指令编码

> 不同的技术需要不同大笑的存储空间来存储寻蛋代码：利于SHE 的寻蛋方法需要大约60 个字节，利用IsBadReadPtr 的寻蛋方法需要37 个字节，利用NtDisplayString 的寻蛋方法需要32 字节。
> — 《Exploit编写系列教程1-10》第八篇 Win32 Egg Hunting

## I — 方法论骨架 (Interpretation)

这张卡解决「跳转链已经打通、但真正要执行的代码写不出来或放不下」的问题。它处理三件事：让 shellcode 知道自己在哪（GetPC）、让 shellcode 不含禁用字节（去 null/坏字符）、以及空间不够时怎么把真正的代码藏到别处再找回来（egg hunter）。它只关心「执行的代码本身」，不关心「怎么让代码被执行」（那是 `crash-to-exploit` 与 `mitigation-bypass-and-rop`）。

GetPC 解决位置无关问题：编码过的 shellcode 需要知道自己的内存地址才能解码，但不能硬编码（注入点位置随环境变）。x86 上四种取当前执行地址的方法——`call $+5; pop reg`（利用 call 压入下一条指令地址）、`FNSTENV [esp-0xC]; pop reg`（FPU 状态保存了上一条 FPU 指令地址）、backward call（call 跳到自身末尾再 pop）、SEH GetPC（构造异常从记录里取出错地址）。它们都要求指令不含 00。取舍上优先无 00 的短写法（如 `call $+4/ret/pop ecx` 7 字节、`FLDPI; FSTENV [esp-0xC]; pop ebx` 8 字节）；用 alpha2 之类编码器时按其要求提供基址寄存器，SEH GetPC 在 unicode/大写字母编码下不稳定。

去 null 字节靠等价重构而非整体编码。每个 00 都有明确来源（指令编码 / 字符串终止符 / 常量）：指令类用等价无 00 指令替换（`xor eax,eax` 替 `mov eax,0`）；常量类拆成 `mov reg,X; add reg,Y`（把含 00 的 dword 拆成两个不含 00 的值相加，如 0xEF5D505B + 0x11111111 = 0x006E616C）；字符串终止符用 sniper 手法（先把非零字节写入栈，再用已置零寄存器按负偏移写 0，负偏移产生 `\xff` 而非 `\x00`）或逐字节写。代价是长度增加，但对小 payload 或编码器不可用时是唯一出路。与「直接用 shikata_ga_nai/alpha_upper 整体编码」的区别在于：本手法只改必要指令、长度可控，编码器是整体变换、代价是体积与解码器依赖。风险点包括改写后长度暴涨超缓冲区、`\xff` 本身是坏字符、`add/sub` 中间值仍含 00、改写破坏标志位影响后续条件跳转。

egg hunter 解决空间不够：跳转后可用空间装不下完整 shellcode 时，只放一段「扫描内存找标记」的小代码（hunter），真正 shellcode 连同标记藏在堆/栈/.data 别处。hunter 逐页探测可读性（`or bx,0xfff; inc ebx` 跳过整页），再逐 dword 比较标记，命中后 `jmp edi` 执行标记之后的代码。按可用空间选变体——SEH 型约 60 字节、IsBadReadPtr 型 37 字节、NtDisplayString 型 32 字节。标记必须唯一且写两遍：只写一遍时 hunter 自身的标记常量也会命中，导致跳到自己的数据上。

Unicode exploit 是另一类特殊约束：输入被 `MultiByteToWideChar` 转宽字符后每个 ASCII 字节前插 00，EIP 变成 `0x00410041` 形态、单字节指令流被切碎。两条应对同时使用——① 只用 `0x00nn00mm` 形式的地址（低两字节是目标、高两字节由转换自动补 00），在该格式下找 `jmp/call reg` 或 `pop pop ret`；② 每两条指令间插 `\x6e`（`006e00: add [esi],ch`）把注入的 00 吸收成合法指令的一部分，使后一条重新对齐；shellcode 须先用 alpha2/venetian 编码器处理，并用 `push eax; ret`（写成 `\x50\x6e\xc3`）跳入。失败模式包括用普通 4 字节地址（高字节不为 00 转换后错位）、`\x6e` 依赖的寄存器不可写导致违例、区域设置不同转换表不同。

## A1 — 应用示例 (Application Example)

### 示例 1: msgbox shellcode 手工消除 null 字节
- **类型与来源**: 【亲历】《Exploit编写系列教程1-10》第九篇
- **问题/输入**: 一段 msgbox shellcode 含 00，而目标通过字符串函数接收输入，00 会截断 payload。
- **方法论的使用**: 列出 payload 中所有 00 的位置与来源；指令类用 `xor eax,eax` 替代 `mov eax,0`；常量类把 `\x68\x6c\x61\x6e\x00`（push "lan\0"）改写为 `mov ebx,0xEF5D505B; add ebx,0x11111111; push ebx`（结果 0x006E616C，两段都不含 00）；字符串终止符用 sniper/逐字节写；在调试器单步核对每条改写后指令语义等价。
- **结论**: 不改语义也能去掉 null；分解常量与 sniper 写 0 是小 payload / 编码器不可用时的关键手段，代价是长度增加。
- **结果**: 原书得到 92 字节、null 数为 0 的 msgbox shellcode，并在 Easy RM to MP3 上验证。

### 示例 2: Eureka Email 用 NtDisplayString hunter 找隐藏 shellcode
- **类型与来源**: 【亲历】《Exploit编写系列教程1-10》第八篇
- **问题/输入**: Eureka Email 溢出后 ESP 处仅约 700 字节，装不下完整 shellcode。
- **方法论的使用**: 量可用空间，选 32 字节的 NtDisplayString hunter（≤ 可用空间）；选唯一 4 字节标记 `w00t`；在真实 shellcode 前写两份标记（`w00tw00t`，8 字节）避免 hunter 命中自身常量；hunter 放跳转落点，后面填 NOP，再放带标记的 shellcode；hunter 逐页探测可读性、逐 dword 比较标记，命中后 `jmp edi` 执行；用断点确认跳转目标等于标记后地址。
- **结论**: 标记必须唯一且双写；hunter 不依赖网络（区别于 staged/下载第二阶段），只在本地内存找已存在的副本；扫描耗 CPU（3G 内存尤甚）。
- **结果**: 原书在 0x00473992 附近找到 shellcode 并成功执行。

## A2 — 触发场景 (Future Trigger)

### 用户会在什么情境下需要它
1. 跳转链已通（EIP 可控、落点验证通过），但编码 shellcode 需要知道自身基址，需要选一种 GetPC。
2. 目标用 strcpy/sprintf 等字符串函数接收输入，shellcode 里的 00 会截断 payload，需要手工去 null。
3. 坏字符集很多、编码器会超长或不可用，需要按指令/常量/终止符分类改写。
4. 跳转落点可用空间装不下完整 shellcode，需要 egg hunter 把真代码藏到别处再找回。
5. 输入被转成宽字符，EIP 呈 00410041 形态，需要 venetian 对齐与 Unicode 兼容跳转地址。

### 语言信号（出现这些就该激活）
- 中文：「shellcode 怎么取自身地址」「GetPC 有哪些写法」「编码 shellcode 基址怎么来」「shellcode 里有 00 怎么办」「不用编码器去 null」「坏字符太多编码器用不了」「空间不够放 shellcode」「egg hunter 怎么用」「shellcode 找不到」「EIP 是 00410041」「unicode 漏洞怎么利用」「venetian shellcode」
- English: "shellcode GetPC", "FSTENV call pop", "remove null bytes shellcode", "bad characters encoder", "egg hunter w00t", "venetian shellcode", "unicode exploit 00410041", "position independent shellcode"

### 与相邻能力的区分
- 与 `crash-to-exploit` 的区别：那张卡用 NOP+int3 验证跳转链、拿到落点，本卡负责「落点之后执行的代码怎么写」；本卡的成果是那张卡第 5 步「放真实 shellcode」的内容。
- 与 `mitigation-bypass-and-rop` 的区别：那张卡让代码能执行（绕过 DEP/GS），本卡写被执行的代码本身；ROP 链里也会用到去 bad char 的技巧，但那属于编排的辅助。
- 与 `binary-analysis-toolchain` 的区别：本卡不分析别人的代码，只构造自己的载荷。

## E — 可执行步骤 (Execution)

**必需输入**: 已验证可控的跳转落点与可用空间字节数；完整坏字符集（哪些字节会被过滤/截断）；目标 CPU 架构（本卡以 32 位 x86 为主）与区域设置（Unicode 场景）。缺坏字符集时须先通过 fuzz 全部 256 字节确定，不能假设只有 00。

**交付物与完成标准**: ① GetPC 方案与字节码；② 去 null/坏字符后的 shellcode（长度与坏字符计数）；③ egg hunter 变体与双写标记（如需要）；④ Unicode/venetian 对齐方案（如需要）；⑤ 调试器单步验证与行为验证结果。完成标准：shellcode 在目标环境执行预期动作，且不含任何坏字符。

1. **确认是否需要基址与选 GetPC**
   - 做什么：确认 shellcode 含解码器/需引用自身数据（存在需要绝对地址的指令）；选无 00 的 GetPC——优先 `call $+4 / ret / pop ecx`（7 字节 `\xe8\xff\xff\xff\xff\xc3\x59`）或 `FLDPI; FSTENV [esp-0xC]; pop ebx`（8 字节 `\xd9\xeb\x9b\xd9\x74\x24\xf4\x5b`）；把地址放入基址寄存器，后续用 `[reg+offset]` 引用数据；用 alpha2 类编码器时按其要求提供基址寄存器。
   - 完成标准：解码器能正确定位编码数据。
   - 判停：`call $+5` 后忘了 pop（栈上多返回地址破坏布局）→ 补 pop；FNSTENV 前未先执行 FPU 指令 → 取到旧值；SEH GetPC 在 unicode/大写字母编码下失败 → 换其他 GetPC。

2. **列坏字符来源并分类改写**
   - 做什么：列出 payload 中所有坏字节位置，判断来源（指令编码 / 字符串终止符 / 常量）；指令类用等价无坏字节指令（`xor eax,eax`、`push 0` 改 `xor eax,eax; push eax`）；常量类拆成 `mov reg,X; add reg,Y`；字符串终止符用 sniper（`mov ebp,esp` + 零寄存器 + 负偏移写 0）或逐字节写；每条改写后在调试器单步核对语义等价。
   - 完成标准：完整坏字符集计数为 0，语义与原指令一致。
   - 判停：改写后长度暴涨超缓冲区 → 权衡是否改用编码器；负偏移写 0 产生 `\xff` 而 `\xff` 本身是坏字符 → 换写法；`add/sub` 中间值仍含 00 → 重拆；改写破坏标志位影响条件跳转 → 调整指令顺序。

3. **空间不够时部署 egg hunter**
   - 做什么：量跳转落点可用空间；按 60/37/32 字节选 hunter 变体（SEH 型 / IsBadReadPtr 型 / NtDisplayString 型）；选唯一 4 字节标记（如 `w00t`）；在真实 shellcode 前写两份标记（8 字节）；hunter 放跳转落点，后填 NOP，再放带标记 shellcode；用断点确认命中位置。
   - 完成标准：hunter 执行后 EIP 落在 shellcode。
   - 判停：只写一次标记 hunter 找到自己 → 双写；标记在 payload 别处重复出现 → 换标记；SEH 型 hunter 在启用 SafeSEH 的系统失效 → 换变体；扫描耗时过长（3G 内存）→ 记录代价。

4. **Unicode 场景的 venetian 对齐（按需）**
   - 做什么：确认 EIP 呈 00410041 形态（输入被转宽字符）；用 `!pvefindaddr j eax`/`p2` 筛 "Unicode compatible" 且形如 0x00nn00mm 的地址；只用低两字节覆盖 RET（如 `\x18\x5e` → 0x005e0018）；每两条指令间插 `\x6e`（`006e00: add [esi],ch`）吸收 00；用 `push eax`+`ret`（`\x50\x6e\xc3`）跳入 shellcode；shellcode 先用 alpha2/venetian 编码器处理。
   - 完成标准：反汇编显示目标指令完整、EIP 落到 shellcode 入口。
   - 判停：用普通 4 字节地址（高字节不为 00）→ 转换后错位；`\x6e` 依赖的寄存器不可写 → 写违例；区域设置不同转换表不同 → 换机器须重测。

5. **调试验证与回归**
   - 做什么：用 NOP+int3 已验证的跳转链作为前置；把 shellcode 放进落点，单步确认第一条指令正确解码；捕获断点/int3 命中位置；验证目标动作（弹计算器/回连）发生且进程未立即死亡；换环境回归（不同区域设置/SP/语言）。
   - 完成标准：预期动作稳定复现且无坏字符触发截断。
   - 判停：只测一次就下结论 → 先用 int3 解耦跳转链与载荷；调试器吞异常 → 配置 AeDebug；回归失败 → 检查区域设置/转换表差异导致字节变形。

## B — 边界 (Boundary)

### 不要用的情况
- 跳转链尚未打通（EIP 不可控或落点未验证）时，写 shellcode 是浪费，先转 `crash-to-exploit`。
- 目标 DEP/ASLR 导致代码页不可执行或地址不可用时，先转 `mitigation-bypass-and-rop`。
- 只需要 DoS 效果或严重性评级，不需要执行代码，转 `memory-integer-audit`。
- 目标是 64 位或 ARM 架构时，本卡的 x86 指令序列（GetPC/venetian/popad 配套）不适用，需重写。

### 已知失败模式
- SEH GetPC 在 alpha3 的 XP SP3 上不工作（第九篇明确记录）。
- 用 `call $+5` 后忘了 pop，栈上多出返回地址破坏后续布局；FNSTENV 前没先执行 FPU 指令取到旧值（第九篇）。
- 改写去 null 时长度暴涨超出缓冲区；负偏移写 0 产生 `\xff` 而 `\xff` 本身是坏字符；`add/sub` 中间值仍含 00（第九篇）。
- egg hunter 只写一次标记导致 hunter 找到自身常量、跳到自己的数据上；扫描 3G 内存耗时长（第八篇）。
- Unicode 场景用普通 4 字节地址（高字节不为 00）转换后错位；`\x6e` 依赖的寄存器不可写导致违例；区域设置不同导致同一字节换机器后变成别的值（第七篇）。

### 作者与时代的局限
- 全部手法基于 32 位 x86 与 Win32 API；x64 的调用约定（寄存器传参）、`RIP-relative` 寻址与 DEP 默认开启使传统 GetPC/venetian 写法不再直接使用。
- 编码器（alpha2/alpha3/shikata_ga_nai）与现代 AV/EDR 的内存扫描已成为对抗焦点，教程写作时的「能过杀软」假设不再成立。
- NtDisplayString/IsBadReadPtr 等 egg hunter 依赖的 API 行为随 Windows 版本变化；现代系统的 ASLR 与内存布局使扫描策略需调整。
- Unicode exploit 示例（Xion Audio Player）针对特定区域设置，转换表依赖系统 locale。

### 容易混淆的方法
- 「GetPC」（知道自己在哪）与「去 null」（不含禁用字节）是两个独立问题：前者解决基址，后者解决内容；编码器可同时涉及两者但要分开验证。
- 「手工改写去 null」（只改必要指令、长度可控）与「整体编码器变换」（体积大、依赖解码器）：不是互斥，按坏字符数量与长度预算选择。
- 「egg hunter」（本地内存找已存在副本、不依赖网络）与「staged shellcode / 下载第二阶段」（依赖网络）：空间不足时的两条不同路线。
- 「Unicode venetian 对齐」（每字节后插 00，需双字节重算）与「普通短跳机器码换算」（见 `crash-to-exploit`）：同一跳转目的、不同字节布局。

### 授权与合规边界
> 待补充（用户自行填写）
