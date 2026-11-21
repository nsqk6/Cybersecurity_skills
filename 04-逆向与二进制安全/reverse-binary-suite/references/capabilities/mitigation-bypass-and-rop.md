# 缓解绕过与 ROP 链编排

## R — 原文 (Reading)

> Payload必须要完成下面的事情 1 触发一个异常 2 用jumpcode覆盖next SEH record域（这样它才能跳到shellcode） 3 用指向pop pop ret指令串的指针覆盖SE Handler域
> — 《Exploit编写系列教程1-10》第三篇 基于SEH的Exploit

> 我们可以通过在检查cookie 前触发异常来挫败栈的这种保护。
> — 《Exploit编写系列教程1-10》第六篇 栈中的cookie/GS 绕过方法

> 在写单独的一行代码前，你要做的第一件事是设置你的策略，通过问自己下面的问题：
> — 《Exploit编写系列教程1-10》第十篇 用ROP绕过DEP

## I — 方法论骨架 (Interpretation)

这张卡解决「目标开了 GS/SafeSEH/DEP/ASLR，怎么拿到 EIP 并执行代码」的问题。核心思路不是「破解防护」，而是「让防护的检查不发生、检查被跳过、或检查对象落在检查范围之外」。

SEH 覆盖型利用的本质是「借异常分发器之手完成一次 ret」：覆盖 SE Handler 为 `pop/pop/ret` 后，分发器调用它时栈顶正好是 EstablisherFrame（指向 nSEH record），两次 pop 把栈抬到 nSEH 地址，ret 把 nSEH 地址装入 EIP——于是 nSEH 那 4 字节被当代码执行。所以 nSEH 放跳过 SE Handler 的短跳（默认 `EB 06 90 90`）、SEH 域放 `pop pop ret` 地址、shellcode 紧跟 SEH 域之后。偏移有两个（nSEH 与 SEHandler 相差 4），且必须停在第一次异常读 `!exchain` 反查——不能继续运行到第二次异常，那会重建栈帧改变布局。payload 里出现 NULL 空洞（程序把数据当宽字符/结构处理而插入的 00，不是自己 payload 的内容）时，改用更大跳距（`EB 1E` + 前置 NOP）整体越过空洞，而不是去换编码器。`pop pop ret` 模块选择三判据：程序自带 DLL（基址不随 OS 变）、无 SafeSEH、地址不含 00；找不到时用 `call/jmp [esp+nn]`/`[ebp±nn]` 间接跳转族替代。

GS/cookie 绕过靠「让检查不发生」：/GS 只在函数正常返回路径比较 cookie，若漏洞函数在返回前因继续使用被破坏的缓冲区而访问违例，异常分发器先接管，`__security_check_cookie` 根本没机会执行——此时只要 EH record 也被覆盖就能走 SEH 路径。前提是「拷贝后仍有对该缓冲区的读写」（如两次 strcpy），拷贝后立即返回则此路不通。另一条路是覆盖 C++ 对象 vtable 指针：拷贝后紧跟虚函数调用时，调用序列「取对象指针 → 取 vtable → 取函数指针 → call eax」全在函数返回前，溢出改 vtable 指针与表项即可劫持 EIP，不需要异常机制、不需要知道 cookie 值。

SafeSEH 绕过的四条判据：handler 地址落在栈范围（被拒）、落在启用 SafeSEH 的模块内（被拒，需查 Load Configuration Directory 与已注册 handler 表）、不在任何模块内（视为安全，可用堆/未映射区域）、模块缺少 Load Configuration Directory（可执行）。特殊情形：模块基址含 00 时仍可用模块内地址（00 在最后一字节），但 shellcode 只能放在覆盖点之前并用后向跳。

DEP 绕过有两条路线。① 调现成例程关掉 DEP：`LdrpCheckNXCompatibility` 中有一段「检查镜像 NX 兼容、不兼容就关本进程 DEP」的代码，把执行流送进它的 `cmp al,1` 中段并让 `al=1`、`esi=2`，它会以 `ProcessExecuteFlags=0x22` 调 `NtSetInformationProcess` 关掉 NX，随后正常 `leave/ret` 回到栈执行。栈布局极考究：`addr1 | 4字节填充 | addr2 | 4字节填充 | 54字节 | 跳板 | shellcode`，每个 `ret n` 补 n 字节，`leave` 按 EBP 恢复 ESP 要先填 54 字节，且 EBP 必须指向可写内存（例程写 `[ebp-4]`）。失败两大结构性原因：`ret 4` 当第一跳没补 4 字节导致 EIP=43434343（ESP 错位）、EBP 设为 ESP 后 push 冲刷 `[ebp-4]` 使参数不再是 2。此技术只在 DEP OptIn/OptOut 有效，Vista+ 永久 DEP/AlwaysOn 直接失效。② ROP：不需要 gadget 时先「四问定策略」（用哪个 API / 当前 DEP 模式是否允许 / 有哪些 gadget / 如何进入链），并手工在调试器里「人肉布栈 + 直接调 API」证明该 API 调用本身可行，再编排链。gadget 采集用 `!pvefindaddr rop` 从 ret 反向回看最多 8 条指令，并做「机器码分片」（`ADD AL,0x58` 末字节 0x58 正是 `pop eax`），按副作用检索（能写内存/加减寄存器/pushad/mov [reg+off],reg）并确认不破坏链。ASLR 下定位 API 用「栈上残留的模块内返回指针 − 固定偏移」——模块基址每次变，但「指针 − API」差值不变，须跨重启验证。

## A1 — 应用示例 (Application Example)

### 示例 1: Soritong MP3 的 SEH 四要素布局
- **类型与来源**: 【亲历】《Exploit编写系列教程1-10》第三篇
- **问题/输入**: Soritong MP3 Player 1.0 的 m3u 溢出，如何按 SEH 路径拿到 EIP？
- **方法论的使用**: 用 pattern 填满 payload 触发后**停在第一次异常**，`!exchain` 显示 `Invalid exception stack at 35744134`，反查得 SE Handler 偏移 588、nSEH=584；nSEH 填 `EB 06 90 90`（4 字节恰好占满，跳过 SE Handler），SE Handler 填 Player.dll 中 `0x1001E812`（pop pop ret，无 00、无 SafeSEH），shellcode 紧接其后；用 `\xcc\xcc\xcc\xcc` 覆盖 nSEH 单步确认 EIP 落在 nSEH、其后是 shellcode。
- **结论**: 必须停在第一次异常（继续 g 会重建栈帧改变偏移）；nSEH 与 SEHandler 偏移相差 4；SEH 利用的本质是借分发器完成一次 ret。
- **结果**: 原书成功执行 shellcode。

### 示例 2: 用 ret 4 未补字节诊断 DEP 关闭链跑飞
- **类型与来源**: 【亲历/译注】《Exploit编写系列教程1-10》第六篇
- **问题/输入**: 同一关闭 DEP 的 exploit 两次失败，第一次 EIP=43434343、第二次 `[ebp-4]` 写违例，原因是什么？
- **方法论的使用**: 看失败现场 EIP 是否等于填充字符 → 等于则定位为「ESP 错位」而非「地址无效」；核对链上每条指令的栈副作用（ret n / leave / push/pop）与填充字节数，发现第一个地址 0x77eedc70 上是 `ret 4` 却没补 4 字节，返回后 ESP 越过目标地址落到 CCCC；第二次是 `mov esp,ebp` 把 EBP 设为 ESP 后，后续 push 覆盖 `[ebp-4]` 使参数不再是 2，改用抬高 EBP 的 gadget。
- **结论**: 该链依赖「每步执行完 ESP 恰好指向下一个地址」，`ret n`/`leave`/`push` 都会移动 ESP；只检查「地址是否有效」而不检查「执行到该地址时 ESP 是否指对」必然失败。
- **结果**: 原书通过补 4 字节与抬高 EBP 修正两次失败。

## A2 — 触发场景 (Future Trigger)

### 用户会在什么情境下需要它
1. 目标开了 /GS（栈 cookie），直接覆盖返回地址会触发 cookie 检查终止，需要绕过。
2. SEH 覆盖型漏洞要布局 nSEH/SEH/shellcode，或遇到 `pop pop ret` 找不到、SafeSEH 全开。
3. 目标开了 DEP，要关掉 DEP 或构造 ROP 链调 VirtualProtect/VirtualAlloc。
4. ASLR 开启导致模块基址每次变，需要在运行时反推 API 地址。
5. 跳板/链执行后 EIP 变成 CCCC/41414141 或 `[ebp-4]` 写违例，需要诊断栈布局错误。

### 语言信号（出现这些就该激活）
- 中文：「SEH 怎么利用」「pop pop ret 为什么能跳过去」「nSEH 和 SEH 分别放什么」「SEH 偏移怎么找」「SafeSEH 怎么绕」「全部模块都开了 safeSEH」「开了 /GS 还能打吗」「cookie 校验怎么绕过」「vtable 覆盖」「DEP 怎么关」「关 DEP 的链跑飞了」「EIP 变成 CCCC」「ROP gadget 怎么找」「VirtualProtect 链怎么排」「ROP 没有头绪」「ASLR 下怎么调 API」「nSEH 跳过去落在 00 上」
- English: "SEH exploit pop pop ret", "nSEH offset", "bypass SafeSEH", "bypass /GS cookie", "vtable overwrite", "disable DEP NtSetInformationProcess", "ROP gadget collection", "VirtualProtect ROP chain", "ASLR API address from stack pointer"

### 与相邻能力的区分
- 与 `crash-to-exploit` 的区别：那张卡解决「拿到可控 EIP 并落到 shellcode」，本卡解决「目标有防护时怎么拿到 EIP / 怎么在 DEP 下执行代码」；SEH 覆盖型利用的起点（偏移定位）在那张卡，本卡接手四要素布局与绕过。
- 与 `shellcode-engineering` 的区别：本卡负责「让代码被执行」，那张卡负责「执行的代码本身怎么写」（GetPC、去 null、egg hunter）；本卡的手工验证阶段使用简单 NOP+int3 或弹计算器 shellcode 即可。
- 与 `memory-integer-audit` 的区别：那张卡的「六问」列出「有哪些防护」这一问，本卡处理如何绕过这些防护。

## E — 可执行步骤 (Execution)

**必需输入**: 已确认的控制点（RET 覆盖或 SEH 覆盖）与偏移；目标 OS 版本与补丁级别（地址/保护策略依赖）；能枚举模块与安全选项（`!pvefindaddr`/OllySSEH）；已确定坏字符集。缺 OS 版本时须按具体 SP 列地址假设。

**交付物与完成标准**: ① SEH 四要素布局（nSEH 短跳 / SEH 地址 / shellcode）或 GS/vtable 绕过路径判定；② SafeSEH 可用性判定；③ DEP 绕过路线（关 DEP 栈布局 或 ROP 链）；④ gadget 库与四问策略表；⑤ ASLR 下 API 偏移（跨重启验证）；⑥ 失败归因。完成标准：执行流落到 shellcode，且换环境回归仍成立。

1. **判定防护组合与绕过路径**
   - 做什么：反汇编漏洞函数确认 `__security_cookie` 装载与 `__security_check_cookie` 位置；判断漏洞是否会在返回前再次解引用被破坏的缓冲区（第二次 strcpy 等）；列出加载模块及 SafeSEH 状态；确认 DEP 模式（OptIn/OptOut/AlwaysOn/永久）；确认 ASLR 状态。
   - 完成标准：防护组合清单 + 选定绕过路径（异常抢先 / vtable / ROP）。
   - 判停：拷贝后立即返回（无第二次解引用）→ 异常抢先路径不通；Vista+ 永久 DEP → 关 DEP 路径不通，只能用 ROP；函数无字符串缓冲区因而无 cookie → 不需要 GS 绕过。

2. **SEH 四要素布局（SEH 型时）**
   - 做什么：停在第一次异常读 `!exchain` 反查 nSEH/SEH 偏移；nSEH 填 `EB 06 90 90`；SE Handler 填程序自带 DLL 的 `pop pop ret`（无 00、无 SafeSEH）；shellcode 紧接 SEH 域；用 `\xcc\xcc\xcc\xcc` 覆盖 nSEH 验证落点。
   - 完成标准：EIP 落在 nSEH 且其后紧跟 shellcode。
   - 判停：只覆盖 nSEH 没覆盖 SEH → 补；pop pop ret 地址含 00 → 换；寄存器值与 POC 不符 → 先确认是 SEH 型还是 RET 型。

3. **处理 NULL 空洞与短跳**
   - 做什么：0xCC 命中 nSEH 后 dump，确认 SEH 后约 32 字节是否出现程序注入的连续 00；量空洞长度 L，重算跳距 d=4+L+前置 NOP（≤127），写成 `EB d`；shellcode 前放等量 NOP；后向跳用 32 位补码取低字节（−7 → `EB F9`），跨距 >127 用 `E9`+4 字节偏移；单步确认落点在 NOP 区。
   - 完成标准：执行流越过空洞落在 NOP/shellcode。
   - 判停：以为空洞是自己 payload 里的 00 去换编码器 → 白费功夫；跳距按「看起来的距离」估算而非 dump 实际地址 → 重算。

4. **GS 绕过（异常抢先或 vtable）**
   - 做什么：异常抢先——确认拷贝后仍有对缓冲区的读写，覆盖到 EH record 并让异常在 cookie 检查前发生，按 SEH 路径完成利用；vtable——确认拷贝后紧跟虚函数调用，记录 call 前取指链与 vtable 指针栈偏移，用溢出覆盖该指针指向伪造 vtable，表项放跳转目标，断在 `call eax` 验证 eax 等于目标。
   - 完成标准：EIP 在 cookie 检查前被劫持。
   - 判停：对象在堆上（栈溢出覆盖不到）→ vtable 路径不通；虚函数调用在拷贝之前 → 不通；只覆盖返回地址 → cookie 先被破坏函数直接终止。

5. **SafeSEH 绕过四判据**
   - 做什么：用 OllySSEH/`!pvefindaddr nosafeseh` 列未启用 SafeSEH 的模块；若全部启用，查是否有模块缺 Load Configuration Directory；若仍不行，考虑堆地址或模块外稳定地址（重启后不变、无坏字符）；特殊情形（模块基址含 00）把 shellcode 放覆盖点之前、nSEH 用后向跳。
   - 完成标准：handler 地址可执行且不破坏 shellcode。
   - 判停：用栈地址覆盖 handler → 必被拒；以为「地址在模块内就一定行」→ 启用 SafeSEH 则被拒；基址含 00 却把 shellcode 放 handler 之后 → 拷贝在 00 处中断。

6. **DEP 绕过 A：关 DEP 的栈布局**
   - 做什么：找 `mov al,1; ret` 类指令地址（确认 ret 立即数）；找 `LdrpCheckNXCompatibility` 中 `cmp al,1` 地址（`uf` 追踪确认会用 esi=2 写 `[ebp-4]` 并调 ZwSetInformationProcess）；布置栈 `addr1 | 4字节 | addr2 | 4字节 | 54字节 | 跳板 | shellcode`；先把 EBP 调到可写栈地址（`push esp; pop ebp; ret`）且略高于 ESP 给 `[ebp-4]` 留安全区；单步走完确认 ret 后 EIP 落跳板。
   - 完成标准：`ZwSetInformationProcess` 参数指针指向 0x2，NX 被关，shellcode 执行。
   - 判停：EIP=43434343 → ret n 未补字节；`[ebp-4]` 写违例或被冲刷 → 抬高 EBP；AlwaysOn/永久 DEP → 此路不通转 ROP。

7. **DEP 绕过 B：ROP 四问 + gadget 编排**
   - 做什么：回答四问（用哪个 API / 当前 DEP 模式是否允许 / 有哪些 gadget / 如何进入链）并写下每个参数来源；手工验证——用 API 地址覆盖 EIP、手动压 5 个参数、shellcode 放其后，断点命中 API 且 shellcode 运行；采集 gadget（`!pvefindaddr rop <module>`，无 00 加 `nonull`），按副作用筛选并检查完整指令序列，对缺失指令做机器码分片，记录栈副作用；编排链（保存 ESP、加减偏移、写回占位符），确认到 API 时栈顶 5 个参数正确。
   - 完成标准：ROP 链执行到 API 且参数正确，DEP 被绕过。
   - 判停：直接抄别人的链 → 错；未确认 DEP 策略 → 某些 API 必失败；参数含 00 却没准备动态生成 → 补；在全部模块上跑 gadget 耗时过长 → 只对本模块；用 ASLR 模块地址重启后失效 → 转第 8 步。

8. **ASLR 下定位 API**
   - 做什么：在栈视图找指向目标模块的返回地址；记录当前 API 实际地址算差值（示例：指针 0x7664D0E9 − VirtualProtect 0x76601DC3 = 0x4B326）；重启后重复测量，确认基址变而差值不变；构造链把栈指针读入寄存器 → `sub eax, 偏移` → call/jmp 目标，断点命中 API。
   - 完成标准：跨重启差值恒定的 API 偏移 + 链命中 API。
   - 判停：用「模块基址」作常量（ASLR 下每次变）→ 错；用不稳定栈位置（不同调用路径偏移不同）→ 换；指针指向模块与 API 不在同一模块 → 换指针。

## B — 边界 (Boundary)

### 不要用的情况
- 目标没有任何缓解（无 GS/SafeSEH/DEP/ASLR）时，`crash-to-exploit` 的 `jmp esp` 路线更直接，不必构造 ROP。
- 只是要执行一小段已有代码而非绕过执行防护，转 `crash-to-exploit` / `shellcode-engineering`。
- 崩溃尚未稳定复现或偏移未定，转 `fuzzing-triage-infra` / `crash-to-exploit`。
- 目标是 DoS 评级而非利用开发，转 `memory-integer-audit`。

### 已知失败模式
- 一路 `g` 到第二次异常才读 `!exchain`，偏移已不是第一次异常的布局；把 EIP 覆盖型当 SEH 型（或反之），偏移全作废（第三篇）。
- nSEH 跳距按「看起来的距离」估算，落在程序注入的 00 空洞中间；以为空洞是自己 payload 的 00 去换编码器（第三篇b）。
- `pop pop ret` 用了带 SafeSEH 的模块导致 handler 被拒；用了系统 DLL 在换 SP 后失效；地址含 00 被截断（第三篇/第六篇）。
- 只覆盖返回地址 → /GS 的 cookie 先被破坏函数直接终止；函数在拷贝后立即返回（无第二次解引用）则异常抢先路径不通（第六篇）。
- 关闭 DEP 链用 `ret 4` 当第一跳却没补 4 字节（EIP=43434343）；EBP 设为 ESP 后 `[ebp-4]` 被 push 冲刷使参数不再是 2（第六篇译注）。
- 在 gadget 采集时忽略隐式副作用（`popad` 改一堆寄存器）；用了 ASLR 模块地址重启后链失效（第十篇）。
- 未确认 DEP 策略就抄别人的链（AlwaysOn/永久 DEP 下某些 API 必失败）；参数含 00 却没准备动态生成（第十篇）。

### 作者与时代的局限
- 教程基于 Windows XP/2003 SP1 与 32 位 x86、 Immunity Debugger + pvefindaddr；Vista+ 永久 DEP、Windows 8+ 的 CFG、Windows 10 的 CET/Shadow Stack 使其中多条技术（尤其关 DEP）不再适用。
- SafeSEH 检查「2003 起才有」是当时结论；现代 Windows 的异常处理保护已演进。
- `LdrpCheckNXCompatibility` 与 `NtSetInformationProcess` 的具体地址随 SP 变化，教程地址仅对所列版本有效。
- ASLR 反推 API 的示例基于 Vista SP2 + IE，依赖「栈上残留稳定模块内指针」这一条件，现代编译器的栈布局可能不保留该指针。
- ROP 四问强调「先手工证明 API 可行再编排」，是工程经验而非硬性规则。

### 容易混淆的方法
- 「异常抢先」（让 cookie 检查不发生）与「vtable 覆盖」（返回前就发生的间接调用）都不需要知道 cookie 值，但前者依赖异常机制、后者不依赖。
- 「挑一个合规 handler 地址」（CU-4-13，属本卡）与「当没有合规地址时让 SafeSEH 检查失效」（本卡第 5 步）是「选地址」与「破检查」两层。
- 「关 DEP 后回栈执行」（本卡第 6 步）与「ROP 调 VirtualProtect 改内存权限」（第 7 步）是两条独立路线，前者依赖 DEP 模式、后者不依赖。
- 「模块基址」与「栈上指针 − 固定偏移」：ASLR 下前者每次变不可用，后者差值恒定可用，须跨重启验证。

### 授权与合规边界
> 待补充（用户自行填写）
