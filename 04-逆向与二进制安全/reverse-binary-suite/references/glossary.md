# 逆向与二进制安全 — 术语表

只收「读能力卡时会卡住」的域内术语；通用词（缓冲区、指针、函数调用等）不收。共 30 条。

| 术语 | 英文 | 在本域语境下的含义 |
|---|---|---|
| 候选点 | candidate point | 源码/二进制里「可能藏漏洞的最低层构造」（危险函数调用、movsx 指令等）。候选点法是先批量生成候选再回溯到入口验证，而不是通读全部代码。见 `source-audit-dataflow`。 |
| 交叉引用 | cross-reference (xref) | 反汇编器里「谁引用了这段代码/数据」的索引。`p` 直接调用、`j` 跳转、`r` 读取、`w` 写入、`o` 取地址——漏掉 `o` 会漏掉经函数指针的间接调用。 |
| FLIRT | Fast Library Identification and Recognition Technology | IDA 的库函数签名匹配技术，把静态链接二进制里的 libc 等库代码整片识别重命名，把分析面压缩到应用代码那一小条。 |
| 符号扩展 | sign extension | 小有符号类型转大类型时符号位复制到高位，负值变成极大正值（`movsx`）。即使目标是无符号也照样发生，故 `(unsigned)len` 强转未必能修。 |
| 截断 | truncation | 大类型赋值给小类型丢高位（只发生在赋值/强转/带原型调用三处）。「校验用大类型、使用用小类型」使检查被绕过，如 65536→0 变 root。 |
| 整型提升/寻常算术转换 | integral promotion / usual arithmetic conversions | C 语言决定比较两侧真实类型的规则。`sizeof` 是无符号，会把 `length - sizeof(x)` 整体拉成无符号，使负值判断失效。 |
| saved set-user-ID | saved set-user-ID | UNIX 进程的三个用户 ID 之一（real/effective/saved）。`setuid()` 仅当 EUID=0 时同时改三者；临时降权态下调 `setuid(realuid)` 常常不改 saved，可 `seteuid(0)` 复原 root。 |
| fd / FD_CLOEXEC | file descriptor / close-on-exec | fd 的权限在 `open()` 时一次性固化，改权限/删除都不影响；`fork+exec` 默认继承 fd，未设 `FD_CLOEXEC` 等于把权限打包送给子进程。 |
| TOCTOU | time-of-check to time-of-use | 检查与使用之间对象被替换的竞态。判据：不是「一次按文件名 open + 后续全按 fd 操作」就可能有竞态。 |
| O_NOFOLLOW / O_EXCL | O_NOFOLLOW / O_EXCL | open 标志。`O_EXCL` 把「检查是否存在」与「创建」合成原子操作、阻止解引用末级 symlink；`O_NOFOLLOW` 只拒末级是链接。 |
| mkstemp | mkstemp | 查名字与创建是同一原子动作并直接返回 fd，替代只返回可预测名字、留有竞态窗口的 `mktemp/tmpnam`。 |
| DREAD | Damage/Reproducibility/Exploitability/Affected users/Discoverability | 威胁评分五维，各打 1–10 分取均值（≤3 低、4–7 中、≥8 高），把威胁分累加到组件上转成审计工作量分配。 |
| 攻击树 | attack tree | 以攻击者目标为根的树，节点标 AND（缺一不可）/OR（任一即可）；缓解节点作降权而非删除，且必须验证后才加。 |
| ACC 日志 | allocation-check-copy log | 把每个内存块的「分配公式 / 长度校验 / 拷贝长度」三列并排 + 疑点列，不一致直接暴露内存破坏。 |
| 元字符 | metacharacter | 下游解释器赋予特殊含义的字符（shell 的 `\n`、SQL 的 `'`、路径的 `..`）。注入判定 = 危险元字符集 − 已过滤集非空。 |
| 剥离式过滤 | character stripping filter | 删掉命中片段的过滤器；若删除后跳过若干字节或不回溯重扫，可用 `....//` 让过滤器自己拼回禁用序列。 |
| 格式串 `%n` | format string %n | `printf` 家族的 `%n` 把已输出字符数写入指针参数，等于「任意地址写任意值」。判据是 format 参数是否为常量。 |
| 二阶注入 | second-order injection | 数据先存储后被解释的注入；判定要追到「真正解释它的代码」，而不是只看输入点。 |
| 农药效应 | pesticide effect | 确定性/生成式 fuzzer 的测试集有限可枚举，被厂商针对性修完后有效性单调下降（PROTOS 自承）。随机成分无此固定靶子。 |
| 覆盖引导 | coverage-guided fuzzing | 把「造更多用例」换成「造触发新基本块/边的用例」（AFL 的 queue、libFuzzer 进程内喂数据）。高覆盖率只是必要条件，非「已测比例」。 |
| 攻击面覆盖率 | attack surface coverage | 覆盖率分母用「从该接口可达的基本块」而非全程序块。1000 块中可达 180、命中 90 → 50%，而非 9%。 |
| 三级指纹 | three-level fingerprint | 崩溃去重递进：生成器日志（字段+异常）→ OS 日志（模块+异常码+offset）→ 栈回溯（函数名序列）。精度与侵入性同时上升。 |
| 最小化 / test case reduction | test case reduction | 把崩溃样本删到「必要且充分」的最小输入序列：每删一块重跑，只保留「删了就复现不了」的部分；不稳定崩溃不可最小化。 |
| Guard Malloc | guard malloc | 替换 malloc，每次分配独占页、末尾贴页尾、下一页不映射，把静默越界变成必然 bus error。慢 100 倍以上，是监控与时间的权衡。 |
| 病态分片 | pathological fragment sets | 偏离预期布局的分片（缺首片、多终止片、重叠 teardrop、乱序），在「何时算重组完成/总长/空洞填充」上产生歧义，可造成 IDS 与主机解释不一致。 |
| TLV / BER / DER | tag-length-value | 自描述变长格式。长度本身也可变长；`remaining -= declared` 前不校验 `declared ≤ remaining` 就回绕，是 ASN.1/DNS 解析漏洞的根源。 |
| SEH / nSEH | structured exception handler / next SEH | Windows 异常处理链。覆盖 SE Handler 为 `pop pop ret`、nSEH 放短跳，借分发器把 nSEH 地址装入 EIP。nSEH 在 SEH 之前 4 字节。 |
| pop pop ret / SafeSEH | pop pop ret / SafeSEH | SEH 利用的跳板指令与防护。SafeSEH 校验 handler 地址是否在栈内/已注册模块内；绕过靠模块外地址、无 Load Configuration Directory 的模块等。 |
| GS / cookie / /GS | stack cookie | 栈保护。只在函数正常返回路径比较 cookie；「异常抢先」（返回前触发违例）或「覆盖返回前发生的 vtable 调用」可让检查不发生。 |
| ROP gadget | ROP gadget | 以 `ret` 结尾的短指令序列。采集时从 ret 反向回看并做「机器码分片」（如 `ADD AL,0x58` 末字节即 `pop eax`），按副作用筛选并算清 ESP 走向。 |
| GetPC | get program counter | shellcode 取自身地址的办法（`call $+5;pop reg`、`FNSTENV;pop reg` 等），供编码器定位自身数据，且指令须无 00。 |
| egg hunter | egg hunter | 空间不足时先放一小段扫描内存的代码，逐页探可读性、逐 dword 比标记（须唯一且双写如 `w00tw00t`），命中后跳到藏别处的真 shellcode。 |
| venetian 对齐 / Unicode exploit | venetian shellcode | 输入被转宽字符后每字节插 00，指令流被切碎。应对：只用 `0x00nn00mm` 形式地址，并在每两条指令间插 `\x6e`（`add [esi],ch`）吸收 00 重新对齐。 |
| 跳板 | trampoline | 覆盖 EIP 的间接跳转指令（如程序自带 DLL 里的 `jmp esp`、模块内 `pop pop ret`）。要求不含 00、落在指令起始、模块基址稳定。 |
| 落点校准 | landing alignment | `ret n` 弹参数或对齐使 ESP 越过缓冲区开头若干字节，须用标记串量出差值并补等长前缀，让跳转后从 shellcode 首字节开始执行。 |
| 离线分诊 / 去重不丢样本 | dedup without discarding | 去重只用于排序与分配人力，不用于删证据；补丁后对全组原始样本重测，否则同组里的第二个根因会被漏掉。 |
