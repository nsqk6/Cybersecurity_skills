# CTF与靶场 — 术语表

只收「读能力卡时会卡住」的词；通用编程词汇不收。相关术语合并为一行。共 35 条。

| 术语 | 英文 | 在本域语境下的含义 |
|---|---|---|
| checksec | checksec | 读 ELF 保护组合的工具；四列 RELRO/CANARY/NX/PIE 各自对应一条「禁止动作」，不是难度标签 |
| RELRO | RELocation Read-Only | Partial 仍可写 `.got.plt`；Full 在启动时解析 GOT 并置只读，封死「改 GOT 为 system」这条路 |
| Canary | stack canary | 函数入口放在栈上的校验值，返回前 xor `gs:0x14`（x64 为 `fs:0x28`）；覆盖返回地址会先踩坏它，触发 `*** stack smashing detected ***` |
| PIE / ASLR | PIE / ASLR | PIE 是程序基址随机化，ASLR 是系统级地址随机化；只随机化基址、不改模块内偏移，拿到一个指针即可推出整块地址空间 |
| GOT / PLT | GOT / PLT | GOT 存外部函数实际地址，`.got.plt` 是 fmt「改 printf 为 system」的写入目标；PLT 是调用跳板，BROP 中定位 write/puts 的 PLT 是泄漏内存的前提 |
| stripped / 静态链接 | stripped / statically linked | stripped 指符号表被剥离，not stripped 则函数名可读；静态链接把 libc 编进程序内部，可当普通 ROP 目标，与「动态链接但没给 libc.so」不同 |
| libc | libc.so | C 运行库；给定版本可按偏移换算 system 地址，未给时可走 libc-database 反查或 DynELF |
| offset（fmt） | argument index | 格式化字符串中「自己放在栈上的数据是第几个参数」；忘算格式串本身是第一个参数会差 1 |
| fmtstr_payload | fmtstr_payload | pwntools 的 fmt 写 payload 生成器，输入为 offset 与 `{地址: 值}` 字典；需人先给出正确 offset |
| `%n` / `%s` | %n / %s | `%n` 把已输出字符数写到指定地址（任意写），`%s` 按地址读字符串直到 `\x00`（任意读）；地址含 `\x00` 时必须把地址放到格式串之后 |
| BROP / stop gadget / brop gadget | Blind ROP / stop gadget / brop gadget | 无二进制无泄漏时靠「崩不崩」一位信息量构造 ROP；stop gadget 是「跳过去不死」的兜底落点，brop gadget 是能弹多个寄存器、用来传参的通用 gadget |
| DynELF | DynELF | pwntools 模块：不查 libc 版本，用同一个 leak 回调遍历目标进程内存的动态符号表解析 `system` 等地址 |
| 三级指针链（%hhn） | p1→p2→p3 chain | fmt 输入在堆上时，借调用栈上天然的 p1→p2→p3 指向，用 `%hhn` 每次改 1 字节逐级改写，最终实现任意地址写 |
| `__printf_chk` / Fortify | `_FORTIFY_SOURCE` | 开启 Fortify 后 printf 被替换为 `__printf_chk`：位置参数必须 1..n 用满，含 `%n` 的格式串不能位于可写内存；任意写被封但 `%s` 任意读仍可用 |
| 侧信道 / Pin | side channel / Intel Pin | 本域特指「用可观测执行量反推已匹配前缀长度」：Pin 插桩在比较点统计指令执行次数，或 gdb 在成功/失败点之间数命中；`Count N` 对应匹配 N-1 字节 |
| BitVec / Z3 | Z3 BitVec | Z3 中按字节建的 8 位符号变量；配合「等于目标数组 + 可打印区间 + flag 前缀」三类约束求解 |
| angr find / avoid / blank_state | angr find / avoid / blank_state | 符号执行的地址设定：find 是成功路径终点，avoid 是所有失败分支共用的出口，blank_state 从输入函数下一条开始以跳过启动自检；不给 avoid 会状态爆炸 |
| 花指令 / 指令混淆 | junk byte / obfuscation | `EB 01 FF` 类字节让线性反汇编错位；混淆三类指纹是指令膨胀、控制流伪造（`push label; ret`）、数据引用绕道（`dummy_data+offset`）；对策是转动态或符号执行 |
| 反调试 | anti-debug | 依赖「是否处于调试」才改变行为，按检测面分函数/窗口/特征码/行为/断点五类；用软件断点绕断点检测等于自投罗网 |
| 启动期自检 | startup self-check | 无条件的 `cmp` + `je exit`，不调试也秒退；与反调试不同，直接改分支（`je`→`jne`）或 nop 桩函数即可 |
| gopclntab | `.gopclntab` / `.gosymtab` | Go 二进制的段名，出现即可判定语言并恢复函数名，避免在 Go 调度代码里硬读 |
| FindCrypt / FLIRT / BinDiff | FindCrypt / FLIRT / BinDiff | 算法与库识别工具链：FindCrypt 扫硬编码密码学常量，FLIRT 按函数签名给库函数命名，BinDiff 用带符号样本做二进制相似度比对 |
| 魔数 / binwalk / foremost / IEND | magic number / binwalk / foremost / IEND | 魔数是文件头签名（ZIP `PK\x03\x04` 等）；binwalk 按签名报偏移并 `-e`/`-M` 提取，foremost 按头尾恢复段内文件；IEND 是 PNG 结束块，其后追加内容不影响看图 |
| LSB / 盲水印 | LSB / blind watermark | LSB 改每像素 RGB 最低位（每像素 3 bit），Stegsolve/zsteg 可提取；盲水印在频域叠加，提取时需把含水印图与原图相减，通常需要原图 |
| ZIP 伪加密 | ZIP pseudo-encryption | 通用标志位最低位被改成 `0x01` 导致索要密码但内容未加密；核心目录区 `504B0102`+8 与文件头 `504B0304`+6 两处都要改回 0 |
| pcap / Tshark | pcap / Tshark | pcap 是流量包文件；先看 Protocol Hierarchy 与 Conversations 缩范围，大包换 Tshark（Wireshark GUI 会卡死），TCP 用 Follow Stream、HTTP 用 Export Objects |
| usb.capdata | usb.capdata | Wireshark 中 USB 流量字段；键盘 8 字节包看 byte0 组合键与 byte2 键码，鼠标 3 字节包看按键位与 X/Y 位移 |
| Volatility / imageinfo / psscan / filescan | Volatility / imageinfo / psscan / filescan | 内存取证工具与命令顺序：`imageinfo` 判 OS 与 profile，`psscan` 扫出被摘链隐藏的进程，`filescan` 列打开文件，`dumpfile`/`memdump` 导出待测对象 |
| fdisk offset / mount loop | fdisk -l / mount -o loop,offset | 磁盘镜像挂载参数：本地文件加 `loop`，多分区镜像加 `offset` 指定分区起始字节，非原生文件系统（NTFS）需装 NTFS-3g |
| Base64 填充 | Base64 padding | 结尾 `=` 填充（1 字节剩 2 个、2 字节剩 1 个），但原文长度恰为 3 倍数时本就没有填充——「无 `=`」不能否定 Base64 |
| 凯撒 / 维吉尼亚 | Caesar / Vigenère | 凯撒是 26 字母固定偏移可穷举 25 次；维吉尼亚是多表替换，密钥长度必是密文重复子串间隔的因子，需分段频率分析 |
| php://filter | php://filter | PHP 文件流变换机制：用 Base64 Filter 把含 `<?php` 的源码编码成不含 PHP 标签的文本回显，再本地解码，绕开「包含即执行」 |
| gopher | gopher:// | SSRF 中发送任意 TCP 内容的协议；载荷套路是本地抓包（socat/tcpdump）→ 剥方向标记与返回包 → 换行转 `%0d%0a` 并 URL 编码 → 改 IP 时同步改长度字段 |
| 图片马 / 日志投毒 | image webshell / log poisoning | LFI getshell 的两条载体路径：图片马把一句话插入图片并上传后用包含点执行；日志投毒把一句话写入服务日志（由侦察的开放服务清单决定读哪个日志）再包含 |
| 777 / SUID | world-writable / SUID | 两类权限配置错误：777 是 root 拥有且当前用户可写，可直接改脚本内容为反弹 shell；SUID 是执行时继承 owner 权限，利用方式不同但都源于配置错误 |
