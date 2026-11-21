# 协议解析与竞态审计

## R — 原文 (Reading)

> Before software can be safely work with an IP datagram, the fields that make up the IP header need to be validated to ensure that the packet is legitimate.
> — 《The Art of Software Security Assessment》Ch14 Basic IP Header Validation

> In general, if you see anything besides a single filename-based system call to open a resource followed by multiple file-descriptor-based calls, there's a reasonable chance of a race condition occurring.
> — 《The Art of Software Security Assessment》Ch9 File Race Redux

> A few subtle attacks can be performed against IP fragment reassembly code by deviating from the expected layout.
> — 《The Art of Software Security Assessment》Ch14 Pathological Fragment Sets

## I — 方法论骨架 (Interpretation)

这张卡把两个共享同一底层机制的主题放在一起：**「同一份数据被两次解释/被中途改动，检查结论与使用对象脱钩」**。文件系统层叫 TOCTOU，协议层叫「字段自描述 / 多包状态机 / 两端解释不一致」。

协议解析部分有三条主线。① 单包字段自洽：把「我到手多少字节」作为唯一可信基准，按「最小长度 → 头长度合法性 → 选项 → 分片」顺序逐层扣减，任一步不足即拒；`ihl` 必须 ≥5 且 `ihl*4 ≤ 到手长度`，`tot_len < ihl*4` 即非法，UDP 长度字段须与 IP 载荷长度一致（允许 0 表示 65535 的特例），TCP data offset ≥5 且 ≤ 段长；必须记录「用的长度变量来自哪里」（报文/驱动/上层），三者混用即缺陷点。② 自描述变长字段（TLV/BER/DER）：`remaining -= declared` 前必须有 `declared ≤ remaining`，否则回绕成巨值；ASN.1 的 tag 与 length 都可变长，两层都可能读到缓冲区外；16 位长度用 `short` 承载会符号扩展成负数再转 `size_t` 变巨值（应用 `unsigned short`/`size_t`）；`ROUNDUP` 宏先溢出再对齐也不安全。③ 多包状态机与歧义：重组代码假设「按序到达、只有一个 MF=0 终止片、偏移连续无缝」，四类病态分片（缺首片、多终止片、重叠 teardrop、乱序）每种都在「何时算完成、总长度取多少、空洞怎么填」上产生歧义；关键是对每个用例同时记录「终端主机怎么解释」与「防火墙虚拟重组怎么解释」，两者不一致即绕过面。状态设备「窥探自己不懂的层」同理：为做 FTP PASV 开洞在 TCP 段里找 `227 Entering Passive Mode (`，但不做重组/不处理跨段/不区分响应行与用户输入回显——同一段字节在设备眼里是开洞请求、在真实服务器眼里只是回显的密码串。

未知协议识别用差分法：同一对主机重复建连 N 次抓包、对齐报文头逐字节标「固定/变化」；变化幅度大的是随机 ID、与包长线性相关的是长度字段、只在特定消息出现小整数增量的是 opcode；按变化字节数推字段宽度并注意字节序；改写单个字段重放验证或推翻假设，再套到其他消息上迭代。

竞态部分（文件系统与内存执行流）的核心是三条判据。TOCTOU 的形态识别：凡「检查用路径名、使用也用路径名」即候选，安全形态是「一次 `open()` + 后续全 `fstat/fchmod/fchown/read/write`」；「先 open 后检查」同样不安全——攻击者可在 open 之后把 symlink 删掉换成普通文件让 `lstat` 看到正常文件，而 fd 仍指向最初目标。创建型 `open(O_CREAT)` 会跟随最后一级 symlink，用 `O_EXCL`（检查+创建原子化）或 `O_NOFOLLOW` 封死；`mktemp/tmpnam/tempnam` 只返回可预测名字不创建文件，返回到 `open(O_CREAT)` 之间有窗口，应改用 `mkstemp()` + 全程 fd 操作。文件是否安全取决于整条路径链——从父目录上溯到根逐级确认不可被非特权者写/改名；sticky 位只挡「创建后改名/删除」不挡「预置同名」。字符串级路径检查（`strncmp` 前缀、`strstr("..")`）挡不住开头 `../`、深层 `/../`、URL 编码、尾部 `%00`、PATH_INFO 伪造——应改为「解析后按规范化绝对路径比对 + fd 操作」。

内存/执行流竞态三要素：共享状态（全局/静态/堆共享结构）、可中断窗口（无锁的「读—判断—写」序列）、外部可触发（线程、信号 handler、回调、fork 子进程）。信号把「并发」塞进单线程：handler 与主流程共享全局状态却不受锁保护，且只能用 async-signal-safe 函数（`malloc`/`printf`/mutex 都不安全，mutex 还会死锁）；判据是「handler 安装期间主流程可能处于哪些中间状态」（尤其 `free()` 之后、赋值之前）。竞态成立需三要素同时满足，识别不需要先构造时序——找出「检查与使用之间共享变量可被第三方改写」的代码形状即可，可利用性另评。

## A1 — 应用示例 (Application Example)

### 示例 1: Kerberos 4 lstat→open 的 symlink 竞态
- **类型与来源**: 【转述】《The Art of Software Security Assessment》Ch9 File Race Redux
- **问题/输入**: 特权守护进程先 `lstat()` 检查文件、再 `open()` 使用，为什么能以 root 覆写任意文件？
- **方法论的使用**: 列出所有接收路径名的系统调用，找出「检查用路径名、使用也用路径名」的成对调用，直接标 TOCTOU 候选；写出窗口内可被替换的对象（最后一级 → symlink；某级目录 → 整体换目录）；判可利用性——攻击者能否在窗口内触发（磁盘压力、作业控制信号、inotify 观察）。
- **结论**: 每次传入路径名内核都要逐级解析，得到的是「此刻」的 inode；fd 锁定到 open 那一刻的 inode。检查与使用各走一次路径解析，中间任一级被替换，结论就与使用对象脱钩。
- **结果**: 原书以 Kerberos 4 登录守护进程与 SunOS binmail（`lstat()`→`open(O_CREAT)`）两个案例说明该判据。

### 示例 2: fragment_add 的多终止片误判完成
- **类型与来源**: 【转述】《The Art of Software Security Assessment》Ch14 Pathological Fragment Sets
- **问题/输入**: 先发高偏移分片、再发低偏移终止片，重组代码为何会把带空洞的数据报判为完成？
- **方法论的使用**: 构造四类病态分片集合——① 高偏移 MF 片 + 低偏移终止片（缺 0 偏移数据）；② 多个 MF=0 分片（完成判定提前触发）；③ 完全被前片覆盖的重叠片（teardrop，`新片 end − 旧片 start` 越界）；④ 交错乱序（空洞区零填/未初始化内存填充）；对每个用例记录终端主机解释与防火墙虚拟重组解释。
- **结论**: 重组代码假设「按序、单一终止片、偏移连续」，任何假设被打破就在「何时算完成/总长/空洞填充」上产生歧义；两端解释不一致既是解析器漏洞也是绕过检测的原语。
- **结果**: 原书给出 `fragment_add()` 代码——offset=32 的 MF 片 + offset=16 的终止片使 `chain->datalength == end` 成立而被判完成。

## A2 — 触发场景 (Future Trigger)

### 用户会在什么情境下需要它
1. 审计 IP/UDP/TCP 解析器、抓包工具、IDS/防火墙重组模块，担心长度字段未校验导致越界。
2. 审计 ASN.1/BER/DER、DNS RR 或私有 TLV 格式解析器，担心长度自描述字段回绕。
3. 面对一个未加密的私有协议，需要在没有文档/源码时反推字段语义。
4. 审计特权程序的文件操作，判断是否可被 symlink/目录替换/临时文件抢占。
5. 审计多线程/信号处理器代码，判断竞态三要素是否成立、可用信号/并发触发。

### 语言信号（出现这些就该激活）
- 中文：「协议解析器审计」「长度字段没校验」「IP 头校验」「包太小导致越界」「分片重组漏洞」「teardrop」「ASN.1 长度解析」「TLV 溢出」「DNS 解析漏洞」「私有协议怎么逆」「流量差分」「TOCTOU」「检查和使用之间被换掉」「race condition in file check」「mktemp 安全吗」「临时文件竞态」「目录权限够不够」「信号处理函数安全吗」「竞态条件怎么找」「非重入函数」
- English: "protocol parser audit", "IP header validation", "pathological fragments", "ASN.1 BER DER length underflow", "unknown protocol reverse engineering", "TOCTOU symlink race", "mkstemp vs mktemp", "async-signal-safe", "race condition three elements", "IDS evasion via fragmentation"

### 与相邻能力的区分
- 与 `injection-filter-audit` 的区别：先检查后解码属表示层顺序问题（那张卡），文件系统层检查/使用分离与协议层多包状态机属本卡。
- 与 `privilege-windows-audit` 的区别：那张卡处理 Windows 对象命名空间、ACL、DLL 搜索顺序、降权与 fd 继承；本卡处理 UNIX 文件竞态与网络协议/TLV 解析。
- 与 `fuzzing-triage-infra` 的区别：本卡是静态审计判据，那张卡是动态 fuzz 找崩溃后的分诊；协议 fuzz 的畸形输入生成在那张卡。

## E — 可执行步骤 (Execution)

**必需输入**: 待审代码（C/C++ 为主）或协议规范/抓包；目标系统目录权限与实际部署环境（判竞态可利用性必需）；原始 IP 包构造能力（测分片时）。缺实际权限时只能给「候选 + 条件」，不能判可利用。

**交付物与完成标准**: ① 单包字段校验顺序审查表；② TLV 长度校验审查表；③ 四类病态分片用例与两端解释对照；④ 未知协议字段语义表；⑤ TOCTOU 候选点与 fd 安全形态判定；⑥ 竞态三要素分析表。完成标准：每个结论都能指回具体代码形态与「谁在什么时候改了什么」。

1. **审单包字段自洽**
   - 做什么：到手字节数 ≥ 最小头长（IP 20）→ 否则丢弃；`ihl ≥ 5` 且 `ihl*4 ≤ 到手长度`；头含选项时解析代码按变长头跳转而非硬编码 20 字节结构体；`tot_len ≥ ihl*4` 且与实际到手长度一致；UDP 长度字段 vs IP 载荷长度（允许 0=65535）、TCP data offset ≥5 且 ≤ 段长；非首片不做传输层解析、重组完成前不交上层；记录每个长度变量的来源。
   - 完成标准：逐字段校验顺序表齐全，长度来源无混用。
   - 判停：用 `struct iphdr` 直接套缓冲区（选项存在时字段错位）→ 判缺陷；`length - offset` 未判负 → 判缺陷（pcap 例子中 memcpy 计数为 −10）。

2. **审 TLV/变长长度字段**
   - 做什么：多字节 tag 循环是否检查「还有字节可读」；长形式 length 首字节声明「后续 N 字节」时是否校验 N ≤ 剩余；每条 `remaining -= header_len` 前是否有 `header_len ≤ remaining`；分配前检查 `len`、`len+overhead`、`(len+7)/8` 是否回绕；长度变量类型是否为 `short`/`int`（16 位字段高位置 1 时符号扩展成负值再转 size_t 变巨值）；记录同一数据被几个解析器解析。
   - 完成标准：长度校验审查表 + 类型判定。
   - 判停：用有符号比较校验「长度 > 剩余」（负数直接通过）→ 判缺陷；`ROUNDUP` 宏先溢出再对齐 → 判缺陷；ID S 与终端多解析器差异 → 标绕过面。

3. **跑四类病态分片用例**
   - 做什么：发高偏移 MF 片 + 低偏移终止片看是否缺 0 偏移仍判完成；发多个 MF=0 看完成判定是否提前；发完全覆盖的重叠片（teardrop）看长度计算是否越界；交错乱序看空洞是否零填/未初始化填充；对每个用例同时记录终端主机与防火墙虚拟重组的解释。
   - 完成标准：四类用例结果 + 两端解释对照表。
   - 判停：忽略「先到优先 vs 后到覆盖」策略差异 → 补测；只在终端主机上验证 → 必须补防火墙路径。

4. **审状态设备 ALG 解析差异**
   - 做什么：找设备的应用层识别逻辑是否在单段内做 `strstr`/定长偏移匹配；构造「把关键字藏进用户可控字段」的会话（如 `USER 227 Entering Passive Mode (...)`）；用极小 MSS/MTU 把关键字切成多段看是否仍命中；用「只确认部分数据迫使服务端重传」让关键字独立成段；两侧都写「设备以为发生了什么/实际发生了什么」。
   - 完成标准：两侧解释差异报告 + 可复现流量。
   - 判停：只测「能不能穿过去」不记录为什么两端理解不同 → 换协议即失效；忽略设备可能做虚拟重组从而部分免疫。

5. **未知协议差分识别**
   - 做什么：同主机重复建连 N 次抓包、对齐头逐字节标固定/变化；对变化字段问幅度/是否与包长相关/是否只在特定消息出现；按变化字节数推字段宽度并注意字节序；改写单字段重放观察响应/错误码；把已确认头格式套到其他消息、标未知字段、迭代；无符号时补二进制侧手段（字符串、调试信息、PDB、库调用交叉引用）。
   - 完成标准：字段语义表（id/unknown/length/opcode）与重放验证结果。
   - 判停：只看一次会话就下结论（随机字段当常量）→ 禁止；把长度字段误判为序列号 → 改动包长验证。

6. **审文件系统 TOCTOU 与路径安全**
   - 做什么：列所有接收路径名的系统调用，找出「检查用路径名 + 使用也用路径名」的成对调用标候选；确认安全形态是「一次 open + 后续全 fd 操作」；「先 open 后检查」仍用路径名 `lstat` 的判缺陷；搜 `O_CREAT` 无 `O_EXCL`/`O_NOFOLLOW` 的调用；凡 `mktemp/tmpnam/tempnam` 出现即标候选并查返回到 open 的空隙；从父目录上溯到根逐级列权限与属主，标任何 0777/组可写/非特权属主层级；对路径字符串检查试四种变形（开头 `../`、深层 `/../`、URL 编码、尾部 `%00`）与 PATH_INFO 伪造。
   - 完成标准：TOCTOU 候选清单 + 安全前缀清单 + 变形验证结果。
   - 判停：以为「先 open 后检查」安全 → 破之；认为 sticky 目录安全 → 破之（只挡改名/删除不挡预置）；任何字符串级检查都不足以判路径归属，应改为规范化绝对路径比对 + fd 操作。

7. **审内存/执行流竞态**
   - 做什么：列全局/静态/堆共享结构，标多执行流访问的字段；找「读—判断—写」序列判是否可被打断（无锁/无原子）；判断打断者是否存在（线程、信号 handler、回调、fork 子进程共享 open file 结构）；判外部可控性（多连接并发、定时信号、磁盘/网络压力、inotify）；影响归类（double free、越界拷贝、状态错乱、仅 DoS）；信号场景另查 handler 内函数是否 async-signal-safe、handler 访问的全局量在主流程的「半完成状态」（`free()` 后、赋值前）、是否用 `longjmp`/`siglongjmp`。
   - 完成标准：三要素分析表 + 风险等级 + Signal Handler Scoreboard。
   - 判停：要求「必须先证明能赢竞态」才记录 → 错，应记录机制、可利用性另评；把 thread-safe 当 async-signal-safe → 错（mutex 在信号上下文死锁）。

## B — 边界 (Boundary)

### 不要用的情况
- 纯 Web 注入/SQL 注入问题，转 `injection-filter-audit`。
- Windows 命名对象抢占、ACL、DLL 搜索顺序、降权问题，转 `privilege-windows-audit`。
- 动态 fuzz 找协议解析器崩溃后的分诊与去重，转 `fuzzing-triage-infra`。
- 整型符号/截断问题（非长度字段自描述），转 `memory-integer-audit`。

### 已知失败模式
- 用固定 `struct etherpacket` 套在缓冲区上解析，遇 IP/TCP 选项即字段错位；只校验 `caplen` 不校验 `tot_len`（Ch14）。
- 先把 offset=32 的 MF 片、再发 offset=16 的终止片，`chain->datalength == end` 成立而被误判完成（Ch14 fragment_add）。
- 「先 open 后检查」仍用路径名 `lstat`：攻击者 open 后删 symlink、建普通文件让检查通过，fd 仍指向恶意目标（Ch9 Listing 9-5）。
- 用 `mktemp()` 返回名字到 `open(O_CREAT)` 之间留窗口；用 `mkstemp()` 后又 `fopen(name)` 重开即失效；把 TMPDIR 环境变量当可信（Ch9 gcc 案例）。
- 认为「只监听 127.0.0.1」「私有协议」安全——攻击者「find a singular joy in reverse engineering a proprietary protocol」（Ch1/Ch2）。
- 把 thread-safe 当 async-signal-safe；认为 `do_cleanup` 加了 `called` 标志就万事大吉（被调函数仍可能非重入）——OpenSSH `grace_alarm_handler` → `fatal()` → `do_cleanup()` → 非重入 `krb5_cleanup_proc()`（Ch13）。
- 对带强校验的协议只做位翻转 fuzz，变异全被协议层拒掉——属 `fuzzing-campaign` 的目标形态判断。

### 作者与时代的局限
- IP/TLV 示例基于 IPv4、ASN.1 BER/DER 与 2007 年前后的协议栈；IPv6 扩展头、QUIC 等新协议需按同样顺序重新建校验表。
- `O_NOFOLLOW` 是 FreeBSD 扩展、Linux 2.1.126 起支持，目标平台不支持时该防御不可用（Ch9）。
- `mktemp`/`tmpnam` 案例是历史 API 缺陷；现代 libc 已有更安全的替代，但遗留系统仍常见。
- 竞态示例中 fork 子进程共享 open file 结构属 UNIX 语义；Windows 的句柄继承问题见 `privilege-windows-audit`。

### 容易混淆的方法
- 「TOCTOU 文件系统层」（路径被换）与「内存/执行流竞态」（共享变量被打断）判据相似但层次不同；与信号的 async-signal-safe 函数集又不同（mutex 在信号上下文会死锁）。
- 「先检查后解码」（表示层，属 `injection-filter-audit`）与「检查用路径名、使用用 fd」（文件系统层，本卡）都叫「检查与使用不一致」，但修复手段不同。
- 「终端主机 vs 防火墙虚拟重组」与「设备 ALG vs 真实服务器」都是「两端解释不一致」，层次分别为 IP 重组与应用层语义。
- 「判定竞态机制」与「证明能赢竞态时序」是两步，本卡要求先记机制，不要因暂时无法构造时序而漏记。

### 授权与合规边界
> 待补充（用户自行填写）
