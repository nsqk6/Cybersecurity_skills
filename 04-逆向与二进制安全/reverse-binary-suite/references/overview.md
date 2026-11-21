# 逆向与二进制安全 — 域总览

## 这个域在真实工作中解决什么问题

拿到一个没有源码、没有符号、甚至带壳带反调试的二进制，或者面对一份几十万行的 C 代码和一堆 fuzz 崩溃，安全从业者要回答的是同一类问题：**「危险的操作是否被攻击者可控的数据触达，以及触达后能否改变执行流」**。本域把这件事拆成从侦察到利用、从审计到工程的完整链条——静态/动态逆向搞清「它是什么、关键逻辑在哪」，源码审计与漏洞定位搞清「洞在哪、多严重」，利用与提权搞清「崩溃怎么变成可控执行」，工程化能力则保证 fuzz 与审计能稳定、可复现、可运维地交付。四个对外入口（陌生二进制逆向、源码审计数据流、崩溃到利用、模糊测试工程）分别对应「拿到样本、拿到源码、拿到崩溃、系统性找洞」四类最常见起点。

## 能力地图

| 二级分类 | 能力 slug | 中文标题 | promotion |
|---|---|---|---|
| 逆向分析 | `unknown-binary-triage` | 陌生二进制逆向流程 | **promoted** |
| 逆向分析 | `malware-behavior-analysis` | 恶意样本分阶段行为分析 | router |
| 工具链 | `binary-analysis-toolchain` | 脱壳与反分析工具链 | router |
| 审计 | `security-review-planning` | 威胁建模与审计规划 | router |
| 审计 | `source-audit-dataflow` | 源码审计数据流与候选点回溯 | **promoted** |
| 漏洞定位 | `memory-integer-audit` | 内存破坏与整数漏洞定位 | router |
| 漏洞定位 | `injection-filter-audit` | 注入与过滤器绕过审计 | router |
| 漏洞定位 | `protocol-and-race-audit` | 协议解析与竞态审计 | router |
| 漏洞定位 | `privilege-windows-audit` | 特权边界与 Windows 对象审计 | router |
| 利用与提权 | `crash-to-exploit` | 从崩溃到可控利用的推进 | **promoted** |
| 利用与提权 | `mitigation-bypass-and-rop` | 缓解绕过与 ROP 链编排 | router |
| 利用与提权 | `shellcode-engineering` | Shellcode 工程化 | router |
| 工程化 | `fuzzing-campaign` | 模糊测试战役工程 | **promoted** |
| 工程化 | `fuzzing-triage-infra` | 崩溃分诊与 fuzz 基础设施 | router |

共 14 个能力，覆盖全部六个二级分类；promoted 4 个（对外入口上限），其余 10 个作为域内路由入口保留。

## 域的共性失败模式

1. **把现象当根因**：崩溃点 ≠ 根因点、字符串存在 ≠ 被使用、「本函数内安全」≠「端到端安全」、弹错误框 ≠ 没崩——必须靠回溯/交叉引用/动态验证把现象翻译成可归因的事实。
2. **检查与使用脱钩**：TOCTOU（路径被换）、先检查后解码（表示层替换）、剥离过滤器自己拼回禁用序列、两端对同一 URI/分片的解释不一致——凡是「检查看到的对象」与「使用时被解释的对象」不是同一个，检查就失效。
3. **只看「有没有检查」不看「检查是否生效」**：有符号比较配无符号长度（`JL/JLE` vs `size_t`）使 −1 通过检查、`sizeof(ptr)` 返回指针宽度、`x < 0` 恒假、加了强转却没改类型（antisniff 三版皆被绕）。
4. **用静态结论冒充动态事实**：不验证交叉引用就把字符串映射成功能、不验证可达性就报候选点为漏洞、不加护栏就以为「小幅越界不崩=没问题」、不重扫就以为「删了 ../ 就安全」。
5. **硬编码偶然值**：照抄教程偏移与跳板地址、用本机栈地址（含 00 且随 SP/语言变）、用模块基址当 ASLR 下的常量、把平台特定的 snprintf 返回值语义当通用——换环境即失效。
6. **过度简化结论**：去重后把「10 个崩溃」记成「1 个漏洞」、把「一段时间没新发现」当挖完、把 DoS/资源耗尽当可利用、把内存 fuzz 造出的不可达状态当漏洞、把「修了」当「修好了」。
7. **在错误层级动手**：补丁补在症状层而非类型层、注入绕不过就硬凑 payload 而不重算原语、字符串级检查路径而不做规范化后比对、用模式匹配去补语义差异（F5 缓解被两轮绕过）。
8. **把 fuzz 当「写个生成器」**：缺监控/去重/最小化/报告，得到一堆无法归因的噪声；或靠「fuzzer 进程还活着」判断健康，产出「目标很健壮」的错误结论。

## 覆盖说明：哪些书贡献了哪些能力

| 来源书目 | 贡献的能力 | 主要贡献内容 |
|---|---|---|
| The Art of Software Security Assessment（P0，约 380 万字） | `security-review-planning`、`source-audit-dataflow`、`memory-integer-audit`、部分 `injection-filter-audit`、`protocol-and-race-audit`、`privilege-windows-audit`、`crash-to-exploit` | 威胁建模与 DREAD、数据流与候选点法、ACC/函数审计日志、内存破坏六问与整型三机制、元字符注入四步、文件竞态/路径安全、信号与线程竞态、IP/TLV 校验、降权/fd/ACL/RPC 审计、崩溃回溯三步法——本域方法论骨架的主要来源（batch-1、batch-2 共 55 单元） |
| Fuzzing for Software Security Testing and QA（P0） | `fuzzing-campaign`、`fuzzing-triage-infra` | 六阶段生命周期、目标甜区、接口枚举、智能 vs dumb 成本、数据来源与取值、BNF 语法测试、种子与多 fuzzer 并联、三级指纹去重、最小化、护栏监控、覆盖率闸门与引导、农药效应——覆盖 fuzz 的战役与工程两端（batch-3 共 24 单元） |
| Exploit 编写系列教程 1-10（P0） | `crash-to-exploit`、`mitigation-bypass-and-rop`、`shellcode-engineering` | 崩溃到利用六阶段、二分+pattern 定偏移、跳转技术与落点校准、SEH 四要素、GS/SafeSEH/DEP/ASLR 绕过、ROP gadget 与链编排、GetPC、去 null、egg hunter、Unicode venetian——利用链的完整工艺（batch-4 共 25 单元，第五篇因文本残缺无产出） |
| IDAPro 权威指南 + 从零开始学 IDA 逆向（上/中）（P0） | `unknown-binary-triage`、`binary-analysis-toolchain`、部分 `memory-integer-audit` | 三级静态侦察、FLIRT 剥离库代码、四判据定位 main、交叉引用穷举、结构体/调用约定恢复、extern→got→plt、反调试识别、静态去模糊、去同步修复、加壳识别/OEP/IAT 重建、栈帧偏移算距离、有符号比较绕过——逆向与工具链的手法库（batch-5 共 26 单元） |
| 恶意软件逆向工程手册 + 有趣的二进制（P0） | `malware-behavior-analysis`、部分 `binary-analysis-toolchain`、`unknown-binary-triage` | 恶意样本分阶段分析、假互联网( host-only+INetSim)、反虚拟化排查、PE 结构异常、导入表能力草图、三面监控与持久化、硬件断点/脱壳、崩溃转储反查——行为分析与动态工具链（batch-6 前段） |
| 163 酒仙桥六号部队系列（P1） | `injection-filter-audit`、部分 `unknown-binary-triage` | changelog/issue 反推补丁绕过、双过滤器解码顺序、字符白名单原语替换、黑盒异常作白盒入口、换参数绕过校验、官方缓解的同源解析绕过、Android 弹窗劫持逆向——补丁绕过与实战案例（batch-6 后段 7 单元） |

合计 155 个 verified 单元全部映射到 14 张能力卡，无丢弃、无重复归类。

## 与其他域的边界

- 与「Web/服务端逻辑」域：SQL 注入/XSS 的 payload 构造与鉴权逻辑属那两域；本域只保留「注入判定的通用方法论（解释器语义 + 集合运算 + 顺序）」与「从黑盒异常反推审计起点」的跨域手法。
- 与「取证与溯源 / 检测与响应」域：恶意样本分析在本域止于「理解样本 + 产出 IOC/YARA」，不处置系统；日志溯源、遏制清除属那两域。
- 与「移动安全」域：Android 系统应用弹窗劫持（CU-6-25）在本域作为「逆向系统应用定位关键代码」的例题保留，移动端整体的权限模型与组件安全属移动域。
