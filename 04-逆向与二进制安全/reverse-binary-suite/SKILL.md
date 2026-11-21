---
name: reverse-binary-suite
description: |
  逆向分析与二进制漏洞挖掘的能力包。当用户要逆一个陌生二进制搞清它做什么、要从崩溃样本判断能不能利用、要做模糊测试找崩溃、要分析恶意样本行为、或要审计 C/C++ 源码里的内存与并发缺陷时使用。覆盖：逆向标准流程、静态与动态分析配合、漏洞利用开发、缓解机制绕过、模糊测试工程、崩溃分类与可利用性判定、恶意代码分析、源码审计缺陷族。不适用于：Web 应用漏洞（走 web-security-suite）、内网横向（走 intranet-redteam-suite）。
metadata:
  cangjie.generated-by: cangjie-tools v2.5.0
  cangjie.variant: single
  cangjie.bundle-id: bundle.reverse-binary-suite
  cangjie.capability-count: 14
  cangjie.entrypoint-count: 1
---
# 逆向与二进制安全 — 全书能力入口

## 触发与不触发

**适用**：与本书能力域相关的咨询与任务（见下方路由表的意图列）。
**不适用**：
- 对未授权目标实施攻击
- Web 应用层漏洞挖掘
- 纯 CTF 解题技巧（走 ctf-range-suite）

## 核心原则（常驻速览，概览类问题读到这里即可回答）

1. 先建立程序骨架再读细节：不看整体逻辑就逐条读汇编是浪费
2. 静态判断假设、动态验证事实，两者必须交替
3. 崩溃不等于漏洞，必须证明可控性才有价值
4. 审计追数据流与信任边界，不按文件顺序读
5. 每个结论都要能被另一条路径独立验证

## 能力路由（先读本表，按意图加载 1 张能力卡）

| 用户意图 | 先读 | 补读/备注 |
|---|---|---|
| 拿到一个无符号无文档的 exe/dll/so，第一小时怎么花；快速定位校验/授权逻辑与关键判断分支；静态链接巨大二进制里剥离库代码、找到 main、压缩分析面 | references/capabilities/unknown-binary-triage.md | references/capabilities/binary-analysis-toolchain.md、references/capabilities/malware-behavior-analysis.md |
| 拿到可疑样本快速判断做什么并产出IOC；沙箱报告为空判断是不是反沙箱装死；搭可控分析网络让样本吐出C2 | references/capabilities/malware-behavior-analysis.md | references/capabilities/unknown-binary-triage.md、references/capabilities/binary-analysis-toolchain.md |
| 样本加壳/混淆/反调试，怎么拿到真实代码；脱壳断点总在解密循环停或自己消失；样本不宜执行或跨架构，不执行就拿到去模糊镜像；只有崩溃dmp无符号时黑箱归因 | references/capabilities/binary-analysis-toolchain.md | references/capabilities/unknown-binary-triage.md、references/capabilities/malware-behavior-analysis.md |
| 一次代码审计从哪下手、怎么排优先级、怎么交付；没有设计文档时选 top-down/bottom-up/hybrid；审计到一半没方向时重新校准 | references/capabilities/security-review-planning.md | references/capabilities/source-audit-dataflow.md、references/capabilities/injection-filter-audit.md |
| 有静态扫描报告，判断哪些是真漏洞哪些是误报；确认参数是否用户可控、污点数据流到哪；fuzz没问题但怀疑有隐藏分支漏洞 | references/capabilities/source-audit-dataflow.md | references/capabilities/security-review-planning.md、references/capabilities/memory-integer-audit.md、references/capabilities/injection-filter-audit.md |
| 一处溢出/整数问题能不能利用、严重到什么程度；signed→unsigned长度参数、x<0、length-sizeof为何绕过检查；逆向时算缓冲区到返回地址的距离与必须填的合法值 | references/capabilities/memory-integer-audit.md | references/capabilities/source-audit-dataflow.md、references/capabilities/crash-to-exploit.md、references/capabilities/injection-filter-audit.md |
| 判定一处输入能否注入并系统枚举元字符；过滤器/补丁能不能绕、原payload失效后怎么找绕过；白名单禁掉函数后重算可用注入原语 | references/capabilities/injection-filter-audit.md | references/capabilities/source-audit-dataflow.md、references/capabilities/protocol-and-race-audit.md、references/capabilities/memory-integer-audit.md |
| 审IP/UDP/TCP解析器、TLV/ASN.1/DNS长度字段；未加密私有协议无文档时反推字段语义；审特权程序文件操作的symlink/目录/临时文件竞态 | references/capabilities/protocol-and-race-audit.md | references/capabilities/injection-filter-audit.md、references/capabilities/privilege-windows-audit.md、references/capabilities/fuzzing-triage-infra.md |
| 审setuid/setgid守护进程降权是否彻底；判特权程序exec外部程序时fd是否泄漏；找Windows未引号服务路径/DLL劫持/命名对象抢占/RPC接口 | references/capabilities/privilege-windows-audit.md | references/capabilities/protocol-and-race-audit.md、references/capabilities/injection-filter-audit.md、references/capabilities/binary-analysis-toolchain.md |
| 有一个稳定崩溃，想知道能不能写exploit、下一步做什么；崩溃地址41414141但不知道填多少字节控制EIP；jmp esp跳过去执行乱码或shellcode不执行 | references/capabilities/crash-to-exploit.md | references/capabilities/fuzzing-triage-infra.md、references/capabilities/mitigation-bypass-and-rop.md、references/capabilities/shellcode-engineering.md |
| 目标开了GS/SafeSEH/DEP/ASLR怎么拿到EIP并执行代码；SEH四要素布局、pop pop ret找不到、SafeSEH全开；关DEP链跑飞或ROP链怎么开始写 | references/capabilities/mitigation-bypass-and-rop.md | references/capabilities/crash-to-exploit.md、references/capabilities/shellcode-engineering.md、references/capabilities/memory-integer-audit.md |
| 编码shellcode需要知道自身基址，选哪种GetPC；字符串函数接收输入，shellcode含00会被截断；落点空间不够放完整shellcode | references/capabilities/shellcode-engineering.md | references/capabilities/crash-to-exploit.md、references/capabilities/mitigation-bypass-and-rop.md |
| 要启动一次fuzz战役，选目标/接口/工具/种子；一上来写完整协议模型却与位翻转覆盖率相同；平台期要不要关掉、目标是否挖完 | references/capabilities/fuzzing-campaign.md | references/capabilities/fuzzing-triage-infra.md、references/capabilities/security-review-planning.md、references/capabilities/protocol-and-race-audit.md |
| 几千个崩溃怎么按根因分组排优先级；崩溃样本太大或来自多报文序列需最小化；fuzz没出崩溃怀疑监控盲区或fuzzer在悄悄失效 | references/capabilities/fuzzing-triage-infra.md | references/capabilities/fuzzing-campaign.md、references/capabilities/crash-to-exploit.md、references/capabilities/security-review-planning.md |

**非能力类查询**：
- 书名/作者/章节/整书概览 → references/overview.md
- 术语解释 → references/glossary.md
- 决策规则速查（不需要原文依据时） → references/cheatsheet.md
- 完整意图与关键词索引（本表未覆盖的意图先查这里） → references/capability-index.md

## 加载规则

- 每次任务先读本文件，再按路由表加载 **1** 张能力卡；任务明确跨域时最多加载 2 张。
- 概览/书名类问题不加载能力卡，用「核心原则」与 overview.md 回答。
- 路由表与 capability-index.md 都无法命中的意图，明确告知超出本书范围，不要硬套。

## 边界与判停

- 样本来源不明或可能带破坏性载荷时，先在隔离环境处理
- 分析对象体量超出可读范围且无明确入口时，先缩小到具体函数
- 利用开发连续多次在同一缓解机制上失败时，回到崩溃可控性重新评估
