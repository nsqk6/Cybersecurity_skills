---
name: security-foundation-suite
description: |
  安全工程师的系统与网络功底能力包。当用户需要补齐 Linux/Shell/网络协议/编程基础、要写自动化脚本处理安全任务、要读懂日志与流量、或要把重复工作工程化时使用。覆盖：Linux 命令行与文本处理、Shell 与 Python 自动化、网络协议与流量分析、HTTP 与 Web 基础、日志处理、脚本工程化、常见环境搭建。不适用于：具体漏洞挖掘（走对应专项域）、纯语言教程。
metadata:
  cangjie.generated-by: cangjie-tools v2.5.0
  cangjie.variant: single
  cangjie.bundle-id: bundle.security-foundation-suite
  cangjie.capability-count: 10
  cangjie.entrypoint-count: 1
---
# 系统与网络功底 — 全书能力入口

## 触发与不触发

**适用**：与本书能力域相关的咨询与任务（见下方路由表的意图列）。
**不适用**：
- 语言语法系统教学
- 系统运维全流程
- 安全产品的部署实施

## 核心原则（常驻速览，概览类问题读到这里即可回答）

1. 能在命令行一次搞定的事不写脚本，能写脚本的不手工重复
2. 先看清数据形态再选工具：文本、二进制、流、结构化各有一套
3. 协议要按层看，出问题时先定位在哪一层
4. 脚本必须可重复执行且失败可见
5. 基本功的价值在于缩短从「看到现象」到「定位原因」的时间

## 能力路由（先读本表，按意图加载 1 张能力卡）

| 用户意图 | 先读 | 补读/备注 |
|---|---|---|
| 从日志里快速统计总量、Top N 或字段分布；从大配置/日志里截取一个区块；把一次性排查固化成可交接复核的命令 | references/capabilities/text-processing-pipeline.md | references/capabilities/text-field-and-regex.md、references/capabilities/batch-file-operations.md、references/capabilities/untrusted-file-inspection.md |
| 命令跑通了却搜不到/统计不对，定位是哪层语义错；从 Python/Perl 迁移正则到 sed 后替换失效；批量多文件统计结论偏大或不可复现 | references/capabilities/text-field-and-regex.md | references/capabilities/text-processing-pipeline.md、references/capabilities/shell-script-reliability.md、references/capabilities/batch-file-operations.md |
| find 结果批量处理时选择传递方式；批量删除/清理前看到确切清单；遇到 Argument list too long 或 sed -i 原地修改需留退路 | references/capabilities/batch-file-operations.md | references/capabilities/text-field-and-regex.md、references/capabilities/permission-operations.md、references/capabilities/text-processing-pipeline.md |
| 定位 shell 脚本报错或静默无输出的根因；让批量任务的失败显式可见；解决脚本里变量未替换、参数被拆的问题 | references/capabilities/shell-script-reliability.md | references/capabilities/text-field-and-regex.md、references/capabilities/batch-file-operations.md、references/capabilities/text-processing-pipeline.md |
| 把异常外连/监听端口归因到进程；查某账号或在占用文件在做什么；构造命令与日志对齐的事件时间线 | references/capabilities/cli-forensics.md | references/capabilities/untrusted-file-inspection.md、references/capabilities/permission-operations.md、references/capabilities/text-processing-pipeline.md |
| 枚举 suid/sgid 风险面并剔除无效设置；批量改权限前界定半径并留快照；确认有执行权限的文件是否真是可执行程序 | references/capabilities/permission-operations.md | references/capabilities/batch-file-operations.md、references/capabilities/cli-forensics.md、references/capabilities/untrusted-file-inspection.md |
| 不改动原件、不被内容诱导执行地查看可疑文件；判断"内容缺了一段"是不是超长行显示假象；崩溃后从 swap 残留找回未写回内容 | references/capabilities/untrusted-file-inspection.md | references/capabilities/cli-forensics.md、references/capabilities/text-processing-pipeline.md、references/capabilities/text-field-and-regex.md |
| 遇到「这个系统安全吗」时，查本域 OCR 增补材料中的对应方法与判据；遇到「帮我加固一下」时，查本域 OCR 增补材料中的对应方法与判据；遇到「how do I secure this」时，查本域 OCR 增补材料中的对应方法与判据 | references/capabilities/ocr-framework-judgement.md | references/capabilities/text-processing-pipeline.md、references/capabilities/text-field-and-regex.md |
| 遇到「海量整数去重」时，查本域 OCR 增补材料中的对应方法与判据；遇到「大范围小规模排序」时，查本域 OCR 增补材料中的对应方法与判据；遇到「bitmask filter」时，查本域 OCR 增补材料中的对应方法与判据 | references/capabilities/ocr-recipe-troubleshooting.md | references/capabilities/text-processing-pipeline.md、references/capabilities/text-field-and-regex.md |
| 遇到「优化」时，查本域 OCR 增补材料中的对应方法与判据；遇到「这算法很简单」时，查本域 OCR 增补材料中的对应方法与判据；遇到「ICMP 重定向要不要禁用」时，查本域 OCR 增补材料中的对应方法与判据 | references/capabilities/ocr-counter-example.md | references/capabilities/text-processing-pipeline.md、references/capabilities/text-field-and-regex.md |

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

- 脚本会批量改动生产文件时先备份并小范围试跑
- 命令涉及删除/覆盖时先确认路径
- 对不确定的数据格式先取样再处理
