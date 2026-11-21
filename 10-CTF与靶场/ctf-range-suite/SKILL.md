---
name: ctf-range-suite
description: |
  CTF 竞赛与靶场实战的能力包。当用户在打 CTF、要按题型快速定位解法、要在靶场里找突破点、或要把竞赛技巧迁移到实战时使用。覆盖：题型识别与解题顺序、Web/Misc/Crypto/Pwn/Reverse 各类题的通法、信息搜集与隐写、编码与流量分析、靶场渗透路径、时间与分数策略。不适用于：真实授权项目的渗透（走对应专业域）、纯理论学习。
metadata:
  cangjie.generated-by: cangjie-tools v2.5.0
  cangjie.variant: single
  cangjie.bundle-id: bundle.ctf-range-suite
  cangjie.capability-count: 10
  cangjie.entrypoint-count: 1
---
# CTF与靶场 — 全书能力入口

## 触发与不触发

**适用**：与本书能力域相关的咨询与任务（见下方路由表的意图列）。
**不适用**：
- 比赛作弊与题目泄露
- 对非靶场目标的攻击
- 真实项目的合规判断

## 核心原则（常驻速览，概览类问题读到这里即可回答）

1. 先判题型再动手，题型判错会白花时间
2. 从题目给的线索出发，不做无根据的猜测
3. 卡住时换维度：换工具、换视角、换信息源
4. 分数与时间要管理，不要在一道题上耗死
5. 赛题技巧要提炼成可迁移方法，不是背 payload

## 能力路由（先读本表，按意图加载 1 张能力卡）

| 用户意图 | 先读 | 补读/备注 |
|---|---|---|
| 参加线下 AWD 赛，开赛第一时间不知道该做什么。；写好了 pwn exp，但发现需要 `interactive()` 才能拿 flag，无法批量打全场。；flag 每五分钟轮换，手工提交跟不上节奏。 | references/capabilities/awd-attack-defense.md | references/capabilities/pwn-opening-protection-read.md、references/capabilities/blind-rop-brop.md、references/capabilities/lab-workflow-and-triage.md |
| 题目只给一个 `nc host port`，既没有 binary 也没有 libc，需要判断有没有解、走哪条路。；发探针确认是栈溢出后，发现没有任何 `%s`/write 泄漏点，无法按常规路线拿地址。；想理解 BROP 为什么必须先找 stop gadget，以及每一步的判据是什么。 | references/capabilities/blind-rop-brop.md | references/capabilities/pwn-opening-protection-read.md、references/capabilities/format-string-exploitation.md、references/capabilities/awd-attack-defense.md |
| 找到可控文件路径参数，不确定漏洞是否真实存在、下一步读什么。；`include` 读源码文件，回显里没有 `<?php` 文本，只有空白或执行结果。；`?file=/etc/passwd` 加在 URL 上没反应，怀疑被过滤或走不同分支。 | references/capabilities/file-read-and-include.md | references/capabilities/web-vuln-channel-selection.md、references/capabilities/web-recon-source-leak.md、references/capabilities/rce-egress-and-shell.md |
| 确认题目存在格式化字符串漏洞后，需要把「能读栈」变成「能拿 shell」。；payload 用 `%n` 写过去没反应，或写到了错误地址，需要重新定偏移。；只有 nc 地址，想用 `%s` 把程序代码从内存里读回来继续分析。 | references/capabilities/format-string-exploitation.md | references/capabilities/pwn-opening-protection-read.md、references/capabilities/blind-rop-brop.md |
| 拿到 shell 后执行 `su` 报 "no tty present"。；提权 exp 在目标上编译不了（没有 gcc）。；提权 exp 编译后运行报错，不知道是内核版本还是架构问题。 | references/capabilities/lab-privesc.md | references/capabilities/lab-workflow-and-triage.md、references/capabilities/rce-egress-and-shell.md、references/capabilities/web-recon-source-leak.md、references/capabilities/awd-attack-defense.md |
| 第一次打 Boot2root 靶机，不知道标准推进流程是什么。；侦察完不知道下一步该干什么，或扫完描没发现漏洞。；某个注入/包含点死活打不进去，纠结要不要继续死磕。 | references/capabilities/lab-workflow-and-triage.md | references/capabilities/lab-privesc.md、references/capabilities/web-recon-source-leak.md、references/capabilities/awd-attack-defense.md |
| 刚解压一个 CTF pwn 附件，面对一堆文件不知道先打开哪个、先看什么。；已经有一份能崩的 exp，但换了环境/保护选项后失效，需要判断是哪一项保护在起作用。；题目只给 `nc host port`，没有任何附件，需要先判断有没有可能做、走哪条路线。 | references/capabilities/pwn-opening-protection-read.md | references/capabilities/format-string-exploitation.md、references/capabilities/blind-rop-brop.md |
| 命令执行 payload 发出去了，但页面完全不显示结果。；目标似乎不能出网，不知道还能怎么把数据带出来。；反弹 shell 一种姿势连不上，不知道换什么。 | references/capabilities/rce-egress-and-shell.md | references/capabilities/web-vuln-channel-selection.md、references/capabilities/file-read-and-include.md、references/capabilities/lab-privesc.md、references/capabilities/awd-attack-defense.md |
| Web 题刚拿到 URL，不知道第一步该做什么。；扫目录扫出 `.git` 返回 403，不确定还有没有戏。；`.git` 泄露已经确认，但源码里和最新提交里都找不到 flag。 | references/capabilities/web-recon-source-leak.md | references/capabilities/web-vuln-channel-selection.md、references/capabilities/file-read-and-include.md、references/capabilities/lab-workflow-and-triage.md |
| 发现一个可疑参数，但不知道是数字型还是字符型 SQLi，不确定怎么闭合。；找到 URL 参数，怀疑能打内网，但不知道从哪个协议入手。；gopher 串照抄过来打不通，改了 IP 之后服务解析错乱。 | references/capabilities/web-vuln-channel-selection.md | references/capabilities/web-recon-source-leak.md、references/capabilities/file-read-and-include.md、references/capabilities/rce-egress-and-shell.md |

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

- 同一题超过预定时间无进展时切换
- 解题手段涉及攻击非靶场资产时立即停止
- 环境异常（题目挂掉）时先确认再换题
