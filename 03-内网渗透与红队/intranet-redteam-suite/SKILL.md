---
name: intranet-redteam-suite
description: |
  内网渗透与红队行动的能力包。当用户已拿到一个内网立足点、要做信息收集与权限提升、抓取凭据、横向移动到其他主机、打域控、配置 C2 与隧道出网、做免杀规避、或规划一条从边界到目标资产的完整攻击路径时使用。覆盖：内网侦察、提权、凭据获取、横向移动、域渗透、权限维持、代理隧道、C2 部署、免杀与 OPSEC、红队演练组织。不适用于：Web 单点漏洞挖掘（走 web-security-suite）、恶意样本逆向（走 reverse-binary-suite）。
metadata:
  cangjie.generated-by: cangjie-tools v2.5.0
  cangjie.variant: single
  cangjie.bundle-id: bundle.intranet-redteam-suite
  cangjie.capability-count: 15
  cangjie.entrypoint-count: 1
---
# 内网渗透与红队 — 全书能力入口

## 触发与不触发

**适用**：与本书能力域相关的咨询与任务（见下方路由表的意图列）。
**不适用**：
- 未授权环境下的真实入侵
- Web 应用层单点漏洞的原理与验证
- 软件逆向与漏洞利用开发

## 核心原则（常驻速览，概览类问题读到这里即可回答）

1. 路径优先于漏洞：先想清楚到目标要走哪几步，再找能支撑每一步的缺口
2. 每一步都要留退路：横向与提权前先确认当前权限能做什么、失败会不会暴露
3. 凭据是内网的核心资产，拿到凭据的价值通常高于再打一个漏洞
4. 隐蔽性与效率是权衡关系，按演练规则决定偏哪边
5. 动作前先想日志：这一步会在哪些设备上留下什么痕迹

## 能力路由（先读本表，按意图加载 1 张能力卡）

| 用户意图 | 先读 | 补读/备注 |
|---|---|---|
| 木马/beacon 一直不上线，需要判断是出口、拓扑还是载荷问题。；内网深处主机不出网，需要选「中继监听」还是「对等 Beacon」。；需要在一个只放行 80/443（或只有 DNS）的环境里建通道。 | references/capabilities/c2-tunnel-infrastructure.md | references/capabilities/evasion-and-opsec.md、references/capabilities/lateral-execution-channels.md、references/capabilities/domain-recon-path.md |
| 拿到一台主机，需要判断「先抓什么、抓得到什么」。；mimikatz 抓不到明文，需要判断是配置问题、PPL 保护还是工具被杀。；手上有一个 hash，需要判断它能 P2H、能爆破，还是只能中继。 | references/capabilities/credential-extraction.md | references/capabilities/domain-recon-path.md、references/capabilities/password-attack-reuse.md、references/capabilities/ntlm-relay-coercion.md、references/capabilities/kerberos-ticket-abuse.md |
| 刚拿到第一台内网主机（webshell / 反弹 shell），不知道下一步该收集什么、按什么顺序做。；需要在不触发 NIDS/HIDS 的前提下摸清域结构（域、DC、域管、机器清单）。；需要找「下一个跳点」：哪台机器值得打、为什么值得打。 | references/capabilities/domain-recon-path.md | references/capabilities/external-recon-pretext.md、references/capabilities/credential-extraction.md、references/capabilities/lateral-execution-channels.md |
| 刚拿到 shell，需要决定要不要先做冗余再横向。；反弹 shell 老是掉，需要判断是网络问题还是缺落点。；需要留一个重启后仍能触发的入口，但不想新建计划任务/服务。 | references/capabilities/endpoint-persistence.md | references/capabilities/kerberos-ticket-abuse.md、references/capabilities/lateral-execution-channels.md、references/capabilities/c2-tunnel-infrastructure.md |
| 载荷被杀，需要判断是特征码、导入表还是位数问题。；载荷免杀了但一执行就被行为检测抓，需要看命令行与进程树。；Web 侧 payload 被 WAF 拦，需要让危险字符串不以字面量出现。 | references/capabilities/evasion-and-opsec.md | references/capabilities/initial-access-delivery.md、references/capabilities/c2-tunnel-infrastructure.md、references/capabilities/credential-extraction.md |
| 拿到一个新目标（公司/园区/系统）要做外部情报，但不知道查什么、查到哪算够。；要设计一个到场、通话或邮件的身份，不确定选哪种角色、怎么让对方不起疑。；OSINT 收了一大堆材料，需要判断哪些能用于接触、哪些只是浪费时间。 | references/capabilities/external-recon-pretext.md | references/capabilities/domain-recon-path.md、references/capabilities/initial-access-delivery.md |
| 钓鱼邮件发了但没人点，怀疑被网关拦，需要判断是「没到」还是「到了没人信」。；需要在有限名单里决定先打谁，避免一次投递就惊动防守方。；登录口有验证码/锁定打不动，需要找页面层之外的鉴权边界。 | references/capabilities/initial-access-delivery.md | references/capabilities/external-recon-pretext.md、references/capabilities/evasion-and-opsec.md、references/capabilities/credential-extraction.md |
| 拿到 krbtgt hash 或服务账户 hash，需要决定造金票还是银票。；发现域内有非约束/约束委派配置，需要判断能不能利用、怎么利用。；对某台机器有写权限，需要判断能否用 RBCD 打通。 | references/capabilities/kerberos-ticket-abuse.md | references/capabilities/credential-extraction.md、references/capabilities/lateral-execution-channels.md、references/capabilities/ntlm-relay-coercion.md、references/capabilities/endpoint-persistence.md |
| 有管理员凭据，需要决定用 WMI / PsExec / WinRM / 计划任务中的哪一个。；只需要跑一条命令，不确定该不该派生会话。；PsExec 报「拒绝访问」但共享明明是开的，需要定位原因。 | references/capabilities/lateral-execution-channels.md | references/capabilities/ntlm-relay-coercion.md、references/capabilities/c2-tunnel-infrastructure.md、references/capabilities/domain-recon-path.md、references/capabilities/password-attack-reuse.md |
| Responder 抓到了 hash 但没有会话，需要判断断在哪一段。；想用 NTLM 中继但不确定目标签名情况与落点。；有一个「能让目标访问 URL」的原语（数据库、XXE、LFI），需要判断能否转成凭据窃取。 | references/capabilities/ntlm-relay-coercion.md | references/capabilities/credential-extraction.md、references/capabilities/lateral-execution-channels.md、references/capabilities/domain-recon-path.md |
| 手上有一批用户名但没有口令，需要在不知锁定策略下试探。；发现多台主机密码「看起来有规律」，需要判断能否外推。；已有几组凭据，需要决定「继续挖漏洞还是先横向滚一轮」。 | references/capabilities/password-attack-reuse.md | references/capabilities/credential-extraction.md、references/capabilities/domain-recon-path.md、references/capabilities/lateral-execution-channels.md |
| 拿到一个普通用户 shell，不知道从哪类路径开始。；手上有多个候选 EXP，需要判断哪个风险最低、最可能成功。；SQL 注入只有 db_owner，需要判断能不能提到 sysadmin 或直接执行命令。 | references/capabilities/windows-db-privesc.md | references/capabilities/credential-extraction.md、references/capabilities/lateral-execution-channels.md、references/capabilities/domain-recon-path.md |
| 遇到「红队怎么打内网」时，查本域 OCR 增补材料中的对应方法与判据；遇到「蓝队攻击流程」时，查本域 OCR 增补材料中的对应方法与判据；遇到「攻防演练攻击方分几步」时，查本域 OCR 增补材料中的对应方法与判据 | references/capabilities/ocr-framework-judgement.md | references/capabilities/c2-tunnel-infrastructure.md、references/capabilities/credential-extraction.md |
| 遇到「供应链攻击怎么做」时，查本域 OCR 增补材料中的对应方法与判据；遇到「驻场人员怎么打」时，查本域 OCR 增补材料中的对应方法与判据；遇到「软件升级包篡改」时，查本域 OCR 增补材料中的对应方法与判据 | references/capabilities/ocr-recipe-troubleshooting.md | references/capabilities/c2-tunnel-infrastructure.md、references/capabilities/credential-extraction.md |
| 遇到「攻防演练规则」时，查本域 OCR 增补材料中的对应方法与判据；遇到「哪些攻击不允许」时，查本域 OCR 增补材料中的对应方法与判据；遇到「演习红线」时，查本域 OCR 增补材料中的对应方法与判据 | references/capabilities/ocr-counter-example.md | references/capabilities/c2-tunnel-infrastructure.md、references/capabilities/credential-extraction.md |

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

- 目标范围或演练规则不明确时停止
- 操作可能导致域内服务中断（如改 GPO、批量重置）时停止并改方案
- 发现已触发目标告警且演练要求隐蔽时停止当前路径
