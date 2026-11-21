---
name: web-security-suite
description: |
  Web 应用漏洞挖掘与代码审计的完整能力包。当用户要对一个 Web 站点/接口做安全测试、判断某个输入点能不能注入、分析 XSS/SSRF/CSRF/文件上传/反序列化/越权等漏洞是否存在、要从源码里追危险数据流、或要把一个可疑现象验证成可复现的漏洞时使用。覆盖：攻击面枚举、注入通道选择、客户端与服务端注入、身份认证与访问控制缺陷、业务逻辑漏洞、中间件与框架特定漏洞、WAF 绕过、代码审计、报告与影响定级。不适用于：纯网络层扫描、内网横向、二进制逆向（分别走 intranet-redteam-suite / reverse-binary-suite）。
metadata:
  cangjie.generated-by: cangjie-tools v2.5.0
  cangjie.variant: single
  cangjie.bundle-id: bundle.web-security-suite
  cangjie.capability-count: 16
  cangjie.entrypoint-count: 1
---
# Web安全与代码审计 — 全书能力入口

## 触发与不触发

**适用**：与本书能力域相关的咨询与任务（见下方路由表的意图列）。
**不适用**：
- 未授权的真实目标攻击（本包只提供方法，不代替授权）
- 二进制层面的漏洞挖掘与利用开发
- 内网横向移动与域渗透

## 核心原则（常驻速览，概览类问题读到这里即可回答）

1. 先画攻击面再谈漏洞：不清楚有哪些入口、参数、角色时不下结论
2. 每个漏洞必须有可复现的验证链，不能只凭响应差异猜
3. 区分设计缺陷与实现 bug：前者改代码修不掉，影响定级更高
4. 同一注入点要选对提取通道，通道选错会得出「无漏洞」的错误结论
5. 审计按数据流追，不按文件顺序读；先找 sink 再回溯来源

## 能力路由（先读本表，按意图加载 1 张能力卡）

| 用户意图 | 先读 | 补读/备注 |
|---|---|---|
| 刚拿到一个新目标，需要确定从哪开始、先测什么；扫描器结果里全是噪音，需要判断哪些资产与入口是真的；需要给甲方出一份攻击面清单与测试排期 | references/capabilities/recon-asset-surface.md | references/capabilities/source-code-audit.md、references/capabilities/access-control-idor.md、references/capabilities/waf-bypass-encoding.md |
| 判断一个参数是真注入还是输入校验在报错；无回显时决定该走布尔、条件错误、时间延迟还是带外；排序/列名参数「怎么测都没反应」，需要结构型判据；后端是 MongoDB，SQL payload 全部失效 | references/capabilities/injection-channel-selection.md | references/capabilities/command-file-injection.md、references/capabilities/waf-bypass-encoding.md、references/capabilities/source-code-audit.md |
| 疑似调用外部命令但页面不回显，需要确认；文件包含能否从读文件升级到 RCE；上传只允许图片，想知道图片马怎么被执行；Redis/数据库未授权，能写哪、写完怎么执行 | references/capabilities/command-file-injection.md | references/capabilities/injection-channel-selection.md、references/capabilities/server-request-injection.md、references/capabilities/deserialization-rce.md |
| 参数里能带 URL，想打内网或云元数据；XML 请求体，想验证能否读文件；有发信/邀请功能，想验证邮件头注入；有跳转参数，判断是开放重定向还是无害；输入出现在页面/邮件里，想验证模板注入 | references/capabilities/server-request-injection.md | references/capabilities/command-file-injection.md、references/capabilities/waf-bypass-encoding.md、references/capabilities/csrf-ui-redress.md |
| 提交了 payload 但没弹窗，需要判断卡在哪一步；SPA 页面源码为空，怀疑 DOM 型 XSS；个人资料/工单/日志，想找存储型；只有 POST 接口能触发，不知道还能不能利用；上传头像，想知道能否让其他用户浏览器执行 | references/capabilities/xss-context-runtime.md | references/capabilities/csrf-ui-redress.md、references/capabilities/waf-bypass-encoding.md、references/capabilities/server-request-injection.md |
| 改密码/转账请求只带 cookie，想知道能否伪造；有 token，需要判断它到底有没有用；多步确认页看起来有防护，想验证能否跳过；页面能被 iframe，想知道点击劫持是否可行 | references/capabilities/csrf-ui-redress.md | references/capabilities/xss-context-runtime.md、references/capabilities/access-control-idor.md、references/capabilities/auth-session-bypass.md |
| 登录框疑似可绕过，不知从哪一侧入手；有锁定/限速，想判断能否重置计数；验证码看起来能绕过，需要区分 OCR 与服务端约束缺失；找回密码流程可疑，想判断是改收件人还是猜 token；JWT/OAuth 实现可疑，想验证签名与回调校验 | references/capabilities/auth-session-bypass.md | references/capabilities/access-control-idor.md、references/capabilities/business-logic-flaws.md、references/capabilities/csrf-ui-redress.md |
| URL 里有 id/uid，想知道改成别人的会怎样；后台进不去，判断是真鉴权还是只是藏起来；多步流程想验证每一步是否都做了鉴权；同一功能有 Web/App/API 多套入口，怀疑某套漏了 | references/capabilities/access-control-idor.md | references/capabilities/auth-session-bypass.md、references/capabilities/business-logic-flaws.md、references/capabilities/recon-asset-surface.md |
| 业务流程感觉不对，想知道能否跳过支付/审批；下单/领券/退款涉及金额与配额，想试改值或重复；判断一个现象是逻辑漏洞还是配置问题；扫描器没报，但直觉认为业务上能薅 | references/capabilities/business-logic-flaws.md | references/capabilities/access-control-idor.md、references/capabilities/auth-session-bypass.md、references/capabilities/finding-to-report.md |
| Cookie/参数像序列化数据，想知道能否打；目标是 Shiro/Fastjson/WebLogic/RMI/JNDI，需要选链；确认有反序列化点但目标不出网；URLDNS 成功但真实 gadget 打不动 | references/capabilities/deserialization-rce.md | references/capabilities/command-file-injection.md、references/capabilities/waf-bypass-encoding.md、references/capabilities/server-request-injection.md |
| payload 一发就被拦，不知道是谁拦的；编码/注释都试过，需要判断是不是原理不成立；sqlmap 全红，想换 tamper/分块/手注；想知道目标前是什么设备；拿到 shell 但 disable_functions 禁了命令 | references/capabilities/waf-bypass-encoding.md | references/capabilities/injection-channel-selection.md、references/capabilities/xss-context-runtime.md、references/capabilities/deserialization-rce.md |
| 拿到一套源码，不知道从哪看起；只有一个登录框，需要从代码找突破口；判断「这套 CMS 有没有洞」；代码里到处是转义函数，判断哪里仍可注入；权限系统很复杂，想找低权限 getshell 的点 | references/capabilities/source-code-audit.md | references/capabilities/recon-asset-surface.md、references/capabilities/injection-channel-selection.md、references/capabilities/finding-to-report.md |
| 一批参数/端点需要批量筛；扫描器结果需要判断真假；报告被打回「无法复现」；提交前想知道会不会被判 N/A；低危洞要不要报、怎么串 | references/capabilities/finding-to-report.md | references/capabilities/recon-asset-surface.md、references/capabilities/business-logic-flaws.md、references/capabilities/source-code-audit.md |
| 遇到「这个 PHP 站点怎么快速找漏洞」时，查本域 OCR 增补材料中的对应方法与判据；遇到「按危险函数反查输入」时，查本域 OCR 增补材料中的对应方法与判据；遇到「逆向追踪审计」时，查本域 OCR 增补材料中的对应方法与判据 | references/capabilities/ocr-framework-judgement.md | references/capabilities/recon-asset-surface.md、references/capabilities/injection-channel-selection.md |
| 遇到「审计环境怎么搭」时，查本域 OCR 增补材料中的对应方法与判据；遇到「不同 PHP 版本切换」时，查本域 OCR 增补材料中的对应方法与判据；遇到「这个漏洞在我环境复现不了」时，查本域 OCR 增补材料中的对应方法与判据 | references/capabilities/ocr-recipe-troubleshooting.md | references/capabilities/recon-asset-surface.md、references/capabilities/injection-channel-selection.md |
| 遇到「PDO prepare 还能注入吗」时，查本域 OCR 增补材料中的对应方法与判据；遇到「PHP 5.3 宽字节」时，查本域 OCR 增补材料中的对应方法与判据；遇到「ATTR_EMULATE_PREPARES 是什么」时，查本域 OCR 增补材料中的对应方法与判据 | references/capabilities/ocr-counter-example.md | references/capabilities/recon-asset-surface.md、references/capabilities/injection-channel-selection.md |

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

- 目标范围未明确时停止，先确认测试边界
- 验证动作可能造成数据破坏或服务中断时停止，改用只读验证
- 连续三次同类型验证失败且无新线索时停止，回到攻击面重排优先级
