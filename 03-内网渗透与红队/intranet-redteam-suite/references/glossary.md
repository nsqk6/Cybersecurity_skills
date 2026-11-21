# 内网渗透与红队 — 术语与能力速查

## 能力速查（每条含义取自对应能力卡的 I 段）

| 术语 / 能力 | 英文或 slug | 在本域语境下的含义 |
|---|---|---|
| C2 出网通道与隧道基础设施 | `c2-tunnel-infrastructure` | 这个能力解决的是「打进去了、但会话不上线」这一类最消耗时间的问题 |
| 凭据取用：从配置、内存到目录复制 | `credential-extraction` | 这个能力解决的是「拿到一台机器后，怎么把凭据从『存在但看不见』变成『可复用的认证材料』」，以及一个更重要的判断： 我拿到的这个值，到底能用来干什么 |
| 域内侦察与突破路径定位 | `domain-recon-path` | 这个能力解决的是「刚打进内网、只有一两台机器时，用什么顺序把『值不值得冒险』问清楚」 |
| 端点持久化与入口冗余 | `endpoint-persistence` | 这个能力解决的是「怎么保证明天还能进来」，但它真正的判断点不在「用什么手法」，而在 先分清要维持的是哪一种「在」 |
| 载荷免杀与行动 OPSEC | `evasion-and-opsec` | 这个能力解决的是「怎么让对手看不见我」，但它不是一种技术，而是 三层互不替代的隐蔽 |
| 外部情报与社工接近设计 | `external-recon-pretext` | 这个能力解决的是「面对一个几乎一无所知的组织，怎么在不动手之前就把入口想清楚」：包括查什么、查到的东西算不算数、最后用什么身份站到对方面前 |
| 外部打点：投递、接口面与多因素绕过 | `initial-access-delivery` | 这个能力解决的是「外部第一个口子从哪来」，以及更关键的： 当最直接的那条投递路径被静默拦掉时，怎么判断被拦、往哪降级 |
| Kerberos 票据伪造与委派滥用 | `kerberos-ticket-abuse` | 这个能力解决的是「拿到某类 hash 之后，怎么把它变成一张能用来访问资源的票」，以及在三条路（借合法机制、伪造票、跨信任越界）之间怎么选 |
| 横向执行通道选择 | `lateral-execution-channels` | 这个能力解决的是「手上有了管理员口令或 hash、目标机器就在那里，我用什么方式把命令送过去」 |
| NTLM 带外窃取与中继 | `ntlm-relay-coercion` | 这个能力解决的是「不破解、不猜口令，直接借用别人的一次认证过程来拿权限」 |
| 口令攻击与复用滚雪球 | `password-attack-reuse` | 这个能力解决的是「在没有漏洞可打的情况下，怎么靠口令本身把权限面扩开」，核心是三件事： 节奏、规则、复用 |
| Windows 与数据库提权路径 | `windows-db-privesc` | 这个能力解决的是「拿到一个普通用户 shell（或一个只有 db_owner 的数据库账号）之后，怎么在十分钟内找对提权路径，而不是挨个试 EXP」 |

## 卡片中出现的英文术语

- `Reading`（见对应能力卡上下文）
- `Interpretation`（见对应能力卡上下文）
- `Application Example`（见对应能力卡上下文）
- `wmic/schtasks/xp_cmdshell`（见对应能力卡上下文）
- `Future Trigger`（见对应能力卡上下文）
- `C2 over tunnel`（见对应能力卡上下文）
- `Execution`（见对应能力卡上下文）
- `Boundary`（见对应能力卡上下文）
- `AWS/GCP`（见对应能力卡上下文）
- `DPAPI`（见对应能力卡上下文）
- `lsass`（见对应能力卡上下文）
- `DCSync`（见对应能力卡上下文）
- `VSS/ntdsutil`（见对应能力卡上下文）
- `Pass-the-Hash`（见对应能力卡上下文）
- `response`（见对应能力卡上下文）
- `Linux / Windows 2003`（见对应能力卡上下文）
- `DCSync vs VSS`（见对应能力卡上下文）
- `RunAsPPL`（见对应能力卡上下文）
- `FIDO2`（见对应能力卡上下文）
- `LocalSystem/NetworkService`（见对应能力卡上下文）
- `Hybrid Azure AD Join`（见对应能力卡上下文）
- `Command/Nightly/Oobe/Maintenance`（见对应能力卡上下文）
- `AppLocker/WDAC`（见对应能力卡上下文）
- `Win11`（见对应能力卡上下文）
- `PII/HIPAA/PCI`（见对应能力卡上下文）
- `the objective`（见对应能力卡上下文）
- `tieback`（见对应能力卡上下文）
- `Recon`（见对应能力卡上下文）
- `Pretext`（见对应能力卡上下文）
- `Disregard`（见对应能力卡上下文）

> 术语释义以能力卡正文为准；本表只做索引，不另作解释。
