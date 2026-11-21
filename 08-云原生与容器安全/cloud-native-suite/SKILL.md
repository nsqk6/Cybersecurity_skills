---
name: cloud-native-suite
description: |
  云原生与容器安全的能力包。当用户要评估 Docker/Kubernetes 环境的安全性、要判断容器逃逸是否可行、要审计镜像与编排配置、要查云上身份与元数据服务的滥用路径、或要设计云环境的分层防护时使用。覆盖：容器侦察、镜像与运行时安全、逃逸路径判定、K8s 控制面与 RBAC 审计、云元数据与凭证链、云上日志与检测、云安全架构。不适用于：传统 Web 漏洞（走 web-security-suite）、主机应急响应细节（走 blue-team-ir-suite）。
metadata:
  cangjie.generated-by: cangjie-tools v2.5.0
  cangjie.variant: single
  cangjie.bundle-id: bundle.cloud-native-suite
  cangjie.capability-count: 11
  cangjie.entrypoint-count: 1
---
# 云原生与容器安全 — 全书能力入口

## 触发与不触发

**适用**：与本书能力域相关的咨询与任务（见下方路由表的意图列）。
**不适用**：
- 对未授权云账号的访问
- K8s 集群的破坏性测试
- 物理机房安全

## 核心原则（常驻速览，概览类问题读到这里即可回答）

1. 先分清责任边界：哪一层是云厂商的，哪一层是租户的
2. 容器不是虚拟机，隔离强度决定逃逸可行性
3. 云上身份即权限，凭证链比漏洞更常被利用
4. 配置错误是云环境的主要风险来源，优先查配置再查漏洞
5. 一切结论绑定具体的运行时与版本

## 能力路由（先读本表，按意图加载 1 张能力卡）

| 用户意图 | 先读 | 补读/备注 |
|---|---|---|
| 评估一套容器环境的整体安全性与隔离是否够用；判断能否用容器跑不可信代码或多租户负载；复核"开了 namespace/配了限额"这类以偏概全的安全结论 | references/capabilities/container-isolation-boundary-assessment.md | references/capabilities/container-privilege-surface-hardening.md、references/capabilities/container-escape-path-assessment.md、references/capabilities/container-security-tooling.md、references/capabilities/container-network-exposure.md、references/capabilities/image-build-supply-chain.md、references/capabilities/cloud-attack-surface-and-responsibility.md |
| 识别容器是否已被过度授权、是否等价宿主 root；为排障引入的 privileged/cap-add 找精确替代并收敛；对容器做运行时最小加固（只读、非 root、禁 shell、SSH 收敛） | references/capabilities/container-privilege-surface-hardening.md | references/capabilities/container-isolation-boundary-assessment.md、references/capabilities/container-escape-path-assessment.md、references/capabilities/container-network-exposure.md、references/capabilities/docker-daemon-api-exposure.md |
| 拿到 Shell 后判断环境是否为容器；判定当前弱点属于哪类逃逸路径并核对触发条件；对蜜罐怀疑做实证复核而非盲从放弃 | references/capabilities/container-escape-path-assessment.md | references/capabilities/container-privilege-surface-hardening.md、references/capabilities/container-isolation-boundary-assessment.md、references/capabilities/cloud-platform-lateral-movement.md |
| 收敛 daemon 的监听通道与 TLS 配置；划定谁能控制 Docker 引擎（socket / docker 组 / 上层系统服务账号） | references/capabilities/docker-daemon-api-exposure.md | references/capabilities/container-isolation-boundary-assessment.md、references/capabilities/container-privilege-surface-hardening.md、references/capabilities/container-security-tooling.md、references/capabilities/cloud-credential-and-storage-attack.md |
| 判断容器端口的实际对外暴露范围（-p/EXPOSE/-P 的区别）；收敛容器间横向访问（--icc=false + --link / 自定义网络）；评估 --net=host 放弃网络边界的信任后果 | references/capabilities/container-network-exposure.md | references/capabilities/container-privilege-surface-hardening.md、references/capabilities/docker-daemon-api-exposure.md、references/capabilities/container-isolation-boundary-assessment.md、references/capabilities/cloud-credential-and-storage-attack.md |
| 排查镜像层残留的敏感数据与 commit 黑箱交付链；用多阶段构建与 .dockerignore 在构建时不产生残留；验证镜像来源并收敛 insecure-registry 的适用前提；判定 CI/CD 管道中毒执行（PPE）与依赖混淆投毒 | references/capabilities/image-build-supply-chain.md | references/capabilities/container-security-tooling.md、references/capabilities/container-incident-forensics.md、references/capabilities/container-isolation-boundary-assessment.md、references/capabilities/cloud-credential-and-storage-attack.md |
| 用 Docker Bench 跑主机侧 CIS 配置基线并处置 WARN；用 clair 对镜像层做静态漏洞扫描并归因到包版本；区分配置合规/镜像漏洞/敏感数据三类检查 | references/capabilities/container-security-tooling.md | references/capabilities/container-isolation-boundary-assessment.md、references/capabilities/image-build-supply-chain.md、references/capabilities/docker-daemon-api-exposure.md、references/capabilities/container-incident-forensics.md |
| 判断上云后渗透范围，列租户侧传统+云特性与平台侧架构模块两条攻击面；按服务模型判定配置错误或事件的归属方与下一步动作；为具体测试选择路由（凭据/对象存储/容器逃逸/平台横向/取证） | references/capabilities/cloud-attack-surface-and-responsibility.md | references/capabilities/cloud-credential-and-storage-attack.md、references/capabilities/cloud-platform-lateral-movement.md、references/capabilities/container-incident-forensics.md、references/capabilities/container-isolation-boundary-assessment.md |
| 按泄露面清单搜集 AK/SK 并判定账号类型与权限价值；用云助手命令链或 SSRF+元数据链把凭据转成实例/角色控制；判对象存储五类入口、桶 ACL 与前端直传凭据是否安全；用 RAM 最小权限与轮换吊销止血 | references/capabilities/cloud-credential-and-storage-attack.md | references/capabilities/cloud-attack-surface-and-responsibility.md、references/capabilities/container-escape-path-assessment.md、references/capabilities/container-network-exposure.md、references/capabilities/cloud-platform-lateral-movement.md、references/capabilities/container-incident-forensics.md |
| 在容器被删除或清痕前冻结可写层为证据副本并离线分析；按服务模型划定取证可见范围并约定 CSP 支持；核对日志三信号、处置背板流量与冷启动防护间隙盲区 | references/capabilities/container-incident-forensics.md | references/capabilities/image-build-supply-chain.md、references/capabilities/container-isolation-boundary-assessment.md、references/capabilities/container-security-tooling.md、references/capabilities/cloud-attack-surface-and-responsibility.md |
| 判定 OpenStack 初始场景与五类网络暴露面；验证虚机到管理网段的可达性，避免逻辑隔离误判；从计划任务与运维脚本提取硬编码凭据，横向放大到整朵云 | references/capabilities/cloud-platform-lateral-movement.md | references/capabilities/cloud-attack-surface-and-responsibility.md、references/capabilities/cloud-credential-and-storage-attack.md、references/capabilities/container-escape-path-assessment.md、references/capabilities/container-incident-forensics.md |

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

- 测试可能影响其他租户或生产工作负载时停止
- 涉及云账号凭证的操作先确认授权范围
- 逃逸验证只在自建隔离环境进行
