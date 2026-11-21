# 云原生与容器安全 · 域总览

## 这个域在真实工作中解决什么问题

这个域回答的是"容器和云上这套东西到底安不安全、出了问题怎么查、拿到入口后能走到哪一步"。它覆盖两条相互咬合的线：一条是 Docker/容器侧——评估隔离够不够、收敛 daemon 与网络暴露、识别提权面、把镜像与 CI/CD 供应链守住、跑基线与漏洞扫描、事件后固化现场；另一条是云侧——上云后先划清攻击面与责任归属，再处理最高频的 AK/SK 与对象存储攻防、OpenStack 平台横向、日志与取证可见性。两条线通过"SSRF 读实例元数据""特权容器逃逸""云凭据 vs 节点配置凭据"等交叉点联动，不能只做一条。

域的核心判断习惯是：**先分层定范围，再选专项能力**。容器侧按"内核隔离 / daemon 自身 / 外部加固"三层，云侧按"租户 vs 平台"两条攻击面与 IaaS/PaaS/SaaS 责任边界。范围划错，后面的工具与利用都会打偏目标。

## 能力地图（二级分类 → 能力）

| 二级分类 | 能力（slug · 中文标题） | promotion |
|---|---|---|
| 利用与提权 | `container-isolation-boundary-assessment` · 容器隔离边界评估 | promoted |
| 利用与提权 | `container-privilege-surface-hardening` · 容器提权面识别与运行时加固 | router |
| 利用与提权 | `container-escape-path-assessment` · 容器逃逸路径判定与蜜罐误判 | router |
| 服务端逻辑 | `docker-daemon-api-exposure` · Docker daemon/API 暴露面收敛 | promoted |
| 服务端逻辑 | `container-network-exposure` · 容器网络暴露面收敛 | router |
| 工程化 | `image-build-supply-chain` · 镜像与 CI/CD 软件供应链安全 | promoted |
| 工具链 | `container-security-tooling` · 容器安全基线与漏洞扫描工具链 | router |
| 侦察 | `cloud-attack-surface-and-responsibility` · 云上攻击面与责任边界判定 | router |
| 身份认证 | `cloud-credential-and-storage-attack` · 云凭证与对象存储攻击面攻防 | promoted |
| 取证与溯源 | `container-incident-forensics` · 容器与云取证、日志可见性盲区 | router |
| 横向移动 | `cloud-platform-lateral-movement` · 云平台后渗透横向与配置收集 | router |

共 11 个能力，覆盖 8 个二级分类；必选四类（利用与提权、服务端逻辑、工具链、工程化）全部覆盖。promoted 4 个（上限 4）：容器隔离边界评估、daemon/API 暴露面、镜像与 CI/CD 供应链、云凭证与对象存储攻击面——分别对外暴露"容器防御 / 容器控制面 / 工程供应链 / 云身份"四个独立入口，其余 7 个作为 router 由 promoted 卡路由。

## 域的共性失败模式

1. **以偏概全判安全**：看到"namespace 开了""内存限制配了""CIS 检查没报 ERROR"就下"已隔离/已合规"结论，漏掉 daemon 层、加固层或具体 WARN（《docker_practice》11 章、《Docker技术入门与实战》19.6）。
2. **把资源配额当访问控制**：cgroup 只防 DoS 不裁决访问，多租户只配限额不配 capabilities，任一容器可读他人数据（19.2）。
3. **为图方便放弃边界后不复原**：`--privileged`、`--net=host`、把 `-p` 绑到 `0.0.0.0`、把用户加进 docker 组、照抄集群教程开 `0.0.0.0:2375`——解决连通性/排障问题后长期留在生产。
4. **只看运行态不看参数/层**：容器里 `ls` 看不到敏感文件就判干净（下层仍在，`docker save` 可取回）；只看容器内行为不看 `-v` 启动参数（挂载通道逃逸）；只看 Dockerfile 的 `EXPOSE` 就判端口已发布。
5. **用单一表象下结论**：见 AK 就当主账号、见前端有密钥就判漏洞、见 Alpine 内核就判蜜罐、见"临时密钥"就判安全——都不做第二步复核（IAM 粒度 / 权限配置 / `mount`/`df` 实证 / 最小权限核对）。
6. **只打一头漏另一头**：只按传统 Web 渗透漏掉 AK/OSS/元数据；只盯云特性漏掉 Shiro/Fastjson；只扫控制台漏掉 API 未授权；镜像、PipeLine、依赖三段只做一段就宣称供应链安全。
7. **拿到单点就停 / 证据先删后取**：云节点 root 后不翻计划任务脚本（凭据就藏在那里）；容器被 `docker rm` 后才想起取证（存储层已随容器销毁）；只 commit 不另存元数据（上下文无法补采）。
8. **以为"有权限就能查一切/日志有就能用"**：IaaS 下网络快照与内存镜像要 CSP 支持；云日志缺时区、动态资源未接入、可被清除时，日志不可直接当证据（指南 D9、D13）。

## 覆盖说明：哪些书贡献了哪些能力

| 来源书 | 贡献的能力 | 主要单元 |
|---|---|---|
| 《docker_practice》 | 容器隔离边界评估、daemon/API 暴露面、容器网络暴露面、镜像与 CI/CD 供应链、容器与云取证 | CU-1-01/02/06/07/08/11/12/13/17/20 等；三层评估框架、docker 组、分层存储、commit 保存现场 |
| 《Docker技术入门与实战_第3版》 | 容器隔离边界评估、提权面加固、daemon 暴露面、网络暴露面、镜像供应链、工具链 | CU-1-02~19、21/22；namespace/cgroup/能力机制、daemon 防护、端口映射、Docker Bench、clair、多阶段构建 |
| 《云安全攻防入门》 | 云攻击面与责任边界、云凭证与对象存储攻防、容器逃逸路径、镜像与 CI/CD 供应链（CI/CD 段）、容器与云取证（日志留痕）、云平台横向 | CU-2-01/03~15/16~22；AK 泄露利用链、SSRF 元数据、OpenStack 场景、容器识别与逃逸、PPE 与依赖混淆 |
| 《云计算安全指南v3.0》 | 云攻击面与责任边界、容器与云取证、虚拟化盲区 | CU-2-02/11/12/13/23/24；IaaS/PaaS/SaaS 责任与取证可见性、日志质量三信号、背板流量与防护间隙 |

两批候选共 46 个单元，全部 verified 并映射到 11 张能力卡，无遗漏、无孤儿。batch-1（22 单元）构成容器侧主体，batch-2（24 单元）补入云攻防与虚拟化主题，其中容器逃逸单元（CU-2-16~20）独立成卡、CI/CD 投毒单元（CU-2-21/22）并入供应链卡、日志与盲区单元（CU-2-11/12/13/23/24）并入取证卡。
