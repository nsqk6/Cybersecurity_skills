# 云原生与容器安全 · 术语表

只收"读能力卡时会卡住"的域内术语，不收通用词。按能力域分组排列。

| 术语 | 英文 | 在本域语境下的含义 |
|---|---|---|
| 命名空间隔离 | namespace | 容器隔离原语之一，隔离的是"视图"（进程/网络/挂载等看见什么），所有容器共用同一内核，系统调用面完全暴露，非硬件级安全沙箱；user namespace 未启用时容器 root ≈ 宿主 root 候选 |
| 控制组 | cgroup | 隔离原语之一，只做资源用量配额与计费（CPU/内存/pids/blkio），防 DoS 但完全不裁决访问，不能据此得出"权限被限制"结论 |
| 能力位 | capability | 把 root 单一特权切成若干位，Docker 默认走白名单；`CAP_SYS_ADMIN`/`CAP_SYS_MODULE`/`CAP_DAC_READ_SEARCH`/`CAP_MKNOD` 任一持有即视为有逃逸原语；`--cap-add` 是逐位追加，无理由追加应收回 |
| CapEff | CapEff | `/proc/self/status` 中实际生效的能力位图；特权容器典型值为 `0000003fffffffff`（攻击侧判据见容器逃逸卡） |
| privileged | privileged mode | `--privileged` 不是"多给一点权限"，而是整包放弃能力白名单、放开设备访问与挂载，容器内 root 直接持宿主硬件与内核接口 |
| bind mount | bind mount | `-v` 把宿主路径挂进容器；宿主根/`/etc`/docker.sock 等可写挂载会让容器等价宿主 root，判据须放在参数准入层 |
| docker.sock / docker 组 | Docker socket / docker group | `/var/run/docker.sock`，daemon 的 Unix socket；连接语义，挂 `:ro` 仍能连接控制 daemon；docker 组成员即特权主体，加入等于获得宿主 root 等价权限 |
| REST API（daemon） | Docker Remote API | daemon 以 root 创建任意容器的远程过程调用；`2375`（明文）/ `2376`（TLS），无认证 TCP 监听即整机沦陷最短路径 |
| `--net=host` | host network | 放弃网络命名空间，端口空间与宿主合并、可直连仅绑 127.0.0.1 的管理服务；是继承宿主全部本地信任，不是连通性补丁 |
| `EXPOSE` vs `-p` | EXPOSE vs publish | `EXPOSE` 只声明意图、参与 `-P` 随机映射，本身不发布端口；`-p IP:Host:Container` 省略 IP 即绑 `0.0.0.0` 全网可达 |
| 分层存储 | layer / union FS | 镜像层只读叠加，删除只在当前层加 whiteout 标记（标记删除，不是真删除），旧层内容仍随镜像分发——`docker save` 逐层解包可取回"已删除"文件 |
| `docker commit` | commit | 把容器当前可写层拍成镜像；交付场景是黑箱禁令（不可复现/层膨胀），取证场景是固化现场的正当用法——判据是用途 |
| 多阶段构建 | multi-stage build | 把编译工具链留在 build stage，只 `COPY --from` 产物到干净 runtime stage，使运行镜像不含编译器/源码/缓存/构建凭证 |
| `.dockerignore` | dockerignore | 阻止敏感文件（`.ssh`/token/`.git`）进入构建上下文；缺失时构建上下文整体发送给 daemon |
| content trust / 签名 | image signing | 验证"拉到的 digest 是不是发布者签的那个"；仓库地址与 `latest` 标签都不提供完整性，标签可被重新指向（虚悬镜像） |
| insecure-registry | insecure registry | 让指定仓库地址免于 TLS 证书校验；关的是传输完整性，与镜像签名（发布者身份）不是一回事，正当性建立在"仅受控网段可达"前提上 |
| Docker Bench | Docker Bench for Security | 按 CIS 规范做主机侧配置基线自查，输出六维分级（INFO/NOTE/WARN）；价值在摊开偏差而非打分；本身需高权限挂载，不可长期驻留 |
| clair | clair | 对镜像层做静态漏洞扫描，把层内包版本与漏洞库比对，产出按层归因的 CVE 清单；查"已知漏洞"而非配置或敏感数据 |
| AK/SK | AccessKey / SecretKey | 云 API 身份凭据；利用价值取决于背后 IAM/RAM 策略粒度，不是 AK 本身，主账号全权限、子用户可能只能读某桶 |
| IAM / RAM | IAM / RAM | 云身份与权限管理（AWS 称 IAM、阿里称 RAM）；判据是"先判权限、再定打法"，最小权限是止血核心 |
| STS 临时密钥 | STS | 有时效的临时凭据（默认 1800 秒，可到 2h/36h）；前端/小程序 AK/SK 配 STS 会带 Token，过期后读不到桶信息，需转抓 STS 签发点 |
| 实例元数据 / IMDSv2 | instance metadata / IMDSv2 | 实例内网可达的特殊 Web 服务（169.254 端点），含 IP/region/vpc-id 与角色名；经 SSRF 读 `cam/security-credentials/{role}` 可拿角色临时凭证；IMDSv2 强制 token 时简单 SSRF 链不通 |
| 云助手命令 | cloud assistant command | 云 API 自带在目标 ECS 执行运维命令的能力：`DescribeInstances` → `CreateCommand`（Base64 ≤16KB）→ `InvokeCommand`，把 AK 转成实例代码执行 |
| 对象存储 | OSS / COS / S3 / OBS | 各厂商叫法不同但机制相通；攻击面按五类初始访问（主密钥/SDK/工具配置/前端直传/账号登录）盘，可达性由凭据权限+桶 ACL 共同决定 |
| 前端直传 | frontend direct upload | 前端 SDK 直传对象存储；安全判据是"临时密钥(STS) + 最小权限"，不是"有没有直传功能"；永久密钥或权限配错即可被抓凭据越权 |
| PPE | Poisoned Pipeline Execution | 中毒管道执行：能改代码仓库但进不了构建环境，通过注入 CI 配置文件操纵构建；分 D-PPE/I-PPE/P-PPE 三型，判据是"配置文件在哪、能改哪些" |
| 依赖混淆 | dependency confusion / typosquatting | 用高度相似包名（request vs requests）诱骗拉取恶意包，安装脚本"拉取后立即执行"；对策是代理审查+校验和+锁定版本 |
| 共享责任模型 | shared responsibility model | 按"控制可见性"切责任：IaaS 云商管 Hypervisor 及以下、用户管 OS/应用/数据；SaaS 几乎全归云商；判据是"配错的层配置权在谁手里" |
| 取证可见性 | forensics visibility | 按服务模型判"证据在哪层、谁控制"：IaaS 可查 VM 内，但网络流量/内存快照/磁盘镜像需 CSP 支持，须在 SLA 中预先约定 |
| 日志三信号 | log quality signals | 判日志能否用于分析：①时钟同步+时区标记；②新增资源日志自动接入；③日志防篡改（只读存储/服务器分离） |
| 硬件背板流量 | backplane traffic | 同一物理机上 VM 间不经网络层的通信，传统网络 IDS/防火墙看不见；须用 Hypervisor API 内嵌虚拟设备补监控 |
| 防护间隙 | Instant-On Gap | VM 关机期间威胁演化，冷启动时镜像可能已过时；须在启动路径前置虚拟补丁/NAC 隔离，更新规则库并扫描后再放行 |
| `.dockerenv` / cgroup 识别 | container detection | 判断 Shell 是否在容器内的证据：`.dockerenv` 文件、`/proc/1/cgroup` 含 docker、`ps` 进程异常少且无 init/systemd；须三证交叉，不能凭 Alpine 内核判蜜罐 |
| containerd-shim | containerd-shim | 特定 containerd 版本 + host 网络模式下其 API 暴露（CVE-2020-15257），`cat /proc/net/unix | grep containerd-shim` 可见 socket 即命中前提 |
| 翻配置（横向） | config harvesting | 云节点 getshell 后从计划任务/运维脚本/环境变量/keystone.conf 提取硬编码节点凭据，把单点放大到整朵云；政务云案例中 294 节点凭据藏在计划任务脚本里 |
