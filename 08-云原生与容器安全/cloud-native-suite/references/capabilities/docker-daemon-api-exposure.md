# Docker daemon/API 暴露面收敛

## R — 原文 (Reading)

> 为了加强对服务端的保护，Docker 的 REST API（客户端用来与服务端通信的接口）在 0.5.2 之后使用本地的 Unix 套接字机制替代了原先绑定在 127.0.0.1 上的 TCP 套接字，因为后者容易遭受跨站脚本攻击。

> — 《Docker技术入门与实战_第3版》第 19 章 19.4 Docker 服务端的防护

> Exposing daemon on TCP without TLS helps legacy clients connect to the daemon. It also makes yourself vulnerable to remote code execution attacks. Use with caution.

> — 《Docker技术入门与实战_第3版》第 2 章 Windows 客户端设置页

> 默认情况下，docker 命令会使用 Unix socket 与 Docker 引擎通讯。而只有 root 用户和 docker 组的用户才可以访问 Docker 引擎的 Unix socket。

> — 《docker_practice》第 2 章 建立 docker 用户组

> Ensure only trusted users are allowed to control Docker daemon（Docker Bench 输出项，示例打印 `docker:x:999:baohua`）

> — 《docker_practice》第 11 章 / 《Docker技术入门与实战》19.4

## I — 方法论骨架 (Interpretation)

这个能力回答两个相连的问题："Docker 引擎从哪些通道可达？""谁能碰到这些通道？"它管的是引擎级攻击面——这是整个容器体系里最短的沦陷路径：控制了 daemon，就等于能以 root 创建任意容器，容器内的一切限制都能被"重新创建一个特权容器"绕过。

核心机制：daemon 的 REST API 本质是"以 root 创建任意容器"的远程过程调用，因此等同于宿主 root 的入口。设计上已把默认通道从 TCP 换成 Unix socket，用文件权限做鉴权。一旦有人为了"远程管理方便"把它改回 TCP，鉴权就退化为"网络可达即有权"，且浏览器可发起的请求（CSRF/XSS）也能打进来——这就是书中强调"绑定 127.0.0.1 的 TCP 易受跨站脚本攻击、故改用 Unix socket"的原因。

必须把"传输与监听面"和"主体授权"分开判断，这是本能力最重要的区分：

- 传输与监听面（CU-1-06）：监听方式是 unix socket 还是 TCP、有无 TLS。只保留 unix socket；确需远程时走可信网络/VPN 或证书保护（stunnel / SSL 双向认证），并启用 TLS 证书。判据很硬：出现 `-H tcp://0.0.0.0:2375` 无 TLS 即高危；用 `curl` 从非受信网段探测 `/version`、`/containers/json` 无需认证即可返回，即证明暴露成立。
- 主体授权（CU-1-07）：socket 的可达主体是谁。`docker` 组成员在效果上属于特权主体，而不是"普通运维账号"——把人加入 docker 组是"把 root 权限扩散给更多人"，与服务端防护"只有可信用户才能访问"直接冲突。需要最小权限的容器操作时，应改用受限代理/API 网关，而不是直接给 socket。

为什么这两层必须分开？因为一个环境可以同时"通道安全但主体过宽"（只有本地 socket，但 docker 组塞满研发）或"主体干净但通道暴露"（账号很少，但 2375 对全网开放）。两层独立收敛，才能堵住最短路径。

还要注意几个容易被忽略的细节：2375 和 2376 可能同时存在，封一个忘另一个；`-H unix://...` 存在不等于 TCP 没开；集群教程普遍要求改成 `0.0.0.0:2375`（如 Swarm 章节），照抄即产生无认证控制面；CI 里把 socket 挂进构建容器，等于把宿主 root 交给构建脚本。

## A1 — 应用示例 (Application Example)

### 示例 1: 照抄集群教程开出无认证 2375
- **类型与来源**: 【转述】《Docker技术入门与实战_第3版》第 2 章 TCP 暴露警告 + 第 19 章 19.4 +【合成演练】探测场景
- **问题/输入**: 某主机 `ps` 中出现 `dockerd -H tcp://0.0.0.0:2375 -H unix:///var/run/docker.sock`，运维称"照着集群教程配的，方便远程管理"。
- **方法论的使用**:
  1. 查监听：命中 `-H tcp://0.0.0.0:2375` 且无 TLS → 传输层高危。
  2. 外部验证：从非受信网段 `curl http://host:2375/version`、`/containers/json` → 无需认证返回数据，暴露成立。
  3. 收敛：只保留 unix socket；确需远程改走 VPN 或 TLS 双向证书（2376 + 证书）。
  4. 记录仍可达主体清单，交主体授权步骤判定。
- **结论**: 无认证 TCP 监听必须立即收敛，这是可直接拿到宿主 root 的最短路径。
- **结果**: 原书只给出警告与原理，未交代该演练的处置结果；按 E 段输出暴露清单与收敛动作。

### 示例 2: Docker Bench 发现 docker 组混入普通用户
- **类型与来源**: 【转述】《docker_practice》第 11 章 / 19.4 中 Docker Bench 输出项 `Ensure only trusted users are allowed to control Docker daemon`，示例打印 `docker:x:999:baohua`
- **问题/输入**: 基线检查 WARN 项显示 docker 组含普通研发账号，"为省 sudo 加进去的"。
- **方法论的使用**: `ls -l /var/run/docker.sock` + `getent group docker` 列出可达主体；逐人确认是否能接受其获得宿主 root 等价权限 → 否则移出组；对 CI runner 等挂 socket 的服务账号按同一标准审查；需要最小权限操作时改受限代理。
- **结论**: docker 组等价于特权主体列表，必须按"可信用户"标准逐个审查，不能当便利手段。
- **结果**: 原书给出真实输出片段与判断标准，未交代该账号后续处置；按 E 段输出主体清单与移出建议。

## A2 — 触发场景 (Future Trigger) ★

### 用户会在什么情境下需要它
1. 发现 Docker 主机开在公网/内网可达，要判断"2375 能不能开""docker API 未授权"的风险。
2. 配置远程管理 docker，问"远程管理怎么配才安全"。
3. 要决定"能不能把用户加进 docker 组""CI 里怎么用 docker"。
4. 做事件复盘，追查"谁能控制这台机器的 docker"。
5. 集群搭建教程要求改 `0.0.0.0:2375`，需要评估这条改动是否引入无认证控制面。

### 语言信号（出现这些就该激活）
- 中文：「2375 端口能不能开」「远程管理 docker 怎么配」「docker API 未授权」「能不能把用户加进 docker 组」「CI 里怎么用 docker」「谁能控制这台机器的 docker」
- English: "expose docker daemon tcp", "docker api unauthorized 2375", "add user to docker group", "who can control docker daemon", "remote docker management TLS"

### 与相邻能力的区分
- 与 `container-privilege-surface-hardening` 的区别：本能力看引擎级权限（谁能控制引擎），后者看容器内权限——本能力一旦失守，容器内一切限制都可被重建容器绕过。
- 与 `container-network-exposure` 的区别：网络暴露能力管"容器的端口对外/对内"，本能力管"daemon 自身从哪被控制"。
- 与 `container-security-tooling` 的区别：Docker Bench 的 daemon 相关 WARN 项由本能力解读和收敛，工具链能力负责跑检查本身。
- 与 `cloud-credential-and-storage-attack` 的区别：本卡管本机 daemon 的 socket/TCP/主体授权，那张卡管云上 AK/SK 凭据的利用与止血；两者都涉及"谁能控制资源"，但一个是本地 Unix socket/docker 组，一个是云 API 密钥/IAM 策略，判据与工具不同。

## E — 可执行步骤 (Execution)

**必需输入**: daemon 启动参数与配置文件（`/etc/default/docker`、`docker.service`、`daemon.json`）；宿主 shell 与 `getent group docker`；可发起 `curl` 探测的网络位置；需要"可信用户"名单。缺"谁在远程管理、为何需要"必须先问。
**交付物与完成标准**: 暴露面清单——监听方式（socket/TCP/端口/TLS）、可达主体名单、外部探测结果，每项给出收敛动作。完工标准是：无认证 TCP 监听清零，socket 主体逐一确认为可信。

1. **查传输与监听面**
   - 做什么：`ps`/`docker info` 查 `-H` 参数是否出现 `-H tcp://0.0.0.0:2375` 或 2376 且无 TLS；确认 unix socket 与 TCP 是否同时存在。
   - 完成标准：列出所有监听通道与 TLS 状态。
   - 判停：命中无认证 TCP → 标注高危，进入第 2 步验证；无命中进入第 3 步。

2. **外部探测确认暴露成立**
   - 做什么：从非受信网段 `curl /version`、`/containers/json`，确认是否无需认证返回。
   - 完成标准：有返回即证明暴露成立（不是"内网所以没事"）。
   - 判停：可达即立即收敛——只留 unix socket；确需远程走 VPN/可信网络或 stunnel/SSL 双向证书并启用 TLS；封 2375 时同时检查 2376。

3. **查主体授权（socket 可达性）**
   - 做什么：`ls -l /var/run/docker.sock`、`getent group docker` 列出人员与服务账号；逐人确认是否可信（能接受其获得宿主 root 等价权限）。
   - 完成标准：形成可信主体名单，非可信者移出 docker 组。
   - 判停：需要最小权限容器操作时改用受限代理/API 网关，不直接给 socket；CI 中挂 socket 的构建容器按同一标准审查，否则转 `container-privilege-surface-hardening`。

4. **汇总与交接**
   - 做什么：把通道与主体两份清单合并，记录收敛后仍可达的主体清单。
   - 完成标准：无认证 TCP 为零、socket 主体全部确认可信，剩余告警登记处置。
   - 判停：仍有未处置高危项时不得判定"控制面已收敛"。

## B — 边界 (Boundary) ★

### 不要用的情况
- 评估容器内权限（cap、挂载、privileged）时用 `container-privilege-surface-hardening`。
- 判断容器端口是否对外暴露时用 `container-network-exposure`。
- 需要完整主机基线检查时用 `container-security-tooling` 跑 Docker Bench，本能力只解读其中 daemon 相关项。

### 已知失败模式
- **把 2375 当"内网所以没事"**：集群教程普遍要求改成 `0.0.0.0:2375`，照抄即无认证控制面；浏览器可经 CSRF/XSS 打进来。
- **只封 2375 忘 2376**：2376 仍需双向证书校验，漏封等于留后门。
- **以为 `-H unix://...` 存在就等于 TCP 没开**：两者可同时存在。
- **为省 sudo 全员加入 docker 组**：把 root 权限扩散；CI 里把 socket 挂进构建容器，构建脚本即获宿主 root。
- **只审人不审挂 socket 的容器**：`nginx-proxy` 类 socket 代理容器同样获得控制面权限。

### 作者与时代的局限
- 书中以 Docker 1.x 的单机 daemon 为模型；当今 rootless Docker、远程 daemon 的 SSH 隧道、以及 K8s 场景下 kubelet/CRI 的暴露面需要另行评估。
- "docker 组等价 root"在 rootless 模式下不再完全成立，需按当前 daemon 运行方式判断。
- 端口 2375/2376 是默认约定，实际环境可能自定义，须以实测参数为准。

### 容易混淆的方法
- **通道 vs 主体**：传输监听面（socket/TCP/TLS）与主体授权（谁能碰 socket）是两层，必须分别收敛。
- **传输完整性 vs 发布者身份**：`insecure-registry` 关的是传输校验，镜像签名保证的是发布者身份（见 `image-build-supply-chain`）。
- **2375 vs 2376**：前者明文、后者 TLS，收敛动作不同。

### 授权与合规边界
> 待补充（用户自行填写）
