# 容器提权面识别与运行时加固

## R — 原文 (Reading)

> 默认情况下，Docker 启动的容器有严格限制，只允许使用内核的一部分能力……包括 chown、dac_override、fowner、setgid、setuid、setpcap、net_bind_service、net_raw、sys_chroot、mknod、setfcap、audit_write 等等。

> — 《Docker技术入门与实战_第3版》第 19 章 19.3 内核能力机制

> 恶意用户启动容器的时候将主机的根目录／映射到容器的 /host 目录中，那么容器理论上就可以对主机的文件系统进行任意修改了。

> — 《Docker技术入门与实战_第3版》第 19 章 19.4 Docker 服务端的防护

> 是否给容器高权限，这意味着容器内应用将不受权限的限制，一般不推荐。

> — 《Docker技术入门与实战_第3版》第 4 章 创建容器选项表

> 此外，在将文件系统挂载到容器内部时候，可以通过配置只读(read-only)模式来避免容器内的应用通过文件系统破坏外部环境……包括但不限于 /proc/sys、/proc/irq、/proc/bus 等。

> — 《Docker技术入门与实战_第3版》第 19 章 19.5 更多安全特性的使用

## I — 方法论骨架 (Interpretation)

这个能力回答："这个容器到底有没有等价宿主 root，怎么把它收敛到最小权限？"它处理的是单容器层面的提权面——即配置中哪些选项会让"容器内 root"变成真正的"宿主 root"。

核心机制有四条，必须按优先级串起来判断，不能并列：

第一，先看是否 `--privileged`。它不是"多给一点权限"，而是整包放弃能力白名单、放开设备访问与挂载。它常被当作排障手段引入（解决"不能改网络/不能挂载/不能读设备"的报错）后留在生产。一旦命中，容器内 root 直接持有宿主硬件与内核接口，后续细粒度限制全部失效——所以审计顺序必须"先判 privileged"。

第二，看能力位（capability）。root 的单一特权被切成若干位，Docker 默认走白名单。所以"容器内是 root"并不等于宿主 root，破坏力由实际持有的 capability 集合决定。判据是反查高危位：持有 `CAP_SYS_ADMIN`（挂载/卸载）、`CAP_SYS_MODULE`（加载模块）、`CAP_DAC_READ_SEARCH`（绕过文件读权限）、`CAP_MKNOD`（造设备节点）任意一个，即视为拥有逃逸原语。同时要检查是否有人为了"图省事"用 `--cap-add` 反向添加能力，逐条记录理由，无理由即收回。

第三，看挂载参数。逃逸不需要内核漏洞，只要一个不当的 `-v`：宿主根目录、`/etc`、`/var/run/docker.sock`、`/root/.ssh` 一旦可写挂载，容器内进程就以"文件系统"为通道直接改写宿主，绕开所有 namespace 与 capability 设计，故判据须放在参数准入层。反直觉点：给 `docker.sock` 挂 `:ro` 仍不安全——Unix socket 是连接语义而非文件写入，只读挂载仍能连接它控制 daemon。

第四，看运行时加固：只读挂载掐掉"写"这条落地通道，非 root 运行压低拿到交互式立足点的概率，禁用不必要的 shell 和入口脚本里的 `sudo` 回 root 堵住身份回弹。三者同时执行才完整——能力收敛、文件身份加固、入口收敛是互补而非替代。

此外还要判定"要不要在容器内开 SSH"：这不是"SSH 是否安全"，而是"这个容器的运维模型是什么"——应用容器由编排与日志系统管理、不装 sshd；系统容器保留 SSH 则须收敛暴露、禁密码登录。

四步做完，得到"提权面清单 + 加固动作"交付物。

## A1 — 应用示例 (Application Example)

### 示例 1: 为排障引入的 privileged 长期留在生产
- **类型与来源**: 【转述】《Docker技术入门与实战_第3版》第 20 章高级网络（手动为容器加网络时使用 `--net=none --privileged=true`）+【合成演练】审计场景推演
- **问题/输入**: 某容器的启动参数含 `privileged: true`，团队说"当初为了在容器里配网络加的，现在一直这样"。
- **方法论的使用**:
  1. 按审计顺序先检索到 privileged 命中 → 判定该容器已与宿主同信任域，后续细粒度限制几乎无意义。
  2. 追溯原因：为在容器内修改网络配置（书中明确"较新版本默认不允许在容器内修改网络配置"是常见动因）。
  3. 替代方案：改在宿主侧配网络，或用 `--cap-add NET_ADMIN` 精确授权，而不是整包放开。
  4. 无法替代时，判定必须移除对外暴露面并单独隔离主机。
- **结论**: privileged 应作为高危项限期整改，不能因为"能用"就保留。
- **结果**: 原书只给出动因与风险，无整改结果；按 E 段应输出整改动作清单。

### 示例 2: 早期 Docker 继承 CAP_DAC_READ_SEARCH 的历史教训
- **类型与来源**: 【转述】《Docker技术入门与实战_第3版》第 19 章 19.3（书中提到早期版本不恰当继承 `CAP_DAC_READ_SEARCH`）
- **问题/输入**: 一个老版本 Docker 环境，需要复查是否存在历史能力继承问题。
- **方法论的使用**: 取容器内 `/proc/self/status` 的 CapEff 位图，解码后对照"应被禁用四类"——发现 `CAP_DAC_READ_SEARCH` 位被置起，命中高危；该位允许容器进程通过系统调用访问本地任意文件目录。
- **结论**: 该环境存在宿主文件任意读的逃逸原语，与"容器里是不是 root"的判断无关，必须按高危位判据收回。
- **结果**: 原书交代了该历史缺陷的存在与后果，未交代特定环境的处置结果；本演练按 E 段标注`收回能力并复查`。

## A2 — 触发场景 (Future Trigger) ★

### 用户会在什么情境下需要它
1. 审计容器/编排配置，想知道哪些容器已被过度授权、是否等价宿主 root。
2. 有人用 `--privileged` 解决"容器里不能 mount / 不能改网络"的报错，需要评估并给出精确替代方案。
3. 想知道"容器里是 root 到底危不危险""哪些 cap 加了会出问题"。

### 语言信号（出现这些就该激活）
- 中文：「容器里是 root 危险吗」「--cap-add 加什么会有问题」「-v 挂载有什么风险」「加 --privileged 就能跑了吗」「容器里要 mount / 要改网络」「docker.sock 挂进容器安全吗」「容器怎么加固」「要不要用 root 跑应用」「容器里要不要装 sshd」
- English: "container root vs host root", "which capabilities are dangerous", "container can modify host files", "mount docker.sock into container", "container needs privileged mode", "why is --privileged dangerous", "harden container runtime", "run container as non-root", "sshd inside container good practice"

### 与相邻能力的区分
- 与 `container-isolation-boundary-assessment` 的区别：后者判断"隔离是否够用"的整体框架，本能力处理"具体哪些配置让容器等价 root"的细节；后者判停时路由到本能力。
- 与 `container-network-exposure` 的区别：host 网络只放开网络栈，`--privileged` 放开全部设备与能力；本能力判断顺序是先 privileged 再网络，网络暴露能力专管端口与横向。
- 与 `docker-daemon-api-exposure` 的区别：本能力看容器内的权限，daemon 能力看引擎级权限——后者一旦失守，容器内一切限制都可通过重建容器绕过。
- 与 `container-escape-path-assessment` 的区别：本卡是**防御侧**审计 privileged/CapEff/挂载并收敛，那张卡是**攻击侧**用同样的 privileged/CapEff 判据（`fdisk`、`CapEff=0000003fffffffff`）走逃逸路径；同一物理判据、相反立场。

### 补充单元说明
- 攻击侧对特权容器的硬指标判定（`fdisk -l` 列磁盘、`CapEff` 值比对、mount + chroot 逃逸链，来自《云安全攻防入门》第六章）归属 `container-escape-path-assessment`；本卡只吸收其防御含义：特权容器必须先判定为"与宿主同信任域"并限期收敛。

## E — 可执行步骤 (Execution)

**必需输入**: 容器启动参数与编排文件（`docker inspect` 的 `HostConfig.CapAdd`、`Privileged`、`Binds`、`NetworkMode`）；容器内 `/proc/self/status` 的 CapEff；应用是否依赖写系统目录、绑低端口、需要人工登录。缺"应用为何需要该权限"必须先问。
**交付物与完成标准**: 一份提权面清单（privileged / 高危 cap / 敏感挂载 / 入口出口逐项），每项标注风险等级与加固动作；完工标准是四项都已盘点且每项有明确处置（收回、替代、或书面接受并隔离）。

1. **判 privileged（整包权限）**
   - 做什么：在启动参数与编排文件全量检索 `privileged`、`--privileged=true`、`privileged: true`（含 compose/k8s 模板）。
   - 完成标准：列出全部命中容器。
   - 判停：命中即标注"与宿主同信任域"，进入第 4 步隔离处置；无命中进入第 2 步。

2. **查能力位（逐位授权）**
   - 做什么：取 HostConfig.CapAdd 与 CapEff 位图解码；对照四类高危位（mount、主机套接字、设备/文件属性、模块加载）；逐条审计 `--cap-add` 的添加理由，特别复查老环境的 CAP_DAC_READ_SEARCH 继承。
   - 完成标准：每个高危位都有"保留理由或收回"结论。
   - 判停：无理由的 `--cap-add` 直接收回；命中 SYS_ADMIN/MODULE/DAC_READ_SEARCH/MKNOD 任一，标注逃逸原语并优先处置。

3. **查挂载（文件系统通道）**
   - 做什么：枚举所有 bind mount 宿主路径，与敏感清单（`/`、`/etc`、`/root`、`/var/run`、`/proc`、`/sys`、`/boot`）比对；确认读写属性。
   - 完成标准：敏感路径读写命中即判定容器等价宿主 root（与内核漏洞无关）。
   - 判停：确有共享需求改 `:ro` 并收窄子目录；但 `docker.sock` 即使 `:ro` 仍视为高危（连接语义），转 `docker-daemon-api-exposure`；若平台提供"创建容器"接口，把 `-v`/`--privileged`/`--cap-add` 列为服务端校验黑名单。

4. **运行时加固与入口收敛**
   - 做什么：对系统状态目录配只读挂载；共享宿主目录加 `:ro`；Dockerfile 用 `USER <非root>` 或入口脚本降权；禁用不必要 shell 与脚本内 `sudo` 回 root；按容器类型决定是否保留 SSH（应用容器不装 sshd，系统容器收敛暴露+禁密码）。
   - 完成标准：容器内写只读路径失败、`id` 非 0、CapEff 已收敛、无可绕过降权的入口。
   - 判停：只设 `--read-only` 未给可写 tmp/缓存致应用崩时补可写目录再复核，不要直接回滚加固；需 host 网络转 `container-network-exposure`。

## B — 边界 (Boundary) ★

### 不要用的情况
- 判断"镜像里有没有敏感数据或 CVE"用 `image-build-supply-chain` / `container-security-tooling`；整机结论用 `container-isolation-boundary-assessment`；daemon 暴露面用 `docker-daemon-api-exposure`。

### 已知失败模式
- **把 privileged 当修复开关**（第 20 章）：配网络时临时加、事后不回滚；只查 `docker run` 漏掉 compose/k8s 模板。
- **只查是不是 root 不查有哪些 cap**（19.3）：忽略 CAP_DAC_READ_SEARCH 历史继承。
- **只看容器内行为不看启动参数**（19.4）：错过 `-v` 逃逸通道。
- **`:ro` 就认为安全**：`docker.sock` 只读挂载仍能连接控制 daemon（连接语义）。
- **加固自相矛盾**：只读挂载却仍给 privileged（能力可绕过）；`USER` 指令但入口脚本 `sudo` 回 root。

### 作者与时代的局限
- 书中默认能力清单基于 Docker 1.x 时代，当前版本默认集与设备 cgroup 行为已有变化（如 cgroup v2、默认 cap 集不同），具体位图须实测。
- 容器内 SSH 一节记录的是社区两派观点，属经验性建议而非强制标准，需按实际运维模型判断。

### 容易混淆的方法
- **整包 vs 逐位**：`--privileged` 是放弃全部约束，`--cap-add` 是逐位授权；先判前者再看后者。
- **文件系统通道 vs 控制面通道**：`-v` 挂载（本能力）与 `docker.sock` 连接（`docker-daemon-api-exposure`）可能同时命中，但判据不同。
- **只读挂载 vs 能力绕过**：只读挂载限制写，capability/privileged 可绕过，必须同时收敛。

### 授权与合规边界
> 待补充（用户自行填写）
