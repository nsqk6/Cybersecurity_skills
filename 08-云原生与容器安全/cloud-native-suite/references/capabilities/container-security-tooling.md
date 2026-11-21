# 容器安全基线与漏洞扫描工具链

## R — 原文 (Reading)

> 该项目按照互联网安全中心（Center for Internet Security, CIS）对于 Docker 1.13.0+ 的安全规范进行一系列环境检查，可发现当前 Docker 部署在配置、安全等方面的潜在问题。

> — 《Docker技术入门与实战_第3版》第 19 章 19.6.1 Docker Bench

> 一般要尽量避免出现 WARN 或以上的问题。

> — 《Docker技术入门与实战_第3版》第 19 章 19.6.1（判定标准）

> 除了 Docker Bench 外，还有 CoreOS 团队推出的 clair，它基于 Go 语言实现，支持对容器（支持 appc 和 Docker）的文件层进行静态扫描发现潜在漏洞。

> — 《Docker技术入门与实战_第3版》第 19 章 19.6.2 clair

## I — 方法论骨架 (Interpretation)

这个能力回答："用什么工具把容器的配置合规和镜像漏洞自动化地查出来？"它的核心主张是：手工逐项核对安全配置不可持续，必须把规范变成可重复执行的检查；同时要清楚"配置合规"和"镜像里有已知 CVE"是两件不同的事，要用不同工具分别做，不能互相替代。

工具一，Docker Bench：把 CIS 规范变成可重复执行的检查，输出按严重程度分级（INFO/NOTE/WARN 等），把"配置偏差"变成可排序的待办。它的价值不在打分，而在于把六类偏差一次性摊开——主机配置、Docker 引擎、配置文件权限、镜像管理、容器运行时环境、安全项——避免只盯某一类（例如只加固容器却不管 daemon 配置文件权限）。判定标准很明确：一般要尽量避免 WARN 或以上，所有 WARN 及以上必须给出处置或书面接受理由。运行方式是用官方镜像，但它需要挂载宿主 `/etc`、`/var/lib`、`docker.sock` 等只读信息源——这本身就是高权限挂载，应在受控窗口执行并事后移除，绝不能长期跑在生产机上。需要定制检查项时改用源码方式（`git clone` 后 `docker-compose run --rm`）。

工具二，clair：静态层扫描。镜像层里固化了某个时间点的所有软件包版本，只要不重建就会一直携带旧漏洞。clair 把"层内包版本"与漏洞库比对，产出可定位到层的漏洞清单，使重建与升级有依据。执行上要起 PostgreSQL 与 clair 服务，向 clair API 登记镜像层，再拉报告按层归因到具体包与版本；结论落到动作——能升级基础镜像的走重建，只能等上游修复的记录接受理由与到期时间。

两工具必须配合，还要和同域其他能力分工：Docker Bench 查**配置**，clair 查**漏洞**，`image-build-supply-chain` 的层搜索查**敏感数据/来源**——三种检查都要做。工具只是"发现"，整改要路由到对应能力：daemon 相关 WARN 交 `docker-daemon-api-exposure`，容器内配置交 `container-privilege-surface-hardening`，镜像 CVE 交 `image-build-supply-chain` 重建。

几个关键纪律：别只看总分不看具体 WARN；别把"没报 ERROR"当成合规；扫镜像要扫线上实际运行的 digest 而非只扫 latest 标签；扫描无结果不等于无漏洞（漏洞库有滞后）；书中示例的 `POSTGRES_PASSWORD=""` 不能照搬进生产。

## A1 — 应用示例 (Application Example)

### 示例 1: Docker Bench 输出 WARN 的处置
- **类型与来源**: 【转述】《Docker技术入门与实战_第3版》19.6.1（书中贴出 v1.3.4 实际输出片段）
- **问题/输入**: 在宿主机跑 Docker Bench，输出包含 `[WARN] 1.1 Ensure a separate partition for containers has been created`、`Ensure only trusted users are allowed to control Docker daemon`（打印 `docker:x:999:baohua`）、`Ensure auditing is configured for Docker files and directories - /var/lib/docker`。
- **方法论的使用**:
  1. 运行官方镜像（挂载宿主只读信息源），在受控窗口执行。
  2. 按六维归并输出：主机配置、引擎、文件权限、镜像管理、运行时、安全项。
  3. 判定：所有 WARN 及以上必须给处置或书面接受理由；`Ensure only trusted users` 交 `docker-daemon-api-exposure`，审计项交本域基线复核。
  4. 事后移除 Bench 容器。
- **结论**: Bench 的价值是把六类偏差摊开并分级，而不是给一个总分。
- **结果**: 原书贴出了真实输出片段，未交代该环境 WARN 的最终处置结果；按 E 段输出 WARN 清单与分流。

### 示例 2: clair 扫出基础镜像旧包 CVE
- **类型与来源**: 【合成演练】（依据 19.6.2 clair 机制与 E 段规则推演）
- **问题/输入**: 线上运行的基础镜像基于某旧发行版，想上线前确认有没有已知漏洞。
- **方法论的使用**:
  1. 起 PostgreSQL 与 clair 服务，写 `clair_config/config.yaml`（书中示例用 `POSTGRES_PASSWORD=""`，生产须改）。
  2. 向 clair API 登记镜像层（提交待扫镜像）。
  3. 拉报告，按层归因到具体包与版本 → 发现旧 openssl 版本命中 CVE。
  4. 结论落到动作：能升级基础镜像的走重建，交 `image-build-supply-chain`；暂不能修的记录接受理由与到期时间。
- **结论**: 静态层扫描把"层内包版本"与漏洞库比对，使重建有依据；扫的是线上实际 digest 而非 latest。
- **结果**: 原书未给具体演练结果（仅给工具用法）；按 E 段输出 CVE 清单与整改路由。

## A2 — 触发场景 (Future Trigger) ★

### 用户会在什么情境下需要它
1. 要给容器主机做安全基线自查，问"有没有自动化检查工具""CIS Docker 怎么落地"。
2. 想知道"镜像里有没有已知漏洞""上线前怎么扫镜像""基础镜像 CVE 怎么发现"。
3. 手工核对配置不可持续，需要把规范变成可重复执行的检查并排序待办。
4. 已有 Bench/clair 输出但不知如何解读、分流整改。
5. 需要区分"配置合规""镜像漏洞""敏感数据"三类检查，避免互相替代。

### 语言信号（出现这些就该激活）
- 中文：「容器主机怎么做安全基线」「有没有自动化检查工具」「CIS Docker 怎么落地」「镜像里有没有已知漏洞」「上线前怎么扫镜像」「基础镜像 CVE 怎么发现」「Bench 报 WARN 怎么办」
- English: "docker security benchmark", "CIS docker baseline check", "scan container image for CVEs", "image vulnerability scanning", "docker bench WARN", "clair image scan"

### 与相邻能力的区分
- 与 `container-isolation-boundary-assessment` 的区别：后者给评估维度划分，本能力给逐项打勾的检查工具；先分层再选工具。
- 与 `image-build-supply-chain` 的区别：本能力的 clair 查"已知 CVE"，镜像能力的层搜索查"敏感数据与来源"——三种检查都要做。
- 与 `docker-daemon-api-exposure` / `container-privilege-surface-hardening` 的区别：本能力负责"发现"（跑工具出清单），后两者负责"整改"（解读并收敛具体配置）。
- 与 `container-incident-forensics` 的区别：本能力做日常基线/漏洞"发现"，那张卡做事件响应中的证据固化、云日志可见性与监控盲区诊断；那张卡里"日志质量三信号"是取证视角的日志核对，与本卡的 Bench 配置基线不是一回事。

## E — 可执行步骤 (Execution)

**必需输入**: 宿主 root；可挂载 `/etc`、`/var/lib`、`docker.sock` 的受控窗口；PostgreSQL 与可写配置目录；可访问镜像仓库与 daemon；安全基线与漏洞库。缺"扫描窗口是否受控、扫哪个 digest"必须先问。
**交付物与完成标准**: 两份清单——Bench 六维配置偏差清单（WARN 及以上逐项处置/接受）、clair 按层归因的 CVE 清单（包/版本/整改动作）。完工标准是两类清单齐全且每项有分流去向。

1. **跑 Docker Bench 做配置基线**
   - 做什么：运行官方镜像（挂载宿主侧只读信息源）；按六维归并输出：主机配置、引擎、文件权限、镜像管理、运行时、安全项。
   - 完成标准：六维逐项结论，WARN 及以上全部登记。
   - 判停：所有 WARN 及以上必须给处置或书面接受理由；daemon 相关项交 `docker-daemon-api-exposure`，容器配置项交 `container-privilege-surface-hardening`；受控窗口结束即移除 Bench 容器，不得长期驻留。

2. **按需改用源码方式定制检查**
   - 做什么：需要增删检查项时 `git clone` 源码后 `docker-compose run --rm docker-bench-security`。
   - 完成标准：得到定制检查输出。
   - 判停：官方镜像够用时跳过此步。

3. **部署 clair 做静态漏洞扫描**
   - 做什么：建 `clair_config`、下载 `config.yaml.sample`、配数据库连接；起 `postgres:9.6` 与 `quay.io/coreos/clair-git`；提交待扫镜像向 API 登记层；拉报告按层归因到包与版本（生产禁用示例中的空密码）。
   - 完成标准：产出可定位到层的 CVE 清单。
   - 判停：扫线上实际运行的 digest 而非只扫 latest；无结果不等于无漏洞（库有滞后）；CVE 交 `image-build-supply-chain` 重建或登记到期时间。

4. **汇总与复核**
   - 做什么：合并配置偏差与 CVE 两份清单；确认三类检查（配置/漏洞/敏感数据）都已覆盖。
   - 完成标准：每项有分流去向与责任能力。
   - 判停：只做其中一类不得判定"安全检查完成"。

## B — 边界 (Boundary) ★

### 不要用的情况
- 需要先确定评估维度时用 `container-isolation-boundary-assessment`，本能力只做逐项检查。
- 查镜像敏感数据/来源时用 `image-build-supply-chain` 的层搜索与签名验证。
- 需要整改具体配置时用 `docker-daemon-api-exposure` / `container-privilege-surface-hardening`，本能力只发现不整改。

### 已知失败模式
- **把 Bench 容器长期跑在生产机上**（19.6.1）：它对宿主 `/etc`、`/var/lib`、`docker.sock` 是全权限挂载，本身就是高权限入口。
- **只看总分不看具体 WARN**：把"没报 ERROR"当成合规，忽略关键偏差项。
- **用旧版本 Bench 对新增配置项视而不见**：规范随版本演进，工具版本要跟上。
- **只扫 latest 标签、扫无结果当无漏洞**（19.6.2）：漏洞库有滞后；示例 `POSTGRES_PASSWORD=""` 照搬进生产。

### 作者与时代的局限
- 书中以 Docker 1.13.0+ 时代的 CIS 规范与 clair 早期版为对象；当今有更新的 CIS Benchmark、Trivy/Grype 等扫描器与 Trivy-operator 等集成方案，工具需更新但"配置与漏洞分查"的原则不变。
- clair 的 API 与部署方式已多次演进，书中命令仅作原理示例，需按当前版本调整。
- Bench 的挂载方式反映早期单机模型，现代 K8s 环境需用对应的 kube-bench 等工具。

### 容易混淆的方法
- **配置 vs 漏洞**：Docker Bench 查配置合规，clair 查已知 CVE，不能互相替代。
- **WARN vs ERROR**：书中标准是"尽量避免 WARN 或以上"，不能只盯 ERROR。
- **发现 vs 整改**：本能力出清单，整改路由到各专项能力。

### 授权与合规边界
> 待补充（用户自行填写）
