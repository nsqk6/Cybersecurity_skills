# 镜像与 CI/CD 软件供应链安全

## R — 原文 (Reading)

> 比如，删除前一层文件的操作，实际不是真的删除前一层的文件，而是仅在当前层标记为该文件已删除……该文件会一直跟随镜像。

> — 《docker_practice》第 1 章 镜像 · 分层存储

> 但是，不要使用 docker commit 定制镜像，定制行为应该使用 Dockerfile 来完成。

> — 《docker_practice》第 5 章 利用 commit 理解镜像构成

> 区分编译环境容器和运行时环境容器，使用多阶段镜像创建。

> — 《Docker技术入门与实战_第3版》附录 A.1 第 7 题

> Poisoned Pipeline Execution（PPE）是一种供应链攻击的方法，指的是攻击者利用对源代码管理系统的访问权限，但没有对构建环境的访问权限，来通过向构建流程配置文件中注入恶意代码或命令，从而操纵构建过程，实质上"毒化"了流程。

> — 《云安全攻防入门》第七章 CICD top 10 Security Risk / 中毒管道执行

> 由于预安装脚本在摘取包后立即运行包的代码……名字混淆 - 在公共存储库中创建类似的名称的恶意包，诱骗客户端下载恶意包。依赖包劫持 - 获取公共存储库维护者的帐号权限，上传恶意代码。

> — 《云安全攻防入门》第七章 CICD top 10 Security Risk / 依赖库滥用

## I — 方法论骨架 (Interpretation)

这个能力回答："交付物（镜像 + 构建链）能不能信、干不干净、来源对不对？"它把软件供应链拆成两段——**镜像本身**与**产出镜像的 CI/CD 管道**——因为镜像层残留再干净，只要构建管道被投毒，产出的仍是后门镜像。

镜像段是"三查一做"。查内容干净：镜像层只读叠加，删除只是新增 whiteout 标记，"先 COPY 私钥再 RUN rm"私钥仍完整存在于下层，`docker save` 逐层解包即可取回；判据不是"运行时看不看得见"，而是"有没有在同一层内既不写入也不落地"。查构建可审计：`docker commit` 把当前容器状态拍成黑箱，无法得知执行过什么命令、装过什么包、有无写进凭证，也无法复现；每次 commit 还在原层叠加、镜像膨胀——排查"改容器→commit→push"链并迁移到 Dockerfile。查来源可信：仓库地址与 `latest` 标签都不保证完整性（标签可被重新指向），签名把"digest 是不是发布者签的那个"变成可验证命题；部署用 digest 或已签名 tag，校验失败即中止。正向做法是"构建时不产生残留"：多阶段构建把产物从 build stage 拷到干净的 runtime stage，配 `.dockerignore` 阻止敏感文件进入上下文，选小基础镜像、清缓存、指定版本、还原环境变量、尽量用系统库。

CI/CD 段是"两判"。判中毒管道执行（PPE）：前提是"能改代码仓库、但进不了构建环境"。按配置位置分三型——直接型 D-PPE（改仓库里的 Jenkinsfile/.gitlab-ci.yml 推到未保护分支）、间接型 I-PPE（CI 配置在 Jenkins 自身，改 Makefile/脚本）、公共型 P-PPE（公共仓库投毒，CI 在内网受害更深）。判据是"CI 配置文件在哪、攻击者能改哪些文件"，借 push/PR 触发 WebHook 让恶意命令在构建节点执行。判依赖混淆：利用"习惯性拼写"与"安装即执行"——把 requests 错拼成 request、ruamel.yaml 错拼成 ruamel 就拉到恶意包，且安装脚本会立即执行。判据是"包名是否高度相似、是否来自不受信任源、拉取后是否立即执行代码"，对策是走代理/审查、启用校验和与签名、锁定审查过的稳定版本而非 latest。

两段合起来才是完整供应链防线：镜像三查保证"产出物可信"，CI/CD 两判保证"产出过程没被投毒"。`docker commit` 在本卡是交付禁令，唯一例外是取证留证（见 `container-incident-forensics`）。

## A1 — 应用示例 (Application Example)

### 示例 1: "先 COPY 私钥再 rm"仍泄露
- **类型与来源**: 【合成演练】（依据《docker_practice》第 1 章分层存储机制推演）
- **问题/输入**: Dockerfile 写 `COPY id_rsa /app/` 后 `RUN rm /app/id_rsa`，团队认为"运行时看不到就安全"。
- **方法论的使用**: `docker save` 解包 → 每层搜私钥头 → 在 COPY 所在的旧层命中判泄露 → 反向查 `rm` 在 COPY 之后即无效删除 → 改为同一 RUN 内使用并删除，或改用多阶段/构建期挂载。
- **结论**: 删除标记不等于删除内容；敏感数据必须"从未落地"。
- **结果**: 原书仅给机制，未给演练结果；按 E 段输出泄露层清单与修复动作。

### 示例 2: 私有仓库 insecure-registry 的适用前提
- **类型与来源**: 【转述】《Docker技术入门与实战_第3版》第 5 章（`DOCKER_OPTS="--insecure-registry 10.0.2.2:5000"` 后 pull 成功示例）
- **问题/输入**: 内部私有仓库只用 HTTP，pull 报 https 错误，有人长期用 insecure-registry 解决。
- **方法论的使用**: 先试受信 CA 证书；必须跳过时精确写 `<IP:PORT>`（不写网段/通配）；校验前提——地址只从受控网段可达、容器不可达、无 DNS 劫持，任一不满足回退证书方案；登记技术债纳入基线复核。
- **结论**: insecure-registry 关的是传输校验，与镜像签名（发布者身份）不是一回事，都缺时镜像可被任意替换。
- **结果**: 原书给出 pull 成功示例，未交代前提复核结果；按 E 段输出核查清单与回退方案。

### 示例 3: cicd-goat 中的 PPE 投毒
- **类型与来源**: 【例题】《云安全攻防入门》第七章（cicd-goat 中 White Rabbit 题）
- **问题/输入**: 能改某个代码仓库但不能进构建环境，想验证能否操纵构建流程。
- **方法论的使用**:
  1. 定位 CI 配置文件位置：White Rabbit 仓库内的 Jenkinsfile → 判为直接型 PPE。
  2. 判断写权限：可向未保护分支推送。
  3. 借 push/PR 触发 WebHook，让 Jenkinsfile 中的恶意命令在构建节点执行，访问凭据偷 flag1。
- **结论**: PPE 的判据是"配置文件在哪、能改哪些文件"，不是"能不能登录构建机"。
- **结果**: 原书给出该例题的 flag1 路径，未给其他后续结果；本卡不扩展。

### 示例 4: 依赖名混淆导致投毒
- **类型与来源**: 【转述】《云安全攻防入门》第七章（ruamel.yaml 因 `pip install ruamel` 少写后缀下载恶意包；requests 错拼成 request）
- **问题/输入**: 项目依赖清单里出现"看着眼熟但不太对"的包名。
- **方法论的使用**: 核对全名与官方名是否一字之差 → 查安装来源是否走代理/审查、是否启用校验和与签名 → 避免 latest，锁定审查过的稳定版本；注意安装脚本会立即执行，无需额外交互。
- **结论**: 名字混淆 + 安装即执行是依赖攻击的两个支点，缺一不可。
- **结果**: 原书给出两个真实包名案例，未交代具体受害结果；按 E 段输出判定与锁定动作。

## A2 — 触发场景 (Future Trigger) ★

### 用户会在什么情境下需要它
1. 怀疑镜像残留私钥/token、想知道"删掉的文件是不是还在镜像里"。
2. 镜像历史看不懂、仓库全是 `xxx:snapshot`，想做可信基线。
3. 给镜像瘦身、把编译工具挡在运行镜像外、写多阶段构建。
4. 保证"拉到的镜像没被改"、决定是否开 content trust / 固定 digest。
5. 私有仓库 pull 报 https 错误，判断 insecure-registry 能不能用。
6. 想知道"CI/CD 怎么被打""CI 配置文件被改有什么后果""poisoned pipeline execution types"。
7. 防依赖投毒："typosquatting 是什么""dependency confusion risk"。

### 语言信号（出现这些就该激活）
- 中文：「Dockerfile 里删掉密钥行不行」「镜像里会不会残留密码」「能不能直接 commit 当镜像」「多阶段构建怎么写」「要不要开 content trust」「私有仓库 pull 报 https 错误」「CI/CD 怎么被打」「CI 配置文件被改有什么后果」「依赖包投毒怎么防」「typosquatting 是什么」
- English: "secret leaked in image layers", "docker commit vs Dockerfile", "multi-stage build reduce attack surface", "docker content trust", "insecure registry", "poisoned pipeline execution types", "dependency confusion risk", "supply chain attack via CI"

### 与相邻能力的区分
- 与 `container-security-tooling` 的区别：本卡查"来源可信/内容干净/构建可审计"，工具链的 clair 查"已知 CVE"——三种检查都要做，不能互相替代。
- 与 `container-incident-forensics` 的区别：同一 `docker commit`，本卡是"禁止用于交付"的反例，取证卡是"固化现场"的唯一正当用法。
- 与 `cloud-credential-and-storage-attack` 的区别：那张卡防的是云凭据泄露，本卡防的是构建链投毒；两者都会用到"不要把密钥写进代码/配置"的原则，但对象不同。
- 与 `docker-daemon-api-exposure` 的区别：insecure-registry（本卡，传输校验）与 daemon 暴露面（TCP/TLS）是不同对象。

## E — 可执行步骤 (Execution)

**必需输入**: 镜像 tar 或仓库访问权；Dockerfile 与 `.dockerignore`；构建上下文；部署链的构建/推送/拉取配置；CI 流水线配置文件位置与分支保护规则；项目依赖清单与安装源配置。缺"镜像是否对外分发、CI 配置在哪"必须先问。
**交付物与完成标准**: 镜像三查报告 + CI/CD 两判报告 + 整改动作。完工标准是六项（残留/commit/签名/多阶段/PPE/依赖）各有明确结论。

1. **内容干净：逐层搜敏感数据**
   - 做什么：`docker save` 解包或 `docker history --no-trunc`；每层搜私钥头、`.env`、`id_rsa`、token；反向查 `rm` 是否在 COPY 敏感文件之后。
   - 完成标准：命中层清单与"无效删除"标注。
   - 判停：任一历史层命中即判泄露，进入第 4 步修复。

2. **构建可审计：排查 commit 交付链**
   - 做什么：查 `docker history` 是否极少层且顶部 commit 元数据、仓库有无 snapshot 标签；对已 commit 镜像全层扫敏感数据。
   - 完成标准：判定是否存在 commit 交付。
   - 判停：存在即迁移 Dockerfile 并用 `docker diff` 复核；被入侵固化现场例外转 `container-incident-forensics`。

3. **来源可信：签名与固定引用**
   - 做什么：确认构建/推送/拉取三处 content trust 是否启用；部署用 digest 或已签名 tag，不用 `latest`；拉取校验失败即中止。
   - 完成标准：来源可验证、引用固定。
   - 判停：只用"来自官方仓库"不作可信依据；只在一处启用签名视为未闭环。

4. **正向构建：多阶段 + 私有仓库前提**
   - 做什么：拆 `build`/`runtime` 两 stage，只 `COPY --from=build` 产物；配 `.dockerignore`；选小基础镜像、清缓存、指定版本、还原环境变量、用系统库。私有仓库先试受信 CA，必须 insecure 时精确写 `<IP:PORT>` 并校验受控网段可达、容器不可达、无 DNS 劫持。
   - 完成标准：运行镜像无构建痕迹、上下文无敏感文件、insecure 前提成立并登记技术债。
   - 判停：任一前提不满足回退证书方案；交付前用第 1 步复核无残留。

5. **CI/CD 管道：判 PPE 三型**
   - 做什么：定位 CI 配置文件位置（仓库内/Jenkins 自身/公共仓库）→ 定 D-PPE/I-PPE/P-PPE；判断攻击者对配置文件或被引脚本（Makefile/shell）的写权限；借 push/PR 触发 WebHook 让恶意命令在构建节点执行。
   - 完成标准：注入点与触发路径明确，三型判定有依据。
   - 判停：只盯仓库内 Jenkinsfile 会漏掉 CI 系统自身配置与被引用脚本；公共仓库投毒对内网 CI 危害更深，须单独评估。

6. **依赖：判名字混淆与来源**
   - 做什么：核对依赖全名与官方名是否一字之差（request vs requests、ruamel vs ruamel.yaml）；查安装来源是否走代理/审查、是否启用校验和与签名；避免 latest，锁定审查过的稳定版本。
   - 完成标准：每个可疑包有"可信/投毒嫌疑"结论与锁定动作。
   - 判停：忽略"安装脚本立即执行"会低估危害；公网直拉依赖 + latest 配置放大投毒面。

7. **汇总与复核**
   - 做什么：合并六项结论，确认镜像与管道两段都覆盖。
   - 完成标准：无"镜像干净但管道被投毒"的遗漏。
   - 判停：只做镜像段或只做管道段，不得判定"供应链已安全"。

## B — 边界 (Boundary) ★

### 不要用的情况
- 查镜像已知 CVE 用 `container-security-tooling`（clair），本卡的层搜索找的是敏感数据与残留。
- 保全入侵现场用 `container-incident-forensics`（那里 commit 正当）；整机隔离评估用 `container-isolation-boundary-assessment`。
- 云凭据泄露止血用 `cloud-credential-and-storage-attack`，本卡的"不硬编码密钥"原则不替代那张卡的权限判定。

### 已知失败模式
- **只在运行容器里 `ls` 看不到就判干净**（第 1 章）：下层文件仍在，`docker save` 可取回。
- **`docker history` 只看命令不看层内容**：COPY 大目录时命令简短，看不出写了什么。
- **用 commit 图快做热修复镜像**（第 5 章）：之后说不清基线；以为删文件就清理干净（层叠加不支持）。
- **多阶段只做体积优化不做隔离**：仍把 `~/.ssh`、npm token、`.git` 带进上下文（缺 `.dockerignore`）。
- **insecure-registry 长期保留或写整个网段**（第 5 章）：对所有内网仓库放弃校验；忽略容器也能访问该地址使被拿下容器可投毒。
- **只盯仓库内 Jenkinsfile 忽略 CI 系统自身配置与被引用脚本**（第七章 PPE）：漏掉 I-PPE 注入点。
- **从公网直拉依赖、配置拉 latest 而非锁定版本**（第七章依赖库滥用）：放大投毒风险；忽略安装脚本立即执行。

### 作者与时代的局限
- 签名一节基于 Docker 1.3 content trust；当今 Notary v2/cosign/SBOM 已演进，原则不变但工具需更新。
- PPE 与依赖混淆出自《云安全攻防入门》第七章的 CICD Top 10 清单，反映当时的 CI 生态（Jenkinsfile/gitlab-ci）；现代 GitHub Actions/GitLab CI 的配置位置与触发机制不同，需按实际平台映射三型。
- `docker commit` 禁令针对早期实践；多阶段构建需 Docker 17.05+，老环境须另想隔离手段。

### 容易混淆的方法
- **层残留 vs commit 黑箱**：前者是层语义导致的残留，后者是构建方式导致的不可审计，叠加时更严重。
- **签名 vs insecure-registry**：发布者身份 vs 传输校验，两者都缺时镜像可被任意替换。
- **镜像段 vs 管道段**：镜像三查查产出物，CI/CD 两判查产出过程；只做一段不算完整供应链安全。
- **D-PPE vs I-PPE vs P-PPE**：判据是"CI 配置文件在哪、能改哪些文件"，不是"攻击复杂度"。

### 授权与合规边界
> 待补充（用户自行填写）
