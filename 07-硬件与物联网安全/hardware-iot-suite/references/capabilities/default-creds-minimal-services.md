# 默认凭据与最小服务加固

## R — 原文 (Reading)

> "Everybody with any degree of familiarity with the Raspberry Pi knows that the default username is pi and the default password is raspberry. Thus, if you have any notion of storing confidential data on your Pi, you are best advised to change the password for the pi account immediately."
>
> — 《Hacking Raspberry Pi》Chapter 5, Change User Password

> "By default, VNC transmits all data between the client and the server in plain text. Therefore, if you have need for data confidentiality, you need to select an appropriate VNC server and client software package."
>
> — 《Hacking Raspberry Pi》Chapter 7, Virtual Network Computing (VNC)

> "The IT security and performance principle of least service means that if your computer does not need to have a particular background service (daemon) running, then prevent it from doing so... After all, an attacker can't compromise a service that isn't running!"
>
> — 《Hacking Raspberry Pi》Chapter 18, Various and Sundry Performance Tweaks

## I — 方法论骨架 (Interpretation)

这个能力解决的是"拿到一台设备之后，怎么在攻击者之前把最便宜的入口关掉"。它把四件常被分开做的事——默认凭据、明文远程协议、最小服务原则、开机服务清点——统一到一个逻辑链上：**攻击面 = 对外可达的代码总量；先确认有哪些入口，再判断每个入口是"能进去"还是"进去后看得见"，最后把不必要的入口减到最少**。

核心机制分四层：

第一层是默认凭据——"能进去"的问题。出厂镜像把可用性放在安全性之前：固定用户名 + 固定口令 + SSH 服务默认启用，三者叠加意味着任何能路由到该设备的人都能直接拿到 shell，不需要任何漏洞。判断一台 IoT 设备是否"开箱即失守"，只需问三个问题：有没有固定默认凭据、远程服务是否默认开、服务是否监听在不可信网络上。处置是立即改口令、禁用不需要的远程服务、复测默认凭据登录应失败。

第二层是明文通道——"进去后看得见"的问题。即使认证做对了，远程桌面协议默认不做传输加密，键盘输入、屏幕内容、剪贴板全部明文过网。判据不是"有没有设 VNC 密码"——认证与传输加密是两件事，设了密码仍是明文。处置是换用支持加密的实现，或改走 SSH 端口转发到本地回环再连。

第三层是最小服务原则——"减入口"。每多一个常驻守护进程，就多一组版本、配置、凭据与解析器漏洞需要跟踪。裁剪服务收益双重：既减少可利用入口，又降低资源占用（对低算力设备尤其重要）。执行前提是"知道哪些服务在跑"和"知道它干什么"——禁用前必须搞清用途。

第四层是开机服务清点——"可操作的裁剪"。SysV 启动模型下，每个服务的启用状态是"运行级 × 服务"的矩阵。图形化表格（sysv-rc-conf）把矩阵摊开，避免手工翻 `/etc/rc*.d` 符号链接出错；还要区分运行级，多用户级关掉的服务在救援级可能仍需保留用于排障。

为什么把四者放在一个能力：因为它们的顺序不能乱——先枚举服务才知道该改哪些凭据、该关哪些通道、该裁哪些守护进程；而"默认凭据"和"明文协议"又分别对应"认证"与"加密"两个独立维度，缺一个都会出现"改了密码还被嗅探"或"加密了但默认口令能登"的半吊子结果。

## A1 — 应用示例 (Application Example)

### 示例 1: 默认 pi/raspberry 凭据

- **类型与来源**: 【转述+亲历】《Hacking Raspberry Pi》Chapter 5, Change User Password；Chapter 7, Secure Shell (SSH)
- **问题/输入**: 作者说明熟悉树莓派的人都知道默认用户名 pi、默认密码 raspberry，打算在 Pi 上存机密数据该怎么做。
- **方法论的使用**: 按 E 段：查默认账号口令（厂商文档/镜像内 `/etc/passwd`、`/etc/shadow`）；确认 SSH 默认状态（`raspi-config` 开关 / `ss -lntp`）；立即改口令（`sudo passwd pi`）并禁用不需要的远程服务；复测用默认凭据登录应失败。
- **结论**: 任何能路由到设备的人无需漏洞即可拿到 shell；改口令是"修补既有入口"。
- **结果**: 作者的 SSH 演示即以 `pi/raspberry` 登录，并在 raspi-config 说明中点出默认凭据。

### 示例 2: 默认 VNC 明文传输

- **类型与来源**: 【转述】《Hacking Raspberry Pi》Chapter 7, Virtual Network Computing (VNC)
- **问题/输入**: 需要图形界面远程访问，设备在可能被嗅探的网络（公共 Wi-Fi、酒店网、同广播域）。
- **方法论的使用**: 检查所用 VNC 实现是否默认加密（书中 TightVNC 默认明文）；若必须用 GUI 远程，改为 SSH 端口转发到本地回环再连 VNC，抓包确认看不到明文会话；仅在可信网段临时开启，用后关闭端口。
- **结论**: 认证与传输加密是两件事；设了 VNC 密码仍是明文，"内网所以安全"是误判——公共 Wi-Fi 就是内网。
- **结果**: 原书在 VNC 章节开头即列出该默认缺陷，未给抓包实测数据。

### 示例 3: 用 sysv-rc-conf 把 tty 从 6 个减到 2 个

- **类型与来源**: 【亲历】《Hacking Raspberry Pi》Chapter 18, Various and Sundry Performance Tweaks
- **问题/输入**: 作者要减少开机常驻服务与本地控制台数量，降低攻击面与资源占用。
- **方法论的使用**: 安装并启动 `sysv-rc-conf`，出现服务 × 运行级表格；用方向键移动、空格切换某运行级下的开关，把目标服务在 2–5 级取消；按 Q 退出重启，用 `ss -lntp` 确认端口消失；另编辑 `/etc/inittab` 注释多余的 `respawn:/sbin/getty` 行。
- **结论**: 图形化矩阵比手工改符号链接更可靠；须区分运行级，救援级保留排障能力。
- **结果**: 原书作者把 tty 从 6 个减到 2 个并说明 runlevel 含义。

## A2 — 触发场景 (Future Trigger)

### 用户会在什么情境下需要它
1. 刚拿到一台设备/镜像，要列出"开箱即失守"的入口清单并逐个修补。
2. 设备要放到可能被嗅探的网络（公共 Wi-Fi、酒店、会场），需要确认远程管理通道是否明文。
3. 做基线加固，想按"最小服务"原则裁剪不必要的常驻守护进程，同时不破坏依赖链。
4. 远程管理通道"设了密码还是不放心"，需要区分认证与加密两个维度。

### 语言信号（出现这些就该激活）
- 中文：「拿到设备第一件事做什么」「default creds 怎么查」「IoT 出厂密码风险」「VNC 安全吗」「远程桌面被嗅探」「怎么关开机自启服务」「设备加固从哪开始」「缩小攻击面」
- English: "default credentials on IoT", "change pi password", "plaintext VNC", "disable unused services", "sysv-rc-conf", "reduce attack surface on SBC"

### 与相邻能力的区分
- 与 `device-discovery-exposure-assessment` 的区别：后者解决"设备在不在、是哪台"，本能力解决"找到之后能不能进去、进去后有多少入口"。默认凭据是入口问题，设备发现是定位问题。
- 与 `covert-remote-access-chain` 的区别：后者是把设备当网络链路节点使用（流量隐身），本能力是设备自身入口加固（不被攻破）。一个管"流量被不被看见"，一个管"设备被不被攻破"。
- 与 `remote-node-addressing` 的区别：后者让设备"可达"，本能力让"可达的设备"不那么容易被攻破；可达之后的安全由本能力负责。

## E — 可执行步骤 (Execution)

**必需输入**: 拿到设备或镜像；有网络可达路径或本地控制台；root 权限；有回滚手段（改配置前备份）。缺"本地控制台"时，裁剪服务要格外谨慎，避免把远程通道一起关掉导致失联。

**交付物与完成标准**: 一份入口清单（默认凭据 + 默认服务 + 明文协议 + 自启服务）+ 加固后复测结果。完成标准为"默认凭据登录失败"、"明文远程协议不再直接暴露"、"非必要服务在 2–5 运行级已关闭且核心业务不受影响"。

1. **枚举入口**
   - 做什么：查默认账号口令（厂商文档/`/etc/passwd`/`/etc/shadow`）；列默认监听端口（`ss -lntp`）；枚举开机自启项。
   - 完成标准：得到完整入口清单（凭据 + 服务 + 端口）。
   - 判停：若无法登录且无本地控制台，转 `boot-chain-card-imaging` 通过物理接触改配置，不要盲试。

2. **修补默认凭据**
   - 做什么：`sudo passwd pi` 等改掉默认口令；检查是否漏掉服务账户/数据库账户（如 phpMyAdmin 安装时另设的管理员口令）。
   - 完成标准：默认凭据失效；所有已知默认口令均已改。
   - 判停：仅改口令但保留默认用户名仍可被口令喷洒定向攻击，条件允许时一并改用户名或禁用该账户。

3. **处置明文远程协议**
   - 做什么：确认 VNC 等实现是否默认明文；若需 GUI 远程，改为 SSH 端口转发到本地回环再连 VNC；抓包确认无明文。
   - 完成标准：抓包看不到明文会话；直连端口仅在可信网段临时开启且用后关闭。
   - 判停：若目标网络无法保证可信且无法上隧道，则停用 GUI 远程，不要"设了密码就当安全"。

4. **按最小服务原则裁剪**
   - 做什么：逐项判定自启服务是否业务必需、是否监听外部地址；关闭可关停项并复测业务功能。
   - 完成标准：核心功能不受影响；非必要服务不再运行。
   - 判停：盲关导致依赖链断裂（如关掉网络管理后失联）时，立即从救援级恢复该项；只关端口不改自启会在重启后复现，必须同时处理自启。

5. **运行级精调与记录基线**
   - 做什么：在 SysV 系统用 `sysv-rc-conf` 调整服务 × 运行级矩阵；按需编辑 `/etc/inittab` 减少本地 tty；记录基线供后续变更比对。
   - 完成标准：端口在 `ss -lntp` 中消失；基线文档可复核。
   - 判停：若系统是 systemd 而非 SysV，`sysv-rc-conf` 无效，改用 `systemctl`（本卡命令不适用）；关掉全部 getty 且远程不通会彻底失联，至少保留一个本地控制台。

6. **复测与留痕**
   - 做什么：用默认凭据登录应失败；复测业务功能；汇总加固前后对比。
   - 完成标准：三项复测通过，文档齐备。

## B — 边界 (Boundary) ★

### 不要用的情况
- 设备完全离线、永不接入任何网络时，远程入口加固的优先级降低（本地物理安全另论）。
- 业务必须依赖某个默认开启的服务且无法替换时，不能简单关停，只能做认证/加密加固。
- 使用 systemd 的系统上，`sysv-rc-conf` 与 `/etc/inittab` 方法不适用，照做无效。
- 没有回滚手段且只有远程通道时，不要一次性裁剪多个服务，否则失联后无法恢复。

### 已知失败模式
- **只改口令不改用户名**（《Hacking Raspberry Pi》Ch5）：保留默认用户名仍可被口令喷洒定向攻击。
- **改系统口令漏掉服务账户**（Ch5）：如 phpMyAdmin 安装时另设的管理员口令，漏改则入口仍在。
- **"设了 VNC 密码就安全"**（Ch7）：认证与传输加密是两件事，设密码仍是明文；"内网所以安全"误判——公共 Wi-Fi 就是内网。
- **盲关服务断链**（Ch18）：关掉网络管理后失联；只关端口不改自启，重启后复现。
- **工具版本错配**（Ch18）：systemd 系统上 `sysv-rc-conf` 无效；`/etc/inittab` 已在新版废弃；关掉 getty 后失去本地控制台且远程不通则彻底失联。

### 作者与时代的局限
- 书中以 Raspbian Wheezy 的 SysV/init 为例；现代发行版普遍用 systemd（`systemctl`），命令与配置路径已变，但"枚举入口→最小服务→复测"的机制不变。
- 作者讨论的默认凭据是 pi/raspberry 这一具体值；今天多数 IoT 设备仍有默认口令，但形式各异（序列号、空口令、Web 后台默认管理员），需按实际设备查证。
- 本书是工程手册，不涉及口令喷洒的规模化对抗、账户锁定策略或集中认证，这些不在本能力范围。

### 容易混淆的方法
- **认证 vs 传输加密**：默认凭据是认证问题，明文 VNC 是加密问题；两者独立，任一单独处理都不够。
- **修补入口 vs 减少入口**：CU-1-11 是修既有入口（改口令），CU-1-13 是减入口（关服务）；顺序上先枚举再分别处理。
- **服务暴露 vs 信息暴露**：CU-1-13 管服务暴露，CU-1-09 管信息暴露（公开登记）；前者是"开着多少服务"，后者是"泄露了多少存在性"。
- **常驻服务 vs 定时任务**：CU-1-14 管开机常驻服务，CU-1-22 管 cron 周期触发；裁剪时不要混淆。

### 授权与合规边界
> 待补充（用户自行填写）
