# 远程隐身接入链路的搭建与保护范围判定

## R — 原文 (Reading)

> "Because from the perspective of your ISP or Internet access provider, you are connecting to a 'safe' server. The proxy server masks your true web browsing targets from your ISP."
>
> — 《Hacking Raspberry Pi》Chapter 17, Building Your Raspberry Pi VPN Gateway / Building Your Raspberry Pi Proxy Server

> "As I said earlier, the exit node is the vulnerable point in the Tor network because it is possible for a malicious individual to configure his computer as a Tor exit node, sniff unencrypted traffic from the Tor network... unless you are using HTTPS or another encryption technology, your unencrypted data that enters the Tor network emerges from that network equally unencrypted."
>
> — 《Hacking Raspberry Pi》Chapter 17, Building a Raspberry Pi Tor Proxy

> "Because the Pi is multi-homed (that is to say, it has more than one network interface), you can use the Wi-Fi connection as your entry point for Tor communications and the wired Ethernet connection as your gateway to the Internet."
>
> — 《Hacking Raspberry Pi》Chapter 17, Building a Raspberry Pi Tor Proxy（Onion Pi）

## I — 方法论骨架 (Interpretation)

这个能力解决的是两件绑在一起的事：**用一台廉价单板机搭出一条"对外隐身/可携带"的网络链路，然后判断这条链路到底保护了什么、没保护什么**。拆开看是"搭"和"判"，但必须放在一个能力里——因为不先判清保护范围就去搭，会得到"以为匿名就安全"的错误用法；只判不搭，则没有可交付的链路。

核心机制有三条：

第一条是"叠加而非替代"。单层手段各有盲区：VPN 只保证链路加密，不改变出口地理位置；代理只改写出站目的地，不加密链路。把两者叠在一台 35 美元的 SBC 上——设备既是 VPN 成员又是 HTTP 代理——外部观察者只看到"你连到家里那台机器"，既隐藏目的地又隐藏内容。可用性来自成本极低：一台设备可随时重置、丢弃，不牵涉办公网资产。

第二条是"多宿主解耦"。双网卡把"接入"和"上联"分开：Wi-Fi 侧对客户端提供受控入口，以太网侧接任意不可信上联（酒店、会场）。设备自带完整 OS 与无线网卡，无需在目标主机装任何软件，也不留客户端痕迹。这是廉价 SBC 相对"在笔记本上装工具"的核心优势——环境隔离、可整体丢弃。

第三条是"逐层判断保护范围"。匿名网络只解决"谁在访问"，不解决"访问内容是否可读"。把链路拆成入口段、中继段、出口段，逐段标注"是否加密、谁可见"。任何一段解密后落地明文，该段以下的攻击者就能读内容。因此"用了 Tor/VPN"不能作为传输敏感凭据的理由，必须另加应用层加密（HTTPS）。出口节点是薄弱点：恶意者可把机器配成出口节点嗅探明文，但普通用户主要风险不在被"选中"，而在自身明文外发。

为什么这样做：因为这类设备的价值恰恰在于" disposable（可丢弃）"——链路出了问题可以整机重置，不牵连固定资产。要让这个价值成立，就必须把"搭的流程"和"保护的边界"写在一起，让使用者在配置的时候就同时在心里跑一遍"这段加密了吗"。

## A1 — 应用示例 (Application Example)

### 示例 1: Columbus 工作站经 Nashville 的 Pi 代理后归属地改变

- **类型与来源**: 【亲历】《Hacking Raspberry Pi》Chapter 17, Building Your Raspberry Pi Proxy Server（图 17.7/17.9）
- **问题/输入**: 作者想验证代理是否真的改变了外部看到的访问来源地。
- **方法论的使用**: 先按 E 段搭好双层链路：在 Nashville 的 Pi 上装 Hamachi 客户端并获批、装 Privoxy 并绑定到 Hamachi 隧道地址、把 Columbus 工作站的浏览器代理指向该地址；然后用 IP 地理库站点比对代理前后的归属地。
- **结论**: 代理确实改变了外部观察者的归属判断，且链路地址只对隧道成员可见。
- **结果**: 原书中地理定位从 Columbus 变为 Nashville。

### 示例 2: 按层判断"用 Tor 传口令行不行"

- **类型与来源**: 【转述】《Hacking Raspberry Pi》Chapter 17, Building a Raspberry Pi Tor Proxy
- **问题/输入**: 作者讨论"Tor 是不是就安全了""能不能用 Tor 传密码"。
- **方法论的使用**: 画出链路分段（客户端→入口→中继→出口→目标），逐段标注加密状态；确认入口到出口段在 Tor 内加密，但出口到目标段取决于目标是否支持 TLS；若目标不支持 HTTPS，判定为"只能保护来源、不能保护内容"，因此不能用来传凭据。
- **结论**: 匿名 ≠ 机密；出口节点是薄弱点，明文进入 Tor 就明文离开。
- **结果**: 原书给出该判断，未给实测抓包数据。

### 示例 3: 【合成演练】把 Pi 做成随身多宿主 AP

- **类型与来源**: 【合成演练】按本卡 E 段规则与《Hacking Raspberry Pi》Ch17 工作流推演，非作者亲历结果
- **问题/输入**: 出差场景，现场只有一条不可信的有线上联（酒店网），想让笔记本经一台自带设备上网而不在笔记本上装任何软件。
- **方法论的使用**: 确认设备有 eth0 与 wlan0 两个接口；在设备上装 AP 软件与 Tor 客户端，Wi-Fi 侧做 DHCP/NAT 入口；现场先把以太网插入上联，再让笔记本加入设备自有 SSID；用出口 IP 核对是否走了上联侧；用毕断电。
- **结论**: 双接口把接入与上联解耦，设备可整体丢弃、不留客户端痕迹。
- **结果**: 这是按规则推演的预期行为，不代表任何真实现场的结果；原书也把详细步骤外链到 Adafruit 教程。

## A2 — 触发场景 (Future Trigger)

### 用户会在什么情境下需要它
1. 想在固定地点搭一台长期在线、可被自己随时连回的"出口盒"，又不想为此购买 VPS。
2. 出差/参会时需要一台随身设备，把不可信的现场上联转换成自己控制的入口，且不碰目标笔记本。
3. 团队里有人主张"用了 VPN/Tor 就能安全传口令"，需要有一个明确的逐层判据把关系说清。
4. 评估一条既有链路是否能承载敏感数据，或决定某个目标该走哪条通道。

### 语言信号（出现这些就该激活）
- 中文：「想隐藏真实出口 / 绕过地域限制又不想买 VPS」「cheap box as covert egress」「proxy + vpn on one board」「带一台小盒子出差做匿名接入」「travel router for covert browsing」「Tor 是不是就安全了」「用代理传密码行不行」
- English: "hide my egress with a cheap SBC", "multi-homed SBC as AP", "is Tor enough for credentials", "exit node sniffing", "proxy chained with VPN on one board"

### 与相邻能力的区分
- 与 `device-discovery-exposure-assessment` 的区别：本能力是主动搭建一条对外隐身的链路，后者是对既有环境做被动发现和暴露评估，方向相反。
- 与 `remote-node-addressing` 的区别：后者解决"让部署在外的设备能被连回来"（静态地址+DDNS），本能力解决"连回来之后流量怎么出去、保护什么"。前者是寻址，后者是链路。
- 与 `default-creds-minimal-services` 的区别：后者是设备自身的入口加固，本能力是把设备当作网络链路节点使用；一个管"设备被不被攻破"，一个管"流量被不被看见"。

## E — 可执行步骤 (Execution)

**必需输入**: 一台可 7×24 在线的双接口 SBC；托管 VPN 账号（书中 Hamachi，免费 5 主机）或等效 Mesh VPN；客户端可改代理设置；如做随身 AP 需现场可用的以太网上联。缺"VPN 账号"或"目标客户端可改代理"则先补，否则第 1/4 步无法执行。

**交付物与完成标准**: 一条可验证的链路（设备获得隧道地址、代理只监听隧道地址、客户端出口显示为设备侧地址）+ 一份逐段保护范围判定表（每段标注加密状态与可见方）。完成标准为"能访问 `http://privoxy.org/config` 显示正在被代理"且"归属地变为 SBC 所在地"。

1. **建立 Mesh VPN 并批准设备加入**
   - 做什么：注册托管 VPN，创建 Mesh 网络，保留"管理员手工批准加入"默认项；在 SBC 上安装 ARM 客户端，`hamachi login` / `attach` / `set-nick`，在 Web 控制台批准。
   - 完成标准：控制台可见网络 ID；设备获得 25.x.y.z 地址并出现在成员列表。
   - 判停：若"加入网络"与"批准加入"漏做一步导致连不通，先补齐两步再继续，不要跳到装代理。

2. **把代理绑定到隧道地址**
   - 做什么：`apt-get install -y privoxy`，把 `listen-address` 改为 `<Hamachi_IP>:8118`，`service privoxy restart`。
   - 完成标准：仅监听隧道地址而非 `0.0.0.0`。
   - 判停：若代理绑到 `0.0.0.0`，先改回隧道地址；开放代理会让局域网内任意主机借用，链路失去"只服务自己"的前提。

3. **配置客户端并验证链路**
   - 做什么：客户端浏览器代理指向该地址:8118，访问 `http://privoxy.org/config`；用 IP 地理库站点比对代理前后归属地。
   - 完成标准：页面显示"正在被代理"；归属地变为 SBC 所在地。
   - 判停：若归属地未变，回到第 1 步检查隧道连通性，不要误判为代理失效。

4. **逐层标注保护范围**
   - 做什么：画链路分段（客户端→入口→中继→出口→目标），逐段标注"是否加密、谁可见"；标出明文落地段（通常出口到目标）。
   - 完成标准：得到每段加密状态表。
   - 判停：若目标不支持 TLS，判定该路径"只能保护来源、不能保护内容"，不得用它传凭据，转第 5 步决定是否改用其他通道。

5. **按需切换为随身多宿主 AP**
   - 做什么：确认 `ifconfig` 同时出现 `eth0` 与 `wlan0`；装 AP 软件与 Tor 客户端，Wi-Fi 侧做 DHCP/NAT 入口；现场先插以太网，再让客户端加入自有 SSID；用出口 IP 核对。
   - 完成标准：客户端出口 IP 为上联侧地址；用毕断电无残留配置到宿主。
   - 判停：若 USB Wi-Fi dongle 供电不足导致 AP 不稳，转 `power-supply-hardware-reliability` 排查供电。

6. **输出与留痕**
   - 做什么：汇总链路拓扑图、配置要点、逐段保护范围判定表。
   - 完成标准：三份材料齐备，可被第三方按图复核。

## B — 边界 (Boundary) ★

### 不要用的情况
- 目标链路承载敏感凭据且目标不支持 HTTPS 时，本能力判定"不适用"——匿名链路不能替代应用层加密。
- 设备只有单一网络接口时，做不了"无线入 / 有线出"的多宿主 AP 形态。
- 现场上联本身被防火墙/隔离限制到只允许特定 MAC 时，随身 AP 可能无法获得地址。
- 需要持久、可审计的企业级出口时，廉价可丢弃设备的"无留痕"反而是缺点，本能力不适用。

### 已知失败模式
- **代理绑 0.0.0.0 成开放代理**（《Hacking Raspberry Pi》Ch17）：书的配置示例特意绑隧道地址；绑成全网卡监听会让局域网内任意主机借用。
- **Hamachi 两步分离**（Ch17）："加入网络"与"Web 控制台批准加入"是两步，漏一步就连不通。
- **出口节点嗅探明文**（Ch17）：恶意者可配出口节点嗅探未加密流量；作者同时指出普通用户主要风险在自身明文外发，而非被"选中"。
- **"匿名=机密"误判**（Ch17）：把"用了 Tor/VPN"当成可传口令的理由。
- **Wi-Fi dongle 供电不足**（Ch7/Ch16）：USB 无线网卡供电不足致 AP 不稳；详细步骤外链教程，照书内工作流做会缺细节。

### 作者与时代的局限
- 书中用 Hamachi（免费 5 主机）与 Privoxy 为例，是 2010 年代方案；今天的 Mesh VPN 生态（Tailscale/WireGuard 等）已不同，但"叠加 + 绑定到隧道地址"的机制不变。
- 作者把 Onion Pi 的详细步骤外链到 Adafruit 教程，书内只给工作流；按书照做需自行补细节。
- 本书是工程手册，不涉及绕过企业出口管控、检测规避或主动对抗；把这些期待投射到本能力上是误用。

### 容易混淆的方法
- **VPN vs 代理**：VPN 加密链路但不改出口地理位置，代理改写目的地但不加密；叠加才互补。把它们视为可互相替代会得出错误结论。
- **隐藏出口 vs 隐藏内容**：前者靠链路位置，后者靠应用层加密；本能力要求两者分别判断。
- **固定网关 vs 随身 AP**：CU-1-01 是"固定地点做出口"，CU-1-03 是"随身携带做入口"；形态与信任边界不同。
- **搭建流程 vs 适用范围判定**：CU-1-01 讲怎么搭，CU-1-02 讲能防什么、防不住什么；本卡把两者放在一起但步骤上分开。

### 授权与合规边界
> 待补充（用户自行填写）
