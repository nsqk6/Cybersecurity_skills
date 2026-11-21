# 硬件与物联网安全 — 术语表

只收"读能力卡时会卡住"的域内术语；通用词（SSH、cron、VPN 的一般概念等）不收。

| 术语 | 英文 | 在本域语境下的含义 |
|---|---|---|
| 单板机 | SBC (Single-Board Computer) | 自带完整 OS 的小型计算机（如树莓派），可长期在线、可整体丢弃；与仅跑单一固件的 MCU 相对。 |
| 无头设备 | Headless | 没有接显示器/键盘的设备；定位它不能靠屏幕，要靠二层扫描与厂商字段。 |
| OUI / MAC 厂商前缀 | OUI (Organizationally Unique Identifier) | MAC 地址前 3 字节对应的厂商代码，用于在扫描结果里筛选某型号板卡；换 USB 网卡后会变成网卡厂商。 |
| 厂商字段 | Manufacturer field | 扫描器解析网卡固件元数据得到的厂商标识（如 "Raspberry Pi Foundation"），比猜 IP 更可靠的筛选维度。 |
| 动态域名 | DDNS (Dynamic DNS) | 把易变的公网 IP 绑定到固定域名的服务；解决 ISP 换 IP 后远端失联，因 DHCP 是租约式协议。 |
| DHCP 租约 | DHCP lease | 地址是"租用"的，到期可能变；所有指向该地址的端口转发/记录随之失效，是静态地址存在的理由。 |
| Mesh VPN | Mesh VPN | 成员间可互联的 VPN 拓扑（书中 Hamachi 免费 5 主机）；"加入网络"与"控制台批准"是两步。 |
| 出口节点 | Exit node | 匿名网络中流量离开并抵达目标的最后一跳；恶意者可配成此节点嗅探明文，是分层判断的重点段。 |
| 多宿主 | Multi-homed | 具备多个网络接口（如 eth0 + wlan0）；可把"接入"与"上联"解耦，Wi-Fi 做入口、以太网做上联。 |
| 隧道地址 | Tunnel address | VPN 分配给设备的内网地址（如 25.x.y.z）；代理应只绑定该地址，绑 0.0.0.0 会成开放代理。 |
| 毫安时 | mAh | 电池容量单位；续航(h)=容量(mAh)÷平均电流(mA)，平均电流须含主板+全部 USB 外设。 |
| 欠压 | Undervoltage | 供电不足致随机重启/文件系统只读/外设掉线；板载电容不能补偿持续欠压，判据是换电源后消失。 |
| 纹波 | Ripple | 电源输出上的交流残留波动；与电压跌落共同造成无规律挂起，需万用表测量而非看日志。 |
| 测试点 TP1/TP2 | Test point TP1/TP2 | 板上测量 5V 的两个触点（红/黑）；位置因板型而异，新型号需查原理图。 |
| Shift 旁路 | Shift-key boot bypass | 启动瞬间按住 Shift 仅本次忽略 `/boot/config.txt` 超频项，用于救回改坏配置；只本次生效。 |
| 粘性位 | Sticky bit | SoC 内一旦触发即永久保持的标记；超过安全阈值即置位，用户态无法清除，是硬件层取证判据。 |
| OTP 熔丝 | OTP fuse (One-Time Programmable) | 一次性可编程电路；与 sticky bit 同属不可逆痕迹，比日志更难伪造，但只覆盖厂商定义的越界参数。 |
| CPU Revision 值 | CPU Revision | `/proc/cpuinfo` 中的修订号；书中以 Revision>1000 判 sticky bit 已置位，具体编码随批次/固件变化需同型号基线。 |
| FAT32 /boot 分区 | FAT32 /boot partition | 启动介质中 Windows 唯一可读的分区，存放内核、GPU 固件与启动参数；无权限模型，物理接触即可读写。 |
| cmdline.txt | cmdline.txt | 启动时直接送给固件的底层命令配置文件；改它可影响启动链，属可写启动组件之一。 |
| config.txt | config.txt | 存放超频/电压等启动参数；改坏会导致系统读配置前挂死，需用 Shift 旁路恢复。 |
| start.elf | start.elf | GPU 固件镜像；旧版可用 `arm240_start.elf` 覆盖调整内存划分，新版只剩单一文件，旧改法失效。 |
| dd 的 if/of/bs | dd if/of/bs | 按字节复制整卡的三个参数：输入文件/输出文件/块大小；`of=` 选错会覆盖本机磁盘（"Data Destroyer"）。 |
| 整卡镜像 | Whole-card image | 含分区表+引导扇区+启动分区+根文件系统的原始字节副本；按文件复制无法还原引导能力。 |
| SysV 运行级 | SysV runlevel | "运行级 × 服务"的启用矩阵；裁剪服务要区分多用户级(2-5)与救援级，后者保留排障能力。 |
| sysv-rc-conf | sysv-rc-conf | 把 SysV 启动矩阵摊成图形表格的工具；仅 SysV 适用，systemd 系统无效。 |
| getty / tty | getty / tty | 本地控制台登录进程与终端；减 tty 可降攻击面，但全关且远程不通会彻底失联。 |
| 最小服务 | Least service | "不运行的服务无法被攻破"原则；裁剪既减入口又降资源占用，前提是搞清服务用途并保留回滚。 |
| SPI 总线 | SPI (Serial Peripheral Interface) | 高速板级总线；常被 modprobe 黑名单禁用致 `/dev/spidev*` 不存在，需先解除禁用再装封装库。 |
| I2C 主从 | I2C master/slave | 两线总线；正确配置时可免电平转换器，但主从配错会造成过压烧板（作者原话警告）。 |
| GPIO | GPIO (General-Purpose I/O) | 通用引脚；有 5V 取电引脚不代表 IO 容忍 5V 逻辑，信号仅容 3.3V 且无内置过压保护。 |
| 电平转换器 | Logic level converter | 跨 3.3V/5V 连接时必用的分压电阻或专用芯片；缺它直连会经保护二极管灌电流烧引脚或击穿核心。 |
| modprobe 黑名单 / dtparam | modprobe blacklist / dtparam | 禁用/启用内核模块的两种机制；旧版用 `raspi-blacklist.conf`，新版用 `dtparam=spi=on`，照抄旧文件名无效。 |
