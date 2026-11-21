# CTF与靶场 — 域总览

## 这个域在真实工作中解决什么问题

这个域解决「给定一个竞赛环境里的目标，如何在有限时间内把它拿下并稳定交付」的全流程问题。它覆盖从附件到手后的第一分钟判断（`file`/`checksec`/魔数扫描），到中段的漏洞利用与求解（格式化字符串、BROP、Web 漏洞判型、文件包含、命令外带、逆向求解），再到整场比赛的组织（AWD 自动化进攻与防守）和靶场推进（五段交付物与止损）。其共同特征是**高时间压力 + 信息不完整 + 目标物形态多样**：flag 可能在 `.data` 段里、在远端文件里、在嵌套容器里，也可能是程序期望的一个输入串。因此本域的能力卡都围绕「先判方向再投入」「每一步都有可观测判据」「结果必须回目标验证」三条纪律组织，而不是罗列技巧。

## 能力地图

| 二级分类 | 能力（slug） | 中文标题 | 定位 | 主要来源 |
|---|---|---|---|---|
| 漏洞定位 | `pwn-opening-protection-read` | Pwn 题型起手：可打面与保护组合判读 | promoted | ctf-all-in-one + Handbook Ch6 |
| 利用与提权 | `format-string-exploitation` | 格式化字符串漏洞的四步利用 | promoted | ctf-all-in-one 3.1.1/6.1.2 + Handbook Ch6 |
| 利用与提权 | `blind-rop-brop` | 无附件盲打：从探针到 BROP | router | ctf-all-in-one 6.1.1 |
| 逆向分析 | `reverse-entry-runtime` | Reverse 通法：起手定位与运行期处置 | promoted | ctf-all-in-one + Handbook Ch5 |
| 逆向分析 | `check-solver-trilogy` | 校验逻辑求解三路径 | router | ctf-all-in-one 6.2.1~3 |
| 取证与溯源 | `artifact-forensics` | Misc 与取证附件：分层拆解到取证镜像 | router | ctf-all-in-one 2.4.4/9.1 + Handbook Ch9 |
| 工具链 | `encoding-classical-cipher` | 编码与古典密码的特征识别 | router | Handbook Ch7 |
| 侦察 | `web-recon-source-leak` | Web 起手：元信息收集与源码泄露推进 | router | Handbook Ch1 + Vulnhub |
| 服务端逻辑 | `web-vuln-channel-selection` | Web 漏洞判型与利用通道选择 | router | Handbook Ch1~3 |
| 服务端逻辑 | `file-read-and-include` | 文件读与包含：从确认漏洞到 getshell | router | Handbook Ch1 + Vulnhub |
| 利用与提权 | `rce-egress-and-shell` | 命令执行外带与反弹 shell 落地 | router | Handbook Ch2 + Vulnhub |
| 工程化 | `awd-attack-defense` | AWD 攻防节奏与 flag 通道 | router | ctf-all-in-one 1.1 + Handbook Ch11 |
| 工程化 | `lab-workflow-and-triage` | 靶场推进：阶段交付物与止损判断 | router | Vulnhub + 混合剂 v1.0 |
| 利用与提权 | `lab-privesc` | Linux 靶场提权：路线排序与配置错误 | router | Vulnhub |

共 14 个能力、3 个 promoted（对外独立入口）、11 个 router（域内路由入口）。覆盖 8 个二级分类：漏洞定位、利用与提权、逆向分析、取证与溯源、工具链、侦察、服务端逻辑、工程化。

> 聚类规模说明：任务下达时仅有 batch-1（20 单元），据此建议「5–7 个能力」。执行期间 batch-2、batch-3 陆续落盘，单元数增至 69、来源扩至 4 本，原「单元数少」前提失效，故按 SYNTH_BRIEF 的 8–14 聚类规则调整为 14 个能力；promoted 仍严格保持 3 个。

### 路由关系

- 拿到 pwn 附件 → `pwn-opening-protection-read`，其输出（保护组合、泄漏条件、目标物位置、栈/堆分道）决定下游：确认 fmt → `format-string-exploitation`；无附件且无泄漏原语 → `blind-rop-brop`。
- 拿到逆向附件 → `reverse-entry-runtime`；修到能跑并定位校验逻辑后 → `check-solver-trilogy`。
- 拿到图片/固件/pcap/镜像附件 → `artifact-forensics`；若是文本编码串 → `encoding-classical-cipher`。
- 拿到 Web 目标 → 先 `web-recon-source-leak` 找入口与源码；发现具体漏洞后按类型分流：`web-vuln-channel-selection`（SQLi/SSRF/XSS/逻辑）、`file-read-and-include`（文件读/包含）、`rce-egress-and-shell`（命令执行外带与反弹）。
- 赛制为 AWD → `awd-attack-defense`；单台靶场推进 → `lab-workflow-and-triage` 调度阶段，提权段交 `lab-privesc`。

## 域的共性失败模式

1. **判错方向后继续投入**：不读 checksec 就抄栈溢出模板、把静态链接当动态链接、把 flag 已在程序内的题当必须拿 shell、SQLi 不判型就套闭合（4.4、6.1.13、Ch1）。
2. **把本地/靶场条件当成目标条件**：本地关 ASLR、用 `-fno-stack-protector` 样本自测；把靶场「必有解、可重启、可单用户模式」的预设带进实战（4.4、混合剂 v1.0）。
3. **off-by-one 类偏移错误**：fmt 忘算格式串本身是第一个参数；侧信道把 `Count 5` 当成匹配 5 字节；ZIP 标志位只改一处（3.1.1、6.2.1、Ch9）。
4. **架构与版本经验直接迁移**：x86-64 参数走寄存器、有符号取模写成无符号除法、32/64 位 exp 混用、本地编译环境与目标不一致（3.1.1、6.2.2、Vulnhub The Ether）。
5. **排布与截断**：地址放在格式串前被 `\x00` 截断；dump 遇 `\x00` 不补字节死循环；HTTP 传命令不 urlencode、下载文件不 chmod（6.1.2、Vulnhub The Ether）。
6. **只处理第一处**：angrybird 6 处 patch、反调试多处检测、Git 泄露只跑一个自动工具、ZIP 只改一个标志位、Web shell 不做驻留（6.2.3、3.2.4、Ch1、Ch11）。
7. **把「看不到」当成「没成功」**：工具无回显就放弃（exit 后才刷出哈希）、命令看似没执行其实是缓冲、快照无回显就换 payload、扫描器没扫到就判无漏洞（Vulnhub Breach1.0、Ch2、Vulnhub Acid）。
8. **把中间结果当结果**：Z3 的 sat、angr 的 found、Base64 输出、zsteg 随机候选、找到密码未验证都只是候选，必须回填验证（6.2.2/3、Ch7、Ch9）。
9. **在错误的载体上做分析**：未拆的容器上做 LSB、有 fmt 读却走 BROP、无泄漏却硬做频域相减、真实环境套靶场老漏洞清单（Ch9、6.1.2、Vulnhub Kioptrix1）。

## 覆盖说明

四篇源书均有贡献：

| 源书 | 贡献的能力 |
|---|---|
| 《ctf-all-in-one.pdf》 | pwn 起手、格式化字符串、BROP、Reverse 通法与求解、AWD 基础、binwalk/foremost 工具级用法（20 单元） |
| 《Handbook for CTFers.pdf》 | Web 信息收集与 Git 泄露、SQLi 判型、任意文件读、SSRF/gopher、无回显外带、XSS、逻辑漏洞、算法与库识别、fmt 变体、编码与古典密码、Misc/取证全章、AWD 准备与流量（25 单元） |
| 《Vulnhub靶场实战指南.pdf》 | 五段推进与止损、线程控制、方法绕过、反弹 shell 与落地细节、Linux 提权排序与配置错误、凭据查找、日志投毒、清理脚本（22 单元） |
| 《打造CTF 肾透测试兴奋混合剂v1.0.pdf》 | CTF 与实战的可解性/时间预设差异、手法频率错位（2 单元） |

### 已知缺口（原书无内容）

- **Crypto 现代密码学**：ctf-all-in-one 的 1.6 只有标题、第六章无 Crypto 题解；Handbook 只有编码与古典密码 → 无 RSA/AES/椭圆曲线等方法。
- **Misc 脑洞类**：无编码识别以外的脑洞题型方法。
- **Web 深度利用**：无完整的 WAF 绕过体系、无 Spa/API 安全、无服务端模板注入等现代主题。
- **解题赛选题与时间分配**：只有 AWD 规则与靶场推进，无 Jeopardy 的选题策略。
- **堆利用具体手法**：只到 first_fit / 基础 bin 攻击，未覆盖 tcache stashing、largebin attack 等。
- **APK/智能合约/代码审计**：Handbook 相关章节仅扫读，无候选单元。

这些缺口在 `coverage-audit.md` 中逐项登记，后续批次应新增能力卡而不是塞进现有 14 张卡。
