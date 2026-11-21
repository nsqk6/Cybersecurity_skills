# 系统与网络功底 · 域总览

## 这个域在真实工作中解决什么问题

本域解决的是「在一台 Linux/Unix 主机上，用系统自带工具把现象变成可核验结论」的一类基础工作：从一份日志里快速统计出总量或 Top N，把一堆文件安全地批量处理，让脚本失败了能被看见，把异常外连归因到进程与账号，以及在不动原件的前提下检视可疑文件。它的共同特征是**工具随手可得、单次任务为主、结论必须可复核**——所以方法论的核心不是写复杂程序，而是控制"命令跑通了但结果错"的静默失效，并为不可逆操作留下退路。这些能力是上层渗透、应急响应、取证分析工作的地基：结论口径不稳，后续所有判断都会跟着偏。

## 能力地图（二级分类 → 能力）

| 二级分类 | 能力 | slug | 重要度 | 对外入口 |
|---|---|---|---|---|
| 工具链 | 文本处理管道排查 | `text-processing-pipeline` | critical | promoted |
| 工具链 | 字段与正则正确性 | `text-field-and-regex` | high | router |
| 工程化 | 批量文件操作与传递 | `batch-file-operations` | high | router |
| 工程化 | shell 脚本可靠性 | `shell-script-reliability` | high | promoted |
| 取证与溯源 | 命令行取证组合 | `cli-forensics` | critical | promoted |
| 取证与溯源 | 可疑文件安全检视 | `untrusted-file-inspection` | medium | router |
| 检测与响应 | 权限操作安全 | `permission-operations` | high | router |

共 7 个能力，覆盖 4 个二级分类。**promoted 共 3 个**：受本域"对外最多暴露 3 个入口"的名额上限约束；router 卡同样是 active 能力，通过域内路由触达，并非晋级判据未过（详细判据见 `verified.md`）。

### promoted 入口的典型任务链
- 文本排查：`text-processing-pipeline` →（结果可疑）→ `text-field-and-regex`
- 脚本调试：`shell-script-reliability` →（参数/文件问题）→ `batch-file-operations`
- 主机取证：`cli-forensics` →（看可疑文件内容）→ `untrusted-file-inspection`

## 域的共性失败模式

1. **静默失效优先于报错**：sed 的 `\d`/`+`、awk 的 `==` 与 `~`、grep 未加引号、NR 跨文件累加、漏掉第一段 `sort`——这些错误都"成功执行但结果错"，比直接报错危险得多。统一对策是：每步保留可视输出，用最小样本验证后再进入下一步。
2. **易失数据先抓**：netstat 连接表随进程退出消失，history 可被清空/忽略，swap 会在错误菜单选择中被覆盖。取证顺序错了就无法补救。
3. **不可逆操作无回执**：`chmod -R`、`sed -i`、`find -exec rm` 都不产生"我改了 N 个对象"的回执，也没有撤销键。统一对策是"先列清单/快照 → 留副本 → 变更后抽样比对"。
4. **字段位置与语义漂移**：上游列数变化、分隔符混用、从右数与从左数取值的选择，会让聚合静默偏移。用 `$(NF-n)` 从右数、用正则做 FS、`{print NF}` 抽查是为对抗这一点。
5. **工具方言差异**：sed 用 BRE 而非 PCRE，GNU 与 BSD 的 `-i`/`-print0` 语法不同。从其他语言或系统搬命令时必须先在小样上验证。
6. **引号方向错**：模式要引、通配符文件名不要引；双引号保留展开、单引号字面化。搞反的表现都是"找不到明明存在的东西"。
7. **显示假象被当成数据事实**：vim 里超长单行折行显示，看起来像"跳过很多行"；`wc -l` 与视觉行数不符时先怀疑显示，不要先怀疑采集链路。
8. **权限位被误读**：suid 的大写 `S` 是无效设置，有执行权限不等于可执行程序。枚举结论必须区分大小写并核对文件类型。

## 覆盖说明：哪些书贡献了哪些能力

| 来源书 | 贡献的能力（单元数） | 主要贡献 |
|---|---|---|
| 《grep-find-sed-awk》 | text-processing-pipeline（3）、text-field-and-regex（2）、batch-file-operations（1） | Unix 哲学的管道三段式与增量逼近；find 传递三选一；sed/grep 的静默失效反例 |
| 《Linux 101 Hacks》 | text-processing-pipeline（2）、batch-file-operations（2）、cli-forensics（3） | 频次统计口径；find 空跑与 xargs 收口；netstat/lsof/history 取证组合 |
| 《Sed & awk 101Hacks》 | text-field-and-regex（4）、text-processing-pipeline（1）、batch-file-operations（1） | 模式范围抠块；FS/匹配运算符/NR-FNR；`-i` 备份纪律 |
| 《Linux与unix shell编程指南》 | shell-script-reliability（2）、permission-operations（2） | 脚本调试三纪律与引号规则；suid 按位枚举与 chmod 爆炸半径 |
| 《Vim 101 Hacks》 | untrusted-file-inspection（3） | 只读/受限/二进制三开关；超长行导航；swap 残留恢复 |

合计 25 个候选单元全部进入能力卡，无遗漏（详见 `coverage-audit.md`）。
《Shell脚本学习指南》提取文本仅含站点水印与广告行、无正文，未产出单元。
