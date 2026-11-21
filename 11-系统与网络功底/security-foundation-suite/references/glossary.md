# 系统与网络功底 · 术语表

只收「读能力卡时会卡住」的词；通用 shell 常识（如 `grep`、`awk` 是什么）不收。

| 术语 | 英文 | 在本域语境下的含义 |
|---|---|---|
| 管道 | pipeline | 把排查拆成「选行→整形→聚合」三段，每段只在文本流上做一件事；改错一段不影响其他段。 |
| 文本流 | text stream | 工具之间传递的字节序列，被当作通用接口；管道只传字节不传语义，上游列数变了下游会静默算错。 |
| 增量逼近 | incremental refinement | 先给最小可行命令拿候选集，看剩余噪声后再逐段追加，而不是一次写出长管道。 |
| 选行 / 整形 / 聚合 | selection / reshaping / aggregation | 管道三段的分工：`grep`/`find` 缩小集合，`cut`/`sed`/`awk` 对齐字段，`sort`/`uniq`/`awk END` 出结论。 |
| BRE | Basic Regular Expression | sed 默认正则方言：量词写 `\+`、`\{3\}`，分组写 `\(...\)`，`\d` 不存在；按 PCRE 直觉写会"成功但什么都没替换"。 |
| PCRE | Perl Compatible Regular Expression | Perl/Python 风格正则；从这类语言搬表达式到 sed 是高频静默失效来源。 |
| 反向引用 | backreference | `\1` 等引用前面捕获组；在 sed 的 BRE 中捕获组必须写成 `\(...\)`。 |
| FS | Input Field Separator | awk 的输入字段分隔符；可用正则一次覆盖多种分隔符，如 `FS="[,:%]"`。 |
| NF | Number of Fields | awk 当前记录的字段数；`$(NF-1)` 表示从右数第二段，用来对抗字段数漂移。 |
| NR | Number of Record | awk 整个运行期的累计行号；一次处理多个文件时会跨文件累加，逐文件判定用它必然偏移。 |
| FNR | File Number of Record | awk 当前文件内的行号；多文件批量判定必须用 FNR，不能用 NR。 |
| END 块 | END block | awk 在所有行读完后执行的汇总块；累加器、计数变量在此输出最终结论。 |
| 空跑 | dry-run | 把 `-exec` 里的破坏性动作换成 `ls -l` 或 `echo`，用同一表达式先看确切清单，再执行真实动作。 |
| 爆炸半径 | blast radius | 一条命令实际影响的范围；`chmod -R` 从高位目录执行会把整棵子树纳入半径，且无回执、无撤销。 |
| NUL 分隔 | `-print0` / `xargs -0` | 用 NUL 字节分隔文件名，绕开空白分词；解决"文件名含空格被拆词"与"参数过长"两个独立故障。 |
| 参数过长 | Argument list too long | 一次 exec 传入的参数超过内核上限；交给 xargs 分批，但必须配合 `-0` 才不会拆错对象。 |
| 原地编辑 | in-place edit (`sed -i`) | 写临时文件再改名；中途中断留半截文件、原内容消失，必须 `-ibak` 或"写新文件+diff+mv"。 |
| 模式范围 | address range | sed 用 `/start/,/end/` 按内容锚定区间，比行号稳定；end 不闭合会打到文件尾。 |
| 不可见字符 | hidden characters | 制表符、CRLF、行尾控制字符等；`sed -n l` 把它们显形成 `\t`、`$`，否则"看起来一样却匹配不上"。 |
| 退出码 | exit status (`$?`) | 命令成功/失败的信号；必须 `rc=$?` 先存再判断，中间插 `echo` 读到的是 echo 的 0，失败被伪装成成功。 |
| 展开跟踪 | `set -x` | 显示变量展开后的实际命令与参数，回答"变量到底变成了什么"；关闭用 `set +x`（与直觉相反）。 |
| 命令替换 | command substitution | 反引号或 `$()` 执行的子命令；双引号内会展开，单引号内字面化，不可信文件内容可借此诱导执行。 |
| HISTTIMEFORMAT | history time format | bash 给 history 记录加绝对时间戳的变量；只对设置之后新写入的记录生效，旧记录补不上时间。 |
| suid / sgid | set-user-ID / set-group-ID | 执行时以文件属主/属组身份运行的权限位；是提权面，也可能是正当的权限委托手段。 |
| 小写 s 与大写 S | lowercase `s` vs uppercase `S` | 小写 s = suid 且执行位仍在（有效面）；大写 S = suid 但执行位未设，文件不能执行，应剔除。 |
| 受限模式 | restricted mode (`vim -Z`) | 关闭一切外部 shell 出口（`CTRL-Z`、`:sh`、过滤、`system()`、反引号展开），防止不可信文件内容诱导执行。 |
| 只读模式 | read-only (`vim -R` / `view`) | 防止误按 `dd`/`:wq` 改动证据原件；作者原话是 "avoid making any unintentional modifications"。 |
| swap 文件 | swap file (`.<name>.swp`) | vim 编辑期间的缓冲区写入；崩溃后残留，可能含当前版本已删除/改写的片段及 owner/时间/主机/PID 元数据。 |
| 显示行 | display line (`gj`/`gk`) | 屏幕上折行后的视觉行；超长无换行记录按 `j` 会跳过整段，按 `gj` 才按视觉行移动。 |
| FD 列 | file descriptor column | lsof 输出中标识句柄性质的列：`txt` 是执行的二进制、`cwd` 是工作目录、`mem` 是加载的库。 |
| 易失数据 | volatile data | 进程退出即消失的连接表、可被清空的 history、可被覆盖的 swap；取证时必须先抓先保全。 |
| 时间线 | timeline | 把 netstat/lsof 的 PID 归因与带时间戳的 history、auth/web 日志逐条对齐后形成的有序事件序列。 |
