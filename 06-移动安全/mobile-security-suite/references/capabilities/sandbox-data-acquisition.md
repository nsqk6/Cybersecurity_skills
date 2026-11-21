# 沙盒数据获取

## R — 原文 (Reading)

> This is because a directory can only be entered if it is executable for the caller that is attempting to enter it.

> — 《Mobile App Hackers Handbook》Chapter 7 "Accessing Storage and Logging → File and Folder Permissions"

> In summary, an attacker with physical access to a device can get the data that resides in an application's private data directory provided that the application allows backups.

> — 《Mobile App Hackers Handbook》Chapter 7 "Exploiting Misconfigured Package Attributes → Application Backups"

> The caller is shell or root. / The target package does not run as system. / The target package is debuggable.

> — 《Mobile App Hackers Handbook》Chapter 7 "Debuggable Flag"（run-as 三个前提，原文以三行条件列出）

## I — 方法论骨架 (Interpretation)

这个能力回答的是一句需求：**「不 root（或只要物理接触）能不能拿到一个 App 私有目录里的数据」**。它把三种彼此互补的取数路径放在一起：判文件系统权限链是否真的暴露、走备份接口导出并写回、走调试接口以应用身份执行。三条路径的前提不同、证据强度不同，混用会导致「文件 777 就报任意读取」「shell 能 cat 就报暴露」「能导出就报篡改」这类系统性误报。

核心机制分三块。第一块是**权限链判定**：Android 沿路径逐级检查 `x` 位，访问 `/data/data/<pkg>/databases/db` 要求路径上每一级目录对调用者都有 `x`。所以「文件 777」不等于「别人能读」——只要 `databases` 是 770，第三方 App 就在 `cd` 这一步被拒；反之一个 600 文件若所在目录 world-executable 而文件被误设 644，就是真暴露。判定必须沿整条路径逐级 `ls -ld`，并在**普通 App 上下文**里实测 `cat`，而不是在 root shell 里读权限位。配套口径：数字权限 r4+w2+x1，默认权限由 umask 决定——Android 4.0+ 在 `ZygoteInit` 设 `0077`（新文件 600/700），2.3 时代同代码得到 666，**同一份代码在不同系统版本暴露面不同**。第二块是**备份接口**：`android:allowBackup` 默认 true（IDE 新建工程也默认 true），于是绝大多数应用允许 `adb backup` 把私有目录打包成 `.ab`——本质是「24 字节头 + zlib 压缩的 tar」，去头解压即得明文目录树。价值不在「能读」而在**能写回**：`adb restore` 用改过的 `.ab` 覆盖沙盒，等于以应用自身权限篡改其数据（改密码、改上报 URL、换动态加载的 dex）。判定链：`aapt dump xmltree` 看属性（**缺失即 true**，非 0 皆为 true）→ `adb backup -nosystem -all -apk -noshared -f` → 解包 → 找明文凭据 → 改值写回验证。第三块是**调试接口**：`android:debuggable="true"` 让进程注册到 `@jdwp-control` 并允许 `run-as` 切换 uid（run-as 带 setuid 位，用 `setresuid()`/`setresgid()` 从 shell 切到应用用户），切换后当前目录直接置于 `/data/data/<pkg>`。`adb shell run-as <pkg> <命令>` 一条即可以应用身份执行任意命令，比连 jdb 省事；需要代码执行时再走 `adb forward tcp:4444 jdwp:<pid>` + `jdb -attach`。

为什么放一个能力：三条路径都止于「物理接触 / USB 调试」这一前提，都不需要 root 就能碰到应用私有数据，用户问的是同一句「不用 root 怎么看沙盒」。它们有清晰的判定分工——权限链判「数据到底有没有暴露」，备份/调试判「用什么接口拿到」；也有共同失败模式——root 上下文证据无效、忽略版本差异、只看「能导出」不看「能否还原」。读完这段应该能跑：先看目录 x 位链并实测 → 看 allowBackup 导出解包写回 → 看 debuggable 用 run-as/jdb → 标注每条成立的系统版本区间与前提。

**分发态硬编码数据补充**（Bug Bounty Bootcamp 补充）：还有一类"数据"根本不需要运行时获取，它就随 APK 分发——移动 App 要把访问 Web 服务所需的密钥打包进客户端，因此硬编码密钥比 Web 端更常见。三个固定检查点：`res/values/strings.xml`（字面字符串里的密钥/端点/凭据）、对解包目录用关键字表 grep（api_key/secret/token/password 等）、以及随包携带的 `.db`/`.sqlite` 数据库文件（可能含会话、财务、用户敏感信息）。这与备份/调试取数的区别是：后者取"运行时产生的私有数据"，硬编码取的是"安装包自带的静态数据"；二者都回答"不用 root 能拿到什么"，故归入同一能力。自定义加密/哈希实现需另查不安全算法与弱实现。

## A1 — 应用示例 (Application Example)

### 示例 1: Sieve 目录权限链与 chmod 对照实验
- **类型与来源**: 【亲历】《Mobile App Hackers Handbook》Chapter 7 "File and Folder Permissions"
- **问题/输入**: Sieve 的 `database.db` 被改成 777，要判断是否真的对外暴露。
- **方法论的使用**: (1) 从目标文件向上逐级 `ls -ld`：文件本体、`databases/`、`<pkg>/`、`data/`、`/`；(2) 在 drozer 普通 App 上下文 `cat <path>` 实测 → 能读出内容；(3) 对可疑目录 `chmod 770 databases` 复测 → 同一文件立刻不可读；(4) 记录设备 Android 版本与 umask 结论（4.0+ 为 0077，2.3 为 0000 类）。
- **结论**: 「文件 777」本身不构成暴露，成立依赖 `databases` 目录是 771（world-executable）；把目录改 770 即封堵，说明暴露点是目录的 x 位而非文件的 r 位。
- **结果**: 原书交代对照实验按此成立；另引 DroidWall 把 `droidwall.sh` chmod 777，恶意 App 可在 root 提示期间覆写脚本拿到 root shell。

### 示例 2: 应用锁 App 的 allowBackup 明文手势密码
- **类型与来源**: 【亲历】《Mobile App Hackers Handbook》Chapter 7 "Application Backups" + 《Android应用安全防护和逆向分析》第 11 章
- **问题/输入**: 一个下载量很高的应用锁 App，`allowBackup` 为 true（或属性缺失），要取私有数据并验证篡改。
- **方法论的使用**: (1) `aapt dump xmltree <apk> AndroidManifest.xml | grep -i allowBackup` → true 或缺失；(2) `adb backup -nosystem -all -apk -noshared -f app.ab <包名>`，设备确认页密码留空 → 得到 `app.ab`；(3) `dd if=app.ab bs=24 skip=1 | openssl zlib -d > backup.tar`（openssl 无 zlib 时换 python one-liner）→ `tar xvf backup.tar`；(4) 在 `apps/<pkg>/` 的 xml/db 里找明文凭据 → `SmartLockConfig.xml` 里手势密码明文 `03678`；(5) 改值 → 重新打 ab → `adb restore app.ab` → 旧凭据登录失败即篡改成立。
- **结论**: 能导出只是第一步，能写回才是完整危害；缺 `-nosystem` 会覆盖系统数据（作者特别提醒「非常不好」）。
- **结果**: 原书交代作者据此直接改了密码；另引某社交 App 5.0 可导出、6.0 起改为 false 的版本对比。

### 示例 3: Sieve 的 debuggable run-as
- **类型与来源**: 【亲历】《Mobile App Hackers Handbook》Chapter 7 "Debuggable Flag" + 《Android应用安全防护和逆向分析》第 10 章
- **问题/输入**: Sieve 是 debuggable 应用，要在不 root 的情况下取 `database.db`。
- **方法论的使用**: (1) `run app.package.debuggable` 确认目标包在列表中；(2) `adb shell am start -n <pkg>/<launchActivity>` 启动进程；(3) `adb shell run-as <pkg> sqlite3 databases/database.db .dump` 拿到主密码与全部条目；(4) 对照实验：未 debuggable 时 `ls -l /data/data/...` 报 `opendir failed, Permission denied`；(5) 若要代码执行：`adb forward tcp:4444 jdwp:<pid>` → `jdb -attach` → 断在 `android.os.MessageQueue.next` 后 `print new java.lang.Runtime().exec("...")`。
- **结论**: debuggable 不只是「能调试」，它等于把私有目录权限交给 shell 用户；run-as 的三个前提是「调用者是 shell/root、目标不以 system 身份跑、目标 debuggable」。
- **结果**: 原书交代通过 run-as + sqlite3 .dump 拿到主密码；并记录了部分 4.1–4.3 设备因无权读 `/data/system/packages.list` 导致 run-as 报 `Package '<pkg>' is unknown` 的 AOSP bug。

## A2 — 触发场景 (Future Trigger)

### 用户会在什么情境下需要它
1. 文件权限疑点：「文件权限怎么看」「私有目录为什么能被读」「chmod 777 就一定会泄露吗」。
2. 备份接口：「不用 root 怎么看沙盒」「adb backup 怎么用」「allowBackup 有什么风险」。
3. 调试构建：「debuggable 有什么用」「run-as 怎么用」「debug 包泄露会怎样」。
4. 篡改验证：「能不能改它的配置」「改了以后能不能写回去」「换掉动态加载的 dex」。

### 语言信号（出现这些就该激活）
- 中文：「沙盒数据」「私有目录」「目录 x 位」「umask」「allowBackup」「adb backup」「abe 解包」「adb restore」「debuggable」「run-as」「jdwp 注入」。
- English: "world readable file Android", "umask Android app data", "adb backup extract app data", "allowBackup vulnerability", "run-as app data", "debuggable app exploitation"。

### 与相邻能力的区分
- 与 `<component-exposure-and-exploitation>` 的区别：后者判 IPC 导出链（组件能否被第三方调用），本能力判文件系统权限链与备份/调试接口（能否读到私有数据）。CU-1-05（特权上下文）与 CU-1-12 的区别即「IPC 导出链 vs 文件系统权限链」。
- 与 `<unpacking-and-hook>` 的区别：脱壳也需要 debuggable 才能 attach，但目标是取 dex 代码；本能力目标是取数据。两者共享前提、不同目的。
- 与 `<provider-data-extraction>` 的区别：后者经 provider 的 query/openFile 接口取数，本能力经文件系统/备份/调试接口取数。

## E — 可执行步骤 (Execution)

**必需输入**: 能进 shell（root 或 debuggable 的 run-as）以修改权限做对照实验；一个普通权限 App 上下文用于验证可达性；USB 调试已开；备份分支要求应用未把 allowBackup 设为 false；调试分支要求应用是 debug 构建（或已被重打包改成 debuggable）且 run-as 未踩到 AOSP bug。缺「普通上下文验证」时不得给出「真暴露」结论。

**交付物与完成标准**: 一份「路径权限链 + 实测结果 + 版本区间」表；一个解包后的沙盒目录树与找到的凭据样本；一次写回篡改验证记录。完成标准：每条结论标注「成立的系统版本区间 + 所需前提（物理接触/USB 调试/debug 构建）」，且三态（暴露/取数/篡改）分别有证据。

1. **判权限链：逐级 ls -ld + 普通上下文实测**
   - 做什么：从目标文件向上逐级 `ls -ld`（文件本体、`databases/`、`<pkg>/`、`data/`、`/`），逐级确认 other 位的 x；在普通 App 上下文用 drozer shell `cat <path>` 实测。
   - 完成标准：能定位是哪一级目录放开（对可疑目录 `chmod 770 <dir>` 复测确认「读不到」）。
   - 判停：在 root shell 里 cat 成功不作数——root 不受权限约束；只看文件权限位就报「任意读取」不成立。

2. **记录版本与 umask 结论**
   - 做什么：记录设备 Android 版本，推导 umask（4.0+ 的 `ZygoteInit` 为 0077 → 600/700；2.3 时代同代码 666）。
   - 完成标准：说明该问题在哪些版本区间成立。
   - 判停：不要把 2.3 的 umask 结论套到 4.4+（或反之）；同一份代码在不同系统上暴露面不同。

3. **allowBackup 导出与解包**
   - 做什么：`aapt dump xmltree` 看属性（true 或**缺失即 true**）→ `adb backup -nosystem -all -apk -noshared -f app.ab <包名>`（确认页密码留空）→ `dd if=app.ab bs=24 skip=1 | openssl zlib -d > backup.tar` → `tar xvf backup.tar`。
   - 完成标准：当前目录出现 `app.ab` 并解出 `apps/<pkg>/` 目录树。
   - 判停：`-nosystem` 不能漏（还原时覆盖系统数据）；openssl 无 zlib 支持时换 `dd ... | python -c "import zlib,sys;..."`。

4. **找明文凭据并写回篡改验证**
   - 做什么：在解出的 xml/db 里找明文凭据 → 改值 → 重新打成 ab → `adb restore app.ab` → 用旧凭据登录失败/新 URL 生效即篡改成立。
   - 完成标准：导出与写回两半都有证据，不止「能导出」。
   - 判停：数据被 SQLCipher 加密时导出成功也不能直接读，需另找密钥（从 `openOrCreateDatabase()` 追密钥，或拿 `classes.dex` 里所有字符串逐个试开库）。

5. **debuggable / run-as 取数**
   - 做什么：`run app.package.debuggable` 确认目标在列表 → `adb shell am start -n <pkg>/<launchActivity>` 启动进程 → `adb shell run-as <pkg> sqlite3 databases/database.db .dump`。
   - 完成标准：能看到私有目录内容并取到数据。
   - 判停：应用未启动时 `adb jdwp` 看不到它；目标包以 system 身份运行（sharedUserId）时 run-as 拒绝；4.1–4.3 部分机型 run-as 报 unknown package——三者都停止本分支并标注限制。

6. **（分发态）解包挖硬编码密钥与数据**
   - 做什么：解包 APK → 读 `res/values/strings.xml` 找密钥/端点/凭据线索 → 对整个解包目录用关键字表 grep（api_key/secret/token/password/SharedPreferences 等）→ 查 `.db`/`.sqlite` 文件内容。
   - 完成标准：列出硬编码 secret/API key 与随包敏感数据清单。
   - 判停：只看字符串文件不扫数据库会漏掉随包分发的敏感数据；遇到自定义加密实现需另查不安全算法、弱实现与硬编码密钥，不要把密文当明文。

7. **（可选）jdb 注入执行**
   - 做什么：`adb jdwp` + `ps | grep` 取 pid → `adb forward tcp:4444 jdwp:<pid>` → `jdb -attach localhost:4444` → 断在 `android.os.MessageQueue.next` 后 `print new java.lang.Runtime().exec("...")`。
   - 完成标准：命令在应用上下文执行。
   - 判停：端口可能不是 8700，从 DDMS 看实际映射；仅需取数据时不必走到这一步。

## B — 边界 (Boundary)

### 不要用的情况
- 目标是特权上下文（root/system）可达的组件问题时：转 `<component-exposure-and-exploitation>` 的上下文闸门，那里判「IPC 导出链」，本能力不处理。
- 数据已被强加密且密钥不落盘：本能力止于「取到密文 + 需另寻密钥」。
- 应用 allowBackup=false 且非 debuggable 且目录权限链收紧：三条路径均不成立，不要强行上报「沙盒可窃取」。
- 目标是 dex 代码而非数据时：转 `<unpacking-and-hook>`（脱壳）或 `<static-reverse-and-tampering>`（静态逆向）。

### 已知失败模式
- 只看文件权限位就报「任意读取」；在 root shell 里 cat 成功就当作暴露；忽略版本差异把 2.3 的 umask 结论套到 4.4+（《Mobile App Hackers Handbook》Ch7 File and Folder Permissions）。
- 忘记 `-nosystem`，还原时覆盖系统数据；用 openssl zlib -d 时发行版未编译 zlib 支持直接失败；只看「能导出」不看「能否还原」，漏掉篡改这一半危害（同书 Ch7 Application Backups）。
- 应用未启动时 `adb jdwp` 看不到它；目标包以 system 身份运行时 run-as 拒绝；4.1–4.3 部分机型 run-as 报 unknown package；误以为 debuggable 只是「能调试」（同书 Ch7 Debuggable Flag）。
- 把备份/调试取数写成「远程可窃取」：两条路径都止于「物理接触 + USB 调试」前提，必须标注（同书各节）。

### 作者与时代的局限
- umask 版本结论（4.0+ 为 0077、2.3 为 666）与 AOSP bug（4.1–4.3 run-as unknown package）是 MAHH 写作时的历史状态，现代 Android 已变化；结论需按目标版本重新核对。
- `adb backup` 在新版 Android（尤其 Android 12+）对 `-apk/-all` 与设备确认行为做了限制，命令可用性需实测；`.ab` 格式解析（24 字节头 + zlib）仍是原书口径。
- DroidWall chmod 777 提权案例是历史 CVE，用于说明「文件路径权限链」危害形态，不代表当前设备仍存在。

### 容易混淆的方法
- 「文件 r 位」与「目录 x 位」：访问要求路径每级都有 x，文件 777 可能被目录 770 挡住；判暴露必须沿路径逐级看。
- 「allowBackup」与「debuggable」：前者走备份接口（不需要 debuggable），后者走调试接口（必须 debuggable）；两条都不需要 root，都止于物理接触前提。
- 「能导出」与「能写回」：前者只证明读取，后者才证明篡改；报告要分别列证据。

### 授权与合规边界
> 待补充（用户自行填写）
