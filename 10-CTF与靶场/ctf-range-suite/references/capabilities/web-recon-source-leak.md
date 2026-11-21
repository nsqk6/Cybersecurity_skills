# Web 起手：元信息收集与源码泄露推进

## R — 原文 (Reading)

> If you got the 403 HTTP response code in a CTF challenge when accessing the .git folder, the following action should be accessing the .git/HEAD or the .git/config file. If the corresponding content of the file is shown, it means that there is a git leakage.

> — 《Handbook for CTFers》Ch1 · Information Gathering

> Using the "git log" command can only find the changes on the current branch, so we need to switch other branches to recover the target files.

> — 《Handbook for CTFers》Ch1 · Git branch

## I — 方法论骨架 (Interpretation)

这张卡处理 Web 题最早的一段：**在找注入点之前，先把题目暴露的元信息收干净，并在拿到源码泄露后一路推进到 flag**。它把两类看似不同的工作放在一起，因为在真实解题中它们是连续的——先发现泄露入口，再在泄露里翻找，而「翻不到」恰恰是最常见的卡点。

第一阶段是**元信息收集的三类清单**：敏感目录（`.git`/`.svn`/`.hg`）、编辑器与站点备份（`flag~`、`.flag.swp`、`www.zip`、`robots.txt`）、Banner 指纹（CMS、中间件、操作系统）。三类各自有明确产出：目录泄露给源码，备份给源码或配置，Banner 决定后续绕过手法（已知是 Windows 服务器，上传绕过就要用 Windows 特性）。这里有个关键判据：**403 不是目录不存在的终局，而是目录存在但禁止列目录的信号**，此时应直接猜读该目录下的具体文件（`.git/HEAD`、`.git/config`）来验证。SVN 泄露时先看 `entries`，为空则查 `wc.db`，再从 `pristine` 目录按 checksum 取回源码。

第二阶段是**Git 泄露的三级推进**。难点往往不是「有没有 `.git`」，而是「最新提交里没有 flag」。三种失败形态对应三种推进：flag 被删或被覆盖 → `git reset --hard HEAD^` 回滚，或用 `git log --stat` 找改动文件、`git diff HEAD <commit-id>` 比对；flag 在另一分支 → 自动化工具通常只恢复 master，必须手动下载分支 head 到 `.git/refs/heads/`，再用 `git log --all` 查看；连分支记录都被清理 → `git reflog` 里还留着 checkout 记录，能找出 secret 分支的 commit hash。每一级都建立在前一级「确认事实」之上，而不是反复重跑同一个工具——**反复跑同一个自动恢复工具永远只能拿 master**，这是本卡最常见的失败模式。

第三阶段是**靶场场景下的低成本线索面**。Vulnhub 类靶场的突破口常被故意放在 HTML 注释、图片文件名、页面提示语这类「看得见但不会自动扫出来」的位置。出题人的逻辑是给勤奋的浏览者一条低门槛入口，所以「查看源码」不是形式动作而是性价比最高的第一层侦察：收集注释中的人名、路径、字符串作为账号或目录候选，对编码串尝试解码，再拿去验证。路径也有惯例：线索文件常放在 `images`、`icon`、`upload` 等约定俗成的目录，**先用惯例路径直接试，命中成本远低于启动全字典暴破**，不命中再退回暴破。

三阶段的关系是「发现入口 → 深挖入口 → 在入口之外补低成本线索」。Git 三级推进解决的是「已经确认泄露但工具给不出 flag」；源码注释与惯例路径解决的是「还没找到泄露入口时，有没有更便宜的路」。两者都强调同一纪律：不要反复执行同一个无效动作，要按判据换下一级。

## A1 — 应用示例 (Application Example)

### 示例 1: Git branch 泄露的 secret 分支恢复
- **类型与来源**: 【例题】《Handbook for CTFers》Ch1 (3) Git branch
- **问题/输入**: 已确认 `.git` 泄露，但 GitHacker 恢复的仓库 `git log --all` 只显示 master，源码里没有 flag。
- **方法论的使用**: 先用 `git reflog` 查 checkout 记录，发现 master 之外存在 `secret` 分支名与对应 commit hash；手动 `wget .../.git/refs/heads/secret` 存入本地同名路径；再 `git log --all` 使 secret 分支可见；最后 `git diff HEAD b94c` 得到 flag。
- **结论**: 自动化工具只给 master；「工具没给 flag」不等于「没有 flag」，要看 reflog 与分支。
- **结果**: 原书记录通过 `git diff HEAD b94c` 拿到 flag（Fig. 1.5/1.6）。

### 示例 2: Vulnhub 靶场的源码注释与惯例路径
- **类型与来源**: 【亲历】《Vulnhub靶场实战指南》第七节 FristiLeaks / 第四节 Acid
- **方法论的使用**: 查看 upload 目录页面源码，注释中「此页面是一个叫 eezeepz 的人留下来的」提供用户名候选；Acid 节拿到线索文件名 `wow.jpg` 后，按 `/image/wow.jpg`、`/images/wow.jpg`、`/icon/wow.jpg` 的惯例逐个直接请求，命中 `/images/wow.jpg`，再用 dirbuster 确认 `images` 目录。
- **结论**: 注释是账号/路径候选来源；惯例路径猜测先于全字典暴破，能减少暴破时间和打崩靶机的风险。
- **结果**: 得到用户名 `eezeepz` 与图片线索文件；后续推进见原书各节。

### 示例 3: 403 回探确认 .git 泄露
- **类型与来源**: 【例题】《Handbook for CTFers》Ch1 1.1.2.1
- **问题/输入**: 访问 `/.git/` 返回 403。
- **方法论的使用**: 不把 403 当作「目录不存在」，改读 `.git/HEAD` 与 `.git/config`；有内容回显即确认版本库泄露；随后用 scrabble 从 `.git` 恢复源码。
- **结论**: 403 是「存在但禁止列目录」的信号，直接猜读具体文件是标准回探动作。
- **结果**: 原书以 scrabble 恢复源码作为该节示例，未给出具体 flag。

## A2 — 触发场景 (Future Trigger) ★

### 用户会在什么情境下需要它
1. Web 题刚拿到 URL，不知道第一步该做什么。
2. 扫目录扫出 `.git` 返回 403，不确定还有没有戏。
3. `.git` 泄露已经确认，但源码里和最新提交里都找不到 flag。
4. 自动化工具只恢复出 master 分支，怀疑 flag 在别处。
5. 靶场题里所有漏洞都试过了，怀疑提示藏在页面源码注释或常规目录。

### 语言信号（出现这些就该激活）
- 中文：「Web 题第一步干什么」「扫目录出了 403 还有戏吗」「信息收集怎么做」「.git 泄露但源码里没 flag」「git 回滚怎么找 flag」「靶机给的提示在哪」「首页源码要看吗」
- English: "where to start a web challenge", "403 on .git folder", "git leak flag in another branch", "git reflog secret branch", "where is the hint hidden", "guess the upload directory"

### 与相邻能力的区分
- 与 `web-vuln-channel-selection` 的区别：本卡在「找入口/拿源码」阶段；那张卡在已经发现具体漏洞（SQLi/SSRF/XSS/逻辑）后判型与选利用通道。
- 与 `file-read-and-include` 的区别：那张卡处理「任意文件读/包含」这一类具体漏洞；本卡的 `.git` 泄露属于版本库文件暴露，不走文件读漏洞的参数。
- 与 `lab-workflow-and-triage` 的区别：那张卡管靶场的阶段顺序与止损；本卡是 Web 题起手的第一阶段技术动作，可被调用但不负责阶段边界。

## E — 可执行步骤 (Execution)

**必需输入**: 可访问的 Web 目标；目录字典与指纹库（可二次开发）；git 工具与 `.git` 恢复工具（scrabble/GitHacker）。若只给静态页面无 Web 服务，本卡不适用。
**交付物与完成标准**: 一份「入口与线索清单」，含：暴露的敏感目录/备份文件、Banner 指纹结论、源码泄露是否确认、Git 泄露推进到哪一级、注释与惯例路径得到的候选账号/路径；判据是至少拿到一份源码或一条可验证的凭据/路径候选。

1. **三类元信息收集**
   - 做什么：目录字典扫描（dirsearch）找 `.git`/`.svn`/`.hg` 与备份后缀；用 Wappalyzer 或错误页（404/302、ThinkPHP debug 页）定 Banner。
   - 完成标准：拿到目录/文件清单与「框架/系统类型」结论。
   - 判停：遇到 `.git` 403 → 进第 2 步回探；无泄露但 Banner 明确 → 把指纹结论交给 `web-vuln-channel-selection`。

2. **403 回探与 SVN 处理**
   - 做什么：改读 `.git/HEAD`、`.git/config`，有回显即确认；SVN 泄露先看 `entries`，为空查 `wc.db`，从 `pristine` 按 checksum 取源码。
   - 完成标准：确认泄露类型，或明确排除。
   - 判停：回探无内容 → 判为无版本库泄露，转第 5 步补低成本线索；确认泄露 → 进第 3 步。

3. **Git 泄露三级推进**
   - 做什么：先用工具把 `.git` 对象抓回本地；最新提交无敏感信息时 `git log --stat` + `git diff HEAD <id>`；`git log` 只显示当前分支时查 `git reflog`；发现其他分支后手动下载 head 到 `.git/refs/heads/`，再 `git log --all` 与 diff。
   - 完成标准：定位到 flag 曾存在过的提交或分支，并 diff 出内容。
   - 判停：反复跑同一自动工具仍只拿 master → 立即停止重复，转 reflog 分支；flag 在很早的提交时按 `--stat` 提示继续退，不只退一次 `HEAD^`。

4. **源码注释与路径惯例（靶场场景）**
   - 做什么：查看首页与每个页面的 HTML 源码，收集注释中的人名/路径/字符串；对编码串尝试 base64/hex 解码；拿到线索文件名后按 `image/images/icon/upload` 惯例逐个直接请求，全不命中再上 dirbuster。
   - 完成标准：得到可验证的账号或路径候选，并实际验证一次。
   - 判停：只猜不暴破会漏掉非常规目录，惯例路径全失败后必须退回暴破；注释线索只是候选，未验证前不作为结论。

5. **结果登记与交接**
   - 做什么：把入口、泄露级别、候选凭据/路径写入清单；若已拿到源码，转 `web-vuln-channel-selection` 做漏洞判型，或在靶场场景交给 `lab-workflow-and-triage` 决定下一阶段。
   - 完成标准：清单与后续动作明确。
   - 判停：本卡到「拿到源码或可验证线索」为止，不负责后续漏洞利用。

## B — 边界 (Boundary) ★

### 不要用的情况
- 目标是二进制 pwn 或纯 Crypto 题：没有 Web 服务与目录结构，本卡的清单不适用。
- 站点是纯静态单页且无隐藏目录：信息收集收益很低，应直接转客户端/逻辑分析。
- 已确认具体漏洞类型（已知是 SQLi/SSRF/XSS）：跳过本卡，直接进 `web-vuln-channel-selection` 或对应能力。
- 拿到 `.git` 但题目明确说明是诱饵：按出题人提示止损（见 `lab-workflow-and-triage`），不要在版本库里死磕。

### 已知失败模式
- 看到 403 就放弃，漏掉最常见的源码泄露（Ch1 1.1.2.1）。
- 只依赖自动化工具而不补自定义字典，漏掉后台管理目录等题目特有路径（Ch1）。
- 不读 Banner 直接套通用 payload，在依赖系统特性的上传/命令题上卡住（Ch1）。
- 反复跑同一个自动恢复工具，永远只能拿 master 分支（Ch1 (3)）。
- 只看 `git log` 不看 `git reflog`，漏掉被删除的分支（Ch1 (3)）。
- 只回退一次 `HEAD^`，而 flag 在很早的提交里（Ch1 (2)）。
- 只依赖扫描器找靶场线索，漏掉 HTML 注释里的手工线索（Vulnhub FristiLeaks）。
- 只猜路径不暴破，漏掉非常规目录；或反过来一上来就全字典暴破，浪费时间并有打崩靶机风险（Vulnhub Acid / CU-3-04）。

### 作者与时代的局限
- Git 泄露工具（scrabble、GitHacker）基于当时的仓库结构；新版 Git 的 refs 存储（packed-refs）与服务端配置变化会影响自动化工具命中率。
- 信息收集清单来自 CTF 场景，缺少对真实目标至关重要的证书透明度、子域枚举、云存储暴露等内容（属于侦察域，不在本域范围）。
- 靶场注释线索依赖出题人的「低门槛提示」设计，成熟实战环境不会这样留线索；相关迁移判据见 `lab-workflow-and-triage`。
- 本书未覆盖 `.hg`/`.bzr` 泄露的具体恢复流程，只给出目录名。

### 容易混淆的方法
- **403 回探 vs 目录不存在**：403 是「存在但禁止列目录」，要直接猜读具体文件；404 才更接近不存在。
- **`git log` vs `git reflog`**：前者看当前分支的提交历史，后者看引用变更记录（含被删除分支的 checkout），用途不同。
- **源码注释线索 vs 服务器端配置找密码**：前者是 Web 前端明示线索（本卡第 4 步），后者是拿到 shell 后翻配置文件（`lab-privesc`）。
- **惯例路径猜测 vs 系统暴破**：猜测是低成本先验，暴破是兜底；两者是先后关系不是替代关系。

### 授权与合规边界
> 待补充（用户自行填写）
