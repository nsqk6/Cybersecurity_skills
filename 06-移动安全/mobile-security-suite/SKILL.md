---
name: mobile-security-suite
description: |
  移动端（Android/iOS）安全测试的能力包。当用户要评估一个 App 的安全性、要脱壳反编译看逻辑、要做动态 Hook 绕过检测、要测组件导出与深链、要分析客户端与服务端的通信与存储、或要按移动安全测试标准做完整检查时使用。覆盖：App 侦察与信息收集、脱壳与反编译、静态审计、动态插桩、组件与 IPC 安全、WebView 与 JSBridge、数据存储与传输、越狱/Root 环境对抗、iOS 二进制与运行时。不适用于：Web 站点测试（走 web-security-suite）、服务端内网（走 intranet-redteam-suite）。
metadata:
  cangjie.generated-by: cangjie-tools v2.5.0
  cangjie.variant: single
  cangjie.bundle-id: bundle.mobile-security-suite
  cangjie.capability-count: 12
  cangjie.entrypoint-count: 1
---
# 移动安全 — 全书能力入口

## 触发与不触发

**适用**：与本书能力域相关的咨询与任务（见下方路由表的意图列）。
**不适用**：
- 未授权 App 的破解与二次打包分发
- Web 应用漏洞挖掘
- iOS 越狱工具开发

## 核心原则（常驻速览，概览类问题读到这里即可回答）

1. 先确认拿到的是不是真代码：加固与壳会让静态分析完全失真
2. 客户端结论必须回到服务端验证，客户端能改的东西不算安全边界
3. 测试顺序按攻击面收敛：组件 → 存储 → 通信 → 运行时
4. 动态手段用于验证静态假设，不用于盲扫
5. 版本与系统差异会改变结论，结论必须绑定测试环境

## 能力路由（先读本表，按意图加载 1 张能力卡）

| 用户意图 | 先读 | 补读/备注 |
|---|---|---|
| 面对一个移动 App 规划完整评估；切分攻击面并排除不可达项；决定用哪个构建变体与哪档测试环境 | references/capabilities/attack-surface-scoping.md | references/capabilities/component-exposure-and-exploitation.md、references/capabilities/auth-and-findings-triage.md、references/capabilities/unpacking-and-hook.md |
| 判定 Android 组件是否导出；验证导出组件能否绕过鉴权；给组件问题定危害等级 | references/capabilities/component-exposure-and-exploitation.md | references/capabilities/attack-surface-scoping.md、references/capabilities/provider-data-extraction.md、references/capabilities/sandbox-data-acquisition.md |
| 从 content provider 抽取数据；绕过 path-permission 保护；测 provider SQL 注入与目录穿越 | references/capabilities/provider-data-extraction.md | references/capabilities/component-exposure-and-exploitation.md、references/capabilities/webview-client-injection.md、references/capabilities/sandbox-data-acquisition.md |
| 判断私有目录数据是否真暴露；通过备份接口导出并篡改沙盒数据；用 debuggable/run-as 取数 | references/capabilities/sandbox-data-acquisition.md | references/capabilities/component-exposure-and-exploitation.md、references/capabilities/unpacking-and-hook.md、references/capabilities/provider-data-extraction.md |
| 测 WebView 加载源与危险开关；判 JS Bridge 能否 RCE；测客户端解压路径穿越 | references/capabilities/webview-client-injection.md | references/capabilities/transport-security-testing.md、references/capabilities/provider-data-extraction.md、references/capabilities/sandbox-data-acquisition.md |
| 判定 TLS 证书防护属于哪一档；绕过 SSL pinning 抓取流量；排查抓不到包的原因 | references/capabilities/transport-security-testing.md | references/capabilities/unpacking-and-hook.md、references/capabilities/webview-client-injection.md、references/capabilities/ios-platform-security-testing.md |
| 识别 APK 是否加固；dump 内存 dex 拿真实代码；绕过加固反调试 | references/capabilities/unpacking-and-hook.md | references/capabilities/static-reverse-and-tampering.md、references/capabilities/sandbox-data-acquisition.md、references/capabilities/transport-security-testing.md |
| 定位重打包后闪退的校验点；无越狱机做动态插桩；检查编译期免费防护与做模糊测试 | references/capabilities/static-reverse-and-tampering.md | references/capabilities/unpacking-and-hook.md、references/capabilities/transport-security-testing.md、references/capabilities/attack-surface-scoping.md |
| 测 iOS URL Scheme 跨 App 入口；判 Keychain/存储与生物识别是否达标；绕过越狱检测并评估越狱能力 | references/capabilities/ios-platform-security-testing.md | references/capabilities/attack-surface-scoping.md、references/capabilities/unpacking-and-hook.md、references/capabilities/transport-security-testing.md |
| 量化判定会话/OTP/口令策略；剔除假阳性并给发现定级；写清利用前提让读者复算 | references/capabilities/auth-and-findings-triage.md | references/capabilities/attack-surface-scoping.md、references/capabilities/ios-platform-security-testing.md、references/capabilities/component-exposure-and-exploitation.md |
| 遇到「protectionLevel signature」时，查本域 OCR 增补材料中的对应方法与判据；遇到「权限风险等级」时，查本域 OCR 增补材料中的对应方法与判据；遇到「exported 默认值」时，查本域 OCR 增补材料中的对应方法与判据 | references/capabilities/ocr-framework-judgement.md | references/capabilities/attack-surface-scoping.md、references/capabilities/component-exposure-and-exploitation.md |
| 遇到「检查 APK 证书」时，查本域 OCR 增补材料中的对应方法与判据；遇到「提取 Android 签名指纹」时，查本域 OCR 增补材料中的对应方法与判据；遇到「cert.rsa keytool」时，查本域 OCR 增补材料中的对应方法与判据 | references/capabilities/ocr-recipe-troubleshooting.md | references/capabilities/attack-surface-scoping.md、references/capabilities/component-exposure-and-exploitation.md |

**非能力类查询**：
- 书名/作者/章节/整书概览 → references/overview.md
- 术语解释 → references/glossary.md
- 决策规则速查（不需要原文依据时） → references/cheatsheet.md
- 完整意图与关键词索引（本表未覆盖的意图先查这里） → references/capability-index.md

## 加载规则

- 每次任务先读本文件，再按路由表加载 **1** 张能力卡；任务明确跨域时最多加载 2 张。
- 概览/书名类问题不加载能力卡，用「核心原则」与 overview.md 回答。
- 路由表与 capability-index.md 都无法命中的意图，明确告知超出本书范围，不要硬套。

## 边界与判停

- 目标 App 加固未脱壳时停止静态结论，先解决脱壳
- 测试需要修改生产数据时停止，改用只读路径
- 环境（Root/越狱）与目标实际环境不符时，结论需标注适用范围
