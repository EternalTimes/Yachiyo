# 仓库与自动化配置

公开仓库：[EternalTimes/Yachiyo](https://github.com/EternalTimes/Yachiyo)。

## 自动化

- CI：Linux 单作业运行 `scripts/check_repository.py`，检查文档链接、Python 语法及 Action SHA；尚不覆盖代理内核。
- Dependabot：每周检查 GitHub Actions，分组更新；不自动批准 PR。
- 保留 CODEOWNERS、Issue 模板；PR 模板记录改动与验证。
- 一次性初始化脚本已移除；持续使用的 CI 检查器予以保留。

## 安全设置

GitHub 密钥扫描与推送保护已开启，覆盖其支持的凭据模式。当前账户的通用模式扫描未能启用，补充由 CI 拒绝已跟踪的私钥文件、私钥头部和非示例 `.env` 文件；CI 发生在提交上传之后，不能代替推送前保护。两者均不能保证识别所有凭据。

Actions 默认只读，不允许工作流批准 PR；第三方 Actions 固定提交 SHA，checkout 不保留凭据。私有节点、订阅、令牌与签名材料放在仓库外，不能只依赖 `.gitignore`。发生真实泄漏时先撤销或轮换凭据，再清理文件和历史。

## 分支保护与自动合并

日常 main 要求 PR、`Repository checks`、保持最新及解决讨论；管理员同样受约束，禁止强推和删除。单维护者阶段不要求其他人的批准。

开放 GitHub 原生自动合并功能，由维护者审查后对具体 PR 启用，等待必需检查通过再 squash 合并；不会给全部 PR 或 Dependabot PR 自动开启。敏感改动（工作流、权限、网络和发布）仍需人工审查。当前 CI 只有文档基础检查，不能据此判断代码行为安全。

整理初始历史时临时允许强推及管理员绕过，使用带 lease 的推送，完成后立即恢复原保护。Projects、Wiki 与历史整理无关。
