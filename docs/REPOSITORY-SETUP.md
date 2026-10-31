# 仓库与自动化配置

日期：2026-10-31。目标仓库：`EternalTimes/Yachiyo`；拟创建公开仓库，沿用此前公开单仓库方案。现有仓库的可见性不会由初始化脚本修改。

## 当前状态

本地配置文件已准备；当前代理环境禁止写入项目 `.git`，且命令行无法连接 GitHub API。因此本文件不表示 Git 初始化、推送、bot 或保护规则已在远端生效。以脚本完成后的 API 回读和 CI 结果为准。

## 已准备的配置

- `.gitignore`、`.gitattributes`、`.editorconfig`：统一文本格式，忽略构建物、私有配置与常见私钥文件。
- `.github/workflows/ci.yml`：单个 Linux job，检查当前阶段的文档链接、Python 语法和 Action SHA；不声称覆盖尚未实现的代理内核。
- `.github/dependabot.yml`：每周检查 GitHub Actions 版本，分组并限制待处理 PR 数量；不自动合并。
- CODEOWNERS、Issue 和 PR 模板：归属维护者，记录验收、验证及脱敏要求。
- 初始化脚本：创建或使用目标仓库，采用 SHA-1 Git 对象格式，推送后配置 squash 合并、分支保护、只读 Actions token 和依赖漏洞告警。

## 在维护者终端完成

先确认 `gh auth status` 成功，再在项目目录执行：

```sh
python3 scripts/setup_github.py
```

脚本限定账户 EternalTimes；不会覆盖无关 origin、强推历史或改动现有仓库可见性。遇到已有未提交改动、不同分支、权限或网络问题会停止并报告。新仓库创建为 public；初始提交采用 GitHub noreply 邮箱。

main 要求 PR、`Repository checks` 通过、分支保持最新、讨论已解决，禁止强推和删除。管理员同样受规则约束。单维护者阶段外部批准数为 0，避免无法自行批准导致死锁；以后增加维护者再提高人数要求。

首次 CI 必须单独核验。Dependabot 扫描与 PR 的出现由 GitHub 执行，不以配置文件存在替代实际运行结果。语言确定后再增加对应依赖生态、编译、单元测试和 macOS 运行检查。

本次未安装第三方 AI 审查 bot，没有新增付费 API 或第三方源码访问授权，也未启用自动发布或自动合并。
