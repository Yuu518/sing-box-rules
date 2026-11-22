# sing-box-rules 规则查询面板

独立于 `master` 主分支的静态规则查询与订阅面板，基于纯 Go 标准库读取 `rule_set` 与 `release` 分支产物生成分片索引并部署至 Cloudflare Pages。

## 目录结构

- `web/`：前端静态资源（`index.html`、`styles.css`、`app.js`）
- `main.go`：无第三方依赖的索引构建器与本地预览服务
- `.github/workflows/CloudflarePages.yml`：推送 `web` 分支或手动触发时构建并直接上传部署至 Cloudflare Pages

## 本地构建与预览

准备 `rule_set` 和 `release` 目录后执行：

```bash
go run . -rule-set ./rule_set -release ./release -web ./web -out ./dist -serve 127.0.0.1:8080
```

仅生成静态产物到 `./dist`：

```bash
go run . -rule-set ./rule_set -release ./release -web ./web -out ./dist
```

## Cloudflare Pages 配置

1. 在 Cloudflare 控制台 **Workers & Pages** 新建 **Direct Upload** 模式的 Pages 项目（默认名称 `sing-box-rules`）。
2. 在 Cloudflare **API Tokens** 选择 **从头开始（Custom）**，赋予 `账户 → Cloudflare Pages → 编辑` 权限并创建令牌。
3. 在 GitHub 仓库 **Settings → Secrets and variables → Actions** 配置：
   - Secret `CF_API_TOKEN`：上一步创建的令牌
   - Secret `R2_ACCOUNT_ID`：Cloudflare Account ID（与 R2 复用）
   - 可选 Variable / Secret `CF_PAGES_PROJECT`：当 Pages 项目名不是 `sing-box-rules` 时指定
