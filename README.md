# sing-box-rules 规则查询面板

独立于 `master` 主分支的静态规则查询与订阅面板，基于纯 Go 标准库读取 `rule_set` 与 `release` 分支产物生成分片索引并部署至 GitHub Pages。

## 目录结构

- `web/`：前端静态资源（`index.html`、`styles.css`、`app.js`）
- `main.go`：无第三方依赖的索引构建器与本地预览服务
- `.github/workflows/Pages.yml`：推送 `web` 分支或手动触发时构建并部署至 GitHub Pages

## 本地构建与预览

准备 `rule_set` 和 `release` 目录后执行：

```bash
go run . -rule-set ./rule_set -release ./release -web ./web -out ./dist -serve 127.0.0.1:8080
```

仅生成静态产物到 `./dist`：

```bash
go run . -rule-set ./rule_set -release ./release -web ./web -out ./dist
```

## GitHub Pages 配置

1. 打开仓库 **Settings → Pages**，将 **Source** 设为 **GitHub Actions**。
2. 打开 **Settings → Environments → `github-pages` → Deployment branches and tags**，将 `web` 分支加入允许部署的分支（以便直接推送 `web` 分支时自动部署）。
