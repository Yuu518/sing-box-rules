# sing-box-rules

基于 Go 开发的配置驱动规则集生成工具（参考 [Loyalsoldier/geoip](https://github.com/Loyalsoldier/geoip) 的插件化管道架构），通过声明式 `config.json` 统一拉取、合并、过滤并编译域名、AdGuard DNS 与 IP 规则集，自动产出 **sing-box（v4）**、**mihomo**、**Surge**、**纯文本** 与 **`hosts`** 格式文件。

---

## 规则获取

用法同 [Loyalsoldier/v2ray-rules-dat](https://github.com/Loyalsoldier/v2ray-rules-dat)。

### 产物分支

- **sing-box 规则集（`.srs` / `.json`，RuleSet Version 4）**：[rule_set 分支](https://github.com/Yuu518/sing-box-rules/tree/rule_set)
  - 域名规则：`rule_set_site/`
  - IP 规则：`rule_set_ip/`
- **文本列表 / AdGuard / hosts**：[release 分支](https://github.com/Yuu518/sing-box-rules/tree/release)
- **mihomo（`.mrs` + `.yaml`）/ Surge（`.list`）/ Text（`.txt`）**：[Yuu518/Yuu-rules (`rule-set` 分支)](https://github.com/Yuu518/Yuu-rules/tree/rule-set)

### 自定义与增强类别

- 新增 / 定制类别：`pcdn-cn`、`stream-global`、`category-cdn-!cn`、`download-!cn`、`china-list`、`gfw`
- `category-ads-all` 与 AdGuard 规则上游：
  - [Cats-Team/AdRules](https://github.com/Cats-Team/AdRules)
  - [TG-Twilight/AWAvenue-Ads-Rule](https://github.com/TG-Twilight/AWAvenue-Ads-Rule)

### 常用规则直链（sing-box）

- **域名类**：
  - `category-ads-all`: [srs](https://raw.githubusercontent.com/Yuu518/sing-box-rules/rule_set/rule_set_site/category-ads-all.srs) | [json](https://raw.githubusercontent.com/Yuu518/sing-box-rules/rule_set/rule_set_site/category-ads-all.json)
  - `category-ads-all-adguard`: [srs](https://raw.githubusercontent.com/Yuu518/sing-box-rules/rule_set/rule_set_site/category-ads-all-adguard.srs)
  - `awavenue-ads`: [srs](https://raw.githubusercontent.com/Yuu518/sing-box-rules/rule_set/rule_set_site/awavenue-ads.srs)
  - `stream-global`: [srs](https://raw.githubusercontent.com/Yuu518/sing-box-rules/rule_set/rule_set_site/stream-global.srs) | [json](https://raw.githubusercontent.com/Yuu518/sing-box-rules/rule_set/rule_set_site/stream-global.json)
  - `youtube`: [srs](https://raw.githubusercontent.com/Yuu518/sing-box-rules/rule_set/rule_set_site/youtube.srs) | [json](https://raw.githubusercontent.com/Yuu518/sing-box-rules/rule_set/rule_set_site/youtube.json)
  - `netflix`: [srs](https://raw.githubusercontent.com/Yuu518/sing-box-rules/rule_set/rule_set_site/netflix.srs) | [json](https://raw.githubusercontent.com/Yuu518/sing-box-rules/rule_set/rule_set_site/netflix.json)
  - `category-ai-!cn`: [srs](https://raw.githubusercontent.com/Yuu518/sing-box-rules/rule_set/rule_set_site/category-ai-!cn.srs) | [json](https://raw.githubusercontent.com/Yuu518/sing-box-rules/rule_set/rule_set_site/category-ai-!cn.json)
  - `category-cdn-!cn`: [srs](https://raw.githubusercontent.com/Yuu518/sing-box-rules/rule_set/rule_set_site/category-cdn-!cn.srs) | [json](https://raw.githubusercontent.com/Yuu518/sing-box-rules/rule_set/rule_set_site/category-cdn-!cn.json)
  - `download-!cn`: [srs](https://raw.githubusercontent.com/Yuu518/sing-box-rules/rule_set/rule_set_site/download-!cn.srs) | [json](https://raw.githubusercontent.com/Yuu518/sing-box-rules/rule_set/rule_set_site/download-!cn.json)
  - `google`: [srs](https://raw.githubusercontent.com/Yuu518/sing-box-rules/rule_set/rule_set_site/google.srs) | [json](https://raw.githubusercontent.com/Yuu518/sing-box-rules/rule_set/rule_set_site/google.json)
  - `speedtest`: [srs](https://raw.githubusercontent.com/Yuu518/sing-box-rules/rule_set/rule_set_site/speedtest.srs) | [json](https://raw.githubusercontent.com/Yuu518/sing-box-rules/rule_set/rule_set_site/speedtest.json)
  - `geolocation-!cn`: [srs](https://raw.githubusercontent.com/Yuu518/sing-box-rules/rule_set/rule_set_site/geolocation-!cn.srs) | [json](https://raw.githubusercontent.com/Yuu518/sing-box-rules/rule_set/rule_set_site/geolocation-!cn.json)
  - `cn`: [srs](https://raw.githubusercontent.com/Yuu518/sing-box-rules/rule_set/rule_set_site/cn.srs) | [json](https://raw.githubusercontent.com/Yuu518/sing-box-rules/rule_set/rule_set_site/cn.json)
- **IP 类**：
  - `telegram`: [srs](https://raw.githubusercontent.com/Yuu518/sing-box-rules/rule_set/rule_set_ip/telegram.srs) | [json](https://raw.githubusercontent.com/Yuu518/sing-box-rules/rule_set/rule_set_ip/telegram.json)
  - `cn`: [srs](https://raw.githubusercontent.com/Yuu518/sing-box-rules/rule_set/rule_set_ip/cn.srs) | [json](https://raw.githubusercontent.com/Yuu518/sing-box-rules/rule_set/rule_set_ip/cn.json)

---

## 核心特性

- **配置驱动**：所有上游拉取、去重、移除、过滤与多格式输出均通过 [`config.json`](./config.json)（支持带注释与尾随逗号的 HuJSON）声明，修改规则无需改动代码或 Shell 脚本。
- **全格式自动识别**：
  - `domain` 输入插件自动识别 v2fly/mosdns、dnsmasq、GFWList（Base64 / AutoProxy）、Surge、mihomo/Clash YAML、sing-box JSON / `.srs`、mihomo `.mrs`、Hosts 与 Adblock 域名规则，并自动忽略注释与非域名行。
  - `ip` 输入插件自动识别纯文本 CIDR、sing-box `.srs` 与 mihomo `.mrs`。
  - `adguard` 输入插件自动过滤注释、`[Adblock Plus]` 头部与页面元素隐藏规则。
- **原生 S3 / Cloudflare R2 支持**：内置纯 Go AWS Signature V4 客户端，直接通过 `s3://` 协议拉取私有规则目录或单文件，支持本地目录回退（`fallbackDir` / `fallbackURI`）。
- **一体化多格式输出**：内置 sing-box（v4 `.srs` + `.json` + AdGuard `.srs`）、mihomo（`.mrs` + `.yaml`）、Surge（`.list`）、Text（`full:`/`domain:` 前缀 `.txt`）与 `hosts` 输出插件。

---

## 快速开始

### 构建与运行

```bash
go build -o sing-box-rules .

# 按配置文件构建规则集
./sing-box-rules convert -c ./config.json

# 查看所有已注册的 input / output 插件
./sing-box-rules list

# 本地查询域名或 IP 命中的规则集
./sing-box-rules lookup -c ./config.json google.com 91.108.4.1
```

### 配置与插件文档

完整的输入/输出插件列表、参数说明及 S3/R2 环境变量配置请查看 [`configuration.md`](./configuration.md)。

---

## 项目结构

```text
.
├── .github/workflows/
│   ├── Build.yml           # 定时与推送构建工作流
│   └── test.yml            # 单元测试工作流
├── config.json             # 默认规则构建配置
├── configuration.md        # 插件与配置文档
├── main.go / init.go       # CLI 入口与插件注册
├── convert.go              # convert 子命令
├── list.go                 # list 子命令
├── lookup.go               # lookup 子命令
├── lib/                    # 核心容器、配置解析与纯 Go S3 客户端
└── plugin/
    ├── v2fly/              # v2flyDomain 与 v2flyResolve
    ├── plaintext/          # domain / ip / adguard / surge / mihomo / text 插件
    ├── singbox/            # singboxSRS / singboxDomain / singboxIP / singboxAdGuard
    ├── mihomo/             # mihomoMRS / mihomoDomain / mihomoIP
    └── special/            # cutter / domainFilter
```

---

## 自动化构建（GitHub Actions）

每日定时由 [`Build.yml`](./.github/workflows/Build.yml) 使用最新稳定版 Go 自动构建并推送到各产物分支：

- 自定义增删名单保存在 `src` 分支（`direct.txt`、`proxy.txt`、`reject.txt` 及 `*-need-to-remove*.txt`），CI 运行时自动检出至 `./src`。
- 所需仓库 Secrets：
  - `R2_ACCESS_KEY_ID`、`R2_SECRET_ACCESS_KEY`、`R2_ACCOUNT_ID`、`R2_BUCKET_NAME`：Cloudflare R2 私有规则库访问凭证
  - `RULES_REPO_TOKEN`：推送至 `Yuu518/Yuu-rules` 的访问令牌
