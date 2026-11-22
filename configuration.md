# 配置说明（`config.json`）

`sing-box-rules` 支持标准 JSON 以及带注释、尾随逗号的 HuJSON 配置文件，包含 `input` 与 `output` 两个按顺序执行的管道阶段。

所有插件类型统一采用 `Domain` / `IP` / `AdGuard` 后缀命名，格式与输入输出保持对称。

## 命令行用法

```bash
go build -o sing-box-rules .
./sing-box-rules convert -c ./config.json
./sing-box-rules list
./sing-box-rules lookup -c ./config.json google.com 8.8.8.8
```

## 原生 S3 / Cloudflare R2 支持

所有支持 `uri` 或 `inputDir` 的输入插件均原生支持 `s3://` 协议（纯 Go AWS Signature V4 实现）：

- `s3:///key` 或 `s3:///`：省略 bucket 名称时自动读取环境变量 `R2_BUCKET_NAME` 或 `S3_BUCKET`
- `s3://my-bucket/prefix`：显式指定 bucket 与前缀/对象键

环境变量优先级：

| 配置项 | 环境变量 |
| --- | --- |
| Endpoint | `S3_ENDPOINT`、`AWS_ENDPOINT_URL_S3`、`AWS_ENDPOINT_URL`，或由 `R2_ACCOUNT_ID` 自动拼接 `https://<R2_ACCOUNT_ID>.r2.cloudflarestorage.com` |
| Bucket | `S3_BUCKET`、`R2_BUCKET_NAME` |
| Region | `S3_REGION`、`AWS_REGION`、`AWS_DEFAULT_REGION`（默认 `auto`） |
| Access Key | `S3_ACCESS_KEY_ID`、`R2_ACCESS_KEY_ID`、`AWS_ACCESS_KEY_ID` |
| Secret Key | `S3_SECRET_ACCESS_KEY`、`R2_SECRET_ACCESS_KEY`、`AWS_SECRET_ACCESS_KEY` |

支持配置 `fallbackDir` / `fallbackURI`，当未配置 S3 凭证或拉取失败时自动回退到本地文件。

## Input 插件

### 通用自动识别输入
- **`domain`**（推荐）：不区分格式，自动识别并解析 v2fly/mosdns（`full:`/`domain:`/`keyword:`/`regexp:`/`include:`/`@attr`）、dnsmasq（`server=/.../`、`local=/.../`、`address=/.../`）、GFWList（Base64/AutoProxy）、Surge/QX/Loon（`DOMAIN*`、`HOST*`、`.domain`、`+.domain`、`*.domain`）、Clash/Mihomo YAML（`payload:`）、sing-box JSON 与二进制 `.srs`、mihomo 二进制 `.mrs`、Hosts（`0.0.0.0 example.com`）与 Adblock 域名（`||example.com^`），自动跳过注释、头部与非域名行。
- **`ip`**：加载 IP/CIDR 规则，自动识别纯文本、sing-box `.srs` 与 mihomo `.mrs`（支持 `inputDir`、`name`、`uri`、`ipOrCIDR`、`wantedList`、`excludedList`、`onlyIPType`）。
- **`adguard`**：加载 AdGuard DNS Filter 规则（`name`/`names`、`uri`、`rules`），默认自动跳过空行、`[Adblock Plus ...]` 头、`!`/`#` 注释及页面元素隐藏规则（`##`/`#@#`/`#?#`/`#$#`/`#%#`）。

### 专用格式输入
- **`v2flyDomain`**：加载 `v2fly/domain-list-community` 目录或单文件（保留 `include:` 与 `@attr`）。
- **`textDomain`**：纯文本 / v2fly 单行域名输入。
- **`dnsmasqDomain`**：dnsmasq 格式（`server=/domain/...`、`local=/domain/...`）。
- **`gfwlistDomain`**：GFWList（Base64 AutoProxy 格式）。
- **`surgeDomain`**：Surge `domainset` 与 classical 域名规则。
- **`mihomoDomain`**：mihomo/Clash YAML `payload:` 与纯文本域名格式（精确区分 `+.`/`.` 后缀、裸域名精确匹配与 `DOMAIN*` 规则）。
- **`singboxSRS`**：读取 sing-box 二进制规则集 `.srs`（支持域名、AdGuard、IP，支持 `kind` 与 `onlyIPType`）。
- **`mihomoMRS`**：读取 mihomo 二进制规则集 `.mrs`（自动识别 Domain / IPCIDR behavior）。

### 规则处理
- **`v2flyResolve`**：展开所有 `include:` 引用并生成 `@attr` 子规则集（如 `36kr@ads`、`google@cn`），支持 `generateAttrEntries`（默认 `true`）。
- **`domainFilter`**：按规则集过滤域名规则（支持 `wantedList`、`validDomainOnly`、`excludeSuffixes`、`excludeRuleTypes`）。
- **`cutter`**：按名称清空/移除容器中的规则集（仅 `action: "remove"`，支持 `wantedList`、`kind`: `domain`/`adguard`/`ip`、`onlyIPType`）。

## Output 插件

- **`singboxDomain`**：输出 sing-box 域名规则集 `.srs` 和 `.json`（默认 `version: 4`，支持 `outputDir`、`wantedList`、`excludedList`、`writeSRS`、`writeJSON`）。
- **`singboxIP`**：输出 sing-box IP 规则集 `.srs` 和 `.json`（默认 `version: 4`，支持 `onlyIPType`、`writeSRS`、`writeJSON`）。
- **`singboxAdGuard`**：将 AdGuard 规则编译为 sing-box `.srs`（默认 `version: 4`，支持 `outputDir`、`outputName`、`wantedList`、`excludedList`）。
- **`mihomoDomain`**：输出 mihomo 域名规则集 `.mrs` 和 `.yaml`（支持 `outputDir`、`wantedList`、`excludedList`、`writeMRS`、`writeYAML`）。
- **`mihomoIP`**：输出 mihomo IP 规则集 `.mrs` 和 `.yaml`（支持 `outputDir`、`wantedList`、`excludedList`、`onlyIPType`、`writeMRS`、`writeYAML`）。
- **`surgeDomain`**：输出 Surge 域名 `.list`（`DOMAIN,`、`DOMAIN-SUFFIX,`、`DOMAIN-KEYWORD,`、`DOMAIN-REGEX,`）。
- **`surgeIP`**：输出 Surge IP `.list`（`IP-CIDR,`、`IP-CIDR6,`、可选 `addSuffixInLine`）。
- **`textDomain`**：输出域名 `.txt`（`format` 支持 `prefixed` 带 `full:`/`domain:`/`keyword:`/`regexp:` 前缀、`v2fly`、`tld`，以及 `outputName`、`excludeRuleTypes`、`addPrefixInLine`、`addSuffixInLine`）。
- **`textIP`**：输出 IP `.txt`。
- **`textAdGuard`**：输出 AdGuard 规则 `.txt`。
