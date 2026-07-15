# Magpie · 稍后阅读 / 网页剪藏

Magpie 是 Steadholme 主权基础设施中的**稍后阅读（read-later）/ 网页剪藏（web clipper）**服务，部署于
`clip.w33d.xyz`，内部监听端口 `8980`。它由 Sluice 网关以 `auth=sso` 方式托管：网关完成 OIDC 浏览器登录，
剥离入站的 `X-Auth-*`，并注入经过校验的 `X-Auth-Subject` / `X-Auth-Email`。Magpie 自身**不做任何登录**，
它信任这些请求头作为剪藏的归属者（owner）。

服务遵循 Steadholme 共享模板：Rust + axum、async-trait 的 Postgres 存储层（内存 + PgStore，运行期 SQL、无
编译期宏、无 `block_in_place`）、独立数据库 `magpie`、幂等迁移、企业级 Steadholme UI、POST 接口的 CSRF 防护、
对所有远程内容做转义（杜绝存储型 XSS）、`healthcheck` 子命令、多阶段非 root 镜像、`GET /healthz` 存活探针。

## 工作方式

1. **保存**：在阅读列表页填入网址，或点击书签小工具（bookmarklet）。
2. **抓取**：服务器端通过 HTTPS 抓取该网页（超时、大小上限、SSRF 防护、逐跳校验重定向）。
3. **抽取**：用一个简单的可读性启发式算法，剥离 `script`/`style`/`nav`/`header`/`footer` 等，
   提取标题（`og:title` / `<title>`）与正文，得到**纯文本**摘要（excerpt）与正文（content_text）。
4. **阅读**：在干净的阅读视图中阅读已保存的纯文本；可归档（archive）或删除（delete）。

所有标题、站点名、摘要、正文与 URL 均来自**不可信的远程页面**，一律在渲染时做 HTML 转义，**绝不**输出原始
远程 HTML——因此存储型 XSS 在结构上不可能发生。

## 书签小工具（Bookmarklet）

阅读列表页提供一个可拖拽的 **“Save to Steadholme”** 按钮。把它拖到浏览器书签栏后，在任意网页点击即可保存当前页。

> 网关会话 Cookie（`__Secure-gw`）是 `SameSite=Lax` 的：跨站 **POST** 不会携带它，会导致未登录。因此书签
> 小工具以**顶层 GET** 打开 `clip.w33d.xyz/clip?u=<当前页>`（顶层 GET 会携带 Lax Cookie，完成 SSO），
> 该落地页随后在**同源**上下文中携带真实 CSRF 令牌 `POST /clip`，从而既能 SSO 鉴权又满足 CSRF 防护。

## 接口

| 方法 + 路径 | 鉴权 | 说明 |
|---|---|---|
| `GET /healthz` | 公开 | 存活探针（容器 HEALTHCHECK 使用） |
| `GET /` | SSO | 阅读列表；`?filter=all\|unread\|archived`；含保存表单与书签小工具 |
| `GET /clip?u=<url>` | SSO | 书签落地页：同源确认页，自动 `POST /clip`（携带 CSRF） |
| `POST /clip` | SSO + CSRF | 抓取 URL、抽取正文并保存 → 302 `/`；对已保存 URL 去重 |
| `GET /r/{id}` | SSO | 干净阅读视图（标记为已读） |
| `POST /archive/{id}` | SSO + CSRF | 切换归档状态 → 302 回到来源列表 |
| `POST /delete/{id}` | SSO + CSRF | 删除自己的剪藏 → 302 回到来源列表 |

## 数据模型（数据库 `magpie`，表 `clips`）

| 列 | 类型 | 说明 |
|---|---|---|
| `id` | TEXT PK | 短随机 URL-safe id（`/r/{id}` slug） |
| `owner_sub` | TEXT | 归属者，取自 `X-Auth-Subject`（绝不取自客户端） |
| `url` | TEXT | 重定向后的最终页面 URL |
| `title` | TEXT | 抽取的标题（纯文本） |
| `excerpt` | TEXT | 摘要（纯文本） |
| `content_text` | TEXT | 可读正文（纯文本，按行渲染为转义段落） |
| `site` | TEXT | 站点名（`og:site_name` 或 host） |
| `saved_at` | BIGINT | 保存时间（epoch 秒） |
| `read` | BOOLEAN DEFAULT FALSE | 是否已打开阅读视图 |
| `archived` | BOOLEAN DEFAULT FALSE | 是否已归档 |

仅使用可移植标准 SQL（TEXT/BIGINT/BOOLEAN、PK、NOT NULL、DEFAULT、`INSERT .. ON CONFLICT`、普通索引），
运行期查询、无编译期宏——构建**无需**数据库，同样的语句日后可在 FusionDB（pgwire）上原样运行。

## 安全：SSRF 防护

Magpie 在 `holdfast` 内网中抓取用户提供的 URL，因此是典型的 SSRF 风险点。抓取层：

- 仅允许 `http` / `https`；
- 解析主机并**拒绝**任何落在私网 / 回环 / 链路本地 / 保留段的地址（含 IPv4-mapped IPv6 与
  `169.254.169.254` 云元数据地址）；
- **手动**跟随重定向（reqwest `Policy::none`），**逐跳**复检；
- 限制读取的总字节数与总耗时。

> 已知局限：DNS rebinding 的 TOCTOU 未做地址 pin（用户为可信的 SSO 内部用户，威胁较低）。

## 配置（环境变量）

| 变量 | 默认值 | 说明 |
|---|---|---|
| `BIND_ADDR` | `0.0.0.0:8980` | 监听地址 |
| `MAGPIE_STORE` | `memory` | `memory`（默认，无需 DB）或 `postgres` |
| `DATABASE_URL` | — | `MAGPIE_STORE=postgres` 时必填 |
| `PUBLIC_BASE_URL` | `https://clip.w33d.xyz` | 书签小工具目标的公开基址 |

## 构建与测试

```bash
# clippy（CI 门禁：-D warnings）
cargo clippy --all-targets -- -D warnings

# 默认测试：内存存储 + 桩抓取器，无数据库、无网络
cargo test

# Postgres 集成测试（需要外部 Postgres；本仓约定 127.0.0.1:55482）
docker run --rm -d --name magpie-testpg -e POSTGRES_PASSWORD=pw -e POSTGRES_DB=magpie \
  -p 127.0.0.1:55482:5432 postgres:18-alpine
TEST_DATABASE_URL=postgres://postgres:pw@127.0.0.1:55482/magpie \
  cargo test --test pg_integration -- --nocapture
docker rm -f magpie-testpg

# 构建镜像并冒烟
docker build -t steadholme/magpie:dev .
```

## 部署要点（交给 deploy）

- 数据库：`magpie`（独立 DATABASE_URL，与共享 Postgres 同实例）。
- 端口：内部 `8980`，仅内网可达（无发布端口）。
- 路由：host `clip.w33d.xyz` → `http://magpie:8980`，`auth=sso`。
- Portal 磁贴：`Clips`；Beacon 组件：`Clips`（`http://magpie:8980/healthz`）。

## 延后项（DEFER）

真正的浏览器扩展、正文高亮、富正文重渲染。
