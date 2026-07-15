# Current · Steadholme 订阅河

**Current** 是 Steadholme 主权基建中的 RSS / Atom 阅读器，对应子域 **`rss.w33d.xyz`**，门户磁贴名
**Feeds**。它由 Sluice 网关以 `auth=sso` 方式守护：网关完成 OIDC 登录后注入
`X-Auth-Subject` / `X-Auth-Email`，Current 仅在内网可达、**自身不做任何登录**，直接信任这两个头
作为当前订阅者（owner）。

服务遵循 Steadholme 共享模板：Rust + axum、`async-trait` 的 Postgres 存储（运行期 sqlx 查询，无
编译期宏、无 `block_in_place`、可移植标准 SQL）、独立数据库、幂等迁移、企业级内嵌 UI、POST 全部
带 CSRF、对远程内容做 XSS 清洗、`healthcheck` 子命令、多阶段非 root Dockerfile、`GET /healthz`。

## 功能

- **统一订阅河（`GET /`）**：跨所有订阅源、按时间倒序展示**未读**条目，含订阅源标题、条目标题、
  摘要与时间；可逐条「标记已读」或一键「全部已读」。
- **订阅管理（`GET /feeds`）**：按 URL 添加订阅、删除订阅（连同其条目）。
- **打开条目（`GET /i/{id}`）**：标记已读并 302 跳转到原文链接。
- **后台轮询**：每 `FETCH_INTERVAL` 抓取每个订阅源（带超时），解析 RSS 2.0 + Atom，按 `guid`
  去重 upsert，清洗摘要。**单个坏的 / 不可达的订阅源永远不会让页面或轮询中断**；新增订阅时会立刻
  触发一次后台抓取，无需等待下一轮。

> 已按需求 **DEFER**（暂不实现）：OPML 导入 / 导出、全文检索、文件夹分组。

## 安全模型

- **身份**：owner 恒取自网关注入的 `X-Auth-Subject`，绝不来自客户端字段；`X-Auth-Email` 仅用于
  展示。所有读写均按 owner 过滤，互不可见。
- **CSRF**：所有状态变更 POST（添加 / 删除订阅、标记已读、全部已读）走 double-submit
  校验——`__Host-csrf` Cookie 与表单隐藏字段必须一致。
- **远程内容清洗**：订阅源摘要属于**不可信远程 HTML**。`feed::html_to_text` 会剥离全部标签、解码
  实体、再剥离一次（应对双重转义），并在渲染时再次 HTML 转义（纵深防御，杜绝存储型 XSS）。条目
  链接仅放行 `http`/`https` 绝对地址（`safe_link`），其余一律丢弃。

## 数据模型（数据库 `current`）

```text
feeds(
  id TEXT PRIMARY KEY,
  owner_sub TEXT NOT NULL,
  url TEXT NOT NULL,
  title TEXT NOT NULL,
  last_fetched BIGINT,            -- 可空：尚未抓取
  created_at BIGINT NOT NULL,
  UNIQUE (owner_sub, url)
)
items(
  id TEXT PRIMARY KEY,
  feed_id TEXT NOT NULL,
  guid TEXT NOT NULL,
  title TEXT NOT NULL,
  link TEXT NOT NULL,
  summary TEXT NOT NULL,
  published_at BIGINT,            -- 可空：抓取时回退为抓取时刻以便上浮
  read BOOLEAN NOT NULL DEFAULT FALSE,
  UNIQUE (feed_id, guid)
)
```

仅使用可移植标准 SQL（TEXT/BIGINT/BOOLEAN、PK/UNIQUE/NOT NULL/DEFAULT、`INSERT .. ON CONFLICT`、
普通索引），运行期查询、无编译期宏——构建**无需数据库**，同一批语句日后可原样运行在 FusionDB
（pgwire）上。

## 端点

| 方法 | 路径 | 说明 |
|------|------|------|
| GET  | `/healthz` | 存活探针（公开） |
| GET  | `/` | 统一订阅河（未读、倒序） |
| POST | `/read-all` | 全部已读 → 303 `/`（CSRF） |
| GET  | `/i/{id}` | 打开：标记已读 → 302 跳原文 |
| POST | `/i/{id}/read` | 单条已读 → 303 `/`（CSRF） |
| GET  | `/feeds` | 订阅管理（添加表单 + 列表） |
| POST | `/feeds` | 按 URL 添加订阅 → 303 `/feeds`（CSRF） |
| POST | `/feeds/{id}/delete` | 删除订阅 → 303 `/feeds`（CSRF） |

## 配置

| 环境变量 | 默认值 | 说明 |
|----------|--------|------|
| `BIND_ADDR` | `0.0.0.0:8970` | 监听地址（内网端口 8970） |
| `CURRENT_STORE` | `memory` | `memory`（默认，无 DB）或 `postgres` |
| `DATABASE_URL` | — | `CURRENT_STORE=postgres` 时必填 |
| `FETCH_INTERVAL` | `900` | 后台轮询间隔（秒） |
| `FETCH_TIMEOUT` | `15` | 单次抓取超时（秒） |

## 构建与冒烟

```bash
cargo clippy --all-targets -- -D warnings   # 零告警
cargo test                                   # 默认套件：纯内存，无 DB、无网络

# Postgres 集成测试（一次性临时库，跑完自清理）：
docker run --rm -d -e POSTGRES_PASSWORD=pw -e POSTGRES_DB=current \
  -p 127.0.0.1:55481:5432 postgres:18-alpine
TEST_DATABASE_URL=postgres://postgres:pw@127.0.0.1:55481/current \
  cargo test --test pg_store -- --nocapture

# 实网抓取冒烟（需要外网）：
LIVE_FETCH=1 cargo test --test live_fetch -- --nocapture

# 镜像 + 健康检查冒烟：
docker build -t steadholme/current:dev .
```

## 部署要点

- 镜像 `steadholme/current:dev`，内网端口 **8970**，无对外发布端口。
- 数据库 **`current`**（部署侧 `CREATE DATABASE current`），共用同一 Postgres 用户 / 口令。
- Sluice 路由：host **`rss.w33d.xyz`** → `http://current:8970`，`auth=sso`。
- Portal 磁贴名 **Feeds**；Beacon 组件 **Feeds**（`http://current:8970/healthz`）。
