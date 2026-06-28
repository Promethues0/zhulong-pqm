# 烛龙·后量子迁移治理平台 (Zhulong PQM) — 后端 R1 + R2

国密零信任体系下的**后量子（PQC）迁移治理**后端：对密码使用点做发现、五维风险评分、CBOM 导出与摸底报告，支撑「先存后解（HNDL）」资产的优先迁移决策。

纯 Go 技术栈（避免 CGO，利于信创/交叉编译）：

- Go 1.23 · Gin · GORM + glebarez/sqlite（纯 Go SQLite）· golang-jwt/v5 · gin-contrib/cors

## 运行

```bash
cd backend
go run ./cmd/zhulong-pqm
```

- 默认监听 **:8099**
- 首次启动自动建库（`./zhulong-pqm.db`）、迁移表结构并植入种子数据
- 默认账号：**admin / admin@1234**（role=admin）
- 种子：7 条示例资产（覆盖根 CA / VPN 网关 / 长期档案等画像），首页与评分概览开箱有数据
- 种子（R2）：3 台改造设备（网关 / HSM / CA）+ 1 条 `root-ca-hybrid` 的 **planned** 示例工单（不自动执行）

### 环境变量

| 变量 | 默认值 | 说明 |
|---|---|---|
| `ZPQM_PORT` | `8099` | HTTP 端口 |
| `ZPQM_JWT_SECRET` | `zhulong-pqm-dev-secret` | JWT 签名密钥（生产务必覆盖） |
| `ZPQM_DB_PATH` | `./zhulong-pqm.db` | SQLite 文件路径 |

### 测试

```bash
go build ./...
go vet ./...
go test ./...            # 五维评分引擎含 7 个预设画像断言
```

## 五维评分引擎

综合分 = 加权和（round-half-up 四舍五入，满分 100），原始浮点 `rawScore` 留存供审计。

| 维度 | 含义 | 权重 |
|---|---|---|
| D1 | 算法脆弱性 | 0.30 |
| D2 | 数据敏感度 | 0.25 |
| D3 | 数据生命周期 | 0.20 |
| D4 | 迁移复杂度 | 0.15 |
| D5 | 暴露面 | 0.10 |

- 分级：≥75 → **P1/极高**（0-3 月）；50-74 → **P2/高**（3-6 月）；25-49 → **P3/中**（6-12 月）；<25 → **P4/低**（持续监控）
- **HNDL**（Harvest-Now-Decrypt-Later）标记：D2≥60 且 D3≥60 时置位
- 扫描入库时按算法/密钥位数/TLS 版本/暴露面/层级**自动推导** D1-D5，之后仍可经 `POST /assets/:id/score` 手工覆盖单维并重算

预设画像（`GET /score/presets`，已被单测锁定）：

| 画像 | D1-D5 | 综合分 | 等级 |
|---|---|---|---|
| 内部根CA | 90/100/100/85/10 | 86 | P1 |
| SSL VPN网关 | 90/85/60/85/90 | 82 | P1 |
| 对外TLS证书 | 70/30/10/10/90 | 41 | P3 |
| 长期合规档案 | 90/85/100/35/10 | 75 | P1 |
| IoT设备证书 | 70/60/100/100/40 | 75 | P1 |
| 数据库静态加密 | 40/85/60/35/10 | 52 | P2 |
| 代码签名证书 | 90/85/85/10/70 | 74 | P2 |

## 发现引擎

`scan.TLSScanner` 用 `crypto/tls` 真实握手（超时 5s，`InsecureSkipVerify` 仅为取证书，不做信任判定），提取 TLS 版本、密码套件、公钥算法（RSA/ECDSA/Ed25519）与位数、签名算法、证书主体/签发者/有效期。任务并发上限 16，结果落 `ScanResult` 并据 `Host+Port` 去重建/并 `CryptoAsset`。

目标支持 `host` 与 `host:port`（默认端口 443）；CIDR 网段展开为 TODO。

## API 一览

所有接口前缀 `/api/v1`。除 `login`、`healthz` 外均需 `Authorization: Bearer <token>`。CORS 已对本地前端放开。

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/healthz` | 健康检查 |
| POST | `/auth/login` | 登录，返回 `{token, user}` |
| GET | `/dashboard` | 首页概览（总数/分层/P1/HNDL/极高/均分/扫描数） |
| GET | `/assets` | 资产列表，支持 `layer/level/system/hndl/q` 过滤 |
| GET | `/assets/:id` | 资产详情 |
| POST | `/assets` | 新建资产（含五维分则自动评分） |
| PUT | `/assets/:id` | 更新资产并重算 |
| DELETE | `/assets/:id` | 删除资产 |
| POST | `/assets/:id/score` | 覆盖部分维度分值（`{d1..d5}` 可只传部分）并重算 |
| POST | `/scans` | 创建扫描任务并**异步执行**，返回 job |
| GET | `/scans` | 任务列表 |
| GET | `/scans/:id` | 任务详情 + 结果列表 |
| GET | `/score/summary` | 按等级聚合的评分概览 |
| GET | `/score/presets` | 预设画像 |
| GET | `/score/options` | 五维选项与分值（前端下拉） |
| GET | `/cbom/export` | 导出 CycloneDX 1.6 CBOM JSON |
| POST | `/reports` | 生成摸底报告（可选 `{scope}` 按系统过滤），返回 `{id,title,markdown}` |
| GET | `/reports` | 报告列表（不含正文） |
| GET | `/reports/:id` | 报告全文 |
| GET | `/devices` | 改造设备列表（倒序） |
| POST | `/devices` | 新建改造设备 |
| PUT | `/devices/:id` | 更新改造设备 |
| DELETE | `/devices/:id` | 删除改造设备 |
| POST | `/devices/:id/test` | **真实探测** endpoint 连通性，落库并返回 `{status,latencyMs,detail}`（离线返回 200+offline，非 500） |
| GET | `/playbooks` | 改造剧本库（静态，5 条轨道） |
| GET | `/remediations` | 改造工单列表（倒序） |
| GET | `/remediations/summary` | 工单状态聚合 `{planned,running,done,failed,total}` |
| GET | `/remediations/:id` | 工单详情（含 `steps`/`evidence`） |
| POST | `/remediations` | 按剧本快照建 **planned** 工单 `{assetId?,assetName?,track,targetAlgo?,deviceId}` |
| POST | `/remediations/:id/execute` | 启动编排器**异步执行**，返回工单 |
| POST | `/remediations/:id/rollback` | 置 `rolledback` 并追加「回滚至迁移前状态」步骤 |

## R2 改造主线（改造编排）

以**编排外部设备**为主线，把资产从经典密码迁移到后量子算法。三类对象：

- **Device** 改造执行设备（gateway/hsm/ca/proxy）：持 `endpoint`、`capabilities` 与最近探测出的 `status`/`latencyMs`。
- **Playbook** 剧本（`internal/remediate`，静态不入库）：5 条轨道 `tls-hybrid` / `root-ca-hybrid` / `ssl-vpn-hybrid` / `code-signing` / `gm-hybrid`，各自定义标准步骤、默认目标算法、交付物与验收口径。建工单时按剧本**快照**，剧本演进不影响历史工单。
- **RemediationTask** 工单：含一组 `Step`（嵌入 JSON）、`progress`、`evidence`，状态机 `planned → running → done/failed`，可 `rolledback`。

### 编排器（`remediate.Orchestrator`，模式照抄 `scan.Runner`）

`POST /remediations/:id/execute` 把工单放入 goroutine 异步执行，每步落库后停顿 ~600ms 供前端轮询观察进度：

1. **连通性校验**（首步）：对 `device.Endpoint` 做**真实探测**——先 HTTP `GET {endpoint}/healthz`（超时 3s，任意响应即在线），失败退化为 TCP 连接探测；记录 `latencyMs`，落库设备 `online`/`offline`。
2. **下发/灰度/分发/升级** 等动作步骤：设备在线 → `done` 并写实际动作；**设备离线 → `simulated`**，诚实标记「设备离线，步骤模拟执行」，绝不谎报 `done`。
3. **验收步骤**（步骤名以「验收」结尾）：写 `evidence`（如 `tls-hybrid → {handshake:X25519MLKEM768, verify:ok}`、`ssl-vpn → {ke-method:MLKEM_768+X25519}`、`root-ca → {chain:verify ok}`）。

全部完成 → `done`/`progress=100`/`finishedAt`；真实失败（缺设备/设备不存在/无步骤）→ `failed` + `error`，首个未完成步骤标 `failed`。

### 快速验证

```bash
# 健康检查
curl -s localhost:8099/api/v1/healthz

# 登录拿 token
TOKEN=$(curl -s -X POST localhost:8099/api/v1/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"admin@1234"}' | jq -r .token)

# 概览
curl -s localhost:8099/api/v1/dashboard -H "Authorization: Bearer $TOKEN" | jq

# 发起一次真实 TLS 扫描
curl -s -X POST localhost:8099/api/v1/scans -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"name":"冒烟","targets":["example.com:443","badssl.com"],"exposure":"public"}'

# --- R2 改造主线 ---
# 剧本库与设备
curl -s localhost:8099/api/v1/playbooks -H "Authorization: Bearer $TOKEN" | jq '.[].key'
curl -s localhost:8099/api/v1/devices   -H "Authorization: Bearer $TOKEN" | jq

# 建一条 tls-hybrid 工单（绑设备 1），执行，轮询看步骤逐步推进 + evidence
TID=$(curl -s -X POST localhost:8099/api/v1/remediations -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"track":"tls-hybrid","assetName":"门户TLS","deviceId":1}' | jq -r .id)
curl -s -X POST localhost:8099/api/v1/remediations/$TID/execute -H "Authorization: Bearer $TOKEN" >/dev/null
curl -s localhost:8099/api/v1/remediations/$TID -H "Authorization: Bearer $TOKEN" | jq '{status,progress,steps,evidence}'

# 设备连通性探测（离线 endpoint 返回 200 + status=offline，而非 500）
curl -s -X POST localhost:8099/api/v1/devices/1/test -H "Authorization: Bearer $TOKEN" | jq
```

## 目录结构

```
backend/
  cmd/zhulong-pqm/main.go        # 启动入口
  internal/config/               # 端口/JWT/DB 路径配置
  internal/db/                   # gorm 打开 + AutoMigrate + seed
  internal/model/                # 领域模型（User/CryptoAsset/ScanJob/ScanResult/Report）
  internal/scoring/              # 五维评分引擎（核心）+ 单测
  internal/scan/                 # 发现引擎（Scanner 接口 + 真实 TLS 探测 + 任务执行）
  internal/remediate/            # R2 改造主线：剧本库 + 连通性探测 + 异步编排器
  internal/cbom/                 # CycloneDX 1.6 CBOM 导出
  internal/report/              # 摸底报告（Markdown）生成
  internal/api/                  # gin 路由 + JWT 中间件 + CORS + 各 handler
```
