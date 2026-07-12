# 烛龙·后量子迁移治理平台（Zhulong PQM）

面向私有化/信创交付的 PQC 迁移治理平台：「发现→CBOM建档→五维评估→改造编排→验收监测」五阶段闭环。烛龙家族成员但**独立控制台**。R1+R2 完成，R3 深化（持续监测/47 项验收自动化/审计RBAC/治理大屏/国密真设备适配器）已大量落地。云端演示 http://124.223.225.77/pqm/，内网自服务部署 10.50.93.20（免 nginx，ZPQM_STATIC_DIR）。remote=Promethues0/zhulong-pqm。

## 交流与协作约定

- 全程中文；commit 用 feat(scope): / security: 前缀。
- **主题是「字节跳动蓝」#165DFF**（frontend/src/theme/brand.css），**不是黏土橙**——根 README 和 frontend/README 仍写黏土橙/clay.css 均已过时，勿照着找。只覆写 --primary-*（RGB 三元组）与 --brand-*，铺 :root,body 两层；**严禁覆写 Arco 的 --color-***（brand.css 头注释解释了旧主题为何翻车）。

## 常用命令

```bash
cd backend && go run ./cmd/zhulong-pqm      # :8099，admin/admin@1234，首启自动建库+种子
cd frontend && npm run dev                  # :5390（或 preview_start zhulong-pqm-frontend），/api→:8099
cd frontend && npm run build                # 先 vue-tsc --noEmit，TS 错误直接 fail
cd backend && go build ./... && go vet ./... && go test ./...   # 评分引擎 7 画像断言
cd deploy && ./build.sh                     # 交叉编译 linux amd64+arm64 + 前端 → deploy/dist/
cd deploy && VERSION=1.0.0 ./package.sh     # 产出 tar.gz；目标机 sudo ./install.sh
```

## 架构地图

- `backend/internal/api/` — Gin + JWT + RBAC(admin/operator/viewer) + 审计 + 限流，30 个 handler；router.go 含 ZPQM_STATIC_DIR 自服务前端托管（/pqm/ SPA 回退）
- `backend/internal/scan/` — Agentless 发现：crypto/tls 真实握手探测（超时5s/并发16），Host+Port 去重
- `backend/internal/scoring/` — 五维评分（D1-D5 权重 30/25/20/15/10，P1-P4 分级，HNDL=D2≥60且D3≥60），7 预设画像被单测锁定
- `backend/internal/remediate/` — R2 改造编排：5 轨道静态剧本 + 异步 Orchestrator + **国密真设备只读发现适配器**（hsm_client.go Aigis-sig / signserver_client.go ML-DSA）
- `backend/internal/monitor/ + verify/` — R3 持续监测 + 47 项声明式验收（**动这两块前先读 docs/深化蓝图-R3.md，它是权威规格**）
- `backend/internal/gmtls/` — 国密 TLCP 管理面（ZPQM_TLCP_ADDR 启用，首启自动生成自签 SM2 双证）
- `frontend/src/views/` — 15 页（Dashboard/Discovery/Assets/RiskAssessment/Remediation/Acceptance/Monitor/BigScreen…）
- `frontend/src/api/` — client.ts(axios Bearer+401跳登录) / types.ts 镜像后端契约（后端 uint id=前端 number）
- `backend/internal/cryptoref/` — **后量子识别引擎地基**：TLS 命名组码点表(named_groups)/PQC算法表(algorithms)/进程×加密库检测表(lib_detect)；码点权威·尺寸兜底·GREASE丢弃·EffectiveHNDL共享清除。数据源 `docs/superpowers/specs/2026-07-11-pqc-crypto-lib-research.md`
- `backend/cmd/agent/` — **主机 Agent 二进制(M-C)**：纯Go免CGO单文件，进程×库/监听握手/磁盘证书/SSH主机密钥/内核算法+dpkg-rpm包五路发现；经 M-B 受限通道(X-Agent-Key)上报；**`--role=probe` 为分布式抓包探针(AF_PACKET/tcpdump→ParsePCAP→观测上报,M-D1)**。旧 `agent/zhulong-pqm-agent.sh` bash PoC 仍保留
- `backend/internal/api/agents.go` + `model.Agent` — **M-B Agent身份**：注册→一次性apiKey→X-Agent-Key受限上报(/agent/assets/batch)，资产盖 ReportedBy 归属
- `docs/` — PRD.md、深化蓝图-R3.md、使用说明书.md、**主机Agent安装手册.md**、**deploy-10.50.93.20-runbook.md**、superpowers/{specs,plans}(PQC识别设计/M-A计划/字典附录)

## 关键约定

- **纯 Go 免 CGO 是硬约束**（信创鲲鹏/飞腾交叉编译）：SQLite 用 glebarez，新依赖不得引入 CGO。
- API 统一 /api/v1；除 login/healthz 全 JWT；写操作限 operator/admin；敏感操作落审计。
- 异步任务同构模式：同步 Run 放 goroutine，每步落库，前端 ~2s 轮询。
- GORM：JSON 列存 text + `gorm:"-"` 镜像字段（用 db.Marshal/UnmarshalStrings）；**新模型必须加进 db.Open 的 AutoMigrate 清单**，否则表不建。
- 剧本/验收用例是内存静态表不入库，建工单时快照进 DB。
- 「诚实 simulated」原则：设备离线时步骤标 simulated 绝不谎报 done；探测离线返回 200+offline 而非 500。
- 设备适配器只读原则：发现一律只读，写接口仅编排改造且带确认闸门时调用。

## 坑

- **vite base 双态**（vite.config.ts）：生产 base='/pqm/'，本地 dev 是 '/'——乱改会资源 404 白屏，配置里有整段注释。
- ZPQM_JWT_SECRET 未设则进程级随机密钥、重启全体 token 失效；设备凭据加密 ZPQM_ENCRYPTION_KEY 未设回落 JWT_SECRET——生产两者都要显式设。
- Go 需 ≥1.24（README 写 1.23+ 已过时）。
- 端口 :8099，勿与本机 :8088（flk-vpn-cmp-backend / ipsec-gateway-backend）混淆；CORS 默认只放 localhost:5390。
- 生成物勿手改：frontend/dist、deploy/dist、*.tar.gz、backend/zhulong-pqm.db。

## 真机与部署（会话记忆，仓库外事实，动手前核实）

- 纳管真机：密码机 10.50.93.7(Aigis-sig) / 签名机 10.50.93.6(ML-DSA) / 平台 10.50.93.219——endpoint 是运行期录入 DB 的数据，不在代码里。
- 内网部署经验：目标机 sshd 有 faillock + PerSourcePenalties，连错几次会被封——部署用 ssh ControlMaster 复用一条连接。
