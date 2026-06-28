# 烛龙·后量子迁移治理平台 · Zhulong PQM

> 国密零信任「烛龙」产品家族成员 · 后量子密码（PQC）迁移治理平台
> 内部代号 `zhulong-pqm` · 当前阶段：**R1 (MVP) 脚手架**

扫描现网密码学使用点 → 建立 CBOM 密码使用点清单 → 五维风险建模定优先级 → 编排外部设备（烛龙网关 / HSM / CA）完成后量子改造 → 持续监测，构成一条全生命周期 PQC 迁移治理闭环。

完整产品需求见 [docs/PRD.md](docs/PRD.md)（11 章 / 101 FR / 12 决策点）。

## R1 范围（已按决策收敛）

| 决策 | R1 落地 |
|---|---|
| DP-02 发现策略 | **Agentless 网络扫描为主干**（无需部署主机 Agent）；被动流量为可选增强；主机 Agent 后置 R2 |
| DP-03 改造形态 | **以编排外部设备为主线**（烛龙网关混合 KEM 下发 + HSM 混合根 CA）；内建 CA/反代后置 R2 |
| DP-04 国密 PQC | 算法选型采 **SM2+ML-KEM / SM2+ML-DSA** 混合过渡 |
| DP-10 控制台 | **独立控制台**（自建登录/RBAC，仅共享烛龙品牌与黏土橙视觉） |

R1 闭环：**发现（Agentless）→ CBOM 建档 → 五维评分 → 摸底报告**，并预留改造编排接口。

## 目录结构

```
zhulong-pqm/
├── docs/PRD.md        产品需求文档
├── backend/           Go 后端（Gin + GORM + 纯 Go SQLite，:8099）
│   ├── internal/scan/      发现引擎（真实 TLS 探测）
│   ├── internal/scoring/   五维风险评分引擎
│   ├── internal/cbom/      CycloneDX CBOM 导出
│   └── internal/report/    摸底报告生成
└── frontend/          Vue3 + Vite + Arco Design Vue（黏土橙暖色系，:5390）
```

## 快速开始

```bash
# 1) 后端（:8099，默认账号 admin / admin@1234）
cd backend && go run ./cmd/zhulong-pqm

# 2) 前端（:5390，dev 代理 /api → :8099）
cd frontend && npm install && npm run dev
```

打开 http://localhost:5390 ，用默认账号登录。后端首次启动会落库 `zhulong-pqm.db` 并按 7 个预设画像（内部根CA / SSL VPN / 对外TLS / 长期合规档案 / IoT / 数据库静态加密 / 代码签名）写入示例资产，仪表板与评估页开箱即有数据。

## 技术栈

- **后端**：Go 1.23 · Gin · GORM + glebarez/sqlite（纯 Go，免 CGO，利信创/交叉编译）· JWT
- **前端**：Vue 3 · TypeScript · Vite · Arco Design Vue · Pinia · Axios
- **视觉**：Claude 黏土橙暖色系（accent `#B4552D` / `#DB855C`）+ Hanken Grotesk

各子工程的详细说明见 `backend/README.md` 与 `frontend/README.md`。
