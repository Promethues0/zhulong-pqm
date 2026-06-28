# 烛龙 PQM · 前端控制台

烛龙·后量子迁移治理平台 (Zhulong PQM) R1 的前端控制台。独立控制台，不并入现有烛龙控制台。

> 一句话定位：扫描现网密码学使用点 → 建立 CBOM 清单 → 五维风险建模定优先级 → 编排后量子改造 → 持续监测的全生命周期 PQC 迁移治理闭环平台。

## 技术栈

- Vue 3 + Vite + TypeScript
- vue-router 4 + Pinia
- Arco Design Vue (`@arco-design/web-vue`)
- axios（API 调用）+ marked（报告 Markdown 渲染）

## 视觉主题

「Claude 黏土橙」暖色系（烛龙家族统一视觉）：

- 主强调色 `#B4552D`，次级 `#DB855C`，暖白背景 `#FAF7F2`，文本 `#2B2622`
- 字体优先 `Hanken Grotesk`（Google Fonts CDN），系统无衬线回退
- 主题覆盖在 `src/theme/clay.css`，Arco 的 primary 色阶与 `--color-*` token **同时铺在 `:root` 与 `body`** 上以确保生效

## 运行

```bash
npm install
npm run dev
```

- 前端开发端口：**5390**（见 `vite.config.ts`）
- 需先启动后端（默认监听 **:8099**）；dev 服务器将 `/api` 代理到 `http://localhost:8099`
- 默认账号：**admin / admin@1234**

启动后端（在仓库 `backend/` 目录）：

```bash
cd ../backend && go run ./...   # 监听 :8099，可用 ZPQM_PORT 覆盖
```

## 构建

```bash
npm run build      # = vue-tsc --noEmit（类型检查）+ vite build
npm run preview    # 预览 dist 产物
```

## 页面

| 路由 | 页面 | 说明 |
| --- | --- | --- |
| `/login` | 登录 | 居中卡片，品牌 + 副标，默认账号提示 |
| `/dashboard` | 进度仪表板 | 指标卡 / L1–L4 分布 / P1–P4 优先级汇总 / 最近扫描 |
| `/discovery` | 密码学发现 | Agentless 扫描表单 + 任务轮询 + 结果抽屉 |
| `/assets` | 密码使用点清单 (CBOM) | 资产表格 + 层级/分级/HNDL/关键字筛选 + 详情抽屉 + 导出 CBOM |
| `/risk` | 风险评估 | 五维打分 + 实时综合分/分级/HNDL + 预设画像 + 汇总看板 |
| `/remediation` | 改造编排 | 三标签（改造工单 / 设备纳管 / 剧本库）：工单轮询执行/回滚 + 设备连通性测试 + 剧本对照矩阵 |
| `/reports` | 摸底报告 | 一键生成 + Markdown 渲染 + 历史列表 |

### R2 改造编排（`/remediation`）

改造主线 = **编排外部设备**（网关 / 加密机 / CA / 反代）按「轨道 → 步骤 → 执行体 → 交付 → 验收」下发后量子混合迁移。页面用 `a-tabs` 分三个标签：

1. **改造工单**：顶部 4 个摘要小卡（待执行 / 执行中 / 已完成 / 工单总数，取 `/remediations/summary`）；工单表格（资产名 / 轨道 / 目标算法 / 设备 / 状态 / 进度）。
   - 「新建改造」modal：选资产（下拉 `/assets`）或手填资产名 + 选轨道（下拉 `/playbooks`，选后预览步骤/交付物/验收口径）+ 选设备（按轨道 `deviceType` 过滤 `/devices`）+ 目标算法（默认填 `playbook.targetAlgo`），提交 `POST /remediations`。
   - 行点开抽屉：`a-timeline` 展示 steps 时间线，按状态着色（done=绿 / simulated=橙并显式标「模拟」/ running=蓝 / failed=红 / pending=灰）+ Evidence 键值表 + 交付物 + 验收口径。
   - `status=planned` 显「执行改造」（`execute` 后对该工单 **~2s 轮询** 至 done/failed，期间刷新抽屉步骤）；`status=done` 显「回滚」（`rollback`）。
2. **设备纳管**：设备卡片（名称/类型/厂商/endpoint/能力 tag/状态 tag），「连通性测试」按钮（`POST /devices/:id/test`，回填 `latencyMs` 与 online/offline/unknown 配色），「新增设备」modal（类型中文：网关/加密机/CA/反代）。
3. **剧本库**：把 `/playbooks` 渲染成卡片矩阵（轨道名 + deviceType 徽标 + 有序步骤 + 交付物 + 验收口径 + 默认目标算法），作为「轨道 → 步骤 → 执行体 → 交付 → 验收」对照表。

**闭环联动**：`Assets.vue` 资产详情抽屉的「发起改造」按钮 → `router.push('/remediation', { query:{ assetId, assetName, algo } })`；`Remediation.vue` `onMounted` 读 `route.query`，有则自动打开「新建改造」modal 预填资产名/目标算法，并按算法猜测推荐轨道（SM2→`gm-hybrid`、RSA/ECDSA/ECDH→`tls-hybrid`、含 VPN/IKE→`ssl-vpn-hybrid`，否则 `tls-hybrid`）。

> 后端 `id` 为 `uint`，前端 `Device` / `RemediationTask` 的 `id`、`deviceId` 等均为 `number`；`Playbook.key` 与工单 `track` 为字符串键。

## 风险评分口径

综合分 = D1×30% + D2×25% + D3×20% + D4×15% + D5×10%

| 综合分 | 分级 | 文案 | 配色 |
| --- | --- | --- | --- |
| ≥ 75 | P1 | 极高 | 红 |
| 50–74 | P2 | 高 | 橙 |
| 25–49 | P3 | 中 | 黄 |
| < 25 | P4 | 低 | 绿 |

HNDL（Harvest Now, Decrypt Later）标记规则：D2 ≥ 60 且 D3 ≥ 60。

## 目录结构

```
src/
  main.ts  App.vue
  theme/clay.css           # 黏土橙主题（:root + body 双铺）
  router/index.ts          # 路由 + 登录守卫
  store/auth.ts            # token/user 持久化
  api/client.ts            # axios 实例（Bearer / 401 跳登录）
  api/index.ts             # 接口封装
  api/types.ts             # 后端契约 TS 类型
  utils/format.ts          # 配色 / 日期 / 文案工具
  layout/MainLayout.vue    # 侧边菜单 + 顶栏 + 内容区
  components/              # RemediationSteps（步骤时间线）/ PlaybookCard（剧本卡）
  views/                   # Login / Dashboard / Discovery / Assets / RiskAssessment / Remediation / Reports
```
