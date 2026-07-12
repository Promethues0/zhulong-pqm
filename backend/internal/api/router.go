// Package api 提供烛龙 PQM 的 HTTP 接口（gin）。
package api

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"zhulong-pqm/internal/config"
	"zhulong-pqm/internal/model"
	"zhulong-pqm/internal/scan"
)

// Server 持有 HTTP 层依赖。
type Server struct {
	db    *gorm.DB
	cfg   *config.Config
	sched *scan.Scheduler // B0-5 进程内统一调度框架（①周期扫描/⑤复扫共用）
}

// NewServer 构造 API Server。
func NewServer(db *gorm.DB, cfg *config.Config) *Server {
	return &Server{db: db, cfg: cfg, sched: scan.NewScheduler(0)}
}

// Scheduler 暴露统一调度器，供 ① 周期扫描与 ⑤ 监测复扫注册周期任务。
func (s *Server) Scheduler() *scan.Scheduler { return s.sched }

// Router 构建并返回 gin 引擎。
func (s *Server) Router() *gin.Engine {
	r := gin.New()
	r.Use(gin.Logger(), gin.Recovery())

	// CORS：仅放行配置白名单内的前端来源（ZPQM_CORS_ORIGINS，默认本地开发端口）。
	// 线上为 nginx 同源部署，不受此限制。
	r.Use(cors.New(cors.Config{
		AllowOrigins:     s.cfg.CORSOrigins,
		AllowMethods:     []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowHeaders:     []string{"Origin", "Content-Type", "Authorization"},
		ExposeHeaders:    []string{"Content-Length"},
		AllowCredentials: true,
		MaxAge:           12 * time.Hour,
	}))

	r.GET("/api/v1/healthz", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})

	v1 := r.Group("/api/v1")
	v1.POST("/auth/login", s.login)

	// auth：所有已登录用户可访问（读端点留此）。
	auth := v1.Group("")
	auth.Use(s.authMiddleware())

	// writer：写操作子组，限 operator/admin（B0-3 RBAC）。
	writer := auth.Group("")
	writer.Use(s.requireRole(model.RoleOperator, model.RoleAdmin))

	// adminGrp：admin 专属子组（用户管理等）。
	adminGrp := auth.Group("")
	adminGrp.Use(s.requireRole(model.RoleAdmin))

	{
		// ---- 读端点（所有已登录可访问）----
		auth.GET("/dashboard", s.dashboard)
		auth.GET("/dashboard/trend", s.dashboardTrend) // ⑥ 仪表板趋势（MetricSnapshot 时序）

		// ⑥ 系统设置（读：任意已登录；viewer 只读）。
		auth.GET("/settings", s.listSettings)
		auth.GET("/settings/:key", s.getSetting)

		// ⑥ 资产分组词表（读）。
		auth.GET("/asset-groups", s.listAssetGroups)

		// ⑤ SIEM 外推：监测告警导出 CEF/JSON（静态路由，须在 /monitor/events/:id 之前——本身无 :id 段，注册即安全）。
		auth.GET("/monitor/events/export", s.exportMonitorEvents)

		auth.GET("/assets", s.listAssets)
		// 静态路由 /assets/dedup-candidates、/assets/by-group 必须在 /assets/:id 之前注册，避免 gin 当作 :id。
		auth.GET("/assets/dedup-candidates", s.dedupCandidates) // ② 去重候选
		auth.GET("/assets/by-group", s.assetsByGroup)           // ⑥ 资产分组聚合
		auth.GET("/assets/:id", s.getAsset)
		auth.GET("/assets/:id/history", s.assetHistory)       // ③ 评分时间线（B0-2）
		auth.GET("/assets/:id/evidence", s.listAssetEvidence) // ② 证据链下钻

		// ② 建档深化：CBOM 快照（读）。静态 /snapshots/diff 须在 /snapshots/:id 之前注册。
		auth.GET("/snapshots", s.listSnapshots)
		auth.GET("/snapshots/diff", s.diffSnapshots)
		auth.GET("/snapshots/:id/export", s.exportSnapshot)

		// 覆盖度矩阵（① 遗留，FR-3.6）。
		auth.GET("/coverage", s.coverageMatrix)

		auth.GET("/scans", s.listScans)
		auth.GET("/scans/:id", s.getScan)
		auth.GET("/scans/:id/export", s.exportScan) // 扫描结果 CSV 批量导出

		auth.GET("/score/summary", s.scoreSummary)
		auth.GET("/score/presets", s.scorePresets)
		auth.GET("/score/options", s.scoreOptions)

		// ③ 评估深化：权重方案（读）+ 风险登记册（读/导出）。
		auth.GET("/score/profiles", s.listScoreProfiles)
		auth.GET("/score/profiles/active", s.activeScoreProfile)
		auth.GET("/score/register", s.riskRegister)
		auth.GET("/score/register/export", s.exportRegister)

		auth.GET("/reports", s.listReports)
		auth.GET("/reports/:id", s.getReport)

		auth.GET("/devices", s.listDevices)
		auth.GET("/playbooks", s.listPlaybooks)

		auth.GET("/remediations", s.listRemediations)
		auth.GET("/remediations/summary", s.remediationSummary)
		auth.GET("/remediations/:id", s.getRemediation)

		// ---- ⑤ 持续监测（读端点）----
		auth.GET("/monitor/policies", s.listMonitorPolicies)
		auth.GET("/monitor/events", s.listMonitorEvents)
		auth.GET("/monitor/legacy-risks", s.listLegacyRisks)
		auth.GET("/monitor/dashboard", s.monitorDashboard)
		// ⑤ Wave B-2：SLO 时序（静态路由，无 :id 冲突）+ 威胁情报（读）。
		auth.GET("/monitor/slo/summary", s.sloSummaryEndpoint)
		auth.GET("/monitor/slo/series", s.sloSeries)
		auth.GET("/monitor/intel", s.listThreatIntel)

		// ---- ④ 验收自动化（读端点）----
		auth.GET("/verify/cases", s.listVerifyCases)
		auth.GET("/verify/runs", s.listVerifyRuns)
		auth.GET("/verify/runs/:id", s.getVerifyRun)
		auth.GET("/verify/reports", s.listVerifyReports)
		auth.GET("/verify/reports/:id", s.getVerifyReport)
		auth.GET("/verify/risks", s.listVerifyRisks)

		// ---- ① 发现深化：规则库（读）----
		auth.GET("/rules", s.listRules)
		auth.GET("/rules/:id", s.getRule)

		// /me 任意已登录可访问。
		auth.GET("/me", s.me)

		// ---- 写端点（operator/admin）----
		writer.POST("/assets", s.createAsset)
		writer.PUT("/assets/:id", s.updateAsset)
		writer.DELETE("/assets/:id", s.deleteAsset)
		writer.POST("/assets/:id/score", s.scoreAsset)

		// ③ 评估深化：权重方案 CRUD + 激活全量复算 + 批量复算（写：operator/admin）。
		writer.POST("/score/profiles", s.createScoreProfile)
		writer.PUT("/score/profiles/:id", s.updateScoreProfile)
		writer.DELETE("/score/profiles/:id", s.deleteScoreProfile)
		writer.POST("/score/profiles/:id/activate", s.activateScoreProfile)
		writer.POST("/score/profiles/:id/preview", s.previewScoreProfile) // ③ 只读预演（不落库）
		writer.POST("/score/rescore", s.rescoreAssets)

		// ② 建档深化：状态机 + 证据 + 合并（写）。
		writer.POST("/assets/:id/status", s.setAssetStatus)
		writer.POST("/assets/:id/confirm", s.confirmAsset)
		writer.POST("/assets/:id/archive", s.archiveAsset)
		writer.POST("/assets/:id/evidence", s.addAssetEvidence)
		writer.POST("/assets/merge", s.mergeAssets)

		writer.POST("/scans", s.createScan)

		// ① 发现深化：规则库维护 + 证据导入（写）。
		writer.POST("/rules", s.createRule)
		writer.PUT("/rules/:id", s.updateRule)
		writer.DELETE("/rules/:id", s.deleteRule)
		writer.POST("/assets/import/pem", s.importPem)
		writer.POST("/assets/import/sbom", s.importSbom)
		writer.POST("/assets/import/pcap", s.importPcap) // M2 被动流量发现（pcap 解析）
		writer.POST("/assets/import/cbom", s.cbomImport) // ② CBOM 反向导入（FR-4.8）

		writer.GET("/cbom/export", s.cbomExport) // 导出为写级敏感操作（RBAC 矩阵）

		// ② 建档深化：CBOM 快照管理（写）。
		writer.POST("/snapshots", s.createSnapshot)
		writer.DELETE("/snapshots/:id", s.deleteSnapshot)

		writer.POST("/reports", s.createReport)

		// R2 改造主线：设备编排 + 剧本 + 工单（写）。
		writer.POST("/devices", s.createDevice)
		writer.PUT("/devices/:id", s.updateDevice)
		writer.DELETE("/devices/:id", s.deleteDevice)
		writer.POST("/devices/:id/test", s.testDevice)

		writer.POST("/remediations", s.createRemediation)
		writer.POST("/remediations/:id/execute", s.executeRemediation)
		writer.POST("/remediations/:id/rollback", s.rollbackRemediation)

		// ---- ⑤ 持续监测（写端点：operator/admin）----
		writer.POST("/monitor/policies", s.createMonitorPolicy)
		writer.PUT("/monitor/policies/:id", s.updateMonitorPolicy)
		writer.DELETE("/monitor/policies/:id", s.deleteMonitorPolicy)
		writer.POST("/monitor/policies/:id/run", s.runMonitorPolicy)

		writer.POST("/monitor/events/:id/ack", s.ackMonitorEvent)
		writer.POST("/monitor/events/:id/resolve", s.resolveMonitorEvent)
		writer.POST("/monitor/events/:id/reassess", s.reassessMonitorEvent)

		writer.POST("/monitor/legacy-risks", s.createLegacyRisk)
		writer.PUT("/monitor/legacy-risks/:id", s.updateLegacyRisk)
		writer.POST("/monitor/legacy-risks/:id/close", s.closeLegacyRisk)

		// ⑤ Wave B-2：SLO 遥测回填 + 威胁情报录入/拉取（写）。
		writer.POST("/monitor/slo/ingest", s.ingestSLO)
		writer.POST("/monitor/intel", s.createThreatIntel)
		writer.POST("/monitor/intel/pull", s.pullThreatIntel)

		// ---- ④ 验收自动化（写端点：operator/admin）----
		writer.POST("/verify/runs", s.createVerifyRun)
		writer.POST("/verify/runs/:id/report", s.createVerifyReport)
		writer.POST("/verify/reports/:id/sign", s.signVerifyReport)
		writer.POST("/remediations/:id/verify", s.verifyRemediation)

		// ---- ⑥ 平台横切（Wave C）写端点（operator/admin）----
		writer.POST("/metrics/snapshot", s.captureMetricsSnapshot) // 手动采集当日趋势快照

		// ⑥ 资产分组 CRUD（写）。
		writer.POST("/asset-groups", s.createAssetGroup)
		writer.PUT("/asset-groups/:id", s.updateAssetGroup)
		writer.DELETE("/asset-groups/:id", s.deleteAssetGroup)

		// ---- 审计（查询：admin/operator）----
		writer.GET("/audit-logs", s.listAuditLogs)

		// ---- 用户管理（admin 专属）----
		adminGrp.GET("/users", s.listUsers)
		adminGrp.POST("/users", s.createUser)
		adminGrp.PUT("/users/:id", s.updateUser)
		adminGrp.DELETE("/users/:id", s.deleteUser)

		// ⑥ 审计 CSV 导出（admin 专属，静态路由不与 /audit-logs 冲突）。
		adminGrp.GET("/audit-logs/export", s.exportAuditLogs)

		// ⑥ 系统设置写（admin 专属；scoring.weights 只读由 handler 内拒，C3）。
		adminGrp.PUT("/settings/:key", s.updateSetting)
	}

	// 改密：admin 或本人，handler 内部二次判定（故挂 auth 而非 adminGrp）。
	auth.POST("/users/:id/password", s.changePassword)

	// 前端自服务（免 nginx 单机部署，如内网 10.50.93.20）：配置 ZPQM_STATIC_DIR 时，
	// 后端直接托管 dist/ 并对非 /api 路由做 SPA 回退到 index.html。
	if s.cfg.StaticDir != "" {
		s.serveStatic(r, s.cfg.StaticDir)
	}

	return r
}

// serveStatic 托管前端 dist。dist 由 vite `base:'/pqm/'` 构建（与云端 nginx 的 /pqm/ 子路径同构）：
// 资产引用 `/pqm/assets/*`、Vue 路由 BASE_URL=`/pqm/`。故后端也在 `/pqm/` 下托管，并把 `/` 重定向到 `/pqm/`。
// 非 /api、非 /pqm 的路径一律重定向进 /pqm/（保留原路径，便于直接敲 /screen 等深链）。
func (s *Server) serveStatic(r *gin.Engine, dir string) {
	index := filepath.Join(dir, "index.html")
	r.Static("/pqm/assets", filepath.Join(dir, "assets"))
	r.NoRoute(func(c *gin.Context) {
		p := c.Request.URL.Path
		if strings.HasPrefix(p, "/api/") {
			c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
			return
		}
		if strings.HasPrefix(p, "/pqm/") || p == "/pqm" {
			// /pqm/ 下的真实静态文件（如 favicon）优先命中，否则 SPA 回退 index.html。
			if rel := strings.TrimPrefix(p, "/pqm/"); rel != "" && rel != "pqm" {
				if f := filepath.Join(dir, filepath.Clean(rel)); strings.HasPrefix(f, dir) {
					if st, err := os.Stat(f); err == nil && !st.IsDir() {
						c.File(f)
						return
					}
				}
			}
			c.File(index)
			return
		}
		// 根与其它路径 → 归一进 /pqm/（保留子路径）。
		target := "/pqm" + p
		if p == "/" {
			target = "/pqm/"
		}
		c.Redirect(http.StatusFound, target)
	})
}
