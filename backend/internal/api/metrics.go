package api

import (
	"context"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"zhulong-pqm/internal/model"
	"zhulong-pqm/internal/scan"
)

// ---- ⑥ 仪表板趋势（Wave C）：MetricSnapshot 时序 + 共享 computeMetrics + daily 快照 ----
//
// 快照采集复用 dashboard.go 既有聚合口径（byLayer/p1/hndl/avg），抽成 computeMetrics 共享，
// 避免两套口径漂移。daily 快照任务注册到 B0-5 的单 ticker（C1），不引入第二个 ticker。

// computeMetrics 计算当前资产/风险/改造聚合快照（与 dashboard 同口径）。
func computeMetrics(gdb *gorm.DB) model.MetricSnapshot {
	var assets []model.CryptoAsset
	gdb.Where("status <> ?", model.StatusMerged).Find(&assets)

	var p1, p2, p3, p4, hndl, sum int
	for _, a := range assets {
		switch a.RiskLevel {
		case model.LevelP1:
			p1++
		case model.LevelP2:
			p2++
		case model.LevelP3:
			p3++
		case model.LevelP4:
			p4++
		}
		if a.HNDL {
			hndl++
		}
		sum += a.RiskScore
	}
	avg := 0
	if len(assets) > 0 {
		avg = sum / len(assets)
	}

	// 改造完成资产数（去重 AssetID，Status=done）。
	var remediated int64
	gdb.Model(&model.RemediationTask{}).
		Where("status = ? AND asset_id IS NOT NULL", model.RemDone).
		Distinct("asset_id").Count(&remediated)

	// 已处置告警数（acked/resolved），监测健康趋势。
	var handled int64
	gdb.Model(&model.MonitorEvent{}).
		Where("status IN ?", []string{model.MonAcked, model.MonResolved}).Count(&handled)

	return model.MetricSnapshot{
		Date:            time.Now().Format("2006-01-02"),
		TotalAssets:     len(assets),
		P1Count:         p1,
		P2Count:         p2,
		P3Count:         p3,
		P4Count:         p4,
		HNDLCount:       hndl,
		AvgScore:        avg,
		RemediatedCount: int(remediated),
		HandledCount:    int(handled),
		CreatedAt:       time.Now(),
	}
}

// captureSnapshot 采集当日快照并按 Date upsert（同日重复采集覆盖）。
func captureSnapshot(gdb *gorm.DB, synthetic bool) (model.MetricSnapshot, error) {
	snap := computeMetrics(gdb)
	snap.Synthetic = synthetic

	var existing model.MetricSnapshot
	if err := gdb.First(&existing, "date = ?", snap.Date).Error; err == nil {
		snap.ID = existing.ID
		snap.CreatedAt = existing.CreatedAt
		if err := gdb.Model(&model.MetricSnapshot{}).Where("id = ?", existing.ID).Updates(map[string]interface{}{
			"total_assets":     snap.TotalAssets,
			"p1_count":         snap.P1Count,
			"p2_count":         snap.P2Count,
			"p3_count":         snap.P3Count,
			"p4_count":         snap.P4Count,
			"hndl_count":       snap.HNDLCount,
			"avg_score":        snap.AvgScore,
			"remediated_count": snap.RemediatedCount,
			"handled_count":    snap.HandledCount,
			"synthetic":        snap.Synthetic,
		}).Error; err != nil {
			return snap, err
		}
		return snap, nil
	}
	if err := gdb.Create(&snap).Error; err != nil {
		return snap, err
	}
	return snap, nil
}

// RegisterDailySnapshot 把 daily 快照任务注册到统一调度器（C1：复用 B0-5 单 ticker）。
// 启动即采一次当日快照，之后每 24h 采一次。
func RegisterDailySnapshot(sched *scan.Scheduler, gdb *gorm.DB) {
	// 启动即采一次（demo 立即出点）。
	if _, err := captureSnapshot(gdb, false); err != nil {
		log.Printf("metrics: 启动快照采集失败: %v", err)
	}
	sched.Register("metrics.daily-snapshot", 24*time.Hour, func(ctx context.Context) {
		if _, err := captureSnapshot(gdb, false); err != nil {
			log.Printf("metrics: daily 快照采集失败: %v", err)
		}
	})
}

// dashboardTrend GET /dashboard/trend?days=7 → 最近 N 日 MetricSnapshot 序列（缺日不补零）。
func (s *Server) dashboardTrend(c *gin.Context) {
	days := 7
	if v := c.Query("days"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 365 {
			days = n
		}
	}
	from := time.Now().AddDate(0, 0, -days+1).Format("2006-01-02")
	var rows []model.MetricSnapshot
	if err := s.db.Where("date >= ?", from).Order("date asc").Find(&rows).Error; err != nil {
		serverError(c, err)
		return
	}
	// 多序列时序：前端按点连线。
	type point struct {
		Date        string `json:"date"`
		TotalAssets int    `json:"totalAssets"`
		P1Count     int    `json:"p1Count"`
		Remediated  int    `json:"remediated"`
		AvgScore    int    `json:"avgScore"`
		HNDLCount   int    `json:"hndlCount"`
		Synthetic   bool   `json:"synthetic"`
	}
	series := make([]point, 0, len(rows))
	for _, r := range rows {
		series = append(series, point{
			Date: r.Date, TotalAssets: r.TotalAssets, P1Count: r.P1Count,
			Remediated: r.RemediatedCount, AvgScore: r.AvgScore, HNDLCount: r.HNDLCount,
			Synthetic: r.Synthetic,
		})
	}
	c.JSON(http.StatusOK, gin.H{"days": days, "series": series})
}

// captureMetricsSnapshot POST /metrics/snapshot → 手动采集当日快照（upsert by date，writer 组）。
func (s *Server) captureMetricsSnapshot(c *gin.Context) {
	snap, err := captureSnapshot(s.db, false)
	if err != nil {
		s.audit(c, "setting", "metrics.snapshot", auditTargetStr("MetricSnapshot", snap.Date, snap.Date),
			model.AuditFailure, err.Error())
		serverError(c, err)
		return
	}
	s.audit(c, "setting", "metrics.snapshot", auditTargetStr("MetricSnapshot", snap.Date, snap.Date),
		model.AuditSuccess, "")
	c.JSON(http.StatusOK, snap)
}
