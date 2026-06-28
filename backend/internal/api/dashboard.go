package api

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"

	"zhulong-pqm/internal/model"
	"zhulong-pqm/internal/scoring"
)

// dashboard 返回首页概览统计。
func (s *Server) dashboard(c *gin.Context) {
	var assets []model.CryptoAsset
	s.db.Find(&assets)

	byLayer := map[string]int{"L1": 0, "L2": 0, "L3": 0, "L4": 0}
	var p1, hndl, critical, sum int
	for _, a := range assets {
		byLayer[a.Layer]++
		if a.RiskLevel == model.LevelP1 {
			p1++
		}
		if a.HNDL {
			hndl++
		}
		if a.RiskLevelText == "极高" {
			critical++
		}
		sum += a.RiskScore
	}
	avg := 0
	if len(assets) > 0 {
		avg = sum / len(assets)
	}

	var scanJobs int64
	s.db.Model(&model.ScanJob{}).Count(&scanJobs)

	var lastJob model.ScanJob
	var lastScanAt *time.Time
	if err := s.db.Order("created_at desc").First(&lastJob).Error; err == nil {
		lastScanAt = &lastJob.CreatedAt
	}

	c.JSON(http.StatusOK, gin.H{
		"totalAssets":   len(assets),
		"byLayer":       byLayer,
		"p1Count":       p1,
		"hndlCount":     hndl,
		"criticalCount": critical,
		"avgScore":      avg,
		"scanJobs":      scanJobs,
		"lastScanAt":    lastScanAt,
	})
}

// scoreSummary 返回按等级聚合的评分概览。
func (s *Server) scoreSummary(c *gin.Context) {
	var assets []model.CryptoAsset
	s.db.Find(&assets)

	type bucket struct {
		Count int     `json:"count"`
		Avg   int     `json:"avg"`
		sum   int     // 内部累加
	}
	buckets := map[string]*bucket{
		"P1": {}, "P2": {}, "P3": {}, "P4": {},
	}
	var hndl, critical, sum int
	for _, a := range assets {
		if b, ok := buckets[a.RiskLevel]; ok {
			b.Count++
			b.sum += a.RiskScore
		}
		if a.HNDL {
			hndl++
		}
		if a.RiskLevelText == "极高" {
			critical++
		}
		sum += a.RiskScore
	}
	for _, b := range buckets {
		if b.Count > 0 {
			b.Avg = b.sum / b.Count
		}
	}
	avg := 0
	if len(assets) > 0 {
		avg = sum / len(assets)
	}

	c.JSON(http.StatusOK, gin.H{
		"p1":            gin.H{"count": buckets["P1"].Count, "avg": buckets["P1"].Avg},
		"p2":            gin.H{"count": buckets["P2"].Count, "avg": buckets["P2"].Avg},
		"p3":            gin.H{"count": buckets["P3"].Count, "avg": buckets["P3"].Avg},
		"p4":            gin.H{"count": buckets["P4"].Count, "avg": buckets["P4"].Avg},
		"hndlCount":     hndl,
		"criticalCount": critical,
		"avgScore":      avg,
		"scoredCount":   len(assets),
	})
}

// scorePresets 返回预设画像。
func (s *Server) scorePresets(c *gin.Context) {
	c.JSON(http.StatusOK, scoring.Presets())
}

// scoreOptions 返回五维选项与分值。
func (s *Server) scoreOptions(c *gin.Context) {
	c.JSON(http.StatusOK, scoring.Options())
}
