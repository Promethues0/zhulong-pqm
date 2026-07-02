package api

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"zhulong-pqm/internal/db"
	"zhulong-pqm/internal/model"
	"zhulong-pqm/internal/monitor"
)

// ============ 威胁情报订阅（ThreatIntel）============
//
// R3 离线为主（NFR-8.7.1）：手工录入 + 离线预置源拉取两条路径。
// TriggerReassess=true 且命中 AffectedAlgos 的资产 → 走 ③ rescore 管线（C5）批量重评分。

// loadIntelJSON 反序列化情报受影响算法族。
func loadIntelJSON(t *model.ThreatIntel) {
	t.AffectedAlgos = db.UnmarshalStrings(t.AffectedAlgosJSON)
}

// listThreatIntel GET /monitor/intel?category=&triggerReassess= → 情报条目列表（倒序）。
func (s *Server) listThreatIntel(c *gin.Context) {
	q := s.db.Model(&model.ThreatIntel{})
	if v := c.Query("category"); v != "" {
		q = q.Where("category = ?", v)
	}
	if v := c.Query("source"); v != "" {
		q = q.Where("source = ?", v)
	}
	if v := c.Query("triggerReassess"); v != "" {
		q = q.Where("trigger_reassess = ?", v == "true" || v == "1")
	}
	var total int64
	q.Count(&total)
	limit, offset := pageLimitOffset(c, 50)
	var items []model.ThreatIntel
	if err := q.Order("ingested_at desc, id desc").Limit(limit).Offset(offset).Find(&items).Error; err != nil {
		serverError(c, err)
		return
	}
	for i := range items {
		loadIntelJSON(&items[i])
	}
	c.JSON(http.StatusOK, gin.H{"total": total, "items": items})
}

// createThreatIntel POST /monitor/intel → 手工录入情报条目。
// triggerReassess=true 时对命中资产批量重评分并生成复评批次（FR-7.11，C5）。
func (s *Server) createThreatIntel(c *gin.Context) {
	var t model.ThreatIntel
	if err := c.ShouldBindJSON(&t); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if strings.TrimSpace(t.Title) == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "title 必填"})
		return
	}
	t.ID = 0
	if t.Source == "" {
		t.Source = "manual"
	}
	if t.Category == "" {
		t.Category = model.IntelStandardUpdate
	}
	if t.PublishedAt.IsZero() {
		t.PublishedAt = time.Now()
	}
	t.IngestedAt = time.Now()
	t.AffectedAlgosJSON = db.MarshalStrings(t.AffectedAlgos)
	if err := s.db.Create(&t).Error; err != nil {
		serverError(c, err)
		return
	}

	result := s.applyIntelReassess(c, &t)
	loadIntelJSON(&t)
	s.audit(c, "monitor", "monitor.intel.create", auditTarget("ThreatIntel", t.ID, t.Title),
		model.AuditSuccess, fmt.Sprintf("category=%s 触发复评=%v 命中=%d",
			t.Category, t.TriggerReassess, result["reassessed"]))
	c.JSON(http.StatusCreated, gin.H{"intel": t, "reassess": result})
}

// pullThreatIntelReq 拉取请求体：可携带离线包条目；无则用预置源。
type pullThreatIntelReq struct {
	Items []model.ThreatIntel `json:"items"` // 离线包导入条目（可空）
}

// pullThreatIntel POST /monitor/intel/pull → 离线预置源 / 离线包导入，幂等去重。
// 去重键：Source+Title+PublishedAt。命中已存在条目跳过；新条目入库并按 TriggerReassess 触发复评。
func (s *Server) pullThreatIntel(c *gin.Context) {
	var req pullThreatIntelReq
	_ = c.ShouldBindJSON(&req) // 允许空体（用预置源）
	candidates := req.Items
	if len(candidates) == 0 {
		candidates = monitor.PresetIntelFeed()
	}

	inserted, skipped := 0, 0
	totalReassessed := 0
	for i := range candidates {
		t := candidates[i]
		t.ID = 0
		if t.Source == "" {
			t.Source = "preset"
		}
		// 幂等去重。
		var n int64
		s.db.Model(&model.ThreatIntel{}).
			Where("source = ? AND title = ? AND published_at = ?", t.Source, t.Title, t.PublishedAt).
			Count(&n)
		if n > 0 {
			skipped++
			continue
		}
		t.IngestedAt = time.Now()
		if t.PublishedAt.IsZero() {
			t.PublishedAt = time.Now()
		}
		t.AffectedAlgosJSON = db.MarshalStrings(t.AffectedAlgos)
		if err := s.db.Create(&t).Error; err != nil {
			continue
		}
		inserted++
		r := s.applyIntelReassess(c, &t)
		if v, ok := r["reassessed"].(int); ok {
			totalReassessed += v
		}
	}
	s.audit(c, "monitor", "monitor.intel.pull", auditTargetStr("ThreatIntel", "", "离线拉取"),
		model.AuditSuccess, fmt.Sprintf("新增=%d 跳过=%d 复评资产=%d", inserted, skipped, totalReassessed))
	c.JSON(http.StatusOK, gin.H{
		"inserted":   inserted,
		"skipped":    skipped,
		"reassessed": totalReassessed,
		"source":     "synthetic", // 离线预置源/离线包，诚实标注非真实订阅流
	})
}

// applyIntelReassess 情报 → 复评映射（FR-7.11，C5）：
// Category in (algo_break, algo_deprecate) 或 QubitCount≥4000，且 TriggerReassess=true →
// 对 AffectedAlgos 命中的资产批量走 ③ rescore 管线重评分 + 入复评队列。
// 回填情报 ReassessTaskID（取首个复评批次 ScoreHistory.ID）。返回摘要。
func (s *Server) applyIntelReassess(c *gin.Context, t *model.ThreatIntel) gin.H {
	res := gin.H{"reassessed": 0, "assetIds": []uint{}}
	if !t.TriggerReassess {
		return res
	}
	threatening := t.Category == model.IntelAlgoBreak ||
		t.Category == model.IntelAlgoDeprecate ||
		t.QubitCount >= 4000
	if !threatening {
		return res
	}
	if len(t.AffectedAlgos) == 0 {
		return res
	}

	// 命中算法族的资产（Algorithm 不区分大小写包含任一受影响算法族）。
	var assets []model.CryptoAsset
	q := s.db.Model(&model.CryptoAsset{})
	conds := make([]string, 0, len(t.AffectedAlgos))
	args := make([]any, 0, len(t.AffectedAlgos))
	for _, a := range t.AffectedAlgos {
		conds = append(conds, "UPPER(algorithm) LIKE ?")
		args = append(args, "%"+strings.ToUpper(strings.TrimSpace(a))+"%")
	}
	q.Where(strings.Join(conds, " OR "), args...).Find(&assets)

	actor := actorName(c)
	reassessedIDs := make([]uint, 0, len(assets))
	var firstBatch *uint
	for i := range assets {
		_, hist, err := monitor.Reassess(s.db, assets[i].ID, actor,
			fmt.Sprintf("intel:%s", t.Title))
		if err != nil {
			continue
		}
		reassessedIDs = append(reassessedIDs, assets[i].ID)
		if firstBatch == nil {
			id := hist.ID
			firstBatch = &id
		}
	}
	if firstBatch != nil {
		t.ReassessTaskID = firstBatch
		s.db.Model(t).Update("reassess_task_id", firstBatch)
	}
	res["reassessed"] = len(reassessedIDs)
	res["assetIds"] = reassessedIDs
	return res
}
