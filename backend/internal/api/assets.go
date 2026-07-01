package api

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"zhulong-pqm/internal/db"
	"zhulong-pqm/internal/model"
	"zhulong-pqm/internal/scoring"
)

// listAssets 列出资产，支持 layer/level/system/hndl/q 过滤。
func (s *Server) listAssets(c *gin.Context) {
	q := s.db.Model(&model.CryptoAsset{})

	if v := c.Query("layer"); v != "" {
		q = q.Where("layer = ?", v)
	}
	if v := c.Query("level"); v != "" {
		q = q.Where("risk_level = ?", v)
	}
	if v := c.Query("system"); v != "" {
		q = q.Where("system = ?", v)
	}
	if v := c.Query("hndl"); v != "" {
		q = q.Where("hndl = ?", v == "true" || v == "1")
	}
	if v := strings.TrimSpace(c.Query("group")); v != "" {
		clause, arg := groupFilterClause(v) // ⑥ 资产分组筛选
		q = q.Where(clause, arg)
	}
	if v := strings.TrimSpace(c.Query("q")); v != "" {
		like := "%" + v + "%"
		q = q.Where("name LIKE ? OR system LIKE ? OR algorithm LIKE ? OR endpoint LIKE ?",
			like, like, like, like)
	}

	var assets []model.CryptoAsset
	if err := q.Order("risk_score desc").Find(&assets).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	for i := range assets {
		loadAssetGroupTags(&assets[i])
	}
	c.JSON(http.StatusOK, assets)
}

func (s *Server) getAsset(c *gin.Context) {
	var a model.CryptoAsset
	if err := s.db.First(&a, c.Param("id")).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "资产不存在"})
		return
	}
	loadAssetGroupTags(&a)
	c.JSON(http.StatusOK, a)
}

// createAsset 新建资产；若提供了五维分则自动重算综合分与分级。
func (s *Server) createAsset(c *gin.Context) {
	var a model.CryptoAsset
	if err := c.ShouldBindJSON(&a); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if a.Name == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "name 必填"})
		return
	}
	if a.Source == "" {
		a.Source = model.SourceManual
	}
	if a.Exposure == "" {
		a.Exposure = model.ExposureInternal
	}
	if a.Status == "" {
		a.Status = model.StatusConfirmed
	}
	if a.Confidence == 0 {
		a.Confidence = 100
	}
	a.GroupTagsJSON = db.MarshalStrings(a.GroupTags) // ⑥ 分组标签持久化
	// 手工 / Agent 录入未给五维分时，按算法/密钥/暴露/层级自动推导（与扫描入库口径一致），
	// 避免 SSH 主机密钥、弱算法等被误判为 0 分 / P4。
	if a.D1 == 0 && a.D2 == 0 && a.D3 == 0 && a.D4 == 0 && a.D5 == 0 {
		longLived := a.CertNotAfter != nil && a.CertNotAfter.After(time.Now().AddDate(10, 0, 0))
		d := scoring.Derive(scoring.DeriveInput{
			Algorithm: a.Algorithm,
			KeySize:   a.KeySize,
			Exposure:  a.Exposure,
			Layer:     a.Layer,
			LongLived: longLived,
		})
		a.D1, a.D2, a.D3, a.D4, a.D5 = d.D1, d.D2, d.D3, d.D4, d.D5
	}
	s.recompute(&a)
	if err := s.db.Create(&a).Error; err != nil {
		if strings.Contains(err.Error(), "UNIQUE constraint") {
			c.JSON(http.StatusConflict, gin.H{"error": "该资产锚点（endpoint 或证书指纹）已存在，避免重复录入"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	loadAssetGroupTags(&a)
	c.JSON(http.StatusCreated, a)
}

// updateAsset 全量更新资产并重算评分。
func (s *Server) updateAsset(c *gin.Context) {
	var existing model.CryptoAsset
	if err := s.db.First(&existing, c.Param("id")).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "资产不存在"})
		return
	}
	var in model.CryptoAsset
	if err := c.ShouldBindJSON(&in); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	// 保留主键与创建时间，其余以入参覆盖。
	in.ID = existing.ID
	in.CreatedAt = existing.CreatedAt
	in.GroupTagsJSON = db.MarshalStrings(in.GroupTags) // ⑥ 分组标签持久化
	s.recompute(&in)
	if err := s.db.Save(&in).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	loadAssetGroupTags(&in)
	c.JSON(http.StatusOK, in)
}

func (s *Server) deleteAsset(c *gin.Context) {
	if err := s.db.Delete(&model.CryptoAsset{}, c.Param("id")).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"deleted": true})
}

// scoreReq 单维覆盖请求。指针字段区分"未传"与"传 0"。
type scoreReq struct {
	D1 *int `json:"d1"`
	D2 *int `json:"d2"`
	D3 *int `json:"d3"`
	D4 *int `json:"d4"`
	D5 *int `json:"d5"`
}

// scoreAsset 手工覆盖部分维度分值并重算保存。
func (s *Server) scoreAsset(c *gin.Context) {
	var a model.CryptoAsset
	if err := s.db.First(&a, c.Param("id")).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "资产不存在"})
		return
	}
	var req scoreReq
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if req.D1 != nil {
		a.D1 = clampDim(*req.D1)
	}
	if req.D2 != nil {
		a.D2 = clampDim(*req.D2)
	}
	if req.D3 != nil {
		a.D3 = clampDim(*req.D3)
	}
	if req.D4 != nil {
		a.D4 = clampDim(*req.D4)
	}
	if req.D5 != nil {
		a.D5 = clampDim(*req.D5)
	}
	s.recompute(&a)
	if err := s.db.Save(&a).Error; err != nil {
		s.audit(c, "asset", "asset.score", auditTarget("CryptoAsset", a.ID, a.Name), model.AuditFailure, err.Error())
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	// 成功后写一条 Reason=manual 的不可变评分快照（当前生效方案 + 操作人）。
	s.recordScoreHistory(c, &a, model.ReasonManual)
	s.audit(c, "asset", "asset.score", auditTarget("CryptoAsset", a.ID, a.Name), model.AuditSuccess,
		fmt.Sprintf("综合分=%d(%s) HNDL=%v", a.RiskScore, a.RiskLevel, a.HNDL))
	c.JSON(http.StatusOK, a)
}

// recompute 据资产当前五维分、按当前生效权重方案重算综合分、分级、HNDL、建议算法与风险提示。
// 读 db.ActiveWeights（无生效方案则回退 StandardWeights），保证单资产评分与批量复算口径一致（C3）。
func (s *Server) recompute(a *model.CryptoAsset) {
	a.D1, a.D2, a.D3, a.D4, a.D5 = clampDim(a.D1), clampDim(a.D2), clampDim(a.D3), clampDim(a.D4), clampDim(a.D5)
	w := db.ActiveWeights(s.db)
	r := scoring.ScoreWith(scoring.Dimensions{D1: a.D1, D2: a.D2, D3: a.D3, D4: a.D4, D5: a.D5}, w)
	a.RiskScore = r.Score
	a.RawScore = r.RawScore
	a.RiskLevel = r.Level
	a.RiskLevelText = r.LevelText
	a.HNDL = r.HNDL
	if a.SuggestedAlgo == "" && a.Algorithm != "" {
		a.SuggestedAlgo = scoring.SuggestAlgo(a.Algorithm)
	}
	if a.RiskHint == "" && a.Algorithm != "" {
		a.RiskHint = fmt.Sprintf("%s 综合风险 %d(%s) 建议迁移窗口 %s",
			a.Algorithm, r.Score, r.LevelText, r.Window)
	}
}

// recordScoreHistory 写一条不可变评分快照（取上一条快照填 PrevScore/PrevLevel，取操作人 username）。
// reason 见 model.Reason* 常量。供 ③ 时间线与 ④⑤ 复评回灌共用。
func (s *Server) recordScoreHistory(c *gin.Context, a *model.CryptoAsset, reason string) {
	var prev model.ScoreHistory
	prevScore := -1
	prevLevel := ""
	if err := s.db.Where("asset_id = ?", a.ID).Order("created_at desc").First(&prev).Error; err == nil {
		prevScore = prev.Score
		prevLevel = prev.Level
	}
	profileID := uint(0)
	profileName := ""
	if p, ok := db.ActiveProfile(s.db); ok {
		profileID = p.ID
		profileName = p.Name
	}
	h := model.ScoreHistory{
		AssetID:     a.ID,
		AssetName:   a.Name,
		ProfileID:   profileID,
		ProfileName: profileName,
		D1:          a.D1, D2: a.D2, D3: a.D3, D4: a.D4, D5: a.D5,
		Score:     a.RiskScore,
		RawScore:  a.RawScore,
		Level:     a.RiskLevel,
		LevelText: a.RiskLevelText,
		HNDL:      a.HNDL,
		PrevScore: prevScore,
		PrevLevel: prevLevel,
		Reason:    reason,
		ChangedBy: actorName(c),
		CreatedAt: time.Now(),
	}
	s.db.Create(&h)
}

// assetHistory GET /assets/:id/history 返回某资产的评分快照时间线（倒序，分页）。
func (s *Server) assetHistory(c *gin.Context) {
	var a model.CryptoAsset
	if err := s.db.First(&a, c.Param("id")).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "资产不存在"})
		return
	}
	limit, offset := pageLimitOffset(c, 50)
	var rows []model.ScoreHistory
	s.db.Where("asset_id = ?", a.ID).Order("created_at desc").
		Limit(limit).Offset(offset).Find(&rows)
	c.JSON(http.StatusOK, rows)
}

// clampDim 将维度分值约束到 [0,100]。
func clampDim(v int) int {
	if v < 0 {
		return 0
	}
	if v > 100 {
		return 100
	}
	return v
}
