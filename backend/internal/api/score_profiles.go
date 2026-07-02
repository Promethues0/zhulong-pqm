package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"zhulong-pqm/internal/db"
	"zhulong-pqm/internal/model"
	"zhulong-pqm/internal/scoring"
)

// ---- ③ 评估深化：权重方案 CRUD + 激活全量复算 + 批量复算（C3 唯一真相源）----

// levelDist 统计一批资产的 P1-P4 分布。
func levelDist(assets []model.CryptoAsset) map[string]int {
	d := map[string]int{model.LevelP1: 0, model.LevelP2: 0, model.LevelP3: 0, model.LevelP4: 0}
	for _, a := range assets {
		if _, ok := d[a.RiskLevel]; ok {
			d[a.RiskLevel]++
		}
	}
	return d
}

func marshalIntMap(m map[string]int) string {
	b, _ := json.Marshal(m)
	return string(b)
}

// lowerDist 把内部大写键的 P1-P4 分布投影成前端契约的小写键（p1..p4）。
func lowerDist(m map[string]int) gin.H {
	return gin.H{
		"p1": m[model.LevelP1],
		"p2": m[model.LevelP2],
		"p3": m[model.LevelP3],
		"p4": m[model.LevelP4],
	}
}

// profileWeights 取方案权重（Σ!=100 时回退 StandardWeights，与 db.ActiveWeights 口径一致）。
func profileWeights(p model.ScoreProfile) scoring.Weights {
	w := scoring.Weights{W1: p.W1, W2: p.W2, W3: p.W3, W4: p.W4, W5: p.W5}
	if w.Sum() != 100 {
		return scoring.StandardWeights
	}
	return w
}

// listScoreProfiles GET /score/profiles → 方案列表（IsActive 置顶，其次内置，其次创建时间倒序）。
func (s *Server) listScoreProfiles(c *gin.Context) {
	var profiles []model.ScoreProfile
	s.db.Order("is_active desc, is_builtin desc, created_at desc").Find(&profiles)
	c.JSON(http.StatusOK, profiles)
}

// activeScoreProfile GET /score/profiles/active → 当前生效方案。
func (s *Server) activeScoreProfile(c *gin.Context) {
	p, ok := db.ActiveProfile(s.db)
	if !ok {
		c.JSON(http.StatusNotFound, gin.H{"error": "无生效权重方案"})
		return
	}
	c.JSON(http.StatusOK, p)
}

// profileReq 权重方案创建/更新请求体。
type profileReq struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	W1          int    `json:"w1"`
	W2          int    `json:"w2"`
	W3          int    `json:"w3"`
	W4          int    `json:"w4"`
	W5          int    `json:"w5"`
}

// validateWeights 校验五维权重：各 ≥0 且 Σ==100。
func validateWeights(r profileReq) error {
	if r.W1 < 0 || r.W2 < 0 || r.W3 < 0 || r.W4 < 0 || r.W5 < 0 {
		return fmt.Errorf("各维权重须 ≥0")
	}
	if sum := r.W1 + r.W2 + r.W3 + r.W4 + r.W5; sum != 100 {
		return fmt.Errorf("五维权重之和须为 100，当前 %d", sum)
	}
	return nil
}

// createScoreProfile POST /score/profiles → 创建权重方案（校验 Σw=100），不自动激活。
func (s *Server) createScoreProfile(c *gin.Context) {
	var req profileReq
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if req.Name == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "name 必填"})
		return
	}
	if err := validateWeights(req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	p := model.ScoreProfile{
		Name:        req.Name,
		Description: req.Description,
		W1:          req.W1, W2: req.W2, W3: req.W3, W4: req.W4, W5: req.W5,
		IsActive:  false,
		IsBuiltin: false,
		Version:   1,
		CreatedBy: actorName(c),
	}
	if err := s.db.Create(&p).Error; err != nil {
		s.audit(c, "score", "profile.create", auditTarget("ScoreProfile", 0, req.Name), model.AuditFailure, err.Error())
		serverError(c, err)
		return
	}
	s.audit(c, "score", "profile.create", auditTarget("ScoreProfile", p.ID, p.Name), model.AuditSuccess,
		fmt.Sprintf("%d/%d/%d/%d/%d", p.W1, p.W2, p.W3, p.W4, p.W5))
	c.JSON(http.StatusCreated, p)
}

// updateScoreProfile PUT /score/profiles/:id → 更新方案；内置方案仅允许改 description（拒改权重）。
func (s *Server) updateScoreProfile(c *gin.Context) {
	var p model.ScoreProfile
	if err := s.db.First(&p, c.Param("id")).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "方案不存在"})
		return
	}
	var req profileReq
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if p.IsBuiltin {
		// 内置方案禁改权重：任何与现有权重不一致的入参一律 400。
		if req.W1 != p.W1 || req.W2 != p.W2 || req.W3 != p.W3 || req.W4 != p.W4 || req.W5 != p.W5 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "内置标准方案禁止修改权重，仅可改描述"})
			return
		}
		if req.Description != "" {
			p.Description = req.Description
		}
	} else {
		if err := validateWeights(req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		if req.Name != "" {
			p.Name = req.Name
		}
		p.Description = req.Description
		weightsChanged := req.W1 != p.W1 || req.W2 != p.W2 || req.W3 != p.W3 || req.W4 != p.W4 || req.W5 != p.W5
		p.W1, p.W2, p.W3, p.W4, p.W5 = req.W1, req.W2, req.W3, req.W4, req.W5
		if weightsChanged {
			p.Version++
		}
	}
	if err := s.db.Save(&p).Error; err != nil {
		serverError(c, err)
		return
	}
	s.audit(c, "score", "profile.update", auditTarget("ScoreProfile", p.ID, p.Name), model.AuditSuccess,
		fmt.Sprintf("v%d %d/%d/%d/%d/%d", p.Version, p.W1, p.W2, p.W3, p.W4, p.W5))
	c.JSON(http.StatusOK, p)
}

// deleteScoreProfile DELETE /score/profiles/:id → 删除；内置/激活方案拒删（400）。
func (s *Server) deleteScoreProfile(c *gin.Context) {
	var p model.ScoreProfile
	if err := s.db.First(&p, c.Param("id")).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "方案不存在"})
		return
	}
	if p.IsBuiltin {
		c.JSON(http.StatusBadRequest, gin.H{"error": "内置标准方案不可删除"})
		return
	}
	if p.IsActive {
		c.JSON(http.StatusBadRequest, gin.H{"error": "当前生效方案不可删除，请先激活其他方案"})
		return
	}
	if err := s.db.Delete(&model.ScoreProfile{}, p.ID).Error; err != nil {
		serverError(c, err)
		return
	}
	s.audit(c, "score", "profile.delete", auditTarget("ScoreProfile", p.ID, p.Name), model.AuditSuccess, "")
	c.JSON(http.StatusOK, gin.H{"deleted": true})
}

// rescoreResult 一次全量复算的产出（before/after 分布 + shift 矩阵 + RescoreRun）。
type rescoreResult struct {
	run    model.RescoreRun
	before map[string]int
	after  map[string]int
	shifts map[string]int
}

// recomputeAll 用给定权重对一批资产逐个 ScoreWith 重算并落库，写 ScoreHistory（reason），
// 统计 before/after 分布与等级迁移矩阵，落一条 RescoreRun。事务内执行（activate/rescore 共用）。
//
// fromProfileID/toProfileID 用于 RescoreRun 溯源；profileID/profileName 写入每条 ScoreHistory 快照；
// changedBy 为操作人；scope 为复算范围标识；w 为复算所用权重。
func (s *Server) recomputeAll(assets []model.CryptoAsset, w scoring.Weights,
	fromProfileID, toProfileID uint, profileID uint, profileName, reason, scope, changedBy string) (rescoreResult, error) {

	before := levelDist(assets)
	shifts := map[string]int{}
	shifted := 0
	now := time.Now()
	var run model.RescoreRun

	err := s.db.Transaction(func(tx *gorm.DB) error {
		for i := range assets {
			a := &assets[i]
			prevLevel := a.RiskLevel

			r := scoring.ScoreWith(scoring.Dimensions{D1: a.D1, D2: a.D2, D3: a.D3, D4: a.D4, D5: a.D5}, w)
			a.RiskScore = r.Score
			a.RawScore = r.RawScore
			a.RiskLevel = r.Level
			a.RiskLevelText = r.LevelText
			a.HNDL = r.HNDL
			if a.SuggestedAlgo == "" && a.Algorithm != "" {
				a.SuggestedAlgo = scoring.SuggestAlgo(a.Algorithm)
			}
			if err := tx.Model(&model.CryptoAsset{}).Where("id = ?", a.ID).Updates(map[string]interface{}{
				"risk_score":      a.RiskScore,
				"raw_score":       a.RawScore,
				"risk_level":      a.RiskLevel,
				"risk_level_text": a.RiskLevelText,
				"hndl":            a.HNDL,
				"suggested_algo":  a.SuggestedAlgo,
				"updated_at":      now,
			}).Error; err != nil {
				return err
			}

			// 等级迁移矩阵（仅记录发生变化的）。
			if prevLevel != "" && prevLevel != a.RiskLevel {
				shifts[fmt.Sprintf("%s->%s", prevLevel, a.RiskLevel)]++
				shifted++
			}

			// 写不可变评分快照（PrevScore/PrevLevel 取该资产上一条）。
			prevScore := -1
			prevHistLevel := ""
			var prev model.ScoreHistory
			if e := tx.Where("asset_id = ?", a.ID).Order("created_at desc").First(&prev).Error; e == nil {
				prevScore = prev.Score
				prevHistLevel = prev.Level
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
				PrevLevel: prevHistLevel,
				Reason:    reason,
				ChangedBy: changedBy,
				CreatedAt: time.Now(),
			}
			if err := tx.Create(&h).Error; err != nil {
				return err
			}
		}

		after := levelDist(assets)
		run = model.RescoreRun{
			FromProfileID:  fromProfileID,
			ToProfileID:    toProfileID,
			Trigger:        reason,
			Scope:          scope,
			AssetCount:     len(assets),
			ShiftedCount:   shifted,
			LevelShiftJSON: marshalIntMap(shifts),
			BeforeDistJSON: marshalIntMap(before),
			AfterDistJSON:  marshalIntMap(after),
			RunBy:          changedBy,
			CreatedAt:      time.Now(),
		}
		return tx.Create(&run).Error
	})
	if err != nil {
		return rescoreResult{}, err
	}

	after := levelDist(assets)
	// 回填响应镜像（run.ID 已由事务内 Create 回填）。
	run.ShiftMatrix = shifts
	run.BeforeDist = before
	run.AfterDist = after
	return rescoreResult{run: run, before: before, after: after, shifts: shifts}, nil
}

// activateScoreProfile POST /score/profiles/:id/activate → 激活并全量复算（C3）。
// 置该方案 IsActive（其余取消），对全部资产用新权重重算落库，每资产写 profile-switch 快照，
// 落一条 RescoreRun，返回 before/after 的 P1-P4 分布对比 + shift 矩阵 + 受影响资产数。
func (s *Server) activateScoreProfile(c *gin.Context) {
	var p model.ScoreProfile
	if err := s.db.First(&p, c.Param("id")).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "方案不存在"})
		return
	}
	var body struct {
		Reason string `json:"reason"`
	}
	_ = c.ShouldBindJSON(&body)

	fromProfileID := uint(0)
	if cur, ok := db.ActiveProfile(s.db); ok {
		fromProfileID = cur.ID
	}

	// 切 IsActive：先全部置 false，再置目标方案为 true（同事务内）。
	now := time.Now()
	if err := s.db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Model(&model.ScoreProfile{}).Where("is_active = ?", true).
			Update("is_active", false).Error; err != nil {
			return err
		}
		return tx.Model(&model.ScoreProfile{}).Where("id = ?", p.ID).Updates(map[string]interface{}{
			"is_active":  true,
			"applied_by": actorName(c),
			"applied_at": &now,
		}).Error
	}); err != nil {
		s.audit(c, "score", "profile.activate", auditTarget("ScoreProfile", p.ID, p.Name), model.AuditFailure, err.Error())
		serverError(c, err)
		return
	}
	p.IsActive = true
	p.AppliedBy = actorName(c)
	p.AppliedAt = &now

	var assets []model.CryptoAsset
	s.db.Where("status <> ?", model.StatusMerged).Find(&assets)

	w := profileWeights(p)
	res, err := s.recomputeAll(assets, w, fromProfileID, p.ID, p.ID, p.Name,
		model.ReasonProfileSwitch, "all", actorName(c))
	if err != nil {
		s.audit(c, "score", "profile.activate", auditTarget("ScoreProfile", p.ID, p.Name), model.AuditFailure, err.Error())
		serverError(c, err)
		return
	}

	s.audit(c, "score", "profile.activate", auditTarget("ScoreProfile", p.ID, p.Name), model.AuditSuccess,
		fmt.Sprintf("全量复算 %d 资产，级别变化 %d，理由：%s", res.run.AssetCount, res.run.ShiftedCount, body.Reason))

	c.JSON(http.StatusOK, gin.H{
		"profile": p,
		"run":     res.run,
		"before":  lowerDist(res.before),
		"after":   lowerDist(res.after),
		"shifts":  res.shifts,
		"shifted": res.run.ShiftedCount,
	})
}

// previewScoreProfile POST /score/profiles/:id/preview → 以该方案试算全资产返回 before/after 分布（不落库）。
// 与 activate 区分：只读预演，不切 IsActive、不写 ScoreHistory/RescoreRun（前端 profileApi.preview）。
func (s *Server) previewScoreProfile(c *gin.Context) {
	var p model.ScoreProfile
	if err := s.db.First(&p, c.Param("id")).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "方案不存在"})
		return
	}
	var assets []model.CryptoAsset
	s.db.Where("status <> ?", model.StatusMerged).Find(&assets)

	before := levelDist(assets)
	w := profileWeights(p)
	after := map[string]int{model.LevelP1: 0, model.LevelP2: 0, model.LevelP3: 0, model.LevelP4: 0}
	shifts := map[string]int{}
	shifted := 0
	hndlBefore, hndlAfter := 0, 0

	for i := range assets {
		a := &assets[i]
		if a.HNDL {
			hndlBefore++
		}
		r := scoring.ScoreWith(scoring.Dimensions{D1: a.D1, D2: a.D2, D3: a.D3, D4: a.D4, D5: a.D5}, w)
		if _, ok := after[r.Level]; ok {
			after[r.Level]++
		}
		if r.HNDL {
			hndlAfter++
		}
		if a.RiskLevel != "" && a.RiskLevel != r.Level {
			shifts[fmt.Sprintf("%s->%s", a.RiskLevel, r.Level)]++
			shifted++
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"profile":    p,
		"assetCount": len(assets),
		"before":     lowerDist(before),
		"after":      lowerDist(after),
		"shifts":     shifts,
		"shifted":    shifted,
		"hndlBefore": hndlBefore,
		"hndlAfter":  hndlAfter,
		"persisted":  false,
	})
}

// rescoreReq 批量复算请求体。
type rescoreReq struct {
	AssetIDs []uint `json:"assetIds"`
	Scope    string `json:"scope"` // all/unscored/scan:<jobId>
}

// rescoreAssets POST /score/rescore → 按当前生效方案对范围内资产复算/重推导，记录一次 RescoreRun。
// scope=all（默认全部）/unscored（未评分：risk_level 空）/scan:<jobId>（该扫描任务关联资产）/assetIds 显式。
// unscored 与 scan 范围对缺五维的资产走 scoring.Derive 自动推导后再计分。
func (s *Server) rescoreAssets(c *gin.Context) {
	var req rescoreReq
	_ = c.ShouldBindJSON(&req)
	scope := req.Scope
	if scope == "" && len(req.AssetIDs) == 0 {
		scope = "all"
	}

	q := s.db.Model(&model.CryptoAsset{}).Where("status <> ?", model.StatusMerged)
	reason := model.ReasonRescore
	switch {
	case len(req.AssetIDs) > 0:
		q = q.Where("id IN ?", req.AssetIDs)
		scope = "asset_ids"
	case scope == "unscored":
		q = q.Where("risk_level = ? OR risk_level IS NULL", "")
		reason = model.ReasonScanImport
	case len(scope) > 5 && scope[:5] == "scan:":
		jobID := scope[5:]
		var ids []uint
		s.db.Model(&model.ScanResult{}).Where("scan_job_id = ?", jobID).
			Distinct("asset_id").Pluck("asset_id", &ids)
		if len(ids) == 0 {
			c.JSON(http.StatusOK, gin.H{"updated": 0, "run": nil})
			return
		}
		q = q.Where("id IN ?", ids)
		reason = model.ReasonScanImport
	default:
		scope = "all"
	}

	var assets []model.CryptoAsset
	if err := q.Find(&assets).Error; err != nil {
		serverError(c, err)
		return
	}
	if len(assets) == 0 {
		c.JSON(http.StatusOK, gin.H{"updated": 0, "run": nil})
		return
	}

	// 未评分/扫描范围：对缺五维的资产先用 Derive 自动推导五维，再统一计分。
	if reason == model.ReasonScanImport {
		for i := range assets {
			a := &assets[i]
			if a.D1 == 0 && a.D2 == 0 && a.D3 == 0 && a.D4 == 0 && a.D5 == 0 {
				long := a.CertNotAfter != nil && a.CertNotAfter.After(time.Now().AddDate(10, 0, 0))
				dims := scoring.Derive(scoring.DeriveInput{
					Algorithm: a.Algorithm, KeySize: a.KeySize, TLSVersion: a.Protocol,
					Exposure: a.Exposure, Layer: a.Layer, LongLived: long,
				})
				a.D1, a.D2, a.D3, a.D4, a.D5 = dims.D1, dims.D2, dims.D3, dims.D4, dims.D5
				// 持久化推导出的五维（recomputeAll 仅更新评分结果字段）。
				s.db.Model(&model.CryptoAsset{}).Where("id = ?", a.ID).Updates(map[string]interface{}{
					"d1": a.D1, "d2": a.D2, "d3": a.D3, "d4": a.D4, "d5": a.D5,
				})
			}
		}
	}

	pid := uint(0)
	pname := ""
	if cur, ok := db.ActiveProfile(s.db); ok {
		pid = cur.ID
		pname = cur.Name
	}
	w := db.ActiveWeights(s.db)
	res, err := s.recomputeAll(assets, w, pid, pid, pid, pname, reason, scope, actorName(c))
	if err != nil {
		s.audit(c, "score", "rescore", auditTargetStr("Scope", scope, scope), model.AuditFailure, err.Error())
		serverError(c, err)
		return
	}

	s.audit(c, "score", "rescore", auditTargetStr("Scope", scope, scope), model.AuditSuccess,
		fmt.Sprintf("复算 %d 资产，级别变化 %d", res.run.AssetCount, res.run.ShiftedCount))

	c.JSON(http.StatusOK, gin.H{
		"updated": res.run.AssetCount,
		"run": gin.H{
			"before":  lowerDist(res.before),
			"after":   lowerDist(res.after),
			"shifted": res.run.ShiftedCount,
			"shifts":  res.shifts,
		},
	})
}
