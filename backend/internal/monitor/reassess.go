package monitor

import (
	"fmt"
	"time"

	"gorm.io/gorm"

	"zhulong-pqm/internal/cryptoref"
	"zhulong-pqm/internal/db"
	"zhulong-pqm/internal/model"
	"zhulong-pqm/internal/scoring"
)

// Reassess 复评回灌（C5，J5→J2 闭环）：对一个资产按当前生效权重方案重评分，
// 写 ScoreHistory(Reason=reassess) 快照，并经全局状态机白名单（B0-4）将资产回退到复评态。
//
// 由 ⑤ 漂移 P1、情报命中、API 一键复评共用。changedBy 为触发者 username（漂移/情报用 "system"）。
// 返回重评分后的资产副本，供调用方记录 ReassessTaskID（此处用 ScoreHistory.ID 作为复评批次标识）。
func Reassess(gdb *gorm.DB, assetID uint, changedBy, reasonDetail string) (*model.CryptoAsset, *model.ScoreHistory, error) {
	var a model.CryptoAsset
	if err := gdb.First(&a, assetID).Error; err != nil {
		return nil, nil, err
	}

	// 1) 按当前生效权重方案重算（与单资产手工/批量复算口径一致）。
	w := db.ActiveWeights(gdb)
	r := scoring.ScoreWith(scoring.Dimensions{D1: a.D1, D2: a.D2, D3: a.D3, D4: a.D4, D5: a.D5}, w)
	a.RiskScore = r.Score
	a.RawScore = r.RawScore
	a.RiskLevel = r.Level
	a.RiskLevelText = r.LevelText
	a.HNDL = cryptoref.EffectiveHNDL(r.HNDL, a.KexSafety) // KEX 已迁移→复评不复活 HNDL

	// 2) 资产经状态机白名单回退到复评态（reassessing）。非法迁移则保持原态、不报错（诚实降级）。
	if model.AssetTransitionAllowed(a.Status, model.StatusReassessing) {
		a.Status = model.StatusReassessing
	}
	if err := gdb.Save(&a).Error; err != nil {
		return nil, nil, err
	}

	// 3) 写不可变评分快照（Reason=reassess），PrevScore/PrevLevel 取上一条。
	hist := recordReassessHistory(gdb, &a, changedBy, reasonDetail)
	return &a, hist, nil
}

// recordReassessHistory 写一条 Reason=reassess 的评分快照（取上一条填 Prev*，取当前生效方案）。
func recordReassessHistory(gdb *gorm.DB, a *model.CryptoAsset, changedBy, detail string) *model.ScoreHistory {
	prevScore := -1
	prevLevel := ""
	var prev model.ScoreHistory
	if err := gdb.Where("asset_id = ?", a.ID).Order("created_at desc").First(&prev).Error; err == nil {
		prevScore = prev.Score
		prevLevel = prev.Level
	}
	profileID := uint(0)
	profileName := ""
	if p, ok := db.ActiveProfile(gdb); ok {
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
		Reason:    model.ReasonReassess,
		ChangedBy: changedBy,
		CreatedAt: time.Now(),
	}
	if detail != "" {
		// ScoreHistory 无独立 detail 字段，理由并入 AssetName 上下文由审计承载；此处仅留快照。
		_ = detail
	}
	gdb.Create(&h)
	return &h
}

// reassessSummary 复评结果的可读摘要（写入事件 Detail）。
func reassessSummary(a *model.CryptoAsset, h *model.ScoreHistory) string {
	prev := "无"
	if h.PrevScore >= 0 {
		prev = fmt.Sprintf("%d(%s)", h.PrevScore, h.PrevLevel)
	}
	return fmt.Sprintf("已复评：%s→%d(%s)，资产置 %s，复评批次 #%d",
		prev, a.RiskScore, a.RiskLevel, a.Status, h.ID)
}
