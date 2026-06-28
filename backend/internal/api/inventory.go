package api

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"zhulong-pqm/internal/model"
	"zhulong-pqm/internal/scan"
)

// ---- ② 建档深化：去重指纹 / 证据链 / 状态机 / 合并 ----

// assetFingerprint 计算资产去重锚点（C6 统一公式，复用 scan.AssetFingerprint）。
//
// 去重主键优先级（PRD 4.3）：① certFingerprint → ② endpoint+protocol → ③ name。
// fingerprint 字段值统一由 scan.AssetFingerprint 生成，避免①②双口径漂移。
func assetFingerprint(a *model.CryptoAsset) string {
	if a.CertFingerprint != "" {
		return scan.AssetFingerprint("", 0, "cert", a.CertFingerprint)
	}
	if a.Endpoint != "" {
		host, port := splitEndpoint(a.Endpoint)
		return scan.AssetFingerprint(host, port, a.Protocol, "")
	}
	// 名称兜底：无网络落点无证书，按 name 归一。
	sum := sha256.Sum256([]byte("nm|" + strings.ToLower(strings.TrimSpace(a.Name))))
	return "sha256:" + hex.EncodeToString(sum[:])
}

// fingerprintKeyType 返回去重命中所用键类型，供前端展示分簇依据。
func fingerprintKeyType(a *model.CryptoAsset) string {
	switch {
	case a.CertFingerprint != "":
		return "certFingerprint"
	case a.Endpoint != "":
		return "endpoint"
	default:
		return "name"
	}
}

// splitEndpoint 把 "host:port" 拆为 host 与 port（解析失败 port=0）。
func splitEndpoint(ep string) (string, int) {
	ep = strings.TrimSpace(ep)
	idx := strings.LastIndex(ep, ":")
	if idx < 0 {
		return ep, 0
	}
	host := ep[:idx]
	port := 0
	for _, r := range ep[idx+1:] {
		if r < '0' || r > '9' {
			port = 0
			break
		}
		port = port*10 + int(r-'0')
	}
	return host, port
}

// assetDigest 计算资产内容指纹：关键字段变化即「内容变更」（diff 用）。
func assetDigest(a *model.CryptoAsset) string {
	seed := fmt.Sprintf("%s|%d|%s|%s|%s|%s",
		a.Algorithm, a.KeySize, a.Protocol, a.CertFingerprint, a.Status, a.RiskLevel)
	sum := sha256.Sum256([]byte(seed))
	return hex.EncodeToString(sum[:])
}

// writeEvidence 写一条 AssetEvidence（只追加，hash 固化防篡改）。
func (s *Server) writeEvidence(assetID uint, source, ruleRef, raw, confidence string) {
	sum := sha256.Sum256([]byte(raw))
	now := time.Now()
	ev := model.AssetEvidence{
		AssetID:    assetID,
		Source:     source,
		RuleRef:    ruleRef,
		Raw:        raw,
		Hash:       hex.EncodeToString(sum[:]),
		Confidence: confidence,
		ScannedAt:  &now,
		CreatedAt:  now,
	}
	s.db.Create(&ev)
}

// ---- 资产状态机 ----

// statusReq 状态迁移请求体。
type statusReq struct {
	Status string `json:"status" binding:"required"`
}

// setAssetStatus POST /assets/:id/status：按 C7 全局白名单校验合法迁移（非法 422）。
//
// merged 终态仅由 /assets/merge 触发，手工经此端点置 merged 拒绝（避免绕过合并逻辑）。
func (s *Server) setAssetStatus(c *gin.Context) {
	var a model.CryptoAsset
	if err := s.db.First(&a, c.Param("id")).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "资产不存在"})
		return
	}
	var req statusReq
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	to := strings.TrimSpace(req.Status)
	if to == model.StatusMerged {
		c.JSON(http.StatusUnprocessableEntity, gin.H{"error": "merged 为合并终态，请使用 /assets/merge"})
		return
	}
	from := a.Status
	if err := model.ValidateAssetTransition(from, to); err != nil {
		s.audit(c, "asset", "asset.status", auditTarget("CryptoAsset", a.ID, a.Name), model.AuditDenied, err.Error())
		c.JSON(http.StatusUnprocessableEntity, gin.H{"error": err.Error()})
		return
	}
	a.Status = to
	a.Version++
	if err := s.db.Save(&a).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	// 留痕 who/when/from→to（FR-4.4.1）。
	s.writeEvidence(a.ID, model.EvidenceAudit, "",
		fmt.Sprintf(`{"action":"status","from":%q,"to":%q,"by":%q,"at":%q}`,
			from, to, actorName(c), time.Now().Format(time.RFC3339)), model.ConfHigh)
	s.audit(c, "asset", "asset.status", auditTarget("CryptoAsset", a.ID, a.Name), model.AuditSuccess,
		fmt.Sprintf("%s→%s", from, to))
	c.JSON(http.StatusOK, a)
}

// confirmAsset POST /assets/:id/confirm：状态机便捷动作 → confirmed。
func (s *Server) confirmAsset(c *gin.Context) { s.statusAction(c, model.StatusConfirmed) }

// archiveAsset POST /assets/:id/archive：状态机便捷动作 → archived。
func (s *Server) archiveAsset(c *gin.Context) { s.statusAction(c, model.StatusArchived) }

// statusAction 复用状态机校验执行一次具名迁移。
func (s *Server) statusAction(c *gin.Context, to string) {
	var a model.CryptoAsset
	if err := s.db.First(&a, c.Param("id")).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "资产不存在"})
		return
	}
	from := a.Status
	if err := model.ValidateAssetTransition(from, to); err != nil {
		s.audit(c, "asset", "asset.status", auditTarget("CryptoAsset", a.ID, a.Name), model.AuditDenied, err.Error())
		c.JSON(http.StatusUnprocessableEntity, gin.H{"error": err.Error()})
		return
	}
	a.Status = to
	a.Version++
	if err := s.db.Save(&a).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	s.writeEvidence(a.ID, model.EvidenceAudit, "",
		fmt.Sprintf(`{"action":"status","from":%q,"to":%q,"by":%q,"at":%q}`,
			from, to, actorName(c), time.Now().Format(time.RFC3339)), model.ConfHigh)
	s.audit(c, "asset", "asset.status", auditTarget("CryptoAsset", a.ID, a.Name), model.AuditSuccess,
		fmt.Sprintf("%s→%s", from, to))
	c.JSON(http.StatusOK, a)
}

// ---- 证据链 ----

// evidenceResp 证据响应（附 hash 校验状态）。
type evidenceResp struct {
	model.AssetEvidence
	HashValid bool `json:"hashValid"` // sha256(raw)==hash
}

// listAssetEvidence GET /assets/:id/evidence：返回该 CUP 全部证据，按采集时间倒序（FR-4.7）。
func (s *Server) listAssetEvidence(c *gin.Context) {
	var a model.CryptoAsset
	if err := s.db.First(&a, c.Param("id")).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "资产不存在"})
		return
	}
	var rows []model.AssetEvidence
	s.db.Where("asset_id = ?", a.ID).Order("scanned_at desc, id desc").Find(&rows)
	out := make([]evidenceResp, 0, len(rows))
	for _, e := range rows {
		sum := sha256.Sum256([]byte(e.Raw))
		out = append(out, evidenceResp{AssetEvidence: e, HashValid: hex.EncodeToString(sum[:]) == e.Hash})
	}
	c.JSON(http.StatusOK, out)
}

// addEvidenceReq 手工补录证据请求体（M7 访谈）。
type addEvidenceReq struct {
	Source     string `json:"source"`
	RuleRef    string `json:"ruleRef"`
	Raw        string `json:"raw" binding:"required"`
	Confidence string `json:"confidence"`
}

// addAssetEvidence POST /assets/:id/evidence：手工补录证据（入库计算 hash）。
func (s *Server) addAssetEvidence(c *gin.Context) {
	var a model.CryptoAsset
	if err := s.db.First(&a, c.Param("id")).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "资产不存在"})
		return
	}
	var req addEvidenceReq
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if req.Source == "" {
		req.Source = model.EvidenceManual
	}
	if req.Confidence == "" {
		req.Confidence = model.ConfLow
	}
	s.writeEvidence(a.ID, req.Source, req.RuleRef, req.Raw, req.Confidence)
	s.audit(c, "asset", "asset.evidence.add", auditTarget("CryptoAsset", a.ID, a.Name), model.AuditSuccess, req.Source)
	c.JSON(http.StatusCreated, gin.H{"ok": true})
}

// ---- 去重候选 ----

// dedupGroup 一组疑似重复资产。
type dedupGroup struct {
	Key     string               `json:"key"`     // 去重锚点 fingerprint
	KeyType string               `json:"keyType"` // certFingerprint/endpoint/name
	Assets  []model.CryptoAsset  `json:"assets"`
}

// dedupCandidates GET /assets/dedup-candidates：按 fingerprint 聚类出重复簇（size≥2）。
//
// 已 merged 的资产不参与（终态行保留但不再建议合并）。
func (s *Server) dedupCandidates(c *gin.Context) {
	var assets []model.CryptoAsset
	s.db.Where("status <> ?", model.StatusMerged).Order("id asc").Find(&assets)

	groups := map[string]*dedupGroup{}
	order := []string{}
	for i := range assets {
		fp := assetFingerprint(&assets[i])
		g, ok := groups[fp]
		if !ok {
			g = &dedupGroup{Key: fp, KeyType: fingerprintKeyType(&assets[i])}
			groups[fp] = g
			order = append(order, fp)
		}
		g.Assets = append(g.Assets, assets[i])
	}

	out := make([]dedupGroup, 0)
	for _, fp := range order {
		if len(groups[fp].Assets) >= 2 {
			out = append(out, *groups[fp])
		}
	}
	c.JSON(http.StatusOK, gin.H{"total": len(out), "groups": out})
}

// ---- 合并 ----

// mergeReq 合并请求体。
type mergeReq struct {
	PrimaryID uint   `json:"primaryId" binding:"required"`
	MergeIDs  []uint `json:"mergeIds" binding:"required"`
}

// mergeAssets POST /assets/merge：将 mergeIds 并入 primaryId（C6）。
//
// 被并资产经状态机置 merged 终态 + MergedInto=primaryId（保留行，证据链可溯）；
// 其 RuleHit（经 ScanResult.AssetID）/AssetEvidence 归并到主资产；
// 多来源交叉 → confidence=高(100)；算法冲突时 primary RiskHint 标 [冲突待裁决]；version++。
func (s *Server) mergeAssets(c *gin.Context) {
	var req mergeReq
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	var primary model.CryptoAsset
	if err := s.db.First(&primary, req.PrimaryID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "主资产不存在"})
		return
	}
	if primary.Status == model.StatusMerged {
		c.JSON(http.StatusUnprocessableEntity, gin.H{"error": "主资产已是合并终态，不能作为合并目标"})
		return
	}

	algoConflict := false
	mergedCount := 0
	for _, mid := range req.MergeIDs {
		if mid == req.PrimaryID {
			continue
		}
		var m model.CryptoAsset
		if err := s.db.First(&m, mid).Error; err != nil {
			continue
		}
		if m.Status == model.StatusMerged {
			continue
		}
		if err := model.ValidateAssetTransition(m.Status, model.StatusMerged); err != nil {
			// 状态机不允许该态→merged（理论上各态均可），诚实跳过并审计。
			s.audit(c, "asset", "asset.merge", auditTarget("CryptoAsset", m.ID, m.Name), model.AuditDenied, err.Error())
			continue
		}
		// 算法冲突检测（两边都有算法且不同）。
		if primary.Algorithm != "" && m.Algorithm != "" &&
			!strings.EqualFold(primary.Algorithm, m.Algorithm) {
			algoConflict = true
		}

		// 归并证据链。
		s.db.Model(&model.AssetEvidence{}).Where("asset_id = ?", m.ID).Update("asset_id", primary.ID)
		// 归并扫描结果（RuleHit 经 ScanResult.AssetID 间接挂主资产）。
		s.db.Model(&model.ScanResult{}).Where("asset_id = ?", m.ID).Update("asset_id", primary.ID)
		// 累积来源（合并前为被并资产写一条 audit 证据，记录其原始来源与算法）。
		s.writeEvidence(primary.ID, model.EvidenceAudit, "",
			fmt.Sprintf(`{"action":"merge","mergedAssetId":%d,"mergedName":%q,"source":%q,"algorithm":%q,"by":%q}`,
				m.ID, m.Name, m.Source, m.Algorithm, actorName(c)), model.ConfHigh)

		m.Status = model.StatusMerged
		m.MergedInto = &primary.ID
		m.Version++
		s.db.Save(&m)
		mergedCount++
	}

	// 多来源交叉置信度升级：合并后证据来源去重计数 ≥2 → 高(100)。
	var sources []string
	s.db.Model(&model.AssetEvidence{}).Where("asset_id = ?", primary.ID).
		Distinct("source").Pluck("source", &sources)
	distinct := 0
	for _, src := range sources {
		if src != "" && src != model.EvidenceAudit {
			distinct++
		}
	}
	if distinct >= 2 {
		primary.Confidence = 100
	}
	if algoConflict && !strings.HasPrefix(primary.RiskHint, "[冲突待裁决]") {
		primary.RiskHint = "[冲突待裁决] " + primary.RiskHint
	}
	primary.Version++
	s.db.Save(&primary)

	// 算法字段可能变化（合并不改 primary.Algorithm，但置信度/状态变了），重算保持评分一致。
	s.recompute(&primary)
	s.db.Save(&primary)

	var evCount int64
	s.db.Model(&model.AssetEvidence{}).Where("asset_id = ?", primary.ID).Count(&evCount)

	s.audit(c, "asset", "asset.merge", auditTarget("CryptoAsset", primary.ID, primary.Name), model.AuditSuccess,
		fmt.Sprintf("合并 %d 个资产，证据 %d 条，冲突=%v", mergedCount, evCount, algoConflict))
	c.JSON(http.StatusOK, gin.H{
		"primary":       primary,
		"mergedCount":   mergedCount,
		"evidenceCount": evCount,
		"algoConflict":  algoConflict,
	})
}

// ensureAssetFingerprintEvidence 兜底：为一个资产补一条来源证据（供 scan/import 入库时挂证据）。
// 已存在同 source+hash 证据则不重复写（幂等）。
func (s *Server) ensureEvidenceOnce(assetID uint, source, ruleRef, raw, confidence string) {
	sum := sha256.Sum256([]byte(raw))
	h := hex.EncodeToString(sum[:])
	var n int64
	s.db.Model(&model.AssetEvidence{}).Where("asset_id = ? AND hash = ?", assetID, h).Count(&n)
	if n > 0 {
		return
	}
	now := time.Now()
	s.db.Create(&model.AssetEvidence{
		AssetID:    assetID,
		Source:     source,
		RuleRef:    ruleRef,
		Raw:        raw,
		Hash:       h,
		Confidence: confidence,
		ScannedAt:  &now,
		CreatedAt:  now,
	})
}

// loadAssetByFingerprint 据 fingerprint 找一个未合并的既有资产（CBOM 导入归一用）。
func (s *Server) loadAssetByFingerprint(fp string) (*model.CryptoAsset, bool) {
	var assets []model.CryptoAsset
	s.db.Where("status <> ?", model.StatusMerged).Find(&assets)
	for i := range assets {
		if assetFingerprint(&assets[i]) == fp {
			return &assets[i], true
		}
	}
	return nil, false
}
