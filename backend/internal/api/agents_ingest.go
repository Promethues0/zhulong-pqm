package api

import (
	"strconv"
	"strings"

	"gorm.io/gorm"

	"zhulong-pqm/internal/cryptoref"
	"zhulong-pqm/internal/model"
	"zhulong-pqm/internal/scoring"
)

// upsertAgentAsset 落库一条 Agent 上报的密码使用点：补五维评分、盖 ReportedBy、按锚点去重。
// 去重锚点优先级：Endpoint（含主机事实的合成锚点如 "agent-x#proc/nginx/lib=libssl.so.3"）
// → CertFingerprint → 无锚点则新建。返回 true 表示处理完成。
func (s *Server) upsertAgentAsset(a *model.CryptoAsset, reportedBy string, created, updated *int) bool {
	// 安全态：Agent 端已本地分类（KexSafety/AuthSafety）；未给则由算法名兜底推导。
	kexSafety := a.KexSafety
	if kexSafety == "" {
		kexSafety = cryptoref.SafetyForGroupName(a.KexGroup)
	}
	authSafety := a.AuthSafety
	if authSafety == "" {
		authSafety = cryptoref.AuthSafetyForAlgo(a.Algorithm)
	}
	layer := a.Layer
	if layer == "" {
		layer = model.LayerL4 // 主机内生面（库/进程）默认 L4 硬件/根信任邻接层
	}
	exposure := a.Exposure
	if exposure == "" {
		exposure = model.ExposureInternal
	}
	dims := scoring.Derive(scoring.DeriveInput{
		Algorithm:  a.Algorithm,
		KeySize:    a.KeySize,
		TLSVersion: a.Protocol,
		Exposure:   exposure,
		Layer:      layer,
		KexSafety:  kexSafety,
		AuthSafety: authSafety,
	})
	result := scoring.Score(dims)

	apply := func(dst *model.CryptoAsset) {
		if a.Name != "" {
			dst.Name = a.Name
		}
		if dst.Name == "" {
			dst.Name = a.Endpoint
		}
		dst.System = firstNonEmpty(a.System, dst.System, "主机 Agent")
		dst.Algorithm = a.Algorithm
		dst.KeySize = a.KeySize
		dst.Protocol = a.Protocol
		dst.Endpoint = a.Endpoint
		if a.CertFingerprint != "" {
			dst.CertFingerprint = a.CertFingerprint
		}
		dst.CertNotAfter = a.CertNotAfter
		dst.Layer = layer
		dst.Exposure = exposure
		dst.Source = model.SourceAgent
		dst.ReportedBy = reportedBy
		dst.Confidence = 90
		dst.RiskHint = a.RiskHint
		dst.KexGroup = a.KexGroup
		dst.KexSafety = kexSafety
		dst.AuthSafety = authSafety
		dst.D1, dst.D2, dst.D3, dst.D4, dst.D5 = dims.D1, dims.D2, dims.D3, dims.D4, dims.D5
		dst.RiskScore = result.Score
		dst.RawScore = result.RawScore
		dst.RiskLevel = result.Level
		dst.RiskLevelText = result.LevelText
		dst.HNDL = cryptoref.EffectiveHNDL(result.HNDL, kexSafety)
		if dst.SuggestedAlgo == "" && a.Algorithm != "" {
			dst.SuggestedAlgo = scoring.SuggestAlgo(a.Algorithm)
		}
	}

	var existing model.CryptoAsset
	var err error
	switch {
	case a.Endpoint != "":
		err = s.db.Where("endpoint = ?", a.Endpoint).First(&existing).Error
	case a.CertFingerprint != "":
		err = s.db.Where("cert_fingerprint = ?", a.CertFingerprint).First(&existing).Error
	default:
		err = gorm.ErrRecordNotFound
	}

	if err == gorm.ErrRecordNotFound {
		fresh := model.CryptoAsset{Status: model.StatusDiscovered}
		apply(&fresh)
		if e := s.db.Create(&fresh).Error; e == nil {
			*created++
		}
		return true
	}
	if err == nil {
		apply(&existing)
		if e := s.db.Save(&existing).Error; e == nil {
			*updated++
		}
		return true
	}
	return true
}

// itoaSafe int→string。
func itoaSafe(n int) string { return strconv.Itoa(n) }

// ensureAgentAnchor 兜底：无 endpoint/证书指纹的主机事实，用 reportedBy+name+algorithm 合成锚点，
// 保证同一主机重复上报幂等（不新增行）。Agent 端未给锚点时由此补。
func ensureAgentAnchor(a *model.CryptoAsset, reportedBy string) {
	if a.Endpoint == "" && a.CertFingerprint == "" {
		key := reportedBy + "#" + strings.TrimSpace(a.Name) + "#" + strings.TrimSpace(a.Algorithm)
		a.Endpoint = "agent://" + key
	}
}
