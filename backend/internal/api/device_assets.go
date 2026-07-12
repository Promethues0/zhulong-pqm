package api

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"gorm.io/gorm"

	"zhulong-pqm/internal/model"
	"zhulong-pqm/internal/remediate"
	"zhulong-pqm/internal/scoring"
)

// registerDiscoveredAssets 把设备【只读发现】到的公钥/证书登记成 CBOM 资产（+原始证据），
// 供②建档、③评估、⑥大屏消费真实数据流。全程只读——不触发任何设备写操作。
//
// 幂等去重：合成 endpoint = "<设备endpoint>#<Ref>"（如 http://10.50.93.7:9090#sign:keyIndex=1），
// 命中 crypto_assets 的 endpoint 部分唯一索引；重复"测试连通"只刷新不新增。
// 每条资产按其算法真实跑五维评分（HSM 导出的 EC-256 公钥、签名机 SM2 证书都是抗量子脆弱的经典算法，
// 会被正确评为高风险，进而出现在迁移清单与大屏里）。返回本次新登记（非更新）的资产数。
func (s *Server) registerDiscoveredAssets(dev *model.Device, res remediate.DiscoverResult) int {
	created := 0
	for _, da := range res.Assets {
		ep := dev.Endpoint + "#" + da.Ref

		dims := scoring.Derive(scoring.DeriveInput{
			Algorithm: da.Algorithm,
			Exposure:  model.ExposureInternal, // 密码设备在内网
			Layer:     model.LayerL1,
		})
		result := scoring.Score(dims)

		apply := func(a *model.CryptoAsset) {
			a.Name = dev.Name + " · " + da.Ref
			a.System = "国密设备纳管"
			a.Endpoint = ep
			a.Algorithm = da.Algorithm
			if da.Fingerprint != "" {
				a.CertFingerprint = da.Fingerprint
			}
			a.Source = model.SourceScan
			a.Exposure = model.ExposureInternal
			a.Layer = model.LayerL1
			a.Confidence = 90
			a.D1, a.D2, a.D3, a.D4, a.D5 = dims.D1, dims.D2, dims.D3, dims.D4, dims.D5
			a.RiskScore = result.Score
			a.RawScore = result.RawScore
			a.RiskLevel = result.Level
			a.RiskLevelText = result.LevelText
			a.HNDL = result.HNDL
			a.SuggestedAlgo = scoring.SuggestAlgo(da.Algorithm)
			a.RiskHint = fmt.Sprintf("设备发现%s（%s），算法 %s，综合风险 %d(%s)",
				daKindText(da.Kind), da.Ref, da.Algorithm, result.Score, result.LevelText)
		}

		var asset model.CryptoAsset
		err := s.db.Where("endpoint = ?", ep).First(&asset).Error
		switch {
		case err == gorm.ErrRecordNotFound:
			asset = model.CryptoAsset{Status: model.StatusDiscovered}
			apply(&asset)
			if s.db.Create(&asset).Error == nil {
				created++
			} else {
				continue
			}
		case err == nil:
			apply(&asset)
			s.db.Save(&asset)
		default:
			continue
		}

		// 挂原始证据（PEM/公钥 base64），按 asset_id+hash 幂等去重。
		raw := da.Raw
		if raw == "" {
			raw = res.Evidence[da.Ref]
		}
		if raw != "" && !s.evidenceExists(asset.ID, raw) {
			s.writeEvidence(asset.ID, model.EvidenceScan, "", raw, model.ConfHigh)
		}
	}
	return created
}

// evidenceExists 判断某资产是否已存在相同 Raw 的证据（防重复点"测试连通"灌重复证据）。
func (s *Server) evidenceExists(assetID uint, raw string) bool {
	sum := sha256.Sum256([]byte(raw))
	var n int64
	s.db.Model(&model.AssetEvidence{}).
		Where("asset_id = ? AND hash = ?", assetID, hex.EncodeToString(sum[:])).Count(&n)
	return n > 0
}

func daKindText(kind string) string {
	switch kind {
	case "pubkey":
		return "公钥"
	case "cert":
		return "证书"
	case "pqc-slot":
		return "PQC密钥槽"
	default:
		return kind
	}
}
