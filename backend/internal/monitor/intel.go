package monitor

import (
	"time"

	"zhulong-pqm/internal/model"
)

// PresetIntelFeed 离线预置威胁情报源（NFR-8.7.1 私有化离线）。
// 由 /monitor/intel/pull 在无离线包时使用；幂等去重键=Source+Title+PublishedAt。
// 全部为公开里程碑/标准事件的离线快照，诚实标 Source（非真实在线订阅流）。
func PresetIntelFeed() []model.ThreatIntel {
	return []model.ThreatIntel{
		{
			Source:          "NIST",
			Category:        model.IntelStandardUpdate,
			Title:           "FIPS 203/204/205 正式发布（ML-KEM/ML-DSA/SLH-DSA）",
			Summary:         "NIST 完成首批后量子标准定稿，建议密钥协商迁移 ML-KEM-768、签名迁移 ML-DSA-65，过渡期采用混合方案。",
			AffectedAlgos:   []string{"RSA", "ECDSA", "ECDH"},
			TriggerReassess: false,
			PublishedAt:     time.Date(2024, 8, 13, 0, 0, 0, 0, time.UTC),
		},
		{
			Source:          "学界里程碑",
			Category:        model.IntelQubitMilestone,
			Title:           "容错量子比特里程碑跟踪（逻辑比特进展）",
			Summary:         "前沿厂商逻辑量子比特持续增长；破 RSA-2048 估计需 ~4000 逻辑比特，纳入复评阈值监测。",
			AffectedAlgos:   []string{"RSA", "ECDSA"},
			QubitCount:      1200,
			TriggerReassess: false,
			PublishedAt:     time.Date(2025, 12, 1, 0, 0, 0, 0, time.UTC),
		},
		{
			Source:          "国密局",
			Category:        model.IntelStandardUpdate,
			Title:           "商用密码后量子迁移指引（SM2 混合过渡建议）",
			Summary:         "建议 SM2 场景采用 SM2+ML-KEM / SM2+ML-DSA 混合过渡，逐步退役纯经典商密非对称使用点。",
			AffectedAlgos:   []string{"SM2"},
			TriggerReassess: false,
			PublishedAt:     time.Date(2025, 6, 1, 0, 0, 0, 0, time.UTC),
		},
	}
}
