package scan

import (
	"testing"

	"zhulong-pqm/internal/model"
)

// hasRule 判断候选命中里是否含某规则号。
func hasRule(hits []model.RuleHit, ruleID string) bool {
	for _, h := range hits {
		if h.RuleID == ruleID {
			return true
		}
	}
	return false
}

// TestMatchRules_HybridKexSkipsClassicKEXRule FIX 5：真实 MatchRules 路径上，
// 协商组已是混合(res.KexGroup=X25519MLKEM768)的服务器即便证书是 RSA(KeyAlgo 含 RSA)
// 也不得命中 R-L1-02「经典 KEX」；对照 x25519 经典组必须照常命中。
func TestMatchRules_HybridKexSkipsClassicKEXRule(t *testing.T) {
	hybrid := &model.ScanResult{
		TLSVersion:  "TLS1.3",
		CipherSuite: "TLS_AES_128_GCM_SHA256",
		KeyAlgo:     "RSA", // 证书公钥算法——认证维经典，但 KEX 维已迁移
		KexGroup:    "X25519MLKEM768",
	}
	if hits := MatchRules(hybrid, model.MethodM1ActiveTLS); hasRule(hits, "R-L1-02") {
		t.Errorf("混合 KEX 端点不应命中 R-L1-02（KEX 已迁移），hits=%+v", hits)
	}

	classical := &model.ScanResult{
		TLSVersion:  "TLS1.3",
		CipherSuite: "TLS_AES_128_GCM_SHA256",
		KeyAlgo:     "RSA",
		KexGroup:    "x25519",
	}
	if hits := MatchRules(classical, model.MethodM1ActiveTLS); !hasRule(hits, "R-L1-02") {
		t.Errorf("经典组 x25519 端点应命中 R-L1-02，hits=%+v", hits)
	}

	// KexGroup 未观测（主动 M1 老路径）→ 行为不变，仍按套件/KeyAlgo 判经典。
	unobserved := &model.ScanResult{
		TLSVersion:  "TLS1.2",
		CipherSuite: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
		KeyAlgo:     "RSA",
	}
	if hits := MatchRules(unobserved, model.MethodM1ActiveTLS); !hasRule(hits, "R-L1-02") {
		t.Errorf("未观测组的经典端点应命中 R-L1-02，hits=%+v", hits)
	}
}

func TestIsClassicKEX_ExcludesHybrids(t *testing.T) {
	// 经典应命中
	if !isClassicKEX("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "RSA") {
		t.Error("classic ECDHE_RSA should be classic KEX")
	}
	// 混合/PQC 组名不应判为经典 KEX
	for _, s := range []string{"curveSM2MLKEM768", "X25519MLKEM768", "SecP256r1MLKEM768"} {
		if isClassicKEX(s, "") {
			t.Errorf("%q should NOT be classic KEX", s)
		}
	}
}

func TestIsClassicSig_ExcludesPQC(t *testing.T) {
	if isClassicSig("ML-DSA-65") {
		t.Error("ML-DSA-65 should not be classic sig")
	}
	if !isClassicSig("ECDSA") {
		t.Error("ECDSA should be classic sig")
	}
}
