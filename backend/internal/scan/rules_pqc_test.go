package scan

import "testing"

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
