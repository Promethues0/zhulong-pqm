package cryptoref

import "testing"

func TestAuthSafetyForAlgo(t *testing.T) {
	cases := map[string]string{
		"":                  SafetyNA,
		"RSA":               SafetyClassical,
		"ECDSA":             SafetyClassical,
		"SM2":               SafetyClassical,
		"ML-DSA-65":         SafetySafe,
		"Dilithium3":        SafetySafe,
		"SLH-DSA-SHA2-128s": SafetySafe,
		"Aigis-sig":         SafetySafe,
		"ECDSA+ML-DSA-65":   SafetyHybrid, // 经典+PQC 组合串
	}
	for algo, want := range cases {
		if got := AuthSafetyForAlgo(algo); got != want {
			t.Errorf("AuthSafetyForAlgo(%q) = %q, want %q", algo, got, want)
		}
	}
}

func TestKexMitigatesHNDL(t *testing.T) {
	if !KexMitigatesHNDL(SafetySafe) || !KexMitigatesHNDL(SafetyHybrid) {
		t.Error("safe/hybrid should mitigate HNDL")
	}
	if KexMitigatesHNDL(SafetyClassical) || KexMitigatesHNDL("") {
		t.Error("classical/empty should NOT mitigate HNDL")
	}
}

func TestEffectiveHNDL(t *testing.T) {
	cases := []struct {
		raw       bool
		kexSafety string
		want      bool
	}{
		{true, SafetyHybrid, false},   // 已迁移(混合) → 清除
		{true, SafetySafe, false},     // 已迁移(纯PQC) → 清除
		{true, SafetyClassical, true}, // 经典 → 保留
		{true, SafetyNA, true},        // 未观测 → 保留
		{true, "", true},              // 空 → 保留
		{false, SafetyClassical, false},
		{false, SafetyHybrid, false},
		{false, "", false},
	}
	for _, c := range cases {
		if got := EffectiveHNDL(c.raw, c.kexSafety); got != c.want {
			t.Errorf("EffectiveHNDL(%v, %q) = %v, want %v", c.raw, c.kexSafety, got, c.want)
		}
	}
}

func TestLookupAlgo(t *testing.T) {
	mlkem, ok := LookupAlgo("ML-KEM-768")
	if !ok || mlkem.Primitive != "kem" || mlkem.QuantumLevel != 3 {
		t.Errorf("ML-KEM-768 = %+v ok=%v, want kem/level3", mlkem, ok)
	}
	mldsa, ok := LookupAlgo("ML-DSA-65")
	if !ok || mldsa.Primitive != "signature" {
		t.Errorf("ML-DSA-65 primitive = %q, want signature", mldsa.Primitive)
	}
	if _, ok := LookupAlgo("RSA"); ok {
		t.Error("RSA should not be in PQC algo table")
	}
}
