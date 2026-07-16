package cbom

import (
	"testing"

	"zhulong-pqm/internal/model"
)

func TestAssetToComponent_PQC(t *testing.T) {
	a := model.CryptoAsset{
		Name: "gw-1443", Algorithm: "ML-DSA-65", Protocol: "TLS1.3",
		KexGroup: "curveSM2MLKEM768", KexSafety: "hybrid", AuthSafety: "safe",
	}
	c := assetToComponent(a)
	ap := c.CryptoProperties.AlgorithmProperties
	if ap.Primitive != "signature" {
		t.Errorf("primitive = %q, want signature", ap.Primitive)
	}
	if ap.NISTQuantumSecurityLevel != 3 { // ML-DSA-65 = level 3
		t.Errorf("nistQuantumSecurityLevel = %d, want 3", ap.NISTQuantumSecurityLevel)
	}
	if c.CryptoProperties.OID != "2.16.840.1.101.3.4.3.18" {
		t.Errorf("oid = %q, want ML-DSA-65 oid", c.CryptoProperties.OID)
	}
	// 双维安全态应作为 properties 暴露
	if !hasProp(c, "zhulong:kexSafety", "hybrid") {
		t.Error("missing zhulong:kexSafety=hybrid property")
	}
}

func TestPrimitiveOf_PQC(t *testing.T) {
	if primitiveOf("ML-KEM-768") != "kem" {
		t.Errorf("ML-KEM primitive = %q, want kem", primitiveOf("ML-KEM-768"))
	}
	if primitiveOf("ML-DSA-65") != "signature" {
		t.Errorf("ML-DSA primitive = %q, want signature", primitiveOf("ML-DSA-65"))
	}
}

func hasProp(c Component, name, val string) bool {
	for _, p := range c.Properties {
		if p.Name == name && p.Value == val {
			return true
		}
	}
	return false
}

// TestComponentToAsset_RestoresKexAuthDims 校验 CBOM 反向导入无损回填双维量子安全态。
// KexSafety 丢失会让导入后任意重算路径（recompute 走 EffectiveHNDL）复活已缓解的 HNDL。
func TestComponentToAsset_RestoresKexAuthDims(t *testing.T) {
	a := model.CryptoAsset{
		Name: "gw-1443", Algorithm: "ML-DSA-65", Protocol: "TLS1.3",
		KexGroup: "curveSM2MLKEM768", KexSafety: "hybrid", AuthSafety: "safe",
	}
	got, ok := ComponentToAsset(assetToComponent(a))
	if !ok {
		t.Fatal("cryptographic-asset 组件应可反归一")
	}
	if got.KexGroup != a.KexGroup {
		t.Errorf("KexGroup = %q, want %q", got.KexGroup, a.KexGroup)
	}
	if got.KexSafety != a.KexSafety {
		t.Errorf("KexSafety = %q, want %q（丢失将致 rescore 复活 HNDL）", got.KexSafety, a.KexSafety)
	}
	if got.AuthSafety != a.AuthSafety {
		t.Errorf("AuthSafety = %q, want %q", got.AuthSafety, a.AuthSafety)
	}
}
