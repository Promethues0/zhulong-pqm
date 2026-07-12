package scan

import (
	"testing"
	"time"

	"zhulong-pqm/internal/db"
	"zhulong-pqm/internal/model"
)

func TestUpsertAsset_PQCClearsHNDL(t *testing.T) {
	gdb, err := db.Open(":memory:")
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	r := NewRunner(gdb, nil)

	// 长效证书 → certLongLived()==true → D3=85；配合 D2 默认 60 → rawHNDL=(D2>=60 && D3>=60)=TRUE。
	// 让两个资产都进入 HNDL 易感态，才能真正检验 KEX 迁移对 HNDL 的清除/保留分支。
	longLived := time.Now().Add(11 * 365 * 24 * time.Hour)

	// 案例一：HNDL 易感（长效敏感数据）+ 已迁移 KEX（hybrid）→ HNDL 应被清除。
	// 若无 `&& !KexMitigatesHNDL(kexSafety)` 清除子句，rawHNDL 本为 true，此处 HNDL 会是 true。
	res := &model.ScanResult{
		Host: "10.0.0.1", Port: 1443,
		TLSVersion: "TLS1.3", KeyAlgo: "ECDSA",
		KexGroup:     "curveSM2MLKEM768",
		CertNotAfter: &longLived,
	}
	a := r.upsertAsset(res, model.ExposurePublic)
	if a == nil {
		t.Fatal("upsertAsset returned nil")
	}
	if a.KexSafety != model.KexSafetyHybrid {
		t.Errorf("KexSafety = %q, want hybrid", a.KexSafety)
	}
	if a.HNDL {
		t.Error("HNDL should be cleared when KEX is hybrid (rawHNDL 本为 true)")
	}

	// 案例二（对照）：同样 HNDL 易感（长效证书）但纯经典 KEX（x25519）→ 不清 HNDL，应保持 true。
	res2 := &model.ScanResult{
		Host: "10.0.0.2", Port: 443,
		TLSVersion: "TLS1.2", KeyAlgo: "RSA",
		KexGroup:     "x25519",
		CertNotAfter: &longLived,
	}
	a2 := r.upsertAsset(res2, model.ExposurePublic)
	if a2.KexSafety != model.KexSafetyClassical {
		t.Errorf("classical KexSafety = %q, want classical", a2.KexSafety)
	}
	if !a2.HNDL {
		t.Error("HNDL should remain set when KEX is classical (经典 KEX 不缓解先抓后解)")
	}
}

// TestUpsertAsset_PreservesObservedClassicalForUnknownGroup FIX 2：观测层对未知码点+小 key_share
// 已判 classical（如 ffdhe/brainpool 等表外经典组），该判定必须贯通到资产——
// 不得因 SafetyForGroupName 的 "unknown-"→hybrid 兜底被跨 ScanResult 升级成 hybrid。
func TestUpsertAsset_PreservesObservedClassicalForUnknownGroup(t *testing.T) {
	gdb, err := db.Open(":memory:")
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	r := NewRunner(gdb, nil)

	longLived := time.Now().Add(11 * 365 * 24 * time.Hour)
	res := &model.ScanResult{
		Host: "10.0.0.5", Port: 8443,
		TLSVersion: "TLS1.3", KeyAlgo: "RSA",
		KexGroup:     "unknown-0x1234",
		KexSafety:    model.KexSafetyClassical, // 观测层权威判定：小 key_share → classical
		CertNotAfter: &longLived,
	}
	a := r.upsertAsset(res, model.ExposurePublic)
	if a == nil {
		t.Fatal("upsertAsset returned nil")
	}
	if a.KexSafety != model.KexSafetyClassical {
		t.Errorf("KexSafety = %q, want classical（观测判定不得被名字兜底覆盖成 hybrid）", a.KexSafety)
	}
	if a.D1 == 15 {
		t.Errorf("D1 = 15（hybrid 档），经典 KEX + RSA 认证不应享受迁移分")
	}
	if !a.HNDL {
		t.Error("HNDL should remain set（经典 KEX 未缓解先抓后解，长效证书 rawHNDL=true）")
	}
}
