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

// TestUpsertAsset_ActiveRescanPreservesKex FIX 4：被动导入发现的混合 KEX 端点，
// 被 M1 主动重扫（主动扫描器不带 KexGroup）合并时不得被抹成空/na——
// 既有资产的 PQC 观测须保留，且 D1/HNDL 用保留后的 effective KexSafety 计算。
func TestUpsertAsset_ActiveRescanPreservesKex(t *testing.T) {
	gdb, err := db.Open(":memory:")
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	r := NewRunner(gdb, nil)

	longLived := time.Now().Add(11 * 365 * 24 * time.Hour)

	// 1) 被动导入：观测到混合组 curveSM2MLKEM768。
	res1 := &model.ScanResult{
		Host: "10.50.93.14", Port: 1443,
		TLSVersion: "TLS1.3",
		KexGroup:   "curveSM2MLKEM768", KexSafety: model.KexSafetyHybrid,
		CertNotAfter: &longLived,
	}
	a1 := r.upsertAsset(res1, model.ExposureInternal)
	if a1 == nil || a1.KexSafety != model.KexSafetyHybrid {
		t.Fatalf("前置失败：被动导入未得到 hybrid 资产 (%+v)", a1)
	}

	// 2) 主动重扫同 endpoint：ScanResult 无 KexGroup（M1 扫描器不设），带 RSA 证书。
	res2 := &model.ScanResult{
		Host: "10.50.93.14", Port: 1443,
		TLSVersion: "TLS1.3", KeyAlgo: "RSA", KeySize: 2048,
		CertNotAfter: &longLived,
	}
	a2 := r.upsertAsset(res2, model.ExposureInternal)
	if a2 == nil {
		t.Fatal("upsertAsset returned nil")
	}
	if a2.ID != a1.ID {
		t.Fatalf("应合并到同一资产：a1.ID=%d a2.ID=%d", a1.ID, a2.ID)
	}
	if a2.KexGroup != "curveSM2MLKEM768" {
		t.Errorf("KexGroup = %q, want curveSM2MLKEM768（主动重扫不得抹除被动 PQC 观测）", a2.KexGroup)
	}
	if a2.KexSafety != model.KexSafetyHybrid {
		t.Errorf("KexSafety = %q, want hybrid", a2.KexSafety)
	}
	if a2.HNDL {
		t.Error("HNDL 应保持清除（保留的 hybrid KEX 仍缓解先抓后解）")
	}
	// AuthSafety 按本次 res 更新（主动扫描带证书算法）。
	if a2.AuthSafety != model.KexSafetyClassical {
		t.Errorf("AuthSafety = %q, want classical（RSA 证书）", a2.AuthSafety)
	}
}
