package monitor

import (
	"testing"

	"zhulong-pqm/internal/db"
	"zhulong-pqm/internal/model"
)

// TestReassess_DoesNotResurrectClearedHNDL FIX 3：已迁移(混合 KEX)资产的 HNDL 已被清除，
// 监测复评(R3 漂移/情报)按五维重算 rawHNDL=true 时，不得把 HNDL 翻回 true——
// 清除策略须经共享 EffectiveHNDL 参考资产自身持久化的 KexSafety。
func TestReassess_DoesNotResurrectClearedHNDL(t *testing.T) {
	gdb, err := db.Open(":memory:")
	if err != nil {
		t.Fatalf("open db: %v", err)
	}

	// 混合 KEX 资产：D2=60/D3=85 → rawHNDL=true，但 KexSafety=hybrid 已缓解 → HNDL=false。
	a := model.CryptoAsset{
		Name: "hybrid-endpoint", Endpoint: "10.0.0.9:1443",
		Status: model.StatusDiscovered,
		D1:     15, D2: 60, D3: 85, D4: 35, D5: 60,
		KexGroup: "curveSM2MLKEM768", KexSafety: model.KexSafetyHybrid,
		HNDL: false,
	}
	if err := gdb.Create(&a).Error; err != nil {
		t.Fatalf("create asset: %v", err)
	}

	got, _, err := Reassess(gdb, a.ID, "system", "漂移复评")
	if err != nil {
		t.Fatalf("Reassess: %v", err)
	}
	if got.HNDL {
		t.Error("复评把已迁移(hybrid KEX)资产的 HNDL 复活了，应保持清除")
	}

	// 对照：经典 KEX 资产同样五维 → 复评后 HNDL 应为 true（清除逻辑不误伤）。
	b := model.CryptoAsset{
		Name: "classical-endpoint", Endpoint: "10.0.0.10:443",
		Status: model.StatusDiscovered,
		D1:     90, D2: 60, D3: 85, D4: 35, D5: 60,
		KexGroup: "x25519", KexSafety: model.KexSafetyClassical,
		HNDL: true,
	}
	if err := gdb.Create(&b).Error; err != nil {
		t.Fatalf("create asset: %v", err)
	}
	gotB, _, err := Reassess(gdb, b.ID, "system", "漂移复评")
	if err != nil {
		t.Fatalf("Reassess: %v", err)
	}
	if !gotB.HNDL {
		t.Error("经典 KEX 资产复评后 HNDL 应保持 true（清除策略不得扩大化）")
	}
}
