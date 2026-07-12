package api

import (
	"testing"

	"zhulong-pqm/internal/db"
	"zhulong-pqm/internal/model"
)

func TestUpsertAgentAsset_StampsReportedByAndScores(t *testing.T) {
	gdb, err := db.Open(":memory:")
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	s := &Server{db: gdb}

	// 主机 Agent 发现一个进程加载了铜锁(混合 KEX 能力) —— 无网络端点，合成锚点去重。
	a := &model.CryptoAsset{
		Name:      "nginx 加载 铜锁 Tongsuo 8.5",
		Algorithm: "Tongsuo 8.5.0 (SM2+ML-KEM)",
		KexGroup:  "curveSM2MLKEM768",
		KexSafety: model.KexSafetyHybrid,
		Layer:     model.LayerL4,
	}
	created, updated := 0, 0
	ensureAgentAnchor(a, "agent-abcd")
	if a.Endpoint == "" {
		t.Fatal("ensureAgentAnchor 未补合成锚点")
	}
	s.upsertAgentAsset(a, "agent-abcd", &created, &updated)
	if created != 1 {
		t.Fatalf("首次上报应新建 1，得 %d", created)
	}

	var got model.CryptoAsset
	if err := gdb.Where("endpoint = ?", a.Endpoint).First(&got).Error; err != nil {
		t.Fatalf("落库资产未找到: %v", err)
	}
	if got.ReportedBy != "agent-abcd" {
		t.Errorf("ReportedBy = %q, want agent-abcd", got.ReportedBy)
	}
	if got.KexSafety != model.KexSafetyHybrid {
		t.Errorf("KexSafety = %q, want hybrid", got.KexSafety)
	}
	if got.Source != model.SourceAgent {
		t.Errorf("Source = %q, want agent", got.Source)
	}
	if got.RiskScore == 0 {
		t.Error("应补五维评分，RiskScore 不应为 0")
	}

	// 同一主机事实重复上报 → 幂等更新，不新增。
	a2 := &model.CryptoAsset{
		Name: "nginx 加载 铜锁 Tongsuo 8.5", Algorithm: "Tongsuo 8.5.0 (SM2+ML-KEM)",
		KexGroup: "curveSM2MLKEM768", KexSafety: model.KexSafetyHybrid, Layer: model.LayerL4,
	}
	ensureAgentAnchor(a2, "agent-abcd")
	created2, updated2 := 0, 0
	s.upsertAgentAsset(a2, "agent-abcd", &created2, &updated2)
	if created2 != 0 || updated2 != 1 {
		t.Errorf("重复上报应更新不新建，得 created=%d updated=%d", created2, updated2)
	}
	var count int64
	gdb.Model(&model.CryptoAsset{}).Where("endpoint = ?", a.Endpoint).Count(&count)
	if count != 1 {
		t.Errorf("幂等失败：同锚点资产行数 = %d, want 1", count)
	}
}

func TestHashKey_Deterministic(t *testing.T) {
	k := "zpqm-agent-deadbeef"
	if hashKey(k) != hashKey(k) {
		t.Error("hashKey 应确定性")
	}
	if hashKey(k) == k {
		t.Error("hashKey 不应返回明文")
	}
	if len(hashKey(k)) != 64 {
		t.Errorf("SHA-256 hex 应 64 字符，得 %d", len(hashKey(k)))
	}
}
