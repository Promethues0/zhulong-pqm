package model

import "testing"

// TestAssetTransitionWhitelist 锁定全局资产状态机白名单（B0-4 / C7）的合法与非法迁移。
func TestAssetTransitionWhitelist(t *testing.T) {
	legal := [][2]string{
		{StatusDiscovered, StatusConfirmed},
		{StatusDiscovered, StatusArchived},
		{StatusDiscovered, StatusMerged},
		{StatusConfirmed, StatusRemediating},
		{StatusRemediating, StatusRemediated},
		{StatusRemediated, StatusVerified}, // ④ 验收出口
		{StatusVerified, StatusMonitored},  // ⑤ 纳管
		{StatusMonitored, StatusReassessing},
		{StatusReassessing, StatusConfirmed}, // ⑤ 复评回流
		{StatusArchived, StatusConfirmed},
		{StatusConfirmed, StatusConfirmed}, // 自迁移幂等
	}
	for _, tc := range legal {
		if err := ValidateAssetTransition(tc[0], tc[1]); err != nil {
			t.Errorf("%s→%s 应合法，却被拒：%v", tc[0], tc[1], err)
		}
	}

	illegal := [][2]string{
		{StatusDiscovered, StatusVerified}, // 不可越过改造/验收
		{StatusMerged, StatusConfirmed},    // merged 终态
		{StatusDiscovered, "bogus"},        // 未知目标态
		{"bogus", StatusConfirmed},         // 未知源态
		{StatusArchived, StatusMerged},     // archived 不可直接 merged
	}
	for _, tc := range illegal {
		if err := ValidateAssetTransition(tc[0], tc[1]); err == nil {
			t.Errorf("%s→%s 应非法，却被放行", tc[0], tc[1])
		}
	}
}

// TestAssetStatusKnown 校验已知态判定（含终态 merged）。
func TestAssetStatusKnown(t *testing.T) {
	for _, s := range []string{StatusDiscovered, StatusConfirmed, StatusArchived, StatusMerged,
		StatusVerified, StatusRemediating, StatusRemediated, StatusAccepted, StatusMonitored, StatusReassessing} {
		if !AssetStatusKnown(s) {
			t.Errorf("%q 应为已知态", s)
		}
	}
	if AssetStatusKnown("") || AssetStatusKnown("nope") {
		t.Error("空串/未知值不应判为已知态")
	}
}
