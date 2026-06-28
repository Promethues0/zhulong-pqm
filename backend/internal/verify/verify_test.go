package verify

import (
	"testing"

	"zhulong-pqm/internal/model"
)

// TestBaselineCaseCount 全量用例库须恰好 47 项（工具包文件4 锚定）。
func TestBaselineCaseCount(t *testing.T) {
	if got := len(AllCases()); got != BaselineTotal {
		t.Fatalf("用例总数=%d，期望基线 %d", got, BaselineTotal)
	}
}

// TestBaselineThreeConditionals 全量模拟下基线判定须为 44 通过 / 3 有条件 / 0 未通过。
func TestBaselineThreeConditionals(t *testing.T) {
	pass, cond, other := 0, 0, 0
	for _, cs := range AllCases() {
		switch cs.BaselineVerdict {
		case model.VerdictPass:
			pass++
		case model.VerdictConditional:
			cond++
			if cs.BaselineRiskRef == "" {
				t.Errorf("有条件用例 %s 未预挂遗留风险 RiskRef", cs.Code)
			}
		default:
			other++
		}
	}
	if pass != 44 || cond != 3 || other != 0 {
		t.Fatalf("基线判定 pass=%d cond=%d other=%d，期望 44/3/0", pass, cond, other)
	}
}

// TestCasesForTrackUnknown 未知轨道仅得全轨道通用项（Tracks 为空者）。
func TestCasesForTrackUnknown(t *testing.T) {
	got := CasesForTrack("nonexistent-track")
	for _, cs := range got {
		if len(cs.Tracks) != 0 {
			t.Errorf("未知轨道不应命中轨道专属用例 %s", cs.Code)
		}
	}
	if len(got) == 0 {
		t.Fatal("未知轨道应至少返回全轨道通用用例")
	}
}

// TestGatePass 验证 Gate 公式四个条件。
func TestGatePass(t *testing.T) {
	mkCond := func(ref string) model.TestResult {
		return model.TestResult{Verdict: model.VerdictConditional, RiskRef: ref}
	}

	// 基线 44/3/0，全部 conditional 挂 RiskRef → 过 Gate。
	if !GatePass(GateInput{
		Total: 47, Passed: 44, Conditional: 3, Failed: 0,
		Results: []model.TestResult{mkCond("R-001"), mkCond("R-001"), mkCond("R-002")},
	}) {
		t.Error("基线 44/3/0 且 conditional 全挂应过 Gate")
	}

	// 有 Failed → 不过。
	if GatePass(GateInput{Total: 47, Passed: 43, Conditional: 3, Failed: 1}) {
		t.Error("存在 Failed 不应过 Gate")
	}

	// conditional 未挂 RiskRef → 不过。
	if GatePass(GateInput{
		Total: 47, Passed: 44, Conditional: 3, Failed: 0,
		Results: []model.TestResult{mkCond("R-001"), mkCond(""), mkCond("R-002")},
	}) {
		t.Error("有条件项未挂 RiskRef 不应过 Gate")
	}

	// Passed < floor(47*44/47)=44 → 不过。
	if GatePass(GateInput{
		Total: 47, Passed: 43, Conditional: 4, Failed: 0,
		Results: []model.TestResult{mkCond("R-001"), mkCond("R-001"), mkCond("R-001"), mkCond("R-001")},
	}) {
		t.Error("Passed 低于 44/47 阈值不应过 Gate")
	}

	// Passed+Conditional != Total → 不过。
	if GatePass(GateInput{Total: 47, Passed: 44, Conditional: 2, Failed: 0}) {
		t.Error("Passed+Conditional≠Total 不应过 Gate")
	}
}
