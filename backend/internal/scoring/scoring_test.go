package scoring

import "testing"

// 预设画像的期望综合分（来自设计规范），用于锁定评分引擎行为。
// 字段：五维分、期望综合分、期望分级、期望 HNDL。
var presetExpect = []struct {
	name      string
	dims      [5]int
	wantScore int
	wantLevel string
	wantHNDL  bool
}{
	{"内部根CA", [5]int{90, 100, 100, 85, 10}, 86, "P1", true},
	{"SSL VPN网关", [5]int{90, 85, 60, 85, 90}, 82, "P1", true},
	{"对外TLS证书", [5]int{70, 30, 10, 10, 90}, 41, "P3", false},
	{"长期合规档案", [5]int{90, 85, 100, 35, 10}, 75, "P1", true},
	{"IoT设备证书", [5]int{70, 60, 100, 100, 40}, 75, "P1", true},
	{"数据库静态加密", [5]int{40, 85, 60, 35, 10}, 52, "P2", true},
	{"代码签名证书", [5]int{90, 85, 85, 10, 70}, 74, "P2", true},
}

func TestPresetScores(t *testing.T) {
	for _, tc := range presetExpect {
		t.Run(tc.name, func(t *testing.T) {
			r := Score(Dimensions{D1: tc.dims[0], D2: tc.dims[1], D3: tc.dims[2], D4: tc.dims[3], D5: tc.dims[4]})
			if r.Score != tc.wantScore {
				t.Errorf("综合分 = %d, 期望 %d (raw=%.4f)", r.Score, tc.wantScore, r.RawScore)
			}
			if r.Level != tc.wantLevel {
				t.Errorf("分级 = %s, 期望 %s", r.Level, tc.wantLevel)
			}
			if r.HNDL != tc.wantHNDL {
				t.Errorf("HNDL = %v, 期望 %v", r.HNDL, tc.wantHNDL)
			}
		})
	}
}

// TestPresetsHelper 校验 Presets() 导出的画像与期望一致。
func TestPresetsHelper(t *testing.T) {
	got := Presets()
	if len(got) != len(presetExpect) {
		t.Fatalf("Presets() 数量 = %d, 期望 %d", len(got), len(presetExpect))
	}
	for i, p := range got {
		exp := presetExpect[i]
		if p.Name != exp.name {
			t.Errorf("第 %d 个画像名 = %s, 期望 %s", i, p.Name, exp.name)
		}
		if p.Score != exp.wantScore {
			t.Errorf("%s 综合分 = %d, 期望 %d", p.Name, p.Score, exp.wantScore)
		}
		if p.Level != exp.wantLevel {
			t.Errorf("%s 分级 = %s, 期望 %s", p.Name, p.Level, exp.wantLevel)
		}
		if p.HNDL != exp.wantHNDL {
			t.Errorf("%s HNDL = %v, 期望 %v", p.Name, p.HNDL, exp.wantHNDL)
		}
	}
}

// TestClassifyBoundaries 校验分级边界（≥75 P1、50-74 P2、25-49 P3、<25 P4）。
func TestClassifyBoundaries(t *testing.T) {
	cases := []struct {
		score int
		level string
		text  string
	}{
		{100, "P1", "极高"},
		{75, "P1", "极高"},
		{74, "P2", "高"},
		{50, "P2", "高"},
		{49, "P3", "中"},
		{25, "P3", "中"},
		{24, "P4", "低"},
		{0, "P4", "低"},
	}
	for _, c := range cases {
		l, txt, _ := classify(c.score)
		if l != c.level || txt != c.text {
			t.Errorf("classify(%d) = (%s,%s), 期望 (%s,%s)", c.score, l, txt, c.level, c.text)
		}
	}
}

// TestRoundHalfUp 校验 round-half-up 行为。
func TestRoundHalfUp(t *testing.T) {
	cases := []struct {
		in   float64
		want int
	}{
		{74.5, 75},
		{74.4999, 74},
		{0.5, 1},
		{0.49, 0},
		{86.0, 86},
	}
	for _, c := range cases {
		if got := roundHalfUp(c.in); got != c.want {
			t.Errorf("roundHalfUp(%.4f) = %d, 期望 %d", c.in, got, c.want)
		}
	}
}

// TestScoreWithStandardEqualsScore 回归保护：ScoreWith(d,StandardWeights) 必须与
// 旧 Score(d) 对任意维度组合逐字段相等（含种子 7 资产的精确五维）。
func TestScoreWithStandardEqualsScore(t *testing.T) {
	// 种子 7 资产的精确五维组合。
	for _, tc := range presetExpect {
		d := Dimensions{D1: tc.dims[0], D2: tc.dims[1], D3: tc.dims[2], D4: tc.dims[3], D5: tc.dims[4]}
		a := Score(d)
		b := ScoreWith(d, StandardWeights)
		if a != b {
			t.Errorf("%s: ScoreWith(StandardWeights)=%+v != Score=%+v", tc.name, b, a)
		}
	}
	// 全网格抽样（步长 5），逐字段相等。
	for d1 := 0; d1 <= 100; d1 += 5 {
		for d2 := 0; d2 <= 100; d2 += 5 {
			for d3 := 0; d3 <= 100; d3 += 5 {
				for d4 := 0; d4 <= 100; d4 += 5 {
					for d5 := 0; d5 <= 100; d5 += 5 {
						d := Dimensions{D1: d1, D2: d2, D3: d3, D4: d4, D5: d5}
						if a, b := Score(d), ScoreWith(d, StandardWeights); a != b {
							t.Fatalf("网格 %v: Score=%+v != ScoreWith=%+v", d, a, b)
						}
					}
				}
			}
		}
	}
}

// TestScoreWithHNDLDecoupled 校验 HNDL 与权重解耦：无论权重如何变化，
// HNDL 恒为 D2≥60 ∧ D3≥60。
func TestScoreWithHNDLDecoupled(t *testing.T) {
	weightSets := []Weights{
		StandardWeights,
		{100, 0, 0, 0, 0},   // 全压 D1
		{0, 0, 0, 0, 100},   // 全压 D5
		{20, 20, 20, 20, 20}, // 均权
	}
	cases := []struct {
		d        Dimensions
		wantHNDL bool
	}{
		{Dimensions{0, 60, 60, 0, 0}, true},
		{Dimensions{100, 59, 60, 0, 0}, false},
		{Dimensions{100, 60, 59, 0, 0}, false},
		{Dimensions{100, 100, 100, 100, 100}, true},
		{Dimensions{100, 0, 0, 100, 100}, false},
	}
	for _, w := range weightSets {
		for _, c := range cases {
			if got := ScoreWith(c.d, w).HNDL; got != c.wantHNDL {
				t.Errorf("ScoreWith(%v, w=%+v).HNDL = %v, 期望 %v（HNDL 不得随权重变）",
					c.d, w, got, c.wantHNDL)
			}
		}
	}
}

// TestScoreWithThresholdsStable 校验分级阈值 75/50/25 不随权重变：
// 用不同权重把同一资产推到各分段，分级仍严格按综合分阈值判定。
func TestScoreWithThresholdsStable(t *testing.T) {
	d := Dimensions{D1: 80, D2: 40, D3: 40, D4: 40, D5: 40}
	cases := []struct {
		w         Weights
		wantLevel string
	}{
		{Weights{100, 0, 0, 0, 0}, "P1"}, // 综合=80 → P1
		{Weights{0, 100, 0, 0, 0}, "P3"}, // 综合=40 → P3
	}
	for _, c := range cases {
		r := ScoreWith(d, c.w)
		// 分级必须与 classify(综合分) 一致，且阈值未漂移。
		wantL, _, _ := classify(r.Score)
		if r.Level != wantL {
			t.Errorf("ScoreWith level=%s 与 classify(%d)=%s 不一致", r.Level, r.Score, wantL)
		}
		if r.Level != c.wantLevel {
			t.Errorf("权重 %+v 下 level=%s, 期望 %s", c.w, r.Level, c.wantLevel)
		}
	}
	// 阈值常量化断言：边界分仍严格 75/50/25。
	for _, b := range []struct {
		score int
		level string
	}{{75, "P1"}, {74, "P2"}, {50, "P2"}, {49, "P3"}, {25, "P3"}, {24, "P4"}} {
		if l, _, _ := classify(b.score); l != b.level {
			t.Errorf("classify(%d)=%s, 期望 %s（阈值不得随权重变）", b.score, l, b.level)
		}
	}
}

// TestStandardWeightsSumIs100 校验标准权重之和为 100。
func TestStandardWeightsSumIs100(t *testing.T) {
	if got := StandardWeights.Sum(); got != 100 {
		t.Errorf("StandardWeights.Sum() = %d, 期望 100", got)
	}
	if StandardWeights != (Weights{30, 25, 20, 15, 10}) {
		t.Errorf("StandardWeights = %+v, 期望 {30,25,20,15,10}", StandardWeights)
	}
}

// TestDeriveD1 校验自动推导的算法脆弱性映射。
func TestDeriveD1(t *testing.T) {
	cases := []struct {
		in   DeriveInput
		want int
	}{
		{DeriveInput{Algorithm: "RSA", KeySize: 1024}, 100},
		{DeriveInput{Algorithm: "RSA", KeySize: 2048}, 90},
		{DeriveInput{Algorithm: "ECDSA"}, 70},
		{DeriveInput{Algorithm: "Ed25519"}, 70},
		{DeriveInput{Algorithm: "SM2"}, 90},
		{DeriveInput{Algorithm: "RSA", KeySize: 2048, TLSVersion: "TLS 1.0"}, 100},
		{DeriveInput{Algorithm: "Unknown"}, 70},
	}
	for _, c := range cases {
		if got := deriveD1(c.in); got != c.want {
			t.Errorf("deriveD1(%+v) = %d, 期望 %d", c.in, got, c.want)
		}
	}
}

func TestDeriveD1_PQCBranch(t *testing.T) {
	cases := []struct {
		name string
		in   DeriveInput
		want int
	}{
		{"纯PQC双safe", DeriveInput{KexSafety: "safe", AuthSafety: "safe"}, 10},
		{"混合KEX+safe认证", DeriveInput{KexSafety: "hybrid", AuthSafety: "safe"}, 15},
		{"混合KEX+经典ECDSA认证", DeriveInput{KexSafety: "hybrid", AuthSafety: "classical", Algorithm: "ECDSA"}, 70},
		{"混合KEX+经典RSA认证", DeriveInput{KexSafety: "hybrid", AuthSafety: "classical", Algorithm: "RSA"}, 90},
		{"无安全态回退RSA", DeriveInput{Algorithm: "RSA"}, 90},
		{"无安全态回退弱RSA", DeriveInput{Algorithm: "RSA", KeySize: 1024}, 100},
	}
	for _, c := range cases {
		if got := deriveD1(c.in); got != c.want {
			t.Errorf("%s: deriveD1 = %d, want %d", c.name, got, c.want)
		}
	}
}
