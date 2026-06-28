// Package scoring 实现烛龙 PQM 的五维后量子风险评分引擎。
//
// 五个维度按固定权重加权求和，得到 0-100 的综合分，再据此分级。
// 维度选项与分值以常量表暴露，供 API 与前端下拉对齐。
package scoring

import (
	"math"
	"strings"
)

// 维度权重。五维加权和满分 100。
const (
	WeightD1 = 0.30 // 算法脆弱性
	WeightD2 = 0.25 // 数据敏感度
	WeightD3 = 0.20 // 数据生命周期
	WeightD4 = 0.15 // 迁移复杂度
	WeightD5 = 0.10 // 暴露面
)

// Dimensions 一组五维原始分（每维 0-100）。
type Dimensions struct {
	D1, D2, D3, D4, D5 int
}

// Result 一次评分的完整输出。
type Result struct {
	Score     int     // 综合分（四舍五入，0-100）
	RawScore  float64 // 原始加权浮点分（审计用）
	Level     string  // P1/P2/P3/P4
	LevelText string  // 极高/高/中/低
	Window    string  // 建议迁移窗口
	HNDL      bool    // Harvest-Now-Decrypt-Later 标记
}

// Option 维度的单个可选项（供前端下拉）。
type Option struct {
	Label string `json:"label"`
	Value int    `json:"value"`
}

// Dimension 一个评分维度的元信息及其选项集合。
type Dimension struct {
	Key     string   `json:"key"`
	Name    string   `json:"name"`
	Weight  float64  `json:"weight"`
	Options []Option `json:"options"`
}

// Weights 五维权重（整数百分数，Σ=100）。用整数避免浮点累计误差，
// 与前端滑块自然对齐；引擎内部统一 /100.0 转浮点。
type Weights struct{ W1, W2, W3, W4, W5 int }

// StandardWeights 标准锁定权重 30/25/20/15/10（DP-11 基线，内置只读）。
var StandardWeights = Weights{30, 25, 20, 15, 10}

// Sum 返回五维权重之和（校验 Σ==100 用）。
func (w Weights) Sum() int { return w.W1 + w.W2 + w.W3 + w.W4 + w.W5 }

// Score 计算五维综合分并完成分级（按标准权重 30/25/20/15/10）。
//
// 综合分采用 round-half-up 四舍五入；RawScore 保留原始浮点供审计。
// HNDL（先存后解）标记：当数据敏感度 D2≥60 且 生命周期 D3≥60 时置位，
// 表示该资产即便今天被截获，未来量子算力成熟后仍有解密价值。
//
// 为不破坏既有调用方，Score 保持签名不变，转调 ScoreWith(d, StandardWeights)。
func Score(d Dimensions) Result {
	return ScoreWith(d, StandardWeights)
}

// ScoreWith 以自定义权重计分；分级阈值（75/50/25）、HNDL 判定、迁移窗口
// 口径与 Score 完全一致——HNDL 恒为 D2≥60 ∧ D3≥60，与权重解耦，
// 任何调权不得稀释 HNDL 专项（PRD 口径）。
func ScoreWith(d Dimensions, w Weights) Result {
	raw := (float64(d.D1)*float64(w.W1) +
		float64(d.D2)*float64(w.W2) +
		float64(d.D3)*float64(w.W3) +
		float64(d.D4)*float64(w.W4) +
		float64(d.D5)*float64(w.W5)) / 100.0

	score := roundHalfUp(raw)
	level, text, window := classify(score)

	return Result{
		Score:     score,
		RawScore:  raw,
		Level:     level,
		LevelText: text,
		Window:    window,
		HNDL:      d.D2 >= 60 && d.D3 >= 60,
	}
}

// classify 按综合分映射到风险等级、中文描述与迁移窗口。
func classify(score int) (level, text, window string) {
	switch {
	case score >= 75:
		return "P1", "极高", "0-3月"
	case score >= 50:
		return "P2", "高", "3-6月"
	case score >= 25:
		return "P3", "中", "6-12月"
	default:
		return "P4", "低", "持续监控"
	}
}

// roundHalfUp 实现 round-half-up（0.5 向上进位）的四舍五入。
// 注意 math.Round 对负数远离零取整，但分值恒为非负，二者在本场景等价；
// 这里显式实现以表达意图并避免对负值的歧义。
func roundHalfUp(v float64) int {
	return int(math.Floor(v + 0.5))
}

// ---- 维度选项常量表 ----

// D1 算法脆弱性。
var optionsD1 = []Option{
	{"不受量子影响(AES-256/SHA-3/SM4)", 10},
	{"AES-128(量子下强度减半)", 40},
	{"经典ECC/ECDSA/EdDSA", 70},
	{"RSA/经典DH/SM2", 90},
	{"弱RSA≤1024/DES/RC4", 100},
}

// D2 数据敏感度。
var optionsD2 = []Option{
	{"公开", 10},
	{"内部", 30},
	{"客户隐私/合同/财务", 60},
	{"商业核心机密/IP/重要个人信息", 85},
	{"国家安全/关键基础设施/军事", 100},
}

// D3 数据生命周期。
var optionsD3 = []Option{
	{"<1年", 10},
	{"1-3年", 30},
	{"3-7年", 60},
	{"7-15年", 85},
	{">15年/永久", 100},
}

// D4 迁移复杂度。
var optionsD4 = []Option{
	{"配置变更", 10},
	{"软件升级", 35},
	{"系统改造/协议栈重构", 60},
	{"硬件替换HSM", 85},
	{"硬件+固件+停机", 100},
}

// D5 暴露面。
var optionsD5 = []Option{
	{"完全内网隔离", 10},
	{"内网可访问", 40},
	{"半公开", 70},
	{"互联网公开", 90},
	{"公开且有大规模录制证据", 100},
}

// Dimensions 元信息（供 /score/options）。
var dimensionMeta = []Dimension{
	{"d1", "算法脆弱性", WeightD1, optionsD1},
	{"d2", "数据敏感度", WeightD2, optionsD2},
	{"d3", "数据生命周期", WeightD3, optionsD3},
	{"d4", "迁移复杂度", WeightD4, optionsD4},
	{"d5", "暴露面", WeightD5, optionsD5},
}

// Options 返回五维选项与分值，供 API 与前端下拉对齐。
func Options() []Dimension {
	return dimensionMeta
}

// ---- 预设画像 ----

// Preset 一个预设风险画像。
type Preset struct {
	Name  string `json:"name"`
	Dims  [5]int `json:"dims"`
	Score int    `json:"score"`
	Level string `json:"level"`
	HNDL  bool   `json:"hndl"`
}

// presetDims 预设画像名称→五维分值。综合分由 Score 实时计算，
// 单测会断言其与设计期望一致，避免常量与引擎漂移。
var presetDims = []struct {
	Name string
	Dims [5]int
}{
	{"内部根CA", [5]int{90, 100, 100, 85, 10}},
	{"SSL VPN网关", [5]int{90, 85, 60, 85, 90}},
	{"对外TLS证书", [5]int{70, 30, 10, 10, 90}},
	{"长期合规档案", [5]int{90, 85, 100, 35, 10}},
	{"IoT设备证书", [5]int{70, 60, 100, 100, 40}},
	{"数据库静态加密", [5]int{40, 85, 60, 35, 10}},
	{"代码签名证书", [5]int{90, 85, 85, 10, 70}},
}

// Presets 返回全部预设画像（综合分/分级/HNDL 实时计算）。
func Presets() []Preset {
	out := make([]Preset, 0, len(presetDims))
	for _, p := range presetDims {
		r := Score(dimsFromArray(p.Dims))
		out = append(out, Preset{
			Name:  p.Name,
			Dims:  p.Dims,
			Score: r.Score,
			Level: r.Level,
			HNDL:  r.HNDL,
		})
	}
	return out
}

func dimsFromArray(a [5]int) Dimensions {
	return Dimensions{D1: a[0], D2: a[1], D3: a[2], D4: a[3], D5: a[4]}
}

// ---- 自动推导 ----

// DeriveInput 自动推导五维分值所需的资产属性。
type DeriveInput struct {
	Algorithm  string // 算法名
	KeySize    int    // 密钥位数
	TLSVersion string // TLS 版本（如 "TLS 1.0"）
	Exposure   string // internal/dmz/public
	Layer      string // L1/L2/L3/L4
	LongLived  bool   // 证书有效期距今 >10 年
}

// Derive 从扫描数据/资产属性自动推导五维分值，用于扫描入库。
//
// D1 由算法+密钥位数+TLS 版本映射；D5 由暴露面映射；D4 由资产层级映射；
// D2 默认 60、D3 默认 30（短期），可由 API 手工覆盖后重算。
func Derive(in DeriveInput) Dimensions {
	return Dimensions{
		D1: deriveD1(in),
		D2: 60, // 默认中等敏感度，待人工确认
		D3: deriveD3(in),
		D4: deriveD4(in.Layer),
		D5: deriveD5(in.Exposure),
	}
}

func deriveD1(in DeriveInput) int {
	algo := strings.ToUpper(strings.TrimSpace(in.Algorithm))
	tls := strings.ReplaceAll(strings.ToUpper(in.TLSVersion), " ", "")

	// 弱 RSA 或过时 TLS 直接判为最高脆弱。
	if (strings.Contains(algo, "RSA") && in.KeySize > 0 && in.KeySize <= 1024) ||
		strings.Contains(tls, "TLS1.0") || strings.Contains(tls, "TLS1.1") {
		return 100
	}
	switch {
	case strings.Contains(algo, "RSA"):
		return 90
	case strings.Contains(algo, "SM2"):
		return 90
	case strings.Contains(algo, "ECDSA"), strings.Contains(algo, "ECDH"),
		strings.Contains(algo, "ED25519"), strings.Contains(algo, "EDDSA"),
		strings.Contains(algo, "ECC"):
		return 70
	default:
		return 70 // 未知算法保守按经典 ECC 量级处理
	}
}

func deriveD3(in DeriveInput) int {
	if in.LongLived {
		return 85
	}
	return 30
}

func deriveD4(layer string) int {
	switch strings.ToUpper(strings.TrimSpace(layer)) {
	case "L1":
		return 35
	case "L2":
		return 60
	case "L3":
		return 35
	case "L4":
		return 85
	default:
		return 35
	}
}

func deriveD5(exposure string) int {
	switch strings.ToLower(strings.TrimSpace(exposure)) {
	case "internal":
		return 40
	case "dmz":
		return 70
	case "public":
		return 90
	default:
		return 40
	}
}

// SuggestAlgo 依据算法类别给出后量子迁移目标建议。
func SuggestAlgo(algorithm string) string {
	algo := strings.ToUpper(algorithm)
	switch {
	case strings.Contains(algo, "SM2"), strings.Contains(algo, "SM"):
		return "SM2+ML-KEM/SM2+ML-DSA"
	case strings.Contains(algo, "ECDSA"), strings.Contains(algo, "RSA"),
		strings.Contains(algo, "ED25519"), strings.Contains(algo, "EDDSA"),
		strings.Contains(algo, "DSA"):
		// 签名场景：经典签名 + 后量子签名混合过渡。
		return "ECDSA+ML-DSA-65/ML-DSA-65"
	case strings.Contains(algo, "ECDH"), strings.Contains(algo, "DH"),
		strings.Contains(algo, "KEM"):
		// 密钥协商场景：经典 KEM + 后量子 KEM 混合过渡。
		return "X25519+ML-KEM-768(过渡)/ML-KEM-768"
	default:
		// 默认按 KEM 过渡建议。
		return "X25519+ML-KEM-768(过渡)/ML-KEM-768"
	}
}
