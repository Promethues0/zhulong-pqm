package monitor

import (
	"strings"
	"time"

	"zhulong-pqm/internal/model"
)

// ---- 混合/经典算法判定（口径锚定蓝图：X25519MLKEM768 / ke1_mlkem / SM2+ML-KEM）----

// hybridMarkers 已迁后量子混合算法的特征片段（大写后匹配）。
// 覆盖蓝图三种混合写法：TLS 混合组 X25519MLKEM768、IPSEC ke1_mlkem(MLKEM_768+X25519)、国密 SM2+ML-KEM。
var hybridMarkers = []string{
	"MLKEM", "ML-KEM", "KE1_MLKEM", "X25519MLKEM768", "ML-DSA", "MLDSA",
}

// classicVulnMarkers 经典脆弱算法特征（无量子抗性的密钥协商/签名/公钥）。
var classicVulnMarkers = []string{
	"RSA", "ECDSA", "ECDH", "ED25519", "EDDSA", "SM2", "DSA", "DH",
}

// IsHybrid 判定算法串是否含后量子混合特征（已迁状态）。
func IsHybrid(algo string) bool {
	a := strings.ToUpper(algo)
	for _, m := range hybridMarkers {
		if strings.Contains(a, m) {
			return true
		}
	}
	return false
}

// isPureClassic 判定算法串是否为纯经典脆弱算法（不含任何混合特征）。
func isPureClassic(algo string) bool {
	if algo == "" {
		return false
	}
	if IsHybrid(algo) {
		return false
	}
	a := strings.ToUpper(algo)
	for _, m := range classicVulnMarkers {
		if strings.Contains(a, m) {
			return true
		}
	}
	return false
}

// driftKind 漂移分类结果。
type driftKind int

const (
	driftNone        driftKind = iota
	driftHybridToClassic        // 混合→经典回退（SLO-05，P1+复评）
	driftNewVulnerable          // 新增未纳管脆弱使用点（warning）
	driftCertRenewed            // 证书续期/更换（cbom_diff）
)

// classifyDrift 对照资产「期望算法」(prev) 与复扫得到的「实测算法」(now)，判定漂移类型。
//
// - 已迁混合（prev 为混合或 SuggestedAlgo 为混合）→ 复扫得纯经典：混合回退 = P1。
// - prev 为空/非脆弱，now 为脆弱经典：新增脆弱使用点 = warning。
// - 算法未变但证书指纹/到期变了：由 certRenewed 旁路判定（见 runner）。
func classifyDrift(prevAlgo, nowAlgo string, prevWasHybrid bool) driftKind {
	if nowAlgo == "" {
		return driftNone
	}
	if prevWasHybrid && isPureClassic(nowAlgo) {
		return driftHybridToClassic
	}
	// 之前非脆弱（空或混合），现在变成脆弱经典。
	if !isPureClassic(prevAlgo) && isPureClassic(nowAlgo) {
		return driftNewVulnerable
	}
	return driftNone
}

// ---- 证书到期分级预警（FR-7.9，SLO-06）----

// certClass 证书分级（决定预警提前量）。
type certClass int

const (
	certServer certClass = iota // 服务器证书（默认）
	certCA                      // 根/中间 CA
	certIoT                     // IoT/长效证书
)

// classifyCert 据资产层级/名称/系统判定证书分级。
//   - 根/中间 CA：Layer=L4 或 名称含 CA
//   - IoT/长效证书：Layer=L1 且 系统/名称含 物联网/IoT/工控
//   - 其余按服务器证书
func classifyCert(a *model.CryptoAsset) certClass {
	name := strings.ToUpper(a.Name)
	sys := strings.ToUpper(a.System)
	if a.Layer == model.LayerL4 || strings.Contains(name, "CA") {
		return certCA
	}
	if a.Layer == model.LayerL1 && (strings.Contains(sys, "IOT") ||
		strings.Contains(name, "IOT") || strings.Contains(a.System, "物联网") ||
		strings.Contains(a.System, "工控") || strings.Contains(a.Name, "物联网")) {
		return certIoT
	}
	return certServer
}

// warnDaysFor 据证书分级与策略返回提前量天数。
func warnDaysFor(cl certClass, p *model.MonitorPolicy) int {
	switch cl {
	case certCA:
		return p.CACertWarnDays
	case certIoT:
		return p.IoTCertWarnDays
	default:
		return p.ServerCertWarnDays
	}
}

// certClassLabel 分级中文名（事件标题用）。
func certClassLabel(cl certClass) string {
	switch cl {
	case certCA:
		return "根/中间 CA"
	case certIoT:
		return "IoT/长效证书"
	default:
		return "服务器证书"
	}
}

// hasOTA 粗判资产是否具备 OTA 能力（无 OTA 的 IoT 证书额外标注「需现场检修替换」，关联 R-003）。
// 演示态：IoT 类一律视为无 OTA（对齐 R-003 IoT/工控 47 台无 OTA）。
func hasOTA(a *model.CryptoAsset, cl certClass) bool {
	return cl != certIoT
}

// daysUntil 返回 t 距今的天数（向下取整；已过期为负）。
func daysUntil(t time.Time) int {
	return int(time.Until(t).Hours() / 24)
}
