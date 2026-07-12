// Package cryptoref 集中 TLS 命名组码点、PQC 算法与量子安全态分类，
// 供被动解析、主动探针、评分、CBOM 复用。全部为纯函数、无副作用、无 CGO。
//
// 数据来源与逐条 IANA 校验见 docs/superpowers/specs/2026-07-11-pqc-crypto-lib-research.md。
package cryptoref

import "fmt"

// 量子安全态三分类 + 不适用。
const (
	SafetySafe      = "safe"      // 纯 PQC
	SafetyHybrid    = "hybrid"    // 经典+PQC 混合
	SafetyClassical = "classical" // 纯经典
	SafetyNA        = "na"        // 该维不适用
)

// group 一个命名组的静态元信息。
type group struct {
	name string
	kind string // classical / hybrid / pqc
	iana bool
}

// namedGroups TLS supported_groups/key_share 码点核心表。
// 完整表（含全部 OQS 私有段）见 spec 附录；此处覆盖驱动 M-A 的核心码点。
var namedGroups = map[int]group{
	// 经典基线
	0x0017: {"secp256r1", "classical", true},
	0x0018: {"secp384r1", "classical", true},
	0x0019: {"secp521r1", "classical", true},
	0x001D: {"x25519", "classical", true},
	0x001E: {"x448", "classical", true},
	0x0029: {"curveSM2", "classical", true}, // IANA#41 RFC8998 国密经典指纹
	// 纯 ML-KEM（IANA#512-514）
	0x0200: {"MLKEM512", "pqc", true},
	0x0201: {"MLKEM768", "pqc", true},
	0x0202: {"MLKEM1024", "pqc", true},
	// IANA 混合组（RFC-ietf-tls-ecdhe-mlkem）
	0x11EB: {"SecP256r1MLKEM768", "hybrid", true},
	0x11EC: {"X25519MLKEM768", "hybrid", true}, // 唯一 Rec=Y，互联网主流
	0x11ED: {"SecP384r1MLKEM1024", "hybrid", true},
	0x11EE: {"curveSM2MLKEM768", "hybrid", true}, // 国密 SM2+ML-KEM，铜锁 Tongsuo 8.5+
	// 已废弃/历史（识别旧流量）
	0x6399: {"X25519Kyber768Draft00", "hybrid", true},
	0x639A: {"SecP256r1Kyber768Draft00", "hybrid", true},
	0x4138: {"CECPQ2", "hybrid", false},
	0xFEFE: {"curveSM2MLKEM768(draft-02)", "hybrid", false}, // 旧版铜锁时间指纹
}

// ClassifyGroup 查表：返回组名、kind、是否 IANA、是否已知。GREASE 视为未知（交由上层丢弃）。
func ClassifyGroup(codepoint int) (name string, kind string, isIANA bool, known bool) {
	if g, ok := namedGroups[codepoint]; ok {
		return g.name, g.kind, g.iana, true
	}
	return "", "", false, false
}

// IsGREASEGroup 判断是否 GREASE 占位（0x0A0A、0x1A1A…0xFAFA；RFC 8701）。
func IsGREASEGroup(codepoint int) bool {
	return (codepoint&0x0f0f) == 0x0a0a && (codepoint>>8) == (codepoint&0xff)
}

// SafetyFromKind 组 kind → 量子安全态（pqc→safe，hybrid→hybrid，classical→classical）。
func SafetyFromKind(kind string) string {
	switch kind {
	case "pqc":
		return SafetySafe
	case "hybrid":
		return SafetyHybrid
	default:
		return SafetyClassical
	}
}

// KexSafetyForGroup 由码点（+客户端 key_share 字节数兜底）判密钥交换维安全态。
//
// 判定优先级：① GREASE→噪声（返回空）；② 命中表→按 kind；
// ③ 未知码点→尺寸兜底：client key_share >1000B 基本必是格基 KEM（经典组最大 P-521=133B），
// 保守判 hybrid（含 PQC 成分即可缓解 HNDL），否则 classical。
func KexSafetyForGroup(codepoint int, clientKeyShareLen int) (groupName string, safety string) {
	if IsGREASEGroup(codepoint) {
		return "", ""
	}
	if name, kind, _, known := ClassifyGroup(codepoint); known {
		return name, SafetyFromKind(kind)
	}
	if clientKeyShareLen > 1000 {
		return fmt.Sprintf("unknown-0x%04X", codepoint), SafetyHybrid
	}
	return fmt.Sprintf("unknown-0x%04X", codepoint), SafetyClassical
}
