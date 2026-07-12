package cryptoref

import "strings"

// pqcSigTokens 认证/签名维判为纯 PQC 的算法名子串（大写匹配）。
var pqcSigTokens = []string{"ML-DSA", "MLDSA", "DILITHIUM", "SLH-DSA", "SLHDSA", "SPHINCS", "FALCON", "AIGIS-SIG", "AIGIS_SIG"}

// classicalSigTokens 认证维判为纯经典的算法名子串。
// 注意：不含裸 "DSA"——它是 "ML-DSA"/"SLH-DSA" 的子串，会与 PQC token 误撞导致
// 纯 PQC 算法被误判 hybrid；经典 DSA 场景已由更具体的 "ECDSA" 覆盖。
var classicalSigTokens = []string{"RSA", "ECDSA", "ED25519", "EDDSA", "SM2", "ECC"}

// AuthSafetyForAlgo 由认证/签名算法名判认证维量子安全态。
// 组合串同时含经典与 PQC 子串 → hybrid；仅 PQC → safe；仅经典 → classical；空 → na。
func AuthSafetyForAlgo(algo string) string {
	a := strings.ToUpper(strings.TrimSpace(algo))
	if a == "" {
		return SafetyNA
	}
	hasPQC, hasClassical := false, false
	for _, t := range pqcSigTokens {
		if strings.Contains(a, t) {
			hasPQC = true
			break
		}
	}
	for _, t := range classicalSigTokens {
		if strings.Contains(a, t) {
			hasClassical = true
			break
		}
	}
	switch {
	case hasPQC && hasClassical:
		return SafetyHybrid
	case hasPQC:
		return SafetySafe
	case hasClassical:
		return SafetyClassical
	default:
		return SafetyClassical // 未知保守按经典（与 scoring.deriveD1 默认口径一致）
	}
}

// KexMitigatesHNDL 密钥交换维是否已缓解「先抓后解」（safe/hybrid 均可，混合的 PQC 分量足以抵御）。
func KexMitigatesHNDL(kexSafety string) bool {
	return kexSafety == SafetySafe || kexSafety == SafetyHybrid
}

// AlgoInfo PQC 算法的 CBOM 标识信息。
type AlgoInfo struct {
	Primitive    string // kem / signature / hash
	OID          string
	ParamSet     string
	QuantumLevel int // NIST PQC 安全等级 1/3/5，0=非 PQC
}

// pqcAlgoTable PQC 算法核心表（键为大写规范前缀，前缀匹配）。全表见 spec 附录。
var pqcAlgoTable = []struct {
	prefix string
	info   AlgoInfo
}{
	{"ML-KEM-1024", AlgoInfo{"kem", "2.16.840.1.101.3.4.4.3", "ML-KEM-1024", 5}},
	{"ML-KEM-768", AlgoInfo{"kem", "2.16.840.1.101.3.4.4.2", "ML-KEM-768", 3}},
	{"ML-KEM-512", AlgoInfo{"kem", "2.16.840.1.101.3.4.4.1", "ML-KEM-512", 1}},
	{"ML-DSA-87", AlgoInfo{"signature", "2.16.840.1.101.3.4.3.19", "ML-DSA-87", 5}},
	{"ML-DSA-65", AlgoInfo{"signature", "2.16.840.1.101.3.4.3.18", "ML-DSA-65", 3}},
	{"ML-DSA-44", AlgoInfo{"signature", "2.16.840.1.101.3.4.3.17", "ML-DSA-44", 2}},
	{"SLH-DSA", AlgoInfo{"signature", "2.16.840.1.101.3.4.3.20", "SLH-DSA", 1}},
	{"AIGIS-SIG", AlgoInfo{"signature", "", "Aigis-sig", 2}}, // OID 缺口，待真机补录
	{"AIGIS-ENC", AlgoInfo{"kem", "", "Aigis-enc", 2}},
}

// LookupAlgo 前缀匹配 PQC 算法表；命中返回 CBOM 标识信息。
func LookupAlgo(algo string) (AlgoInfo, bool) {
	a := strings.ToUpper(strings.TrimSpace(algo))
	for _, e := range pqcAlgoTable {
		if strings.Contains(a, e.prefix) {
			return e.info, true
		}
	}
	return AlgoInfo{}, false
}
