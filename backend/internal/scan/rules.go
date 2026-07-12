package scan

import (
	"fmt"
	"strings"

	"zhulong-pqm/internal/cryptoref"
	"zhulong-pqm/internal/model"
)

// RiskHintByRule 规则号→命中时快照的综合风险等级（与 seed 一致，供命中引擎填 RuleHit.RiskHint）。
var RiskHintByRule = map[string]string{
	"R-L1-01": model.RiskHintMedium,
	"R-L1-02": model.RiskHintHigh,
	"R-L1-03": model.RiskHintHigh,
	"R-L1-05": model.RiskHintMedium,
	"R-L2-01": model.RiskHintCritical,
	"R-L2-02": model.RiskHintHigh,
	"R-L2-05": model.RiskHintMedium,
	"R-L2-08": model.RiskHintCritical,
	"R-L4-01": model.RiskHintMedium,
	"R-L4-05": model.RiskHintMedium,
}

// layerOfRule 从规则号 R-Lx-yy 提取层级。
func layerOfRule(ruleID string) string {
	if len(ruleID) >= 4 && strings.HasPrefix(ruleID, "R-L") {
		return "L" + string(ruleID[3])
	}
	return ""
}

// hit 构造一条 RuleHit（layer/riskHint 由规则号查表，置信度由调用方按 FR-3.4.2 给出）。
func hit(ruleID, confidence, evidence, method string) model.RuleHit {
	return model.RuleHit{
		RuleID:     ruleID,
		Layer:      layerOfRule(ruleID),
		Confidence: confidence,
		Evidence:   evidence,
		RiskHint:   RiskHintByRule[ruleID],
		Method:     method,
	}
}

// MatchRules 把一条 ScanResult 的密码学特征匹配到候选规则，产出 RuleHit（不含 ScanResultID）。
//
// 纯函数、不查库；调用方据规则库 Enabled 状态过滤后落库。method 取自扫描器/导入入口。
// 命中条件遵循深化蓝图 ① 命中表：机读直证（KEX/证书签名 OID/库版本）置信度=高。
func MatchRules(res *model.ScanResult, method string) []model.RuleHit {
	if method == "" {
		method = model.MethodM1ActiveTLS
	}
	var hits []model.RuleHit

	tls := strings.ReplaceAll(strings.ToUpper(res.TLSVersion), " ", "")
	cipher := strings.ToUpper(res.CipherSuite)
	keyAlgo := strings.ToUpper(res.KeyAlgo)
	sigAlgo := strings.ToUpper(res.SigAlgo)

	// R-L1-01：弱 TLS 版本（≤1.2，TLS 1.3 不命中）。
	if strings.Contains(tls, "TLS1.0") || strings.Contains(tls, "TLS1.1") || strings.Contains(tls, "TLS1.2") {
		hits = append(hits, hit("R-L1-01", model.ConfHigh,
			fmt.Sprintf("TLS Version: %s", res.TLSVersion), method))
	}

	// R-L1-02：经典 KEX（RSA/ECDH/DHE，混合 X25519MLKEM768 等不命中）。
	if isClassicKEX(cipher, keyAlgo) {
		hits = append(hits, hit("R-L1-02", model.ConfHigh,
			fmt.Sprintf("KEX/CipherSuite: %s (KeyAlgo %s)", res.CipherSuite, res.KeyAlgo), method))
	}

	// R-L1-03：经典证书签名（RSA-PKCS1/ECDSA/Ed25519）。
	if isClassicSig(sigAlgo) {
		hits = append(hits, hit("R-L1-03", model.ConfHigh,
			fmt.Sprintf("Signature Algorithm: %s", res.SigAlgo), method))
	}

	return hits
}

// isClassicKEX 判断套件/公钥算法属于经典（非混合/非 PQC）密钥协商。
func isClassicKEX(cipher, keyAlgo string) bool {
	// 组名本身是混合/PQC（cryptoref 认识的规范名）→ 直接非经典。
	if s := cryptoref.SafetyForGroupName(cipher); s == cryptoref.SafetyHybrid || s == cryptoref.SafetySafe {
		return false
	}
	hay := cipher + " " + keyAlgo
	// 混合/后量子标识：命中则不算经典。
	for _, pq := range []string{"MLKEM", "ML-KEM", "KYBER", "X25519MLKEM", "KE1_MLKEM", "MLDSA", "ML-DSA"} {
		if strings.Contains(hay, pq) {
			return false
		}
	}
	for _, kex := range []string{"RSA", "ECDH", "ECDHE", "DHE", "DH"} {
		if strings.Contains(hay, kex) {
			return true
		}
	}
	return false
}

// MatchSSHRules 针对 SSH 审计结果命中 R-L1-05（KEX）与 R-L2-05（主机密钥）。
//
// kexAlgos 为服务器协商出/优选的 KEX 算法列表，hostKeyType 为主机密钥类型。
// curve25519-* 不命中 R-L1-05（已抗量子降级目标）。
func MatchSSHRules(res *model.ScanResult, kexAlgos []string, hostKeyType string) []model.RuleHit {
	method := model.MethodM1ActiveTLS
	var hits []model.RuleHit

	classic := classicSSHKex(kexAlgos)
	if len(classic) > 0 {
		hits = append(hits, hit("R-L1-05", model.ConfHigh,
			"SSH KEX: "+strings.Join(classic, ","), method))
	}
	hk := strings.ToLower(hostKeyType)
	if strings.Contains(hk, "rsa") || strings.Contains(hk, "ecdsa") || strings.Contains(hk, "dss") {
		hits = append(hits, hit("R-L2-05", model.ConfHigh,
			"SSH HostKey: "+hostKeyType, method))
	}
	return hits
}

// classicSSHKex 过滤出经典 DH/ECDH KEX（curve25519/sntrup/mlkem 不计）。
func classicSSHKex(kexAlgos []string) []string {
	var out []string
	for _, k := range kexAlgos {
		kl := strings.ToLower(k)
		if strings.Contains(kl, "curve25519") || strings.Contains(kl, "sntrup") ||
			strings.Contains(kl, "mlkem") || strings.Contains(kl, "ml-kem") {
			continue
		}
		if strings.Contains(kl, "ecdh") || strings.Contains(kl, "diffie-hellman") || strings.Contains(kl, "dh-") {
			out = append(out, k)
		}
	}
	return out
}

// MatchCertRules 针对导入证书（PEM/M5）命中 L2 证书规则。
//
// isCA 且自签（subject==issuer）且经典算法 → R-L2-01（极高，根/中间 CA）；
// 叶证书经典算法 → R-L2-02。algo 为公钥算法（RSA/ECDSA/SM2…）。
func MatchCertRules(algo, sigAlgo string, isCA, selfSigned bool) []model.RuleHit {
	method := model.MethodM5Cert
	var hits []model.RuleHit
	a := strings.ToUpper(algo)
	classic := isClassicSig(strings.ToUpper(sigAlgo)) || strings.Contains(a, "RSA") ||
		strings.Contains(a, "ECDSA") || strings.Contains(a, "SM2")
	if !classic {
		return hits
	}
	ev := fmt.Sprintf("PublicKey: %s, Signature: %s", algo, sigAlgo)
	if isCA && selfSigned && (strings.Contains(a, "RSA") || strings.Contains(a, "SM2")) {
		hits = append(hits, hit("R-L2-01", model.ConfHigh, "Root/Intermediate CA "+ev, method))
	} else {
		hits = append(hits, hit("R-L2-02", model.ConfHigh, "Leaf cert "+ev, method))
	}
	return hits
}

// MatchSBOMRules 针对 SBOM 组件（M4）命中 L4 加密库规则。
//
// 不支持 ML-KEM 的密码库版本 → R-L4-01（证据为库版本串）；
// 任一外部密码库依赖 → R-L4-05（供应链）。
func MatchSBOMRules(name, version string, supportsMLKEM bool) []model.RuleHit {
	method := model.MethodM4SBOM
	var hits []model.RuleHit
	ev := name
	if version != "" {
		ev = name + " " + version
	}
	if !supportsMLKEM {
		hits = append(hits, hit("R-L4-01", model.ConfHigh, "crypto lib without ML-KEM: "+ev, method))
	}
	hits = append(hits, hit("R-L4-05", model.ConfHigh, "external crypto dependency: "+ev, method))
	return hits
}

// isClassicSig 判断证书签名算法属于经典量子脆弱签名。
func isClassicSig(sig string) bool {
	if cryptoref.AuthSafetyForAlgo(sig) != cryptoref.SafetyClassical {
		return false
	}
	for _, pq := range []string{"MLDSA", "ML-DSA", "DILITHIUM", "SPHINCS", "FALCON"} {
		if strings.Contains(sig, pq) {
			return false
		}
	}
	for _, s := range []string{"RSA", "ECDSA", "ED25519", "SM2", "DSA"} {
		if strings.Contains(sig, s) {
			return true
		}
	}
	return false
}
