package scan

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"strings"
	"time"

	"zhulong-pqm/internal/model"
)

// ParsedCert 一份导入证书的解析结果（M5）。
type ParsedCert struct {
	Result     *model.ScanResult // 已填公钥算法/位数/签名/有效期/指纹的结果壳
	IsCA       bool
	SelfSigned bool
	Algo       string
	SigAlgo    string
}

// ParsePEMCerts 解析一段 PEM 文本中的全部 X.509 证书（M5 证书导入）。
//
// 复用 fillCertInfo 提取算法/位数/签名/有效期/指纹；每张证书产出一份 ParsedCert，
// 含 IsCA / SelfSigned（subject==issuer）供命中 R-L2-01/02 判定。
func ParsePEMCerts(pemText string) ([]ParsedCert, error) {
	var out []ParsedCert
	rest := []byte(pemText)
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			continue // 跳过损坏块，尽力解析
		}
		res := &model.ScanResult{}
		fillCertInfo(res, cert)
		res.Method = model.MethodM5Cert
		res.Source = model.SourceImport
		res.AssetFingerprint = AssetFingerprint("", 0, "cert", res.CertFingerprint)

		raw, _ := json.Marshal(map[string]any{
			"subject":   res.CertSubject,
			"issuer":    res.CertIssuer,
			"keyAlgo":   res.KeyAlgo,
			"keySize":   res.KeySize,
			"sigAlgo":   res.SigAlgo,
			"isCA":      cert.IsCA,
			"notAfter":  res.CertNotAfter,
			"importPem": true,
		})
		res.Raw = string(raw)

		out = append(out, ParsedCert{
			Result:     res,
			IsCA:       cert.IsCA,
			SelfSigned: cert.Subject.String() == cert.Issuer.String(),
			Algo:       res.KeyAlgo,
			SigAlgo:    res.SigAlgo,
		})
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("未在输入中解析到任何 X.509 证书")
	}
	return out, nil
}

// CertHits 计算导入证书命中的规则（R-L2-01/02）。
func (p ParsedCert) Hits() []model.RuleHit {
	return MatchCertRules(p.Algo, p.SigAlgo, p.IsCA, p.SelfSigned)
}

// ---- SBOM 导入（M4，CycloneDX / Syft JSON）----

// SBOMComponent 提取出的密码库组件。
type SBOMComponent struct {
	Name          string
	Version       string
	SupportsMLKEM bool
}

// 已知密码库（小写匹配）。值为「起始支持 ML-KEM 的最小主版本」；<0 表示该库尚不支持。
var cryptoLibMinMLKEMMajor = map[string]int{
	"openssl":  35, // OpenSSL 3.5 起内建 ML-KEM（用 35 表示 3.5：major*10+minor 粗粒度）
	"libressl": -1,
	"mbedtls":  -1,
	"boringssl": -1,
	"wolfssl":  56, // wolfSSL 5.6+ 实验性 PQC
	"gnutls":   -1,
	"bouncycastle": 178, // BC 1.78+ 有 ML-KEM
}

// ParseSBOM 解析 CycloneDX 或 Syft JSON，提取密码库组件（M4）。
//
// 兼容两种结构：CycloneDX 的 components[].name/version，Syft 的 artifacts[].name/version。
func ParseSBOM(data []byte) ([]SBOMComponent, error) {
	var doc struct {
		Components []struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		} `json:"components"`
		Artifacts []struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		} `json:"artifacts"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("SBOM JSON 解析失败: %w", err)
	}

	type nv struct{ name, version string }
	var all []nv
	for _, c := range doc.Components {
		all = append(all, nv{c.Name, c.Version})
	}
	for _, a := range doc.Artifacts {
		all = append(all, nv{a.Name, a.Version})
	}

	var out []SBOMComponent
	for _, c := range all {
		lib, ok := matchCryptoLib(c.name)
		if !ok {
			continue
		}
		out = append(out, SBOMComponent{
			Name:          c.name,
			Version:       c.version,
			SupportsMLKEM: libSupportsMLKEM(lib, c.version),
		})
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("未在 SBOM 中识别到已知密码库组件")
	}
	return out, nil
}

// matchCryptoLib 把组件名归一到已知密码库键。
func matchCryptoLib(name string) (string, bool) {
	n := strings.ToLower(strings.TrimSpace(name))
	n = strings.ReplaceAll(n, "_", "")
	n = strings.ReplaceAll(n, "-", "")
	for lib := range cryptoLibMinMLKEMMajor {
		if strings.Contains(n, lib) {
			return lib, true
		}
	}
	return "", false
}

// libSupportsMLKEM 据库与版本判定是否支持 ML-KEM。
func libSupportsMLKEM(lib, version string) bool {
	min, ok := cryptoLibMinMLKEMMajor[lib]
	if !ok || min < 0 {
		return false
	}
	code := versionCode(version)
	return code >= min
}

// versionCode 把 "3.5.1" 粗粒度折成 major*10+minor 便于阈值比较；解析失败返回 0。
func versionCode(v string) int {
	v = strings.TrimSpace(v)
	v = strings.TrimPrefix(strings.ToLower(v), "v")
	parts := strings.FieldsFunc(v, func(r rune) bool { return r == '.' || r == '-' || r == '+' })
	if len(parts) == 0 {
		return 0
	}
	major := atoiSafe(parts[0])
	minor := 0
	if len(parts) > 1 {
		minor = atoiSafe(parts[1])
	}
	return major*10 + minor
}

func atoiSafe(s string) int {
	n := 0
	for _, r := range s {
		if r < '0' || r > '9' {
			break
		}
		n = n*10 + int(r-'0')
	}
	return n
}

// SBOMHits 计算一个 SBOM 组件命中的规则（R-L4-01/05）。
func (c SBOMComponent) SBOMHits() []model.RuleHit {
	return MatchSBOMRules(c.Name, c.Version, c.SupportsMLKEM)
}

// nowPtr 便捷返回当前时间指针（FirstSeen/LastSeen）。
func nowPtr() *time.Time { t := time.Now(); return &t }
