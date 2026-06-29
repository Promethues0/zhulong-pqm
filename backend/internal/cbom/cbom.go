// Package cbom 将密码资产清单导出为 CycloneDX 1.6 CBOM（密码物料清单）。
package cbom

import (
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"zhulong-pqm/internal/model"
)

// CycloneDX 1.6 子集结构。仅实现 CBOM 导出所需字段。

// BOM 是 CycloneDX 文档根。
type BOM struct {
	BOMFormat   string      `json:"bomFormat"`
	SpecVersion string      `json:"specVersion"`
	SerialNumber string     `json:"serialNumber"`
	Version     int         `json:"version"`
	Metadata    Metadata    `json:"metadata"`
	Components  []Component `json:"components"`
}

// Metadata 文档元信息。
type Metadata struct {
	Timestamp string     `json:"timestamp"`
	Tools     []Tool     `json:"tools"`
	Component *Component `json:"component,omitempty"`
}

// Tool 生成工具信息。
type Tool struct {
	Vendor  string `json:"vendor"`
	Name    string `json:"name"`
	Version string `json:"version"`
}

// Component 一个 CycloneDX 组件。CBOM 中 type 为 "cryptographic-asset"。
type Component struct {
	Type           string          `json:"type"`
	BOMRef         string          `json:"bom-ref"`
	Name           string          `json:"name"`
	Description    string          `json:"description,omitempty"`
	CryptoProperties *CryptoProperties `json:"cryptoProperties,omitempty"`
	Properties     []Property      `json:"properties,omitempty"`
}

// Property 自由形式键值对，用于承载烛龙特有的风险维度。
type Property struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// CryptoProperties CycloneDX 密码属性。
type CryptoProperties struct {
	AssetType           string               `json:"assetType"`
	AlgorithmProperties *AlgorithmProperties `json:"algorithmProperties,omitempty"`
	CertificateProperties *CertificateProperties `json:"certificateProperties,omitempty"`
	OID                 string               `json:"oid,omitempty"`
}

// AlgorithmProperties 算法相关属性。
type AlgorithmProperties struct {
	Primitive              string   `json:"primitive,omitempty"`
	ParameterSetIdentifier string   `json:"parameterSetIdentifier,omitempty"`
	ExecutionEnvironment   string   `json:"executionEnvironment,omitempty"`
	CryptoFunctions        []string `json:"cryptoFunctions,omitempty"`
	ClassicalSecurityLevel int      `json:"classicalSecurityLevel,omitempty"`
	NISTQuantumSecurityLevel int    `json:"nistQuantumSecurityLevel,omitempty"`
}

// CertificateProperties 证书相关属性。
type CertificateProperties struct {
	SubjectName        string `json:"subjectName,omitempty"`
	IssuerName         string `json:"issuerName,omitempty"`
	NotValidAfter      string `json:"notValidAfter,omitempty"`
	SignatureAlgorithmRef string `json:"signatureAlgorithmRef,omitempty"`
}

// Build 由资产列表构造一份 CycloneDX 1.6 CBOM。
func Build(assets []model.CryptoAsset) BOM {
	comps := make([]Component, 0, len(assets))
	for _, a := range assets {
		comps = append(comps, assetToComponent(a))
	}

	return BOM{
		BOMFormat:    "CycloneDX",
		SpecVersion:  "1.6",
		SerialNumber: "urn:uuid:" + uuid.NewString(),
		Version:      1,
		Metadata: Metadata{
			Timestamp: time.Now().UTC().Format(time.RFC3339),
			Tools: []Tool{{
				Vendor:  "Zhulong",
				Name:    "Zhulong PQM",
				Version: "R1",
			}},
			Component: &Component{
				Type:   "application",
				BOMRef: "zhulong-pqm",
				Name:   "烛龙·后量子迁移治理平台",
			},
		},
		Components: comps,
	}
}

func assetToComponent(a model.CryptoAsset) Component {
	c := Component{
		Type:        "cryptographic-asset",
		BOMRef:      fmt.Sprintf("asset-%d", a.ID),
		Name:        a.Name,
		Description: a.RiskHint,
	}

	cp := &CryptoProperties{
		AssetType: classifyAssetType(a),
		AlgorithmProperties: &AlgorithmProperties{
			Primitive:              primitiveOf(a.Algorithm),
			ParameterSetIdentifier: paramSet(a),
			CryptoFunctions:        cryptoFunctions(a.Algorithm),
		},
	}
	if a.CertFingerprint != "" || a.CertNotAfter != nil {
		cp.CertificateProperties = &CertificateProperties{
			SubjectName: a.Name,
			NotValidAfter: notAfterStr(a.CertNotAfter),
		}
	}
	c.CryptoProperties = cp

	// 烛龙特有的风险维度以 properties 承载，保持 CBOM 可消费性；
	// algorithm/protocol/endpoint/certFingerprint 显式存证以支持反向导入 round-trip 无损（FR-4.2.1）。
	c.Properties = []Property{
		{"zhulong:system", a.System},
		{"zhulong:layer", a.Layer},
		{"zhulong:exposure", a.Exposure},
		{"zhulong:algorithm", a.Algorithm},
		{"zhulong:protocol", a.Protocol},
		{"zhulong:endpoint", a.Endpoint},
		{"zhulong:certFingerprint", a.CertFingerprint},
		{"zhulong:riskScore", fmt.Sprintf("%d", a.RiskScore)},
		{"zhulong:riskLevel", a.RiskLevel},
		{"zhulong:status", a.Status},
		{"zhulong:hndl", fmt.Sprintf("%t", a.HNDL)},
		{"zhulong:suggestedAlgo", a.SuggestedAlgo},
		{"zhulong:d1", fmt.Sprintf("%d", a.D1)},
		{"zhulong:d2", fmt.Sprintf("%d", a.D2)},
		{"zhulong:d3", fmt.Sprintf("%d", a.D3)},
		{"zhulong:d4", fmt.Sprintf("%d", a.D4)},
		{"zhulong:d5", fmt.Sprintf("%d", a.D5)},
	}
	return c
}

// classifyAssetType 将资产映射到 CycloneDX 的 cryptographic-asset 子类型。
func classifyAssetType(a model.CryptoAsset) string {
	if a.CertNotAfter != nil || a.CertFingerprint != "" {
		return "certificate"
	}
	if strings.Contains(strings.ToLower(a.Algorithm), "tls") || a.Protocol != "" {
		return "protocol"
	}
	return "algorithm"
}

// primitiveOf 推断算法的 CycloneDX primitive。
func primitiveOf(algo string) string {
	a := strings.ToUpper(algo)
	switch {
	case strings.Contains(a, "RSA"):
		return "pke" // 公钥加密/签名
	case strings.Contains(a, "ECDSA"), strings.Contains(a, "ED25519"),
		strings.Contains(a, "EDDSA"), strings.Contains(a, "SM2"), strings.Contains(a, "DSA"):
		return "signature"
	case strings.Contains(a, "ECDH"), strings.Contains(a, "DH"), strings.Contains(a, "KEM"):
		return "key-agree"
	case strings.Contains(a, "AES"), strings.Contains(a, "SM4"), strings.Contains(a, "DES"):
		return "block-cipher"
	case strings.Contains(a, "SHA"), strings.Contains(a, "SM3"):
		return "hash"
	default:
		return "unknown"
	}
}

func paramSet(a model.CryptoAsset) string {
	if a.KeySize > 0 {
		return fmt.Sprintf("%d", a.KeySize)
	}
	return ""
}

func cryptoFunctions(algo string) []string {
	a := strings.ToUpper(algo)
	switch {
	case strings.Contains(a, "RSA"):
		return []string{"encrypt", "decrypt", "sign", "verify"}
	case strings.Contains(a, "ECDSA"), strings.Contains(a, "ED25519"),
		strings.Contains(a, "EDDSA"), strings.Contains(a, "SM2"):
		return []string{"sign", "verify"}
	case strings.Contains(a, "ECDH"), strings.Contains(a, "DH"):
		return []string{"keygen"}
	default:
		return nil
	}
}

func notAfterStr(t *time.Time) string {
	if t == nil {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}
