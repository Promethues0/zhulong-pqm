package cbom

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"zhulong-pqm/internal/model"
)

// Parse 解析并校验一份 CycloneDX 1.6 CBOM JSON（FR-4.8）。
//
// 校验 bomFormat==CycloneDX 且 specVersion 以 1.6 开头；返回解析后的 BOM。
// 校验失败返回字段级错误，供导入端点回 400。
func Parse(data []byte) (*BOM, error) {
	var bom BOM
	if err := json.Unmarshal(data, &bom); err != nil {
		return nil, fmt.Errorf("CBOM JSON 解析失败: %w", err)
	}
	if bom.BOMFormat != "CycloneDX" {
		return nil, fmt.Errorf("bomFormat 须为 CycloneDX（实际 %q）", bom.BOMFormat)
	}
	if !strings.HasPrefix(bom.SpecVersion, "1.6") {
		return nil, fmt.Errorf("specVersion 须为 1.6（实际 %q）", bom.SpecVersion)
	}
	return &bom, nil
}

// ComponentToAsset 把一个 CycloneDX cryptographic-asset 组件反归一为 CryptoAsset（round-trip）。
//
// 复用导出时写入的 zhulong:* properties 无损回填风险维度；缺失项留默认。
// 仅处理 cryptographic-asset 组件，其余返回 ok=false 由调用方跳过。
func ComponentToAsset(c Component) (model.CryptoAsset, bool) {
	if c.Type != "cryptographic-asset" {
		return model.CryptoAsset{}, false
	}
	a := model.CryptoAsset{
		Name:     c.Name,
		RiskHint: c.Description,
		Source:   model.SourceImport,
	}

	if cp := c.CryptoProperties; cp != nil {
		if ap := cp.AlgorithmProperties; ap != nil {
			if ap.ParameterSetIdentifier != "" {
				if n, err := strconv.Atoi(ap.ParameterSetIdentifier); err == nil {
					a.KeySize = n
				}
			}
		}
		if certp := cp.CertificateProperties; certp != nil {
			if certp.NotValidAfter != "" {
				if t, err := time.Parse(time.RFC3339, certp.NotValidAfter); err == nil {
					a.CertNotAfter = &t
				}
			}
		}
	}

	for _, p := range c.Properties {
		switch p.Name {
		case "zhulong:system":
			a.System = p.Value
		case "zhulong:layer":
			a.Layer = p.Value
		case "zhulong:exposure":
			a.Exposure = p.Value
		case "zhulong:riskScore":
			a.RiskScore = atoi(p.Value)
		case "zhulong:riskLevel":
			a.RiskLevel = p.Value
		case "zhulong:status":
			a.Status = p.Value
		case "zhulong:hndl":
			a.HNDL = p.Value == "true"
		case "zhulong:suggestedAlgo":
			a.SuggestedAlgo = p.Value
		case "zhulong:algorithm":
			a.Algorithm = p.Value
		case "zhulong:protocol":
			a.Protocol = p.Value
		case "zhulong:endpoint":
			a.Endpoint = p.Value
		case "zhulong:certFingerprint":
			a.CertFingerprint = p.Value
		case "zhulong:d1":
			a.D1 = atoi(p.Value)
		case "zhulong:d2":
			a.D2 = atoi(p.Value)
		case "zhulong:d3":
			a.D3 = atoi(p.Value)
		case "zhulong:d4":
			a.D4 = atoi(p.Value)
		case "zhulong:d5":
			a.D5 = atoi(p.Value)
		case "zhulong:kexGroup":
			a.KexGroup = p.Value
		case "zhulong:kexSafety":
			a.KexSafety = p.Value
		case "zhulong:authSafety":
			a.AuthSafety = p.Value
		}
	}

	// 算法名优先取 zhulong:algorithm（round-trip 无损）；缺则从 primitive 兜底无法精确还原，留空由调用方据证据补。
	if a.Algorithm == "" && c.CryptoProperties != nil && c.CryptoProperties.AlgorithmProperties != nil {
		// primitive 是粗类别，不作为算法名硬填，避免污染；仅当组件名像算法时回退。
		if looksLikeAlgo(c.Name) {
			a.Algorithm = c.Name
		}
	}
	if a.Exposure == "" {
		a.Exposure = model.ExposureInternal
	}
	if a.Layer == "" {
		a.Layer = model.LayerL2
	}
	return a, true
}

// AlgoDist 统计一组资产的算法分布 map[algo]count（供快照环比 diff）。
// 算法名空的资产归入 "unknown"。
func AlgoDist(assets []model.CryptoAsset) map[string]int {
	dist := map[string]int{}
	for _, a := range assets {
		k := strings.TrimSpace(a.Algorithm)
		if k == "" {
			k = "unknown"
		}
		dist[k]++
	}
	return dist
}

func atoi(s string) int {
	n, _ := strconv.Atoi(strings.TrimSpace(s))
	return n
}

// looksLikeAlgo 粗判组件名是否像算法名（含已知算法子串）。
func looksLikeAlgo(name string) bool {
	n := strings.ToUpper(name)
	for _, k := range []string{"RSA", "ECDSA", "ECDH", "SM2", "SM4", "AES", "ML-KEM", "ML-DSA", "ED25519", "DH"} {
		if strings.Contains(n, k) {
			return true
		}
	}
	return false
}
