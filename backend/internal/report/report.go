// Package report 由密码资产清单生成后量子摸底报告（Markdown）。
package report

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"zhulong-pqm/internal/model"
)

// levelOrder 用于按风险等级排序（P1 最前）。
var levelOrder = map[string]int{"P1": 0, "P2": 1, "P3": 2, "P4": 3}

// Generate 由资产列表生成一份摸底报告，返回标题与 Markdown 正文。
//
// scope 为可选范围描述（如某系统名），仅用于标题与说明，不做过滤。
// 报告结构对齐工具包模板《PQC 密码资产摸底报告》：总体态势 → 算法分布 →
// 层级分布 → P1 清单 → HNDL 专项 → 算法选型建议 → 迁移批次 → 处置建议。
func Generate(assets []model.CryptoAsset, scope string) (title, markdown string) {
	now := time.Now().Format("2006-01-02 15:04")
	scopeText := scope
	if scopeText == "" {
		scopeText = "全域"
	}
	title = fmt.Sprintf("烛龙 PQM 后量子摸底报告（%s · %s）", scopeText, now)

	var b strings.Builder
	fmt.Fprintf(&b, "# %s\n\n", title)
	fmt.Fprintf(&b, "> 生成时间：%s　范围：%s　密码使用点：%d　基准：NIST FIPS 203/204/205 · CycloneDX CBOM\n\n",
		now, scopeText, len(assets))

	writeOverview(&b, assets)
	writeAlgoDistribution(&b, assets)
	writeLayerBreakdown(&b, assets)
	writeP1Detail(&b, assets)
	writeHNDL(&b, assets)
	writeAlgoSelection(&b)
	writeMigrationBatches(&b)
	writeRecommendation(&b)

	return title, b.String()
}

func writeOverview(b *strings.Builder, assets []model.CryptoAsset) {
	var p1, p2, p3, p4, hndl, critical, sum int
	for _, a := range assets {
		switch a.RiskLevel {
		case "P1":
			p1++
		case "P2":
			p2++
		case "P3":
			p3++
		case "P4":
			p4++
		}
		if a.HNDL {
			hndl++
		}
		if a.RiskLevelText == "极高" {
			critical++
		}
		sum += a.RiskScore
	}
	avg := 0
	if len(assets) > 0 {
		avg = sum / len(assets)
	}

	b.WriteString("## 一、总体态势\n\n")
	fmt.Fprintf(b, "- 平均风险分：**%d**\n", avg)
	fmt.Fprintf(b, "- 极高风险（P1）资产：**%d** 个\n", p1)
	fmt.Fprintf(b, "- HNDL（先存后解）风险资产：**%d** 个\n\n", hndl)
	b.WriteString("| 风险等级 | 数量 | 迁移窗口 |\n|---|---|---|\n")
	fmt.Fprintf(b, "| P1 极高 | %d | 0-3 月 |\n", p1)
	fmt.Fprintf(b, "| P2 高 | %d | 3-6 月 |\n", p2)
	fmt.Fprintf(b, "| P3 中 | %d | 6-12 月 |\n", p3)
	fmt.Fprintf(b, "| P4 低 | %d | 持续监控 |\n\n", p4)
}

// algoFamily 把具体算法名归一到家族键，附量子安全性与典型场景。
// 判定从具体到一般，避免 AES-128 落入 AES-256 桶。
func algoFamily(algorithm string) (family, safety, scenario string) {
	up := strings.ToUpper(algorithm)
	switch {
	case strings.Contains(up, "RSA"):
		return "RSA", "脆弱（Shor 可破）", "TLS 证书、代码签名、密钥交换"
	case strings.Contains(up, "ECDSA"):
		return "ECDSA", "脆弱（Shor 可破）", "TLS、JWT 签名、内部 CA"
	case strings.Contains(up, "ECDH"):
		return "ECDH", "脆弱（Shor 可破）", "TLS 密钥交换、VPN"
	case strings.Contains(up, "SM2"):
		return "SM2(国密)", "脆弱（Shor 可破）", "国密签名/密钥交换"
	case strings.Contains(up, "ED25519"), strings.Contains(up, "EDDSA"):
		return "EdDSA", "脆弱（Shor 可破）", "现代签名"
	case strings.Contains(up, "DH"):
		return "DH", "脆弱（Shor 可破）", "经典密钥交换"
	case strings.Contains(up, "AES-128"), strings.Contains(up, "AES128"):
		return "AES-128", "量子下强度减半（升 AES-256）", "数据加密、VPN 数据面"
	case strings.Contains(up, "AES"):
		return "AES-256", "安全（密钥加倍后）", "数据加密"
	case strings.Contains(up, "SM4"):
		return "SM4(国密)", "安全", "国密数据加密"
	case strings.Contains(up, "SHA"), strings.Contains(up, "SM3"):
		return "哈希(SHA/SM3)", "安全", "完整性、摘要"
	case strings.TrimSpace(up) == "":
		return "未识别", "待评估", "待人工补录"
	default:
		return algorithm, "待评估", "待评估"
	}
}

func writeAlgoDistribution(b *strings.Builder, assets []model.CryptoAsset) {
	type row struct {
		safety, scenario string
		count            int
	}
	order := []string{}
	rows := map[string]*row{}
	for _, a := range assets {
		fam, safety, scenario := algoFamily(a.Algorithm)
		if rows[fam] == nil {
			rows[fam] = &row{safety: safety, scenario: scenario}
			order = append(order, fam)
		}
		rows[fam].count++
	}

	b.WriteString("## 二、算法分布总览\n\n")
	if len(order) == 0 {
		b.WriteString("_当前清单为空，请先在「密码学发现」发起 Agentless 扫描。_\n\n")
		return
	}
	// 脆弱算法优先展示。
	sort.SliceStable(order, func(i, j int) bool {
		vi := strings.Contains(rows[order[i]].safety, "脆弱")
		vj := strings.Contains(rows[order[j]].safety, "脆弱")
		if vi != vj {
			return vi
		}
		return rows[order[i]].count > rows[order[j]].count
	})
	b.WriteString("| 算法 / 密钥类型 | 使用点数量 | 量子安全性 | 主要使用场景 |\n|---|---|---|---|\n")
	for _, fam := range order {
		r := rows[fam]
		fmt.Fprintf(b, "| %s | %d | %s | %s |\n", fam, r.count, r.safety, r.scenario)
	}
	b.WriteString("\n")
}

func writeLayerBreakdown(b *strings.Builder, assets []model.CryptoAsset) {
	byLayer := map[string]int{}
	labels := map[string]string{
		"L1": "L1 应用/会话层", "L2": "L2 协议/传输层",
		"L3": "L3 数据存储层", "L4": "L4 硬件/根信任层",
	}
	for _, a := range assets {
		byLayer[a.Layer]++
	}
	b.WriteString("## 三、按层级分布\n\n")
	b.WriteString("| 层级 | 资产数 |\n|---|---|\n")
	for _, l := range []string{"L1", "L2", "L3", "L4"} {
		fmt.Fprintf(b, "| %s | %d |\n", labels[l], byLayer[l])
	}
	b.WriteString("\n")
}

func writeP1Detail(b *strings.Builder, assets []model.CryptoAsset) {
	p1 := make([]model.CryptoAsset, 0)
	for _, a := range assets {
		if a.RiskLevel == "P1" {
			p1 = append(p1, a)
		}
	}
	sort.SliceStable(p1, func(i, j int) bool {
		return p1[i].RiskScore > p1[j].RiskScore
	})

	b.WriteString("## 四、P1 极高风险资产清单\n\n")
	if len(p1) == 0 {
		b.WriteString("_当前无 P1 级资产。_\n\n")
		return
	}
	b.WriteString("| 资产 | 系统 | 层级 | 算法 | 综合分 | HNDL | 建议迁移 |\n|---|---|---|---|---|---|---|\n")
	for _, a := range p1 {
		hndl := ""
		if a.HNDL {
			hndl = "是"
		}
		fmt.Fprintf(b, "| %s | %s | %s | %s | %d | %s | %s |\n",
			a.Name, a.System, a.Layer, a.Algorithm, a.RiskScore, hndl, a.SuggestedAlgo)
	}
	b.WriteString("\n")
}

func writeHNDL(b *strings.Builder, assets []model.CryptoAsset) {
	hndl := make([]model.CryptoAsset, 0)
	for _, a := range assets {
		if a.HNDL {
			hndl = append(hndl, a)
		}
	}
	sort.SliceStable(hndl, func(i, j int) bool {
		if levelOrder[hndl[i].RiskLevel] != levelOrder[hndl[j].RiskLevel] {
			return levelOrder[hndl[i].RiskLevel] < levelOrder[hndl[j].RiskLevel]
		}
		return hndl[i].RiskScore > hndl[j].RiskScore
	})

	b.WriteString("## 五、HNDL（先存后解）专项\n\n")
	b.WriteString("> 高敏感且长生命周期数据即便今日被截获，也可能在量子算力成熟后被解密，需优先处置。判定口径：数据敏感度 D2≥60 且 数据生命周期 D3≥60。\n\n")
	if len(hndl) == 0 {
		b.WriteString("_当前无 HNDL 标记资产。_\n\n")
		return
	}
	b.WriteString("| 资产 | 等级 | 综合分 | 建议迁移 |\n|---|---|---|---|\n")
	for _, a := range hndl {
		fmt.Fprintf(b, "| %s | %s | %d | %s |\n", a.Name, a.RiskLevel, a.RiskScore, a.SuggestedAlgo)
	}
	b.WriteString("\n")
}

// writeAlgoSelection 输出算法选型建议（过渡混合 → 长期目标）。
// 国密融合采 SM2+ML-KEM / SM2+ML-DSA 混合过渡（决策 DP-04）。
func writeAlgoSelection(b *strings.Builder) {
	b.WriteString("## 六、算法选型建议（过渡混合 → 长期目标）\n\n")
	b.WriteString("| 用途 | 当前算法 | 过渡期（混合） | 长期目标 |\n|---|---|---|---|\n")
	b.WriteString("| 密钥封装 | ECDH / RSA-OAEP | X25519 + ML-KEM-768 | ML-KEM-768 |\n")
	b.WriteString("| 数字签名 | ECDSA / RSA-PSS | ECDSA + ML-DSA-65 | ML-DSA-65 |\n")
	b.WriteString("| 国密融合 | SM2 / SM4 | SM2 + ML-KEM / SM2 + ML-DSA | 待国密 PQC 标准对齐 |\n")
	b.WriteString("| 对称加密 | AES-128 | 直接升级 AES-256（无混合期） | AES-256 |\n")
	b.WriteString("| 哈希 | SHA-256 / SM3 | 无需改变 | SHA-256 / SHA-384 |\n\n")
	b.WriteString("> 标准锚点：NIST FIPS 203 (ML-KEM) / 204 (ML-DSA) / 205 (SLH-DSA)；国密融合采 SM2+ML-KEM / SM2+ML-DSA 混合作为过渡方案（DP-04）。\n\n")
}

// writeMigrationBatches 输出三批迁移建议（对齐工具包迁移计划阶段划分）。
func writeMigrationBatches(b *strings.Builder) {
	b.WriteString("## 七、迁移批次建议\n\n")
	b.WriteString("- **第一批（0-6 月 · P1 立即）**：对外 TLS 启用混合 KEM（X25519+ML-KEM-768）；SSL VPN 网关下发混合 IKEv2 提议；内部根 CA 规划双签名（ML-DSA）。\n")
	b.WriteString("- **第二批（6-12 月 · P2）**：代码/固件签名迁 ML-DSA；内部 mTLS 证书更新；HSM 固件升级并验证 PQC 支持。\n")
	b.WriteString("- **第三批（12-18 月 · 常规系统）**：数据库加密、消息队列、备份归档整体迁移；第三方 SaaS 合规核查；建立密码敏捷（Crypto Agility）长效机制。\n\n")
}

func writeRecommendation(b *strings.Builder) {
	b.WriteString("## 八、处置建议\n\n")
	b.WriteString("1. **P1 资产 0-3 月内启动迁移**：优先对根 CA、VPN 网关等信任锚点采用混合（经典+后量子）方案过渡。\n")
	b.WriteString("2. **HNDL 资产优先**：长期合规档案、核心机密数据应尽快切换至 ML-KEM/ML-DSA 体系。\n")
	b.WriteString("3. **以编排外部设备为改造主线**：通过烛龙国密网关下发混合 KEM、HSM 托管混合根 CA 密钥落地改造（DP-03），平台内建能力作补充兜底。\n")
	b.WriteString("4. **建立密码敏捷能力**：协议栈引入算法可插拔，避免下一轮迁移再次硬编码。\n")
	b.WriteString("5. **持续摸底**：将发现引擎纳入常态化扫描，新增资产自动入清单并评分，CBOM 季度刷新。\n")
}
