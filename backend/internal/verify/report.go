package verify

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"

	"zhulong-pqm/internal/model"
)

// catLabel 类别中文名（报告分段标题用）。
var catLabel = map[string]string{
	model.CatProto:  "协议层",
	model.CatCompat: "兼容性",
	model.CatPerf:   "性能基准",
	model.CatSec:    "安全验证",
	model.CatKeymat: "混合密钥材料溯源",
}

// verdictLabel 判定中文名。
var verdictLabel = map[string]string{
	model.VerdictPass:        "通过",
	model.VerdictConditional: "有条件通过",
	model.VerdictFail:        "未通过",
	model.VerdictSkip:        "跳过",
}

// evidencedLabel 证据来源中文名（诚实标注）。
var evidencedLabel = map[string]string{
	model.EvProbe:     "实测",
	model.EvSimulated: "模拟",
}

// GenerateReport 由一次验收执行与其逐项结果生成验收报告（标题 + Markdown + SHA-256）。
//
// 8 段对齐工具包文件4：① 验收总览 ② 协议层逐项 ③ 兼容性矩阵 ④ 性能基准与阈值门
// ⑤ 安全验证四向量 ⑥ 混合密钥材料溯源 ⑦ 遗留风险登记关联 ⑧ 签署区。
// risks 为台账（R-001…），用于第 ⑦ 段关联展示有条件项挂接的遗留风险。
func GenerateReport(run model.AcceptanceRun, results []model.TestResult, risks []model.LegacyRisk) (title, markdown, hash string) {
	now := time.Now().Format("2006-01-02 15:04")
	scope := run.AssetName
	if scope == "" {
		scope = run.TrackName
	}
	if scope == "" {
		scope = "全域"
	}
	title = fmt.Sprintf("烛龙 PQM 后量子改造验收报告（%s · %s）", scope, now)

	var b strings.Builder
	fmt.Fprintf(&b, "# %s\n\n", title)
	gateText := "未达标 ✗"
	concl := "未通过验收"
	if run.GatePass {
		gateText = "达标 ✓"
		concl = "通过验收"
	}
	modeText := "真实探测(probe)"
	if run.Mode == model.ModeSimulate {
		modeText = "模拟(simulate)·基线期望值"
	}
	fmt.Fprintf(&b, "> 生成时间：%s　轨道：%s　执行模式：%s　基准：NIST FIPS 203/204/205\n\n",
		now, run.TrackName, modeText)

	// ① 验收总览
	b.WriteString("## 一、验收总览\n\n")
	fmt.Fprintf(&b, "- **验收结论：%s**（Gate %s）\n", concl, gateText)
	fmt.Fprintf(&b, "- 测试总项：**%d**（基线 %d）\n", run.Total, BaselineTotal)
	fmt.Fprintf(&b, "- 通过 **%d** / 有条件通过 **%d** / 未通过 **%d**\n", run.Passed, run.Conditional, run.Failed)
	fmt.Fprintf(&b, "- P1 资产覆盖率：**%d/%d**\n", run.P1Covered, run.P1Total)
	fmt.Fprintf(&b, "- Gate 口径：Failed==0 且 Passed+Conditional==Total 且 Passed ≥ ⌊Total×44/47⌋=%d 且 所有有条件项均挂遗留风险\n\n",
		run.Total*44/47)
	if run.Mode == model.ModeSimulate {
		b.WriteString("> 注：本次为模拟态验收，标「模拟」的逐项为工具包基线期望值（非真实探测），用于离线演示与回归基线，诚实标注以免误读。\n\n")
	}

	// ②-⑥ 分类逐项表
	writeCategorySection(&b, "二、协议层验证", model.CatProto, results)
	writeCategorySection(&b, "三、兼容性矩阵", model.CatCompat, results)
	writePerfSection(&b, results)
	writeCategorySection(&b, "五、安全验证（降级攻击四向量）", model.CatSec, results)
	writeCategorySection(&b, "六、混合密钥材料溯源", model.CatKeymat, results)

	// ⑦ 遗留风险登记关联
	writeRiskSection(&b, results, risks)

	// ⑧ 签署区
	writeSignSection(&b, run)

	markdown = b.String()
	sum := sha256.Sum256([]byte(markdown))
	hash = hex.EncodeToString(sum[:])
	return title, markdown, hash
}

// writeCategorySection 输出某类别逐项表（用例号/名称/期望/实测/判定/证据来源/挂接风险）。
func writeCategorySection(b *strings.Builder, heading, cat string, results []model.TestResult) {
	rows := filterByCat(results, cat)
	fmt.Fprintf(b, "## %s\n\n", heading)
	if len(rows) == 0 {
		fmt.Fprintf(b, "_本轨道无 %s 用例。_\n\n", catLabel[cat])
		return
	}
	b.WriteString("| 用例 | 名称 | 期望 | 实测/模拟 | 判定 | 证据 | 挂接风险 |\n|---|---|---|---|---|---|---|\n")
	for _, tr := range rows {
		fmt.Fprintf(b, "| %s | %s | %s | %s | %s | %s | %s |\n",
			tr.Code, tr.Name, mdCell(tr.Expect), mdCell(tr.Actual),
			verdictLabel[tr.Verdict], evidencedLabel[tr.Evidenced], dash(tr.RiskRef))
	}
	b.WriteString("\n")
}

// writePerfSection 输出性能基准与阈值门（含实测毫秒）。
func writePerfSection(b *strings.Builder, results []model.TestResult) {
	rows := filterByCat(results, model.CatPerf)
	b.WriteString("## 四、性能基准与阈值门\n\n")
	if len(rows) == 0 {
		b.WriteString("_本轨道无性能用例。_\n\n")
		return
	}
	b.WriteString("> 阈值门：握手延迟增量 < 15ms · p99 ≤ 46.2ms · 吞吐降幅 ≤ 6.5% · IKEv2 ≤ 437ms。\n\n")
	b.WriteString("| 用例 | 指标 | 实测/模拟 | 实测(ms) | 判定 | 证据 | 挂接风险 |\n|---|---|---|---|---|---|---|\n")
	for _, tr := range rows {
		fmt.Fprintf(b, "| %s | %s | %s | %d | %s | %s | %s |\n",
			tr.Code, tr.Name, mdCell(tr.Actual), tr.MeasuredMs,
			verdictLabel[tr.Verdict], evidencedLabel[tr.Evidenced], dash(tr.RiskRef))
	}
	b.WriteString("\n")
}

// writeRiskSection 输出遗留风险登记关联：列出有条件项挂接的 R-00x 及其台账详情。
func writeRiskSection(b *strings.Builder, results []model.TestResult, risks []model.LegacyRisk) {
	b.WriteString("## 七、遗留风险登记关联\n\n")
	// 收集本次有条件项引用的风险编号。
	refSet := map[string]bool{}
	for _, tr := range results {
		if tr.Verdict == model.VerdictConditional && tr.RiskRef != "" {
			refSet[tr.RiskRef] = true
		}
	}
	if len(refSet) == 0 {
		b.WriteString("_本次验收无有条件项，无需关联遗留风险。_\n\n")
		return
	}
	byCode := map[string]model.LegacyRisk{}
	for _, r := range risks {
		byCode[r.Code] = r
	}
	codes := make([]string, 0, len(refSet))
	for c := range refSet {
		codes = append(codes, c)
	}
	sort.Strings(codes)

	b.WriteString("> 下列遗留风险已与本次验收的有条件通过项绑定，须持续跟踪至闭合（⑤ 监测台账复用）。\n\n")
	b.WriteString("| 编号 | 风险描述 | 等级 | 处置路径 | 状态 |\n|---|---|---|---|---|\n")
	for _, c := range codes {
		if r, ok := byCode[c]; ok {
			fmt.Fprintf(b, "| %s | %s | %s | %s | %s |\n",
				r.Code, mdCell(r.Description), r.Level, mdCell(r.Disposition), r.Status)
		} else {
			fmt.Fprintf(b, "| %s | （台账未登记，请在监测台账补录） | — | — | — |\n", c)
		}
	}
	b.WriteString("\n")
}

// writeSignSection 输出签署区（状态/哈希/评审人/签署人）。
func writeSignSection(b *strings.Builder, run model.AcceptanceRun) {
	b.WriteString("## 八、验收签署\n\n")
	b.WriteString("| 角色 | 账号 | 状态 |\n|---|---|---|\n")
	b.WriteString("| 技术验收负责人（安全团队） | _______________ | 待签 |\n")
	b.WriteString("| DevSecOps 负责人 | _______________ | 待签 |\n")
	b.WriteString("| 合规 / 风险管理负责人 | _______________ | 待签 |\n")
	b.WriteString("| CISO（最终批准） | _______________ | 待签 |\n\n")
	b.WriteString("> 签署状态机：DRAFT → UNDER_REVIEW → SIGNED/REJECTED。报告哈希(SHA-256)在生成时锁定，签署后写入审计。\n")
	b.WriteString("> 仅当 Gate 达标且全部有条件项已挂遗留风险时方可签署；签署后关联资产置「已验收(verified)」。\n\n")
}

// ---- 小工具 ----

func filterByCat(results []model.TestResult, cat string) []model.TestResult {
	out := make([]model.TestResult, 0)
	for _, tr := range results {
		if tr.Category == cat {
			out = append(out, tr)
		}
	}
	return out
}

// mdCell 转义表格单元格中的竖线与换行。
func mdCell(s string) string {
	s = strings.ReplaceAll(s, "|", "\\|")
	s = strings.ReplaceAll(s, "\n", " ")
	if s == "" {
		return "—"
	}
	return s
}

func dash(s string) string {
	if s == "" {
		return "—"
	}
	return s
}
