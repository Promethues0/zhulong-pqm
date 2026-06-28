package api

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"zhulong-pqm/internal/db"
	"zhulong-pqm/internal/model"
)

// ---- 覆盖度矩阵（① 遗留，FR-3.6.1/3.6.3）----

// coverageMatrix GET /coverage：L1-L4 × M1-M7 覆盖矩阵 + 已扫/未扫统计。
//
// 计划维度（planned）：每条 ScanRule 声明的 Layer×Methods 落点；
// 实际维度（achieved）：实际产生 RuleHit 的规则按 Layer×命中 Method 聚合；
// 单元格 covered=该 Layer×Method 下有命中、planned=有规则声明、gap=声明未命中。
func (s *Server) coverageMatrix(c *gin.Context) {
	layers := []string{model.LayerL1, model.LayerL2, model.LayerL3, model.LayerL4}
	methods := []string{
		model.MethodM1ActiveTLS, model.MethodM2Passive, model.MethodM3Agent,
		model.MethodM4SBOM, model.MethodM5Cert, model.MethodM6Config, model.MethodM7Manual,
	}

	// 规则库：按 Layer×Method 统计声明落点（planned）与规则号集合。
	var rules []model.ScanRule
	s.db.Find(&rules)
	planned := map[string]map[string]int{} // layer -> method -> ruleCount
	plannedRules := map[string]map[string][]string{}
	for _, l := range layers {
		planned[l] = map[string]int{}
		plannedRules[l] = map[string][]string{}
	}
	for i := range rules {
		ms := db.UnmarshalStrings(rules[i].MethodsJSON)
		for _, m := range ms {
			if planned[rules[i].Layer] == nil {
				continue
			}
			planned[rules[i].Layer][m]++
			plannedRules[rules[i].Layer][m] = append(plannedRules[rules[i].Layer][m], rules[i].RuleID)
		}
	}

	// 实际命中：按 Layer×Method 统计命中规则号（去重）。
	var hits []model.RuleHit
	s.db.Find(&hits)
	achieved := map[string]map[string]map[string]bool{} // layer -> method -> ruleID set
	for _, l := range layers {
		achieved[l] = map[string]map[string]bool{}
	}
	for _, h := range hits {
		if achieved[h.Layer] == nil {
			continue
		}
		m := h.Method
		if m == "" {
			m = model.MethodM1ActiveTLS // 命中未带方式时按主动归类（兜底）
		}
		if achieved[h.Layer][m] == nil {
			achieved[h.Layer][m] = map[string]bool{}
		}
		achieved[h.Layer][m][h.RuleID] = true
	}

	// 组装矩阵单元格。
	type cell struct {
		Layer       string `json:"layer"`
		Method      string `json:"method"`
		PlannedRules int   `json:"plannedRules"`
		HitRules    int    `json:"hitRules"`
		Planned     bool   `json:"planned"`
		Covered     bool   `json:"covered"`
		Gap         bool   `json:"gap"` // 声明但未命中
	}
	cells := make([]cell, 0, len(layers)*len(methods))
	scannedRuleMethods, totalRuleMethods := 0, 0
	for _, l := range layers {
		for _, m := range methods {
			p := planned[l][m]
			hit := 0
			if achieved[l][m] != nil {
				hit = len(achieved[l][m])
			}
			if p > 0 {
				totalRuleMethods++
				if hit > 0 {
					scannedRuleMethods++
				}
			}
			cells = append(cells, cell{
				Layer: l, Method: m,
				PlannedRules: p, HitRules: hit,
				Planned: p > 0, Covered: hit > 0, Gap: p > 0 && hit == 0,
			})
		}
	}

	// P1/P2/P3 窗口覆盖率（按 Priority 维度统计声明 vs 命中规则号）。
	hitRuleSet := map[string]bool{}
	for _, h := range hits {
		hitRuleSet[h.RuleID] = true
	}
	priorityCov := map[string]gin.H{}
	for _, pr := range []string{model.LevelP1, model.LevelP2, model.LevelP3} {
		total, scanned := 0, 0
		uncovered := []string{}
		for i := range rules {
			if rules[i].Priority != pr {
				continue
			}
			total++
			if hitRuleSet[rules[i].RuleID] {
				scanned++
			} else {
				uncovered = append(uncovered, rules[i].RuleID)
			}
		}
		priorityCov[pr] = gin.H{"total": total, "scanned": scanned, "uncovered": uncovered}
	}

	c.JSON(http.StatusOK, gin.H{
		"layers":  layers,
		"methods": methods,
		"cells":   cells,
		"summary": gin.H{
			"plannedCells": totalRuleMethods,
			"scannedCells": scannedRuleMethods,
			"ruleCount":    len(rules),
			"hitRuleCount": len(hitRuleSet),
		},
		"priorityCoverage": priorityCov,
	})
}
