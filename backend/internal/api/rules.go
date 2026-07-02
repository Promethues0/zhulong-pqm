package api

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"zhulong-pqm/internal/db"
	"zhulong-pqm/internal/model"
)

// listRules GET /rules：列规则库，支持 layer/risk/enabled/method/priority 过滤，
// 响应带统计头 {total, p1High, critical, byLayer}（FR-3.4.1）。
func (s *Server) listRules(c *gin.Context) {
	q := s.db.Model(&model.ScanRule{})
	if v := c.Query("layer"); v != "" {
		q = q.Where("layer = ?", v)
	}
	if v := c.Query("risk"); v != "" {
		q = q.Where("risk_hint = ?", v)
	}
	if v := c.Query("priority"); v != "" {
		q = q.Where("priority = ?", v)
	}
	if v := c.Query("enabled"); v != "" {
		q = q.Where("enabled = ?", v == "true" || v == "1")
	}

	var rules []model.ScanRule
	if err := q.Order("rule_id asc").Find(&rules).Error; err != nil {
		serverError(c, err)
		return
	}
	// method 过滤需反序列化 Methods JSON 后内存过滤。
	method := c.Query("method")
	out := make([]model.ScanRule, 0, len(rules))
	for i := range rules {
		rules[i].Methods = db.UnmarshalStrings(rules[i].MethodsJSON)
		if method != "" && !containsStr(rules[i].Methods, method) {
			continue
		}
		out = append(out, rules[i])
	}

	c.JSON(http.StatusOK, gin.H{
		"stats": s.ruleStats(),
		"items": out,
	})
}

// ruleStats 计算规则库统计头（基于全量内置+自定义；total=30 内置时）。
func (s *Server) ruleStats() gin.H {
	var total, p1, critical int64
	s.db.Model(&model.ScanRule{}).Count(&total)
	s.db.Model(&model.ScanRule{}).Where("priority = ?", model.LevelP1).Count(&p1)
	s.db.Model(&model.ScanRule{}).Where("risk_hint = ?", model.RiskHintCritical).Count(&critical)

	byLayer := gin.H{}
	for _, l := range []string{model.LayerL1, model.LayerL2, model.LayerL3, model.LayerL4} {
		var n int64
		s.db.Model(&model.ScanRule{}).Where("layer = ?", l).Count(&n)
		byLayer[l] = n
	}
	return gin.H{"total": total, "p1High": p1, "critical": critical, "byLayer": byLayer}
}

// getRule GET /rules/:ruleId 单条规则详情。
func (s *Server) getRule(c *gin.Context) {
	var rule model.ScanRule
	if err := s.db.Where("rule_id = ?", c.Param("ruleId")).First(&rule).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "规则不存在"})
		return
	}
	rule.Methods = db.UnmarshalStrings(rule.MethodsJSON)
	c.JSON(http.StatusOK, rule)
}

// updateRuleReq 更新规则请求体（内置仅 enabled 生效，自定义可全字段）。
type updateRuleReq struct {
	Enabled     *bool    `json:"enabled"`
	CheckItem   *string  `json:"checkItem"`
	AlgoFeature *string  `json:"algoFeature"`
	Tools       *string  `json:"tools"`
	RiskHint    *string  `json:"riskHint"`
	Priority    *string  `json:"priority"`
	Methods     []string `json:"methods"`
}

// updateRule PUT /rules/:ruleId：内置仅允许改 enabled；自定义可改全字段。
func (s *Server) updateRule(c *gin.Context) {
	var rule model.ScanRule
	if err := s.db.Where("rule_id = ?", c.Param("ruleId")).First(&rule).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "规则不存在"})
		return
	}
	var req updateRuleReq
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if req.Enabled != nil {
		rule.Enabled = *req.Enabled
	}
	if !rule.Builtin {
		// 自定义规则可改全字段。
		if req.CheckItem != nil {
			rule.CheckItem = *req.CheckItem
		}
		if req.AlgoFeature != nil {
			rule.AlgoFeature = *req.AlgoFeature
		}
		if req.Tools != nil {
			rule.Tools = *req.Tools
		}
		if req.RiskHint != nil {
			rule.RiskHint = *req.RiskHint
		}
		if req.Priority != nil {
			rule.Priority = *req.Priority
		}
		if req.Methods != nil {
			rule.MethodsJSON = db.MarshalStrings(req.Methods)
		}
	}
	if err := s.db.Save(&rule).Error; err != nil {
		s.audit(c, "rule", "rule.update", auditTargetStr("ScanRule", rule.RuleID, rule.CheckItem), model.AuditFailure, err.Error())
		serverError(c, err)
		return
	}
	rule.Methods = db.UnmarshalStrings(rule.MethodsJSON)
	s.audit(c, "rule", "rule.update", auditTargetStr("ScanRule", rule.RuleID, rule.CheckItem), model.AuditSuccess,
		"enabled="+boolStr(rule.Enabled))
	c.JSON(http.StatusOK, rule)
}

// createRuleReq 新增自定义规则请求体。
type createRuleReq struct {
	RuleID      string   `json:"ruleId" binding:"required"`
	CheckItem   string   `json:"checkItem" binding:"required"`
	Layer       string   `json:"layer" binding:"required"`
	AlgoFeature string   `json:"algoFeature"`
	Tools       string   `json:"tools"`
	RiskHint    string   `json:"riskHint"`
	Confidence  string   `json:"baseConfidence"`
	Priority    string   `json:"priority"`
	Methods     []string `json:"methods"`
}

// createRule POST /rules：新增自定义规则（Builtin=false）。
func (s *Server) createRule(c *gin.Context) {
	var req createRuleReq
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if !validLayer(req.Layer) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "layer 须为 L1/L2/L3/L4"})
		return
	}
	var exist int64
	s.db.Model(&model.ScanRule{}).Where("rule_id = ?", req.RuleID).Count(&exist)
	if exist > 0 {
		c.JSON(http.StatusConflict, gin.H{"error": "规则号已存在"})
		return
	}
	if req.RiskHint == "" {
		req.RiskHint = model.RiskHintMedium
	}
	if req.Confidence == "" {
		req.Confidence = model.ConfMedium
	}
	if req.Priority == "" {
		req.Priority = model.LevelP3
	}
	rule := model.ScanRule{
		RuleID:         req.RuleID,
		CheckItem:      req.CheckItem,
		Layer:          req.Layer,
		AlgoFeature:    req.AlgoFeature,
		Tools:          req.Tools,
		RiskHint:       req.RiskHint,
		BaseConfidence: req.Confidence,
		MethodsJSON:    db.MarshalStrings(req.Methods),
		Priority:       req.Priority,
		Builtin:        false,
		Enabled:        true,
	}
	if err := s.db.Create(&rule).Error; err != nil {
		serverError(c, err)
		return
	}
	rule.Methods = db.UnmarshalStrings(rule.MethodsJSON)
	s.audit(c, "rule", "rule.create", auditTargetStr("ScanRule", rule.RuleID, rule.CheckItem), model.AuditSuccess, "")
	c.JSON(http.StatusCreated, rule)
}

// deleteRule DELETE /rules/:ruleId：内置规则禁删返回 409；自定义可删（FR-3.4.3）。
func (s *Server) deleteRule(c *gin.Context) {
	var rule model.ScanRule
	if err := s.db.Where("rule_id = ?", c.Param("ruleId")).First(&rule).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "规则不存在"})
		return
	}
	if rule.Builtin {
		s.audit(c, "rule", "rule.delete", auditTargetStr("ScanRule", rule.RuleID, rule.CheckItem), model.AuditDenied, "内置规则不可删除")
		c.JSON(http.StatusConflict, gin.H{"error": "内置规则只可禁用不可删除"})
		return
	}
	if err := s.db.Delete(&model.ScanRule{}, rule.ID).Error; err != nil {
		serverError(c, err)
		return
	}
	s.audit(c, "rule", "rule.delete", auditTargetStr("ScanRule", rule.RuleID, rule.CheckItem), model.AuditSuccess, "")
	c.JSON(http.StatusOK, gin.H{"deleted": true})
}

// ---- 小工具 ----

func containsStr(ss []string, v string) bool {
	for _, s := range ss {
		if s == v {
			return true
		}
	}
	return false
}

func validLayer(l string) bool {
	switch l {
	case model.LayerL1, model.LayerL2, model.LayerL3, model.LayerL4:
		return true
	}
	return false
}

func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}
