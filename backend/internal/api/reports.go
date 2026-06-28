package api

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"zhulong-pqm/internal/model"
	"zhulong-pqm/internal/report"
)

// createReportReq 生成报告请求体。
type createReportReq struct {
	Scope string `json:"scope"`
}

// createReport 生成摸底报告并落库。scope 为可选范围（按系统过滤）。
func (s *Server) createReport(c *gin.Context) {
	var req createReportReq
	_ = c.ShouldBindJSON(&req) // scope 可空

	q := s.db.Model(&model.CryptoAsset{})
	if req.Scope != "" {
		q = q.Where("system = ?", req.Scope)
	}
	var assets []model.CryptoAsset
	q.Order("risk_score desc").Find(&assets)

	title, md := report.Generate(assets, req.Scope)
	rep := model.Report{Title: title, Scope: req.Scope, Markdown: md}
	if err := s.db.Create(&rep).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	s.audit(c, "report", "report.create", auditTarget("Report", rep.ID, rep.Title), model.AuditSuccess, "范围="+req.Scope)
	c.JSON(http.StatusCreated, gin.H{"id": rep.ID, "title": rep.Title, "markdown": rep.Markdown})
}

// listReports 列出报告（不含正文，减小体积）。
func (s *Server) listReports(c *gin.Context) {
	var reports []model.Report
	s.db.Select("id", "title", "scope", "created_at").Order("created_at desc").Find(&reports)
	c.JSON(http.StatusOK, reports)
}

// getReport 返回单份报告全文。
func (s *Server) getReport(c *gin.Context) {
	var rep model.Report
	if err := s.db.First(&rep, c.Param("id")).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "报告不存在"})
		return
	}
	c.JSON(http.StatusOK, rep)
}
