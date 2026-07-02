package api

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"zhulong-pqm/internal/db"
	"zhulong-pqm/internal/model"
	"zhulong-pqm/internal/scan"
)

// createScanReq 创建扫描任务请求体（①发现深化新增 method/scannerType/schedule/mode/rateLimit）。
type createScanReq struct {
	Name        string   `json:"name"`
	Targets     []string `json:"targets" binding:"required"`
	Exposure    string   `json:"exposure"`
	Method      string   `json:"method"`      // 默认 M1
	ScannerType string   `json:"scannerType"` // tls/ssh/ike/rdp，默认 tls
	Schedule    string   `json:"schedule"`    // cron 表达式，空=一次性
	Mode        string   `json:"mode"`        // full/incremental，默认 full
	RateLimit   int      `json:"rateLimit"`
}

// createScan 创建扫描任务并以 goroutine 异步执行。
//
// 向后兼容：不带新字段的旧请求按 M1/tls/full 行为（默认值由模型 default 与此处兜底）。
func (s *Server) createScan(c *gin.Context) {
	var req createScanReq
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "targets 必填"})
		return
	}
	if len(req.Targets) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "targets 不能为空"})
		return
	}
	if req.Exposure == "" {
		req.Exposure = model.ExposureInternal
	}
	name := req.Name
	if name == "" {
		name = "扫描任务"
	}
	if req.Method == "" {
		req.Method = model.MethodM1ActiveTLS
	}
	if req.ScannerType == "" {
		req.ScannerType = model.ScannerTLS
	}
	if req.Mode == "" {
		req.Mode = model.ModeFull
	}

	job := model.ScanJob{
		Name:            name,
		Targets:         db.MarshalTargets(req.Targets),
		Exposure:        req.Exposure,
		Status:          model.JobPending,
		Method:          req.Method,
		ScannerType:     req.ScannerType,
		Schedule:        req.Schedule,
		ScheduleEnabled: req.Schedule != "",
		Mode:            req.Mode,
		RateLimit:       req.RateLimit,
	}
	if job.Schedule != "" {
		job.NextRunAt = scan.NextCronRun(job.Schedule)
	}
	if err := s.db.Create(&job).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// 异步执行；任务自身在独立上下文中运行，避免随请求结束被取消。
	job.TargetList = req.Targets
	runner := scan.NewRunnerForJob(s.db, req.ScannerType)
	go runner.Run(context.Background(), job.ID)

	s.audit(c, "scan", "scan.create", auditTarget("ScanJob", job.ID, job.Name), model.AuditSuccess,
		fmt.Sprintf("目标数=%d 暴露面=%s 方式=%s 扫描器=%s 模式=%s", len(req.Targets), req.Exposure, req.Method, req.ScannerType, req.Mode))
	c.JSON(http.StatusCreated, job)
}

// scanResults GET /scans/:id/results：列该任务 ScanResult，每条 join 命中规则 hits。
func (s *Server) scanResults(c *gin.Context) {
	var job model.ScanJob
	if err := s.db.First(&job, c.Param("id")).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "任务不存在"})
		return
	}
	var results []model.ScanResult
	s.db.Where("scan_job_id = ?", job.ID).Order("id asc").Find(&results)
	for i := range results {
		var hits []model.RuleHit
		s.db.Where("scan_result_id = ?", results[i].ID).Order("rule_id asc").Find(&hits)
		results[i].Hits = hits
	}
	c.JSON(http.StatusOK, results)
}

// listScans 列出全部扫描任务。
func (s *Server) listScans(c *gin.Context) {
	var jobs []model.ScanJob
	if err := s.db.Order("created_at desc").Find(&jobs).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	for i := range jobs {
		jobs[i].TargetList = db.UnmarshalTargets(jobs[i].Targets)
	}
	c.JSON(http.StatusOK, jobs)
}

// getScan 返回单个任务及其结果列表。
func (s *Server) getScan(c *gin.Context) {
	var job model.ScanJob
	if err := s.db.First(&job, c.Param("id")).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "任务不存在"})
		return
	}
	job.TargetList = db.UnmarshalTargets(job.Targets)

	var results []model.ScanResult
	s.db.Where("scan_job_id = ?", job.ID).Order("id asc").Find(&results)
	s.attachHits(results)

	c.JSON(http.StatusOK, gin.H{"job": job, "results": results})
}

// attachHits 批量为一组结果加载命中规则，避免逐条查询的 N+1（一次 IN 查询 + 分组）。
func (s *Server) attachHits(results []model.ScanResult) {
	if len(results) == 0 {
		return
	}
	ids := make([]uint, len(results))
	for i := range results {
		ids[i] = results[i].ID
	}
	var hits []model.RuleHit
	s.db.Where("scan_result_id IN ?", ids).Order("rule_id asc").Find(&hits)
	byRes := make(map[uint][]model.RuleHit, len(results))
	for _, h := range hits {
		byRes[h.ScanResultID] = append(byRes[h.ScanResultID], h)
	}
	for i := range results {
		results[i].Hits = byRes[results[i].ID]
	}
}

// exportScan GET /scans/:id/export → 该扫描任务全部探测结果的 CSV
// （带 UTF-8 BOM，Excel 友好；含命中规则、失败原因，供分析/合规批量导出）。
func (s *Server) exportScan(c *gin.Context) {
	var job model.ScanJob
	if err := s.db.First(&job, c.Param("id")).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "任务不存在"})
		return
	}
	var results []model.ScanResult
	s.db.Where("scan_job_id = ?", job.ID).Order("id asc").Find(&results)
	s.attachHits(results)

	var b strings.Builder
	b.WriteString("\xEF\xBB\xBF") // UTF-8 BOM
	header := []string{"主机", "端口", "状态", "发现方式", "TLS版本", "密码套件", "密钥算法", "密钥位数", "签名算法", "证书主体", "证书指纹", "证书到期", "命中规则", "失败原因"}
	b.WriteString(strings.Join(header, ",") + "\n")

	for i := range results {
		r := &results[i]
		ruleIDs := make([]string, 0, len(r.Hits))
		for _, h := range r.Hits {
			ruleIDs = append(ruleIDs, h.RuleID)
		}
		notAfter := ""
		if r.CertNotAfter != nil {
			notAfter = r.CertNotAfter.Format("2006-01-02")
		}
		cells := []string{
			r.Host, fmt.Sprintf("%d", r.Port), r.Status, r.Method, r.TLSVersion, r.CipherSuite,
			r.KeyAlgo, fmt.Sprintf("%d", r.KeySize), r.SigAlgo, r.CertSubject, r.CertFingerprint,
			notAfter, strings.Join(ruleIDs, "|"), r.Error,
		}
		for j, cell := range cells {
			if j > 0 {
				b.WriteByte(',')
			}
			b.WriteString(csvCell(cell))
		}
		b.WriteByte('\n')
	}

	s.audit(c, "scan", "scan.export", auditTarget("ScanJob", job.ID, job.Name), model.AuditSuccess,
		fmt.Sprintf("导出结果=%d", len(results)))
	filename := fmt.Sprintf("scan-%d-%s.csv", job.ID, time.Now().Format("20060102-150405"))
	c.Header("Content-Disposition", `attachment; filename="`+filename+`"`)
	c.Data(http.StatusOK, "text/csv; charset=utf-8", []byte(b.String()))
}
