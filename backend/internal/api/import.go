package api

import (
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"

	"zhulong-pqm/internal/db"
	"zhulong-pqm/internal/model"
	"zhulong-pqm/internal/scan"
)

// importPemReq 证书导入请求体（粘贴 PEM 或 multipart 上传）。
type importPemReq struct {
	Name     string `json:"name"`
	PEM      string `json:"pem"`
	Exposure string `json:"exposure"`
}

// importPcap POST /assets/import/pcap：M2 被动流量发现。
//
// 上传 classic .pcap 抓包（span/tap 镜像或 tcpdump -w），解析其中 TLS 握手，
// 按服务端 endpoint 归并出密码学资产（协议版本/协商套件/认证算法/证书），
// 走 ImportPassive（按 endpoint 去重）落库，Method=M2。纯 Go 解析，无 CGO。
func (s *Server) importPcap(c *gin.Context) {
	file, err := c.FormFile("file")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "请上传 pcap 抓包文件（表单字段 file）"})
		return
	}
	f, oErr := file.Open()
	if oErr != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "无法读取上传文件"})
		return
	}
	defer f.Close()
	data, _ := io.ReadAll(io.LimitReader(f, 64<<20)) // 64MB 上限

	obs, stats, err := scan.ParsePCAP(data)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	exposure := model.ExposureInternal
	if e := c.PostForm("exposure"); e != "" {
		exposure = e
	}
	name := "被动流量导入"
	if n := c.PostForm("name"); n != "" {
		name = n
	}

	job := model.ScanJob{
		Name:        name,
		Targets:     db.MarshalTargets([]string{}),
		Exposure:    exposure,
		Status:      model.JobRunning,
		Method:      model.MethodM2Passive,
		ScannerType: "passive",
	}
	now := time.Now()
	job.StartedAt = &now
	s.db.Create(&job)

	runner := scan.NewRunner(s.db, nil)
	results := make([]model.ScanResult, 0, len(obs))
	for i := range obs {
		o := obs[i]
		res := &model.ScanResult{
			Host:            o.Host,
			Port:            o.Port,
			TLSVersion:      o.Version,
			CipherSuite:     o.Cipher,
			KeyAlgo:         o.Algo,
			KeySize:         o.KeySize,
			KexGroup:        o.KexGroup,
			KexSafety:       o.KexSafety,
			CertFingerprint: o.CertFP,
			CertSubject:     firstNonEmpty(o.SNI, o.Subject),
			Method:          model.MethodM2Passive,
			Source:          model.SourceImport,
		}
		candidates := scan.MatchRules(res, model.MethodM2Passive)
		saved := runner.ImportPassive(job.ID, res, candidates, exposure)
		var hits []model.RuleHit
		s.db.Where("scan_result_id = ?", saved.ID).Order("rule_id asc").Find(&hits)
		saved.Hits = hits
		results = append(results, *saved)
	}
	job.Status = model.JobDone
	job.ResultCount = len(results)
	fin := time.Now()
	job.FinishedAt = &fin
	s.db.Save(&job)

	s.audit(c, "scan", "scan.import.pcap", auditTarget("ScanJob", job.ID, job.Name), model.AuditSuccess,
		fmt.Sprintf("包=%d TLS握手=%d 端点=%d 入库=%d", stats.Packets, stats.Handshakes, stats.Endpoints, len(results)))
	c.JSON(http.StatusCreated, gin.H{"job": job, "results": results, "stats": stats})
}

// firstNonEmpty 返回首个非空串。
func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// importPem POST /assets/import/pem：解析 PEM → x509 → 命中 R-L2-01/02 → 建资产（M5）。
//
// 支持 JSON body {name,pem} 或 multipart 上传 file（.pem/.crt）。
func (s *Server) importPem(c *gin.Context) {
	var req importPemReq
	pemText := ""
	exposure := model.ExposureInternal
	name := "证书导入"

	// multipart 上传优先。
	if file, err := c.FormFile("file"); err == nil {
		f, oErr := file.Open()
		if oErr != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "无法读取上传文件"})
			return
		}
		defer f.Close()
		b, _ := io.ReadAll(io.LimitReader(f, 4<<20)) // 4MB 上限
		pemText = string(b)
		if n := c.PostForm("name"); n != "" {
			name = n
		}
		if e := c.PostForm("exposure"); e != "" {
			exposure = e
		}
	} else if err := c.ShouldBindJSON(&req); err == nil {
		pemText = req.PEM
		if req.Name != "" {
			name = req.Name
		}
		if req.Exposure != "" {
			exposure = req.Exposure
		}
	}

	if pemText == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "pem 文本或上传文件必填"})
		return
	}

	parsed, err := scan.ParsePEMCerts(pemText)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	job := model.ScanJob{
		Name:     name,
		Targets:  db.MarshalTargets([]string{}),
		Exposure: exposure,
		Status:   model.JobRunning,
		Method:   "import-pem",
		ScannerType: "import",
	}
	now := time.Now()
	job.StartedAt = &now
	s.db.Create(&job)

	runner := scan.NewRunner(s.db, nil)
	results := make([]model.ScanResult, 0, len(parsed))
	for _, p := range parsed {
		res := runner.ImportResult(job.ID, p.Result, p.Hits(), exposure)
		var hits []model.RuleHit
		s.db.Where("scan_result_id = ?", res.ID).Order("rule_id asc").Find(&hits)
		res.Hits = hits
		results = append(results, *res)
	}
	job.Status = model.JobDone
	job.ResultCount = len(results)
	fin := time.Now()
	job.FinishedAt = &fin
	s.db.Save(&job)

	s.audit(c, "scan", "scan.import.pem", auditTarget("ScanJob", job.ID, job.Name), model.AuditSuccess,
		fmt.Sprintf("解析证书=%d", len(results)))
	c.JSON(http.StatusCreated, gin.H{"job": job, "results": results})
}

// importSbomReq SBOM 导入请求体。
type importSbomReq struct {
	Name     string          `json:"name"`
	SBOM     interface{}     `json:"sbom"`     // 直接内嵌的 CycloneDX/Syft JSON
	SBOMText string          `json:"sbomText"` // 或文本形式
}

// importSbom POST /assets/import/sbom：解析 CycloneDX/Syft JSON → 提取密码库 → 命中 R-L4-01/05（M4）。
func (s *Server) importSbom(c *gin.Context) {
	var raw []byte
	name := "SBOM 导入"

	if file, err := c.FormFile("file"); err == nil {
		f, oErr := file.Open()
		if oErr != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "无法读取上传文件"})
			return
		}
		defer f.Close()
		raw, _ = io.ReadAll(io.LimitReader(f, 8<<20))
		if n := c.PostForm("name"); n != "" {
			name = n
		}
	} else {
		body, _ := io.ReadAll(io.LimitReader(c.Request.Body, 8<<20))
		raw = body
	}

	if len(raw) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "sbom JSON 必填"})
		return
	}

	comps, err := scan.ParseSBOM(raw)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	job := model.ScanJob{
		Name:        name,
		Targets:     db.MarshalTargets([]string{}),
		Exposure:    model.ExposureInternal,
		Status:      model.JobRunning,
		Method:      "import-sbom",
		ScannerType: "import",
	}
	now := time.Now()
	job.StartedAt = &now
	s.db.Create(&job)

	runner := scan.NewRunner(s.db, nil)
	results := make([]model.ScanResult, 0, len(comps))
	for _, comp := range comps {
		res := &model.ScanResult{
			Host:             "",
			Port:             0,
			KeyAlgo:          comp.Name,
			Method:           model.MethodM4SBOM,
			Source:           model.SourceImport,
			AssetFingerprint: scan.AssetFingerprint("", 0, "sbom:"+comp.Name, comp.Name+"@"+comp.Version),
			Raw:              fmt.Sprintf(`{"lib":%q,"version":%q,"supportsMLKEM":%t}`, comp.Name, comp.Version, comp.SupportsMLKEM),
		}
		res.CertSubject = comp.Name + " " + comp.Version
		saved := runner.ImportResult(job.ID, res, comp.SBOMHits(), model.ExposureInternal)
		var hits []model.RuleHit
		s.db.Where("scan_result_id = ?", saved.ID).Order("rule_id asc").Find(&hits)
		saved.Hits = hits
		results = append(results, *saved)
	}
	job.Status = model.JobDone
	job.ResultCount = len(results)
	fin := time.Now()
	job.FinishedAt = &fin
	s.db.Save(&job)

	s.audit(c, "scan", "scan.import.sbom", auditTarget("ScanJob", job.ID, job.Name), model.AuditSuccess,
		fmt.Sprintf("识别密码库=%d", len(results)))
	c.JSON(http.StatusCreated, gin.H{"job": job, "results": results})
}
