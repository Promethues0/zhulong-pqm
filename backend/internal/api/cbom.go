package api

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/gin-gonic/gin"

	"zhulong-pqm/internal/cbom"
	"zhulong-pqm/internal/model"
)

// cbomExport 导出 CycloneDX 1.6 CBOM JSON。
func (s *Server) cbomExport(c *gin.Context) {
	var assets []model.CryptoAsset
	s.db.Where("status <> ?", model.StatusMerged).Order("risk_score desc").Find(&assets)

	bom := cbom.Build(assets)
	s.audit(c, "cbom", "cbom.export", auditTargetStr("CBOM", "zhulong-pqm-cbom.json", "CBOM 导出"), model.AuditSuccess,
		fmt.Sprintf("资产数=%d", len(assets)))
	c.Header("Content-Disposition", `attachment; filename="zhulong-pqm-cbom.json"`)
	c.JSON(http.StatusOK, bom)
}

// cbomImport POST /assets/import/cbom：解析 CycloneDX 1.6 CBOM → 逐组件经 fingerprint 归一并入（FR-4.8）。
//
// 命中既有 CUP 则补证据（不重复建实体），未命中则新建 source=import；非 1.6/非 CycloneDX 返回字段级错误。
// 响应 {imported, merged, skipped, errors}。
func (s *Server) cbomImport(c *gin.Context) {
	var raw []byte
	if file, err := c.FormFile("file"); err == nil {
		f, oErr := file.Open()
		if oErr != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "无法读取上传文件"})
			return
		}
		defer f.Close()
		raw, _ = io.ReadAll(io.LimitReader(f, 16<<20))
	} else {
		raw, _ = io.ReadAll(io.LimitReader(c.Request.Body, 16<<20))
	}
	if len(raw) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "CBOM JSON 必填"})
		return
	}

	bom, err := cbom.Parse(raw)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	imported, merged, skipped := 0, 0, 0
	errs := []string{}
	for _, comp := range bom.Components {
		incoming, ok := cbom.ComponentToAsset(comp)
		if !ok {
			skipped++
			continue
		}
		if incoming.Name == "" {
			skipped++
			continue
		}
		fp := assetFingerprint(&incoming)
		rawComp, _ := json.Marshal(comp)

		if existing, found := s.loadAssetByFingerprint(fp); found {
			// 命中既有 CUP：补证据，不重复建实体。
			s.ensureEvidenceOnce(existing.ID, model.EvidenceImportCBOM, "", string(rawComp), model.ConfMedium)
			existing.Version++
			s.db.Save(existing)
			merged++
			continue
		}

		// 未命中：新建实体并补证据 + 重算评分。
		incoming.Source = model.SourceImport
		if incoming.Status == "" {
			incoming.Status = model.StatusDiscovered
		}
		if incoming.Confidence == 0 {
			incoming.Confidence = 80
		}
		s.recompute(&incoming)
		if cErr := s.db.Create(&incoming).Error; cErr != nil {
			errs = append(errs, fmt.Sprintf("%s: %s", incoming.Name, cErr.Error()))
			continue
		}
		s.ensureEvidenceOnce(incoming.ID, model.EvidenceImportCBOM, "", string(rawComp), model.ConfMedium)
		imported++
	}

	s.audit(c, "cbom", "cbom.import", auditTargetStr("CBOM", "import", "CBOM 反向导入"), model.AuditSuccess,
		fmt.Sprintf("新建=%d 并入=%d 跳过=%d", imported, merged, skipped))
	c.JSON(http.StatusOK, gin.H{
		"imported": imported,
		"merged":   merged,
		"skipped":  skipped,
		"errors":   errs,
	})
}
