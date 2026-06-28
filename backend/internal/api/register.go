package api

import (
	"bytes"
	"encoding/csv"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"zhulong-pqm/internal/model"
)

// ---- ③ 评估深化：风险登记册 + CSV 导出 ----

// RegisterRow 风险登记册一行：CryptoAsset 投影 + 关联最近一条 ScoreHistory.CreatedAt 作 lastScoredAt。
type RegisterRow struct {
	ID            uint       `json:"id"`
	Name          string     `json:"name"`
	System        string     `json:"system"`
	Layer         string     `json:"layer"`
	Department    string     `json:"department"`
	Owner         string     `json:"owner"`
	Algorithm     string     `json:"algorithm"`
	D1            int        `json:"d1"`
	D2            int        `json:"d2"`
	D3            int        `json:"d3"`
	D4            int        `json:"d4"`
	D5            int        `json:"d5"`
	RiskScore     int        `json:"riskScore"`
	RiskLevel     string     `json:"riskLevel"`
	RiskLevelText string     `json:"riskLevelText"`
	HNDL          bool       `json:"hndl"`
	SuggestedAlgo string     `json:"suggestedAlgo"`
	MigrateWindow string     `json:"migrateWindow"`
	LastScoredAt  *time.Time `json:"lastScoredAt"`
}

// migrateWindow 据等级回填迁移窗口文案（与 scoring.classify 口径一致）。
func migrateWindow(level string) string {
	switch level {
	case model.LevelP1:
		return "0-3月"
	case model.LevelP2:
		return "3-6月"
	case model.LevelP3:
		return "6-12月"
	default:
		return "持续监控"
	}
}

// registerQuery 据查询参数构建风险登记册资产查询（复用 listAssets 过滤风格）。
func (s *Server) registerQuery(c *gin.Context) ([]model.CryptoAsset, error) {
	q := s.db.Model(&model.CryptoAsset{})
	// 登记册聚焦在册资产，排除已合并终态。
	q = q.Where("status <> ?", model.StatusMerged)

	if v := c.Query("level"); v != "" {
		q = q.Where("risk_level = ?", v)
	}
	if v := c.Query("hndl"); v == "true" || v == "1" {
		q = q.Where("hndl = ?", true)
	}
	if v := c.Query("layer"); v != "" {
		q = q.Where("layer = ?", v)
	}
	if v := c.Query("system"); v != "" {
		q = q.Where("system = ?", v)
	}
	if v := c.Query("department"); v != "" {
		q = q.Where("department = ?", v)
	}
	if v := strings.TrimSpace(c.Query("q")); v != "" {
		like := "%" + v + "%"
		q = q.Where("name LIKE ? OR system LIKE ? OR algorithm LIKE ? OR endpoint LIKE ?",
			like, like, like, like)
	}

	sort := c.DefaultQuery("sort", "risk_score desc")
	// 白名单排序键，避免注入。
	switch sort {
	case "risk_score desc", "risk_score asc", "name asc", "layer asc", "created_at desc":
	default:
		sort = "risk_score desc"
	}

	var assets []model.CryptoAsset
	if err := q.Order(sort).Find(&assets).Error; err != nil {
		return nil, err
	}
	return assets, nil
}

// lastScoredMap 批量取这批资产各自最近一条 ScoreHistory.CreatedAt。
func (s *Server) lastScoredMap(ids []uint) map[uint]time.Time {
	out := map[uint]time.Time{}
	if len(ids) == 0 {
		return out
	}
	var rows []model.ScoreHistory
	s.db.Where("asset_id IN ?", ids).Order("created_at desc").Find(&rows)
	for _, r := range rows {
		if _, ok := out[r.AssetID]; !ok {
			out[r.AssetID] = r.CreatedAt
		}
	}
	return out
}

func (s *Server) buildRegisterRows(assets []model.CryptoAsset) []RegisterRow {
	ids := make([]uint, 0, len(assets))
	for _, a := range assets {
		ids = append(ids, a.ID)
	}
	scored := s.lastScoredMap(ids)
	rows := make([]RegisterRow, 0, len(assets))
	for _, a := range assets {
		var last *time.Time
		if t, ok := scored[a.ID]; ok {
			tt := t
			last = &tt
		}
		rows = append(rows, RegisterRow{
			ID:            a.ID,
			Name:          a.Name,
			System:        a.System,
			Layer:         a.Layer,
			Department:    a.Department,
			Owner:         a.Owner,
			Algorithm:     a.Algorithm,
			D1:            a.D1, D2: a.D2, D3: a.D3, D4: a.D4, D5: a.D5,
			RiskScore:     a.RiskScore,
			RiskLevel:     a.RiskLevel,
			RiskLevelText: a.RiskLevelText,
			HNDL:          a.HNDL,
			SuggestedAlgo: a.SuggestedAlgo,
			MigrateWindow: migrateWindow(a.RiskLevel),
			LastScoredAt:  last,
		})
	}
	return rows
}

// riskRegister GET /score/register → 风险登记册行集（可按 level/hndl/layer/system/department/q 筛选）。
// ?format=csv → 返回 text/csv 附件。
func (s *Server) riskRegister(c *gin.Context) {
	assets, err := s.registerQuery(c)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	rows := s.buildRegisterRows(assets)

	if c.Query("format") == "csv" {
		s.writeRegisterCSV(c, rows)
		return
	}
	c.JSON(http.StatusOK, rows)
}

// exportRegister GET /score/register/export → 始终 CSV 附件（带 BOM 头，列齐全）。
func (s *Server) exportRegister(c *gin.Context) {
	assets, err := s.registerQuery(c)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	rows := s.buildRegisterRows(assets)
	s.writeRegisterCSV(c, rows)
}

// writeRegisterCSV 输出风险登记册 CSV（UTF-8 BOM 头确保 Excel 中文不乱码）。
func (s *Server) writeRegisterCSV(c *gin.Context, rows []RegisterRow) {
	var buf bytes.Buffer
	buf.WriteString("\ufeff") // UTF-8 BOM，Excel 中文兼容
	w := csv.NewWriter(&buf)
	_ = w.Write([]string{
		"资产", "系统", "层级", "部门", "责任人", "算法",
		"D1", "D2", "D3", "D4", "D5", "综合分", "等级", "等级描述",
		"HNDL", "建议算法", "迁移窗口", "最近评分时间",
	})
	for _, r := range rows {
		last := ""
		if r.LastScoredAt != nil {
			last = r.LastScoredAt.Format("2006-01-02 15:04:05")
		}
		hndl := "否"
		if r.HNDL {
			hndl = "是"
		}
		_ = w.Write([]string{
			r.Name, r.System, r.Layer, r.Department, r.Owner, r.Algorithm,
			itoa(r.D1), itoa(r.D2), itoa(r.D3), itoa(r.D4), itoa(r.D5),
			itoa(r.RiskScore), r.RiskLevel, r.RiskLevelText,
			hndl, r.SuggestedAlgo, r.MigrateWindow, last,
		})
	}
	w.Flush()

	s.audit(c, "score", "register.export",
		auditTargetStr("RiskRegister", "risk-register.csv", "风险登记册导出"),
		model.AuditSuccess, fmt.Sprintf("%d 行", len(rows)))

	c.Header("Content-Disposition", `attachment; filename="risk-register.csv"`)
	c.Data(http.StatusOK, "text/csv; charset=utf-8", buf.Bytes())
}

func itoa(v int) string { return fmt.Sprintf("%d", v) }
