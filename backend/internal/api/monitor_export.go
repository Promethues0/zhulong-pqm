package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"zhulong-pqm/internal/db"
	"zhulong-pqm/internal/model"
)

// ---- ⑤ SIEM 外推（Wave C，NFR-8.8.3）：监测告警导出 CEF / JSON ----
//
// GET /monitor/events/export?format=cef|json，便于对接 SIEM。
// 字段含 severity/kind/asset/ruleSLO/time/detail。沿用 listMonitorEvents 的过滤口径。

// cefSeverity 把 PRD 三级严重度映射为 CEF 0-10 数值（ArcSight 口径）。
func cefSeverity(sev string) int {
	switch sev {
	case model.SevP1:
		return 10
	case model.SevWarning:
		return 6
	case model.SevInspect:
		return 3
	default:
		return 1
	}
}

// cefEscapeHeader 转义 CEF 头字段中的 | 与 \。
func cefEscapeHeader(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	return strings.ReplaceAll(s, "|", `\|`)
}

// cefEscapeExt 转义 CEF 扩展字段中的 = 与 \ 与换行。
func cefEscapeExt(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, "=", `\=`)
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\r", " ")
	return s
}

// monitorEventsFiltered 复用 listMonitorEvents 过滤条件取事件（导出共用口径）。
func (s *Server) monitorEventsFiltered(c *gin.Context) []model.MonitorEvent {
	q := s.db.Model(&model.MonitorEvent{})
	if v := c.Query("kind"); v != "" {
		q = q.Where("kind = ?", v)
	}
	if v := c.Query("severity"); v != "" {
		q = q.Where("severity = ?", v)
	}
	if v := c.Query("status"); v != "" {
		q = q.Where("status = ?", v)
	}
	if v := c.Query("assetId"); v != "" {
		q = q.Where("asset_id = ?", v)
	}
	if v := c.Query("from"); v != "" {
		if t, err := parseDateParam(v); err == nil {
			q = q.Where("occurred_at >= ?", t)
		}
	}
	var events []model.MonitorEvent
	q.Order("occurred_at desc").Limit(50000).Find(&events)
	for i := range events {
		events[i].Evidence = db.UnmarshalMonEvidence(events[i].EvidenceJSON)
	}
	return events
}

// exportMonitorEvents GET /monitor/events/export?format=cef|json → SIEM 外推。
func (s *Server) exportMonitorEvents(c *gin.Context) {
	format := strings.ToLower(c.DefaultQuery("format", "cef"))
	events := s.monitorEventsFiltered(c)

	switch format {
	case "json":
		s.audit(c, "monitor", "monitor.export",
			auditTargetStr("MonitorEvent", "json", fmt.Sprintf("%d 条", len(events))), model.AuditSuccess, "")
		// SIEM 友好的扁平 JSON（NDJSON 风格易解析，但此处给数组）。
		out := make([]gin.H, 0, len(events))
		for _, e := range events {
			assetID := uint(0)
			if e.AssetID != nil {
				assetID = *e.AssetID
			}
			out = append(out, gin.H{
				"id":          e.ID,
				"vendor":      "Zhulong",
				"product":     "PQM",
				"kind":        e.Kind,
				"severity":    e.Severity,
				"cefSeverity": cefSeverity(e.Severity),
				"title":       e.Title,
				"detail":      e.Detail,
				"assetId":     assetID,
				"ruleSlo":     e.RuleSLO,
				"status":      e.Status,
				"occurredAt":  e.OccurredAt.Format(time.RFC3339),
				"evidence":    e.Evidence,
			})
		}
		c.Header("Content-Disposition", `attachment; filename="zhulong-monitor-events.json"`)
		c.JSON(http.StatusOK, gin.H{"vendor": "Zhulong", "product": "PQM", "count": len(out), "events": out})

	case "cef":
		s.audit(c, "monitor", "monitor.export",
			auditTargetStr("MonitorEvent", "cef", fmt.Sprintf("%d 条", len(events))), model.AuditSuccess, "")
		var b strings.Builder
		// CEF:0|Vendor|Product|Version|SignatureID|Name|Severity|Extension
		for _, e := range events {
			assetID := ""
			if e.AssetID != nil {
				assetID = fmt.Sprintf("%d", *e.AssetID)
			}
			ext := []string{
				"rt=" + e.OccurredAt.Format(time.RFC3339),
				"cs1Label=ruleSlo cs1=" + cefEscapeExt(e.RuleSLO),
				"cs2Label=kind cs2=" + cefEscapeExt(e.Kind),
				"cs3Label=status cs3=" + cefEscapeExt(e.Status),
				"cs4Label=assetId cs4=" + cefEscapeExt(assetID),
				"msg=" + cefEscapeExt(e.Detail),
			}
			if ev, _ := json.Marshal(e.Evidence); len(ev) > 2 {
				ext = append(ext, "cs5Label=evidence cs5="+cefEscapeExt(string(ev)))
			}
			fmt.Fprintf(&b, "CEF:0|Zhulong|PQM|1.0|%s|%s|%d|%s\n",
				cefEscapeHeader(e.Kind),
				cefEscapeHeader(e.Title),
				cefSeverity(e.Severity),
				strings.Join(ext, " "))
		}
		c.Header("Content-Disposition", `attachment; filename="zhulong-monitor-events.cef"`)
		c.Data(http.StatusOK, "text/plain; charset=utf-8", []byte(b.String()))

	default:
		c.JSON(http.StatusBadRequest, gin.H{"error": "format 仅支持 cef 或 json"})
	}
}
