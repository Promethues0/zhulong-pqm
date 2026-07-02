package api

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"zhulong-pqm/internal/model"
)

// ---- actor / 上下文取值辅助 ----

// actorID 从 gin.Context 取操作者 UserID（authMiddleware 已 c.Set）。
func actorID(c *gin.Context) uint {
	if v, ok := c.Get("userID"); ok {
		if id, ok := v.(uint); ok {
			return id
		}
	}
	return 0
}

// actorName 取操作者 username。
func actorName(c *gin.Context) string {
	if v, ok := c.Get("username"); ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

// actorRole 取操作者角色。
func actorRole(c *gin.Context) string {
	if v, ok := c.Get("role"); ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

// auditTarget 构造审计目标三元组（类型/ID/名称），ID 转字符串以兼容非数字目标。
type auditTargetT struct {
	Type string
	ID   string
	Name string
}

func auditTarget(typ string, id uint, name string) auditTargetT {
	return auditTargetT{Type: typ, ID: strconv.FormatUint(uint64(id), 10), Name: name}
}

func auditTargetStr(typ, id, name string) auditTargetT {
	return auditTargetT{Type: typ, ID: id, Name: name}
}

// audit 同步写一条审计日志（单机 SQLite 量级小，同步即可）。
// 从 c 取 actor 快照与 IP；module/action/result 见动作字典与 model.Audit* 常量。
func (s *Server) audit(c *gin.Context, module, action string, target auditTargetT, result, detail string) {
	log := model.AuditLog{
		ActorID:    actorID(c),
		ActorName:  actorName(c),
		ActorRole:  actorRole(c),
		Action:     action,
		Module:     module,
		TargetType: target.Type,
		TargetID:   target.ID,
		TargetName: target.Name,
		Result:     result,
		Detail:     detail,
		IP:         c.ClientIP(),
		CreatedAt:  time.Now(),
	}
	s.db.Create(&log)
}

// pageLimitOffset 解析分页参数（支持 page/size 或 limit/offset），返回 limit, offset。
func pageLimitOffset(c *gin.Context, defSize int) (int, int) {
	// 优先 limit/offset。
	if l := c.Query("limit"); l != "" {
		limit, _ := strconv.Atoi(l)
		if limit <= 0 {
			limit = defSize
		}
		offset, _ := strconv.Atoi(c.Query("offset"))
		if offset < 0 {
			offset = 0
		}
		return limit, offset
	}
	size, _ := strconv.Atoi(c.Query("size"))
	if size <= 0 {
		size = defSize
	}
	page, _ := strconv.Atoi(c.Query("page"))
	if page <= 0 {
		page = 1
	}
	return size, (page - 1) * size
}

// listAuditLogs GET /audit-logs 分页+过滤（module/action/result/actor/from/to），按 created_at desc。
// 返回 {total, items}。授权：admin/operator（在 router 挂 requireRole）。
func (s *Server) listAuditLogs(c *gin.Context) {
	q := s.db.Model(&model.AuditLog{})
	if v := c.Query("module"); v != "" {
		q = q.Where("module = ?", v)
	}
	if v := c.Query("action"); v != "" {
		q = q.Where("action = ?", v)
	}
	if v := c.Query("result"); v != "" {
		q = q.Where("result = ?", v)
	}
	if v := strings.TrimSpace(c.Query("actor")); v != "" {
		q = q.Where("actor_name LIKE ?", "%"+v+"%")
	}
	if v := c.Query("from"); v != "" {
		if t, err := parseDateParam(v); err == nil {
			q = q.Where("created_at >= ?", t)
		}
	}
	if v := c.Query("to"); v != "" {
		if t, err := parseDateParam(v); err == nil {
			// to 含当日：加一天作为上界。
			q = q.Where("created_at < ?", t.Add(24*time.Hour))
		}
	}

	var total int64
	q.Count(&total)

	limit, offset := pageLimitOffset(c, 20)
	var items []model.AuditLog
	if err := q.Order("created_at desc").Limit(limit).Offset(offset).Find(&items).Error; err != nil {
		serverError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"total": total, "items": items})
}

// auditFilteredQuery 复用 listAuditLogs 的过滤条件构造 query（导出与列表共用口径）。
func (s *Server) auditFilteredQuery(c *gin.Context) *gorm.DB {
	q := s.db.Model(&model.AuditLog{})
	if v := c.Query("module"); v != "" {
		q = q.Where("module = ?", v)
	}
	if v := c.Query("action"); v != "" {
		q = q.Where("action = ?", v)
	}
	if v := c.Query("result"); v != "" {
		q = q.Where("result = ?", v)
	}
	if v := strings.TrimSpace(c.Query("actor")); v != "" {
		q = q.Where("actor_name LIKE ?", "%"+v+"%")
	}
	if v := c.Query("from"); v != "" {
		if t, err := parseDateParam(v); err == nil {
			q = q.Where("created_at >= ?", t)
		}
	}
	if v := c.Query("to"); v != "" {
		if t, err := parseDateParam(v); err == nil {
			q = q.Where("created_at < ?", t.Add(24*time.Hour))
		}
	}
	return q
}

// csvGuardFormula 防 CSV 公式注入：以 = + - @ Tab CR 开头的单元格会被 Excel/Sheets
// 当公式执行（如恶意证书 CN "=cmd|..."），前置单引号使其被当作纯文本。
func csvGuardFormula(s string) string {
	if s != "" && strings.ContainsRune("=+-@\t\r", rune(s[0])) {
		return "'" + s
	}
	return s
}

// csvCell 转义 CSV 单元格（防公式注入 + 含逗号/引号/换行时加引号）。
func csvCell(s string) string {
	s = csvGuardFormula(s)
	if strings.ContainsAny(s, ",\"\n\r") {
		return `"` + strings.ReplaceAll(s, `"`, `""`) + `"`
	}
	return s
}

// exportAuditLogs GET /audit-logs/export → text/csv（带 UTF-8 BOM，Excel 友好）。
// 列：时间/操作人/角色/模块/动作/对象类型/对象/结果/IP/详情。授权：admin（adminGrp）。
func (s *Server) exportAuditLogs(c *gin.Context) {
	var items []model.AuditLog
	if err := s.auditFilteredQuery(c).Order("created_at desc").Limit(50000).Find(&items).Error; err != nil {
		serverError(c, err)
		return
	}

	var b strings.Builder
	b.WriteString("\xEF\xBB\xBF") // UTF-8 BOM
	b.WriteString("时间,操作人,角色,模块,动作,对象类型,对象,结果,IP,详情\n")
	for _, it := range items {
		row := []string{
			it.CreatedAt.Format("2006-01-02 15:04:05"),
			it.ActorName, it.ActorRole, it.Module, it.Action,
			it.TargetType, it.TargetName, it.Result, it.IP, it.Detail,
		}
		for i, cell := range row {
			if i > 0 {
				b.WriteByte(',')
			}
			b.WriteString(csvCell(cell))
		}
		b.WriteByte('\n')
	}

	s.audit(c, "report", "audit.export",
		auditTargetStr("AuditLog", "export", fmt.Sprintf("%d 行", len(items))), model.AuditSuccess, "")
	filename := fmt.Sprintf("audit-logs-%s.csv", time.Now().Format("20060102-150405"))
	c.Header("Content-Disposition", `attachment; filename="`+filename+`"`)
	c.Data(http.StatusOK, "text/csv; charset=utf-8", []byte(b.String()))
}

// parseDateParam 解析 YYYY-MM-DD 或 RFC3339 时间参数。
func parseDateParam(v string) (time.Time, error) {
	if t, err := time.Parse("2006-01-02", v); err == nil {
		return t, nil
	}
	if t, err := time.Parse(time.RFC3339, v); err == nil {
		return t, nil
	}
	return time.Time{}, fmt.Errorf("无法解析时间 %q", v)
}
