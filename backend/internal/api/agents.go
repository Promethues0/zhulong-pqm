package api

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"zhulong-pqm/internal/db"
	"zhulong-pqm/internal/model"
)

// 主机 Agent / 探针的身份与受限上报（M-B）。
//
// 注册（管理员）→ 一次性 API Key → Agent 用 Key 走 /agent/* 受限上报，资产按 AgentID 归属。
// Key 只存 SHA-256 哈希，明文仅注册那一刻返回一次。

// randToken 生成 n 字节随机十六进制串。
func randToken(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func hashKey(key string) string {
	sum := sha256.Sum256([]byte(key))
	return hex.EncodeToString(sum[:])
}

// createAgentReq 注册 Agent 请求体。
type createAgentReq struct {
	Hostname string   `json:"hostname"`
	Kind     string   `json:"kind"`
	Labels   []string `json:"labels"`
	OS       string   `json:"os"`
}

// createAgent 注册一个 Agent（管理员），返回一次性 API Key（此后不可再取）。
func (s *Server) createAgent(c *gin.Context) {
	var req createAgentReq
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "请求体格式错误"})
		return
	}
	kind := req.Kind
	switch kind {
	case model.AgentKindHost, model.AgentKindProbe, model.AgentKindBoth:
	default:
		kind = model.AgentKindHost
	}
	apiKey := "zpqm-agent-" + randToken(24)
	ag := model.Agent{
		AgentID:    "agent-" + randToken(4),
		Hostname:   strings.TrimSpace(req.Hostname),
		Kind:       kind,
		Labels:     req.Labels,
		LabelsJSON: db.MarshalStrings(req.Labels),
		OS:         strings.TrimSpace(req.OS),
		Status:     model.AgentActive,
		KeyHash:    hashKey(apiKey),
		EnrolledAt: time.Now(),
	}
	if err := s.db.Create(&ag).Error; err != nil {
		serverError(c, err)
		return
	}
	s.audit(c, "agent", "agent.create", auditTarget("Agent", ag.ID, ag.AgentID), model.AuditSuccess,
		"注册 Agent "+ag.AgentID+"("+kind+")")
	// apiKey 仅此一次返回。
	c.JSON(http.StatusCreated, gin.H{"agent": ag, "apiKey": apiKey,
		"note": "请立即保存 apiKey，平台仅存哈希、此后无法再取"})
}

// listAgents 列出全部 Agent（不含 Key 哈希，json:"-" 已屏蔽）。
func (s *Server) listAgents(c *gin.Context) {
	var agents []model.Agent
	if err := s.db.Order("id desc").Find(&agents).Error; err != nil {
		serverError(c, err)
		return
	}
	for i := range agents {
		agents[i].Labels = db.UnmarshalStrings(agents[i].LabelsJSON)
	}
	c.JSON(http.StatusOK, gin.H{"agents": agents})
}

// revokeAgent 撤销一个 Agent（管理员）：Key 立即失效。
func (s *Server) revokeAgent(c *gin.Context) {
	id := c.Param("id")
	var ag model.Agent
	if err := s.db.First(&ag, id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Agent 不存在"})
		return
	}
	ag.Status = model.AgentRevoked
	if err := s.db.Save(&ag).Error; err != nil {
		serverError(c, err)
		return
	}
	s.audit(c, "agent", "agent.revoke", auditTarget("Agent", ag.ID, ag.AgentID), model.AuditSuccess, "撤销 Agent")
	c.JSON(http.StatusOK, gin.H{"agent": ag})
}

// agentAuth Agent 受限鉴权中间件：校验 X-Agent-Key，解析出 Agent 身份并写入上下文。
// 仅供 /agent/* 上报端点；不发放用户 JWT、不触及用户权限面。
func (s *Server) agentAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		key := strings.TrimSpace(c.GetHeader("X-Agent-Key"))
		if key == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "缺少 X-Agent-Key"})
			return
		}
		var ag model.Agent
		if err := s.db.Where("key_hash = ? AND status = ?", hashKey(key), model.AgentActive).First(&ag).Error; err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Agent 凭据无效或已撤销"})
			return
		}
		now := time.Now()
		s.db.Model(&model.Agent{}).Where("id = ?", ag.ID).Update("last_seen_at", &now)
		c.Set("reportedBy", ag.AgentID)
		c.Set("agentKind", ag.Kind)
		c.Set("agentLabels", db.UnmarshalStrings(ag.LabelsJSON)) // M-D2 任务标签匹配用
		c.Next()
	}
}

// reportedByCtx 从上下文取上报 Agent 标识（用户 JWT 路径为空）。
func reportedByCtx(c *gin.Context) string {
	if v, ok := c.Get("reportedBy"); ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

// agentAssetsBatch Agent 批量上报已发现并【本地分类完成】的密码使用点。
// Agent 端已用 cryptoref 完成 KexSafety/AuthSafety 判定与算法命名，平台按 endpoint/指纹去重、
// 补五维评分、盖 ReportedBy 归属。无网络端点的主机事实（进程×库、SSH 主机密钥）用合成锚点去重。
func (s *Server) agentAssetsBatch(c *gin.Context) {
	var req struct {
		Assets []model.CryptoAsset `json:"assets"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "请求体格式错误"})
		return
	}
	if len(req.Assets) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "assets 为空"})
		return
	}
	if len(req.Assets) > 2000 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "单批最多 2000 条"})
		return
	}
	reportedBy := reportedByCtx(c)
	created, updated := 0, 0
	for i := range req.Assets {
		ensureAgentAnchor(&req.Assets[i], reportedBy) // 主机事实补合成锚点，保幂等
		s.upsertAgentAsset(&req.Assets[i], reportedBy, &created, &updated)
	}
	s.audit(c, "agent", "agent.ingest", auditTarget("Agent", 0, reportedBy), model.AuditSuccess,
		"Agent 批量上报："+itoaSafe(created)+" 新建 / "+itoaSafe(updated)+" 更新")
	c.JSON(http.StatusOK, gin.H{"created": created, "updated": updated, "total": len(req.Assets), "reportedBy": reportedBy})
}
