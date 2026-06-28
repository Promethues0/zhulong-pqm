package api

import (
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"

	"zhulong-pqm/internal/model"
)

// tokenTTL JWT 有效期。
const tokenTTL = 12 * time.Hour

// claims 自定义 JWT 载荷。
type claims struct {
	UserID   uint   `json:"uid"`
	Username string `json:"username"`
	Role     string `json:"role"`
	jwt.RegisteredClaims
}

// loginReq 登录请求体。
type loginReq struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
}

// login 校验账号密码并签发 JWT。
func (s *Server) login(c *gin.Context) {
	var req loginReq
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "用户名和密码必填"})
		return
	}

	var user model.User
	if err := s.db.Where("username = ?", req.Username).First(&user).Error; err != nil {
		s.auditLogin(c, req.Username, model.AuditFailure, "用户名或密码错误")
		c.JSON(http.StatusUnauthorized, gin.H{"error": "用户名或密码错误"})
		return
	}
	if bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.Password)) != nil {
		s.auditLogin(c, req.Username, model.AuditFailure, "用户名或密码错误")
		c.JSON(http.StatusUnauthorized, gin.H{"error": "用户名或密码错误"})
		return
	}
	// 禁用用户拒绝登录。
	if user.Status == model.UserDisabled {
		s.auditLogin(c, req.Username, model.AuditDenied, "用户已禁用")
		c.JSON(http.StatusForbidden, gin.H{"error": "用户已禁用"})
		return
	}

	token, err := s.issueToken(user)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "签发令牌失败"})
		return
	}
	now := time.Now()
	user.LastLoginAt = &now
	s.db.Model(&user).Update("last_login_at", &now)
	s.auditLogin(c, user.Username, model.AuditSuccess, "登录成功")
	c.JSON(http.StatusOK, gin.H{"token": token, "user": user})
}

// auditLogin 写一条登录审计（成功/失败/拒绝都记，失败用于暴力破解审计）。
// 登录发生在 JWT 之前，actor 上下文为空，故直接构造日志。
func (s *Server) auditLogin(c *gin.Context, username, result, detail string) {
	s.db.Create(&model.AuditLog{
		ActorName:  username,
		Action:     "auth.login",
		Module:     "auth",
		TargetType: "User",
		TargetName: username,
		Result:     result,
		Detail:     detail,
		IP:         c.ClientIP(),
		CreatedAt:  time.Now(),
	})
}

func (s *Server) issueToken(user model.User) (string, error) {
	now := time.Now()
	cl := claims{
		UserID:   user.ID,
		Username: user.Username,
		Role:     user.Role,
		RegisteredClaims: jwt.RegisteredClaims{
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(tokenTTL)),
			Subject:   user.Username,
		},
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, cl)
	return tok.SignedString([]byte(s.cfg.JWTSecret))
}

// authMiddleware 校验 Bearer JWT，并将身份写入 gin.Context。
func (s *Server) authMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		header := c.GetHeader("Authorization")
		const prefix = "Bearer "
		if len(header) <= len(prefix) || header[:len(prefix)] != prefix {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "缺少 Bearer 令牌"})
			return
		}
		tokenStr := header[len(prefix):]

		var cl claims
		token, err := jwt.ParseWithClaims(tokenStr, &cl, func(t *jwt.Token) (any, error) {
			if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, jwt.ErrSignatureInvalid
			}
			return []byte(s.cfg.JWTSecret), nil
		})
		if err != nil || !token.Valid {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "令牌无效或已过期"})
			return
		}

		// 二次校验用户状态：禁用用户即时失效（无需等 token 过期）；
		// 同时以库内最新角色覆盖 token 内角色，改角色即时生效。
		var user model.User
		if err := s.db.First(&user, cl.UserID).Error; err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "用户不存在"})
			return
		}
		if user.Status == model.UserDisabled {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "用户已禁用"})
			return
		}

		c.Set("userID", user.ID)
		c.Set("username", user.Username)
		c.Set("role", user.Role)
		c.Next()
	}
}

// requireRole 角色守卫中间件：当前用户角色不在 roles 允许集合时返回 403，
// 并落一条 result=denied 审计。读端点不挂此中间件（所有已登录可读）。
func (s *Server) requireRole(roles ...string) gin.HandlerFunc {
	allowed := make(map[string]bool, len(roles))
	for _, r := range roles {
		allowed[r] = true
	}
	return func(c *gin.Context) {
		role := actorRole(c)
		if !allowed[role] {
			s.audit(c, moduleForPath(c.FullPath()), "access.denied",
				auditTargetStr("Route", c.FullPath(), c.Request.Method+" "+c.FullPath()),
				model.AuditDenied, "角色 "+role+" 权限不足")
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "权限不足"})
			return
		}
		c.Next()
	}
}

// moduleForPath 从路由路径粗粒度推断审计 module（仅用于 denied 审计归类）。
func moduleForPath(path string) string {
	switch {
	case strings.Contains(path, "/scans"):
		return "scan"
	case strings.Contains(path, "/assets"):
		return "asset"
	case strings.Contains(path, "/score"):
		return "score"
	case strings.Contains(path, "/verify"):
		return "acceptance"
	case strings.Contains(path, "/remediations"):
		return "remediation"
	case strings.Contains(path, "/devices"):
		return "device"
	case strings.Contains(path, "/reports"):
		return "report"
	case strings.Contains(path, "/cbom"):
		return "cbom"
	case strings.Contains(path, "/users"):
		return "user"
	case strings.Contains(path, "/audit"):
		return "audit"
	default:
		return "platform"
	}
}
