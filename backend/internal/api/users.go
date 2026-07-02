package api

import (
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"

	"zhulong-pqm/internal/model"
)

// 口令强度：最短长度与 bcrypt 代价（cost 12 比默认 10 更抗离线爆破）。
const (
	minPasswordLen = 8
	bcryptCost     = 12
)

// me GET /me 返回当前登录用户（含扩展字段），供前端刷新角色/状态。
func (s *Server) me(c *gin.Context) {
	var user model.User
	if err := s.db.First(&user, actorID(c)).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "用户不存在"})
		return
	}
	c.JSON(http.StatusOK, user)
}

// listUsers GET /users 用户列表（admin）。
func (s *Server) listUsers(c *gin.Context) {
	var users []model.User
	if err := s.db.Order("id asc").Find(&users).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, users)
}

// createUserReq 建用户请求体。
type createUserReq struct {
	Username    string `json:"username" binding:"required"`
	Password    string `json:"password" binding:"required"`
	Role        string `json:"role"`
	DisplayName string `json:"displayName"`
}

// createUser POST /users 建用户（admin）。
func (s *Server) createUser(c *gin.Context) {
	var req createUserReq
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "username 和 password 必填"})
		return
	}
	if len(req.Password) < minPasswordLen {
		c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("密码至少 %d 位", minPasswordLen)})
		return
	}
	if !validRole(req.Role) {
		req.Role = model.RoleViewer
	}
	var dup int64
	s.db.Model(&model.User{}).Where("username = ?", req.Username).Count(&dup)
	if dup > 0 {
		c.JSON(http.StatusConflict, gin.H{"error": "用户名已存在"})
		return
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcryptCost)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "密码哈希失败"})
		return
	}
	u := model.User{
		Username:     req.Username,
		PasswordHash: string(hash),
		Role:         req.Role,
		DisplayName:  req.DisplayName,
		Status:       model.UserActive,
	}
	if err := s.db.Create(&u).Error; err != nil {
		s.audit(c, "user", "user.create", auditTarget("User", 0, req.Username), model.AuditFailure, err.Error())
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	s.audit(c, "user", "user.create", auditTarget("User", u.ID, u.Username), model.AuditSuccess, "角色="+u.Role)
	c.JSON(http.StatusCreated, u)
}

// updateUserReq 改用户请求体（角色/显示名/状态）。
type updateUserReq struct {
	Role        *string `json:"role"`
	DisplayName *string `json:"displayName"`
	Status      *string `json:"status"`
}

// updateUser PUT /users/:id 改角色/显示名/状态（admin）。
// 守卫：禁止把最后一个 active admin 降级或禁用（409）。
func (s *Server) updateUser(c *gin.Context) {
	var u model.User
	if err := s.db.First(&u, c.Param("id")).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "用户不存在"})
		return
	}
	var req updateUserReq
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	newRole := u.Role
	newStatus := u.Status
	if req.Role != nil && validRole(*req.Role) {
		newRole = *req.Role
	}
	if req.Status != nil && (*req.Status == model.UserActive || *req.Status == model.UserDisabled) {
		newStatus = *req.Status
	}

	// 最后一个 active admin 守卫：若该用户当前是 active admin，而本次改动使其不再是
	// active admin，且系统再无其他 active admin，则拒绝（409）。
	demotingAdmin := u.Role == model.RoleAdmin && u.Status == model.UserActive &&
		(newRole != model.RoleAdmin || newStatus != model.UserActive)
	if demotingAdmin && s.activeAdminCount() <= 1 {
		s.audit(c, "user", "user.update", auditTarget("User", u.ID, u.Username), model.AuditDenied, "最后一个管理员不可降级/禁用")
		c.JSON(http.StatusConflict, gin.H{"error": "不能降级或禁用最后一个管理员"})
		return
	}

	u.Role = newRole
	u.Status = newStatus
	if req.DisplayName != nil {
		u.DisplayName = *req.DisplayName
	}
	if err := s.db.Save(&u).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	s.audit(c, "user", "user.update", auditTarget("User", u.ID, u.Username), model.AuditSuccess,
		"角色="+u.Role+" 状态="+u.Status)
	c.JSON(http.StatusOK, u)
}

// passwordReq 改密请求体。
type passwordReq struct {
	Password string `json:"password" binding:"required"`
}

// changePassword POST /users/:id/password 改密（admin 或本人）。
func (s *Server) changePassword(c *gin.Context) {
	var u model.User
	if err := s.db.First(&u, c.Param("id")).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "用户不存在"})
		return
	}
	// admin 或本人方可改密。
	if actorRole(c) != model.RoleAdmin && actorID(c) != u.ID {
		s.audit(c, "user", "user.password", auditTarget("User", u.ID, u.Username), model.AuditDenied, "仅 admin 或本人可改密")
		c.JSON(http.StatusForbidden, gin.H{"error": "权限不足"})
		return
	}
	var req passwordReq
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "password 必填"})
		return
	}
	if len(req.Password) < minPasswordLen {
		c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("密码至少 %d 位", minPasswordLen)})
		return
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcryptCost)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "密码哈希失败"})
		return
	}
	if err := s.db.Model(&u).Update("password_hash", string(hash)).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	s.audit(c, "user", "user.password", auditTarget("User", u.ID, u.Username), model.AuditSuccess, "改密成功")
	c.JSON(http.StatusOK, gin.H{"updated": true})
}

// deleteUser DELETE /users/:id 删用户（admin）。
// 守卫：禁止删自己、禁止删最后一个 active admin。
func (s *Server) deleteUser(c *gin.Context) {
	var u model.User
	if err := s.db.First(&u, c.Param("id")).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "用户不存在"})
		return
	}
	if u.ID == actorID(c) {
		s.audit(c, "user", "user.delete", auditTarget("User", u.ID, u.Username), model.AuditDenied, "不能删除自己")
		c.JSON(http.StatusConflict, gin.H{"error": "不能删除自己"})
		return
	}
	if u.Role == model.RoleAdmin && u.Status == model.UserActive && s.activeAdminCount() <= 1 {
		s.audit(c, "user", "user.delete", auditTarget("User", u.ID, u.Username), model.AuditDenied, "最后一个管理员不可删除")
		c.JSON(http.StatusConflict, gin.H{"error": "不能删除最后一个管理员"})
		return
	}
	if err := s.db.Delete(&model.User{}, u.ID).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	s.audit(c, "user", "user.delete", auditTarget("User", u.ID, u.Username), model.AuditSuccess, "删除用户")
	c.JSON(http.StatusOK, gin.H{"deleted": true})
}

// activeAdminCount 当前 active admin 数量。
func (s *Server) activeAdminCount() int64 {
	var n int64
	s.db.Model(&model.User{}).
		Where("role = ? AND status = ?", model.RoleAdmin, model.UserActive).
		Count(&n)
	return n
}

// validRole 校验角色取值合法。
func validRole(r string) bool {
	switch r {
	case model.RoleAdmin, model.RoleOperator, model.RoleViewer:
		return true
	default:
		return false
	}
}
