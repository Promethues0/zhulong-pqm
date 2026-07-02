package api

import (
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
)

// serverError 统一处理服务端内部错误（多为 DB/GORM 错误）：
//
// 详情记服务端日志（含方法+路径便于定位），客户端只收通用提示，
// 不再把 "UNIQUE constraint failed: users.username" 之类的表名/字段/SQL 细节回给调用方
// （避免信息泄漏 / 侦察）。仅用于 500 场景；400 校验错误仍如实返回以帮助 API 使用方。
func serverError(c *gin.Context, err error) {
	log.Printf("api %s %s 内部错误: %v", c.Request.Method, c.FullPath(), err)
	c.JSON(http.StatusInternalServerError, gin.H{"error": "服务器内部错误，请稍后重试"})
}
