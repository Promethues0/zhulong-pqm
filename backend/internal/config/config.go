// Package config 集中管理烛龙 PQM 后端的运行时配置。
package config

import (
	"log"
	"os"
	"strings"
)

// devJWTSecret 开发期默认 JWT 密钥；生产务必经 ZPQM_JWT_SECRET 覆盖。
const devJWTSecret = "zhulong-pqm-dev-secret"

// Config 持有服务启动所需的全部配置项。
type Config struct {
	Port        string   // HTTP 监听端口
	JWTSecret   string   // JWT 签名密钥
	DBPath      string   // SQLite 数据库文件路径
	CORSOrigins []string // 允许跨域的前端来源白名单

	TLCPAddr    string // 国密 TLCP 监听地址（空=关闭），与明文口并存
	TLCPCertDir string // 国密 TLCP SM2 双证目录（自动生成）
}

// Load 从环境变量加载配置，未设置时回落到约定的默认值。
func Load() *Config {
	jwtSecret := envOr("ZPQM_JWT_SECRET", devJWTSecret)
	if jwtSecret == "" || jwtSecret == devJWTSecret {
		log.Println("===================================================================")
		log.Println("[WARNING] 正在使用开发默认 JWT 密钥（ZPQM_JWT_SECRET 未设置或为默认值），")
		log.Println("[WARNING] 任何人都可伪造令牌！生产环境务必设置强随机 ZPQM_JWT_SECRET。")
		log.Println("===================================================================")
	}

	origins := splitCSV(envOr("ZPQM_CORS_ORIGINS", "http://localhost:5390,http://127.0.0.1:5390"))

	return &Config{
		Port:        envOr("ZPQM_PORT", "8099"),
		JWTSecret:   jwtSecret,
		DBPath:      envOr("ZPQM_DB_PATH", "./zhulong-pqm.db"),
		CORSOrigins: origins,
		TLCPAddr:    envOr("ZPQM_TLCP_ADDR", ""),
		TLCPCertDir: envOr("ZPQM_TLCP_CERT_DIR", "./tlcp"),
	}
}

// splitCSV 按逗号切分并去除空白项。
func splitCSV(s string) []string {
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if v := strings.TrimSpace(p); v != "" {
			out = append(out, v)
		}
	}
	return out
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
