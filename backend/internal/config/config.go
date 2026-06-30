// Package config 集中管理烛龙 PQM 后端的运行时配置。
package config

import (
	"crypto/rand"
	"encoding/hex"
	"log"
	"os"
	"strings"
)

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
	// JWT 密钥：未设置时【生成进程级随机密钥】而非硬编码常量——
	// 安全默认（无人能伪造令牌），代价是重启后旧令牌失效（需重新登录）。
	// 生产应显式设置 ZPQM_JWT_SECRET 以保持令牌跨重启稳定。
	jwtSecret := strings.TrimSpace(os.Getenv("ZPQM_JWT_SECRET"))
	switch {
	case jwtSecret == "":
		b := make([]byte, 32)
		if _, err := rand.Read(b); err != nil {
			log.Fatalf("生成随机 JWT 密钥失败: %v", err)
		}
		jwtSecret = hex.EncodeToString(b)
		log.Println("[WARNING] ZPQM_JWT_SECRET 未设置，已生成进程级随机密钥（重启后令牌失效）。生产请显式设置以保持稳定。")
	case len(jwtSecret) < 16:
		log.Println("[WARNING] ZPQM_JWT_SECRET 过短（<16 字节），建议改用 ≥32 字节强随机密钥。")
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
