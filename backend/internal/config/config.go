// Package config 集中管理烛龙 PQM 后端的运行时配置。
package config

import "os"

// Config 持有服务启动所需的全部配置项。
type Config struct {
	Port      string // HTTP 监听端口
	JWTSecret string // JWT 签名密钥
	DBPath    string // SQLite 数据库文件路径
}

// Load 从环境变量加载配置，未设置时回落到约定的默认值。
func Load() *Config {
	return &Config{
		Port:      envOr("ZPQM_PORT", "8099"),
		JWTSecret: envOr("ZPQM_JWT_SECRET", "zhulong-pqm-dev-secret"),
		DBPath:    envOr("ZPQM_DB_PATH", "./zhulong-pqm.db"),
	}
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
