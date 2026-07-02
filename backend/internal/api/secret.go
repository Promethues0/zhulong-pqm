package api

import "zhulong-pqm/internal/secret"

// 设备凭据（网关/HSM token）静态加密：密钥优先取 ZPQM_ENCRYPTION_KEY，
// 未设置时从 JWT 密钥派生（生产 JWT 密钥已是强随机且稳定），无需额外配置。

// tokenKeySrc 返回对称密钥源串（api 与 remediate 必须一致）。
func (s *Server) tokenKeySrc() string {
	if s.cfg.EncryptionKey != "" {
		return s.cfg.EncryptionKey
	}
	return "zpqm-token-kek|" + s.cfg.JWTSecret
}

func (s *Server) encToken(plain string) string { return secret.Encrypt(s.tokenKeySrc(), plain) }
func (s *Server) decToken(stored string) string { return secret.Decrypt(s.tokenKeySrc(), stored) }
