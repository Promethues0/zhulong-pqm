// Package cryptobox 提供静态凭据的 AES-256-GCM 加密（如设备网关/HSM token）。
//
// 密钥材料取自 ZPQM_ENCRYPTION_KEY，未设时回落到 ZPQM_JWT_SECRET（两者都经 SHA-256
// 派生成 32 字节 AES 密钥）。Encrypt 产出带 "enc:" 前缀的密文；Decrypt 对无前缀的
// 旧明文原样返回（向后兼容，无需危险迁移——旧 token 下次改写时自动升级为密文）。
package cryptobox

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"log"
	"os"
	"strings"
)

const encPrefix = "enc:"

var aead cipher.AEAD

func init() {
	material := os.Getenv("ZPQM_ENCRYPTION_KEY")
	if material == "" {
		material = os.Getenv("ZPQM_JWT_SECRET")
	}
	if material == "" {
		material = "zhulong-pqm-dev-encryption-fallback"
		log.Println("[WARNING] 未设 ZPQM_ENCRYPTION_KEY/ZPQM_JWT_SECRET，凭据加密使用开发回落密钥（生产务必设置）。")
	}
	key := sha256.Sum256([]byte(material))
	block, err := aes.NewCipher(key[:])
	if err != nil {
		log.Fatalf("cryptobox: 初始化 AES 失败: %v", err)
	}
	g, err := cipher.NewGCM(block)
	if err != nil {
		log.Fatalf("cryptobox: 初始化 GCM 失败: %v", err)
	}
	aead = g
}

// Encrypt 加密明文，返回 "enc:"+base64(nonce||ciphertext)；空串原样返回。
func Encrypt(plain string) string {
	if plain == "" {
		return ""
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return plain // 极端失败下不阻断，退回明文（不理想但可用）
	}
	ct := aead.Seal(nonce, nonce, []byte(plain), nil)
	return encPrefix + base64.StdEncoding.EncodeToString(ct)
}

// Decrypt 解密；无 "enc:" 前缀视为旧明文原样返回（向后兼容）。解密失败返回空串。
func Decrypt(stored string) string {
	if !strings.HasPrefix(stored, encPrefix) {
		return stored
	}
	raw, err := base64.StdEncoding.DecodeString(stored[len(encPrefix):])
	if err != nil || len(raw) < aead.NonceSize() {
		return ""
	}
	nonce, ct := raw[:aead.NonceSize()], raw[aead.NonceSize():]
	pt, err := aead.Open(nil, nonce, ct, nil)
	if err != nil {
		return ""
	}
	return string(pt)
}
