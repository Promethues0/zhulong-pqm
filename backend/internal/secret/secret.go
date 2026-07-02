// Package secret 提供设备凭据的静态对称加密（AES-256-GCM），供 api 与 remediate 共用。
package secret

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"io"
	"strings"
)

// Prefix 密文存储前缀；无此前缀视为明文（旧库/种子向后兼容）。
const Prefix = "enc:"

func key32(keySrc string) [32]byte { return sha256.Sum256([]byte(keySrc)) }

// Encrypt 用 keySrc 派生的密钥加密明文；空串原样返回，出错退回明文（不阻断功能）。
func Encrypt(keySrc, plain string) string {
	if plain == "" {
		return ""
	}
	k := key32(keySrc)
	block, err := aes.NewCipher(k[:])
	if err != nil {
		return plain
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return plain
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return plain
	}
	ct := gcm.Seal(nonce, nonce, []byte(plain), nil)
	return Prefix + base64.StdEncoding.EncodeToString(ct)
}

// Decrypt 解密存储值；无前缀=明文；解密失败返回空串（避免用错误串当凭据）。
func Decrypt(keySrc, stored string) string {
	if !strings.HasPrefix(stored, Prefix) {
		return stored
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(stored, Prefix))
	if err != nil {
		return ""
	}
	k := key32(keySrc)
	block, err := aes.NewCipher(k[:])
	if err != nil {
		return ""
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil || len(raw) < gcm.NonceSize() {
		return ""
	}
	nonce, ct := raw[:gcm.NonceSize()], raw[gcm.NonceSize():]
	pt, err := gcm.Open(nil, nonce, ct, nil)
	if err != nil {
		return ""
	}
	return string(pt)
}
