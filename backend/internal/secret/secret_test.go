package secret

import "testing"

func TestEncryptDecryptRoundTrip(t *testing.T) {
	key := "test-key-source-abc123"
	for _, plain := range []string{"admin123", "国密-Token-2026!", "", "a"} {
		enc := Encrypt(key, plain)
		if plain != "" && enc == plain {
			t.Errorf("非空明文应被加密: %q", plain)
		}
		if got := Decrypt(key, enc); got != plain {
			t.Errorf("往返不一致: 明文 %q → 解出 %q", plain, got)
		}
	}
}

func TestDecryptPlaintextBackCompat(t *testing.T) {
	// 无 enc: 前缀 = 旧库明文，原样返回。
	if got := Decrypt("k", "admin123"); got != "admin123" {
		t.Errorf("明文兼容失败: %q", got)
	}
}

func TestDecryptWrongKey(t *testing.T) {
	enc := Encrypt("key-A", "secret")
	if got := Decrypt("key-B", enc); got == "secret" {
		t.Error("错误密钥不应解出原文")
	}
}
