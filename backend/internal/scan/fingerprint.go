package scan

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
)

// AssetFingerprint 计算资产去重锚点（C6 统一公式，①②共用）。
//
// 端点类：sha256(lower(host)+":"+port+"|"+service+"|"+certFingerprint)
// 证书类（无 host:port）：退化为 sha256("cert|"+certfp)
//
// 返回带 "sha256:" 前缀的可读串。②建档侧按其去重主键优先级（cert→endpoint→name）
// 选权威键，但 fingerprint 字段值统一由本函数生成，避免双口径漂移。
func AssetFingerprint(host string, port int, service, certFP string) string {
	var seed string
	if host == "" && port == 0 {
		// 证书类：无网络落点。
		seed = "cert|" + strings.ToLower(strings.TrimSpace(certFP))
	} else {
		seed = fmt.Sprintf("%s:%d|%s|%s",
			strings.ToLower(strings.TrimSpace(host)), port,
			strings.TrimSpace(service), strings.ToLower(strings.TrimSpace(certFP)))
	}
	sum := sha256.Sum256([]byte(seed))
	return "sha256:" + hex.EncodeToString(sum[:])
}
