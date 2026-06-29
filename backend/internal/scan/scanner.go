// Package scan 实现密码资产的发现引擎。
package scan

import (
	"context"
	"net"
	"strconv"
	"strings"
	"time"

	"zhulong-pqm/internal/model"
)

// DefaultPort 未指定端口时的默认探测端口。
const DefaultPort = 443

// Scanner 是发现引擎的统一抽象：对单个目标完成一次探测。
//
// Method/Name 供 Runner 按 ScannerType 装配并在 ScanResult/RuleHit 上标注发现方式。
type Scanner interface {
	Scan(ctx context.Context, host string, port int) (*model.ScanResult, error)
	Method() string // M1 等发现方式标识
	Name() string   // tls/ssh/ike/rdp 扫描器名
}

// HitMatcher 扫描器可选实现：返回本次探测结果命中的规则（不含 ScanResultID）。
// 未实现该接口的扫描器由 Runner 回落到通用 MatchRules。
type HitMatcher interface {
	Hits(res *model.ScanResult) []model.RuleHit
}

// NewScanner 按 scannerType 装配具体扫描器（默认 tls）。占位扫描器返回未实现标注。
func NewScanner(scannerType string) Scanner {
	switch scannerType {
	case model.ScannerSSH:
		return NewSSHScanner()
	case model.ScannerIKE:
		return NewPlaceholderScanner(model.ScannerIKE, 500)
	case model.ScannerRDP:
		return NewPlaceholderScanner(model.ScannerRDP, 3389)
	default:
		return NewTLSScanner()
	}
}

// Target 一个解析后的探测目标。
type Target struct {
	Host string
	Port int
}

// ParseTargets 将原始目标字符串解析为 (host, port) 列表。
//
// 支持 "host" 与 "host:port" 两种写法，未带端口时回落到 DefaultPort。
// CIDR 网段展开暂不支持（TODO），遇到含 "/" 的目标原样保留 host 部分。
func ParseTargets(raw []string) []Target {
	out := make([]Target, 0, len(raw))
	for _, t := range raw {
		t = normalizeTarget(t)
		if t == "" {
			continue
		}
		// TODO: 展开 CIDR 网段（如 10.0.0.0/24）。当前仅保留原始 host。
		host := t
		port := DefaultPort
		if h, p, ok := splitHostPort(t); ok {
			host, port = h, p
		}
		out = append(out, Target{Host: host, Port: port})
	}
	return out
}

// normalizeTarget 规整用户输入：兼容直接粘贴的完整网址。
//
// 例：https://host/path?q#f → host；http://10.0.0.1:8443/x → 10.0.0.1:8443。
// CIDR 写法（10.0.0.0/24）原样保留，避免被当作路径截断（展开为 TODO）。
func normalizeTarget(t string) string {
	t = strings.TrimSpace(t)
	if t == "" {
		return ""
	}
	// 去 scheme：http(s)://host... → host...
	if i := strings.Index(t, "://"); i >= 0 {
		t = t[i+3:]
	}
	// CIDR 原样返回。
	if _, _, err := net.ParseCIDR(t); err == nil {
		return t
	}
	// 去路径/查询/锚点：host[:port]/path?x#y → host[:port]
	if i := strings.IndexAny(t, "/?#"); i >= 0 {
		t = t[:i]
	}
	return strings.TrimSpace(t)
}

// splitHostPort 解析 "host:port"，仅在末段为合法端口号时拆分，
// 避免误伤 IPv6 字面量或带 "/" 的网段写法。
func splitHostPort(s string) (string, int, bool) {
	if strings.Contains(s, "/") {
		return "", 0, false
	}
	idx := strings.LastIndex(s, ":")
	if idx < 0 || idx == len(s)-1 {
		return "", 0, false
	}
	portStr := s[idx+1:]
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return "", 0, false
	}
	return s[:idx], port, true
}

// certLongLived 判断证书有效期是否距今超过 10 年。
func certLongLived(notAfter *time.Time) bool {
	if notAfter == nil {
		return false
	}
	return notAfter.After(time.Now().AddDate(10, 0, 0))
}
