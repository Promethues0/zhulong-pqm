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

// maxCIDRHosts 单个 CIDR 网段展开的主机数上限，防止 /8 之类把任务/内存打爆。
// 超出则只取前 maxCIDRHosts 个（约一个 /22）。
const maxCIDRHosts = 1024

// ParseTargets 将原始目标字符串解析为 (host, port) 列表。
//
// 支持 "host" 与 "host:port" 两种写法，未带端口时回落到 DefaultPort。
// CIDR 网段（如 10.0.0.0/24）会展开为段内全部可探测主机地址（端口取 DefaultPort），
// 上限 maxCIDRHosts；非 IPv4 网段不展开，按单目标处理。
func ParseTargets(raw []string) []Target {
	out := make([]Target, 0, len(raw))
	for _, t := range raw {
		t = normalizeTarget(t)
		if t == "" {
			continue
		}
		if hosts := expandCIDR(t); hosts != nil {
			for _, h := range hosts {
				out = append(out, Target{Host: h, Port: DefaultPort})
			}
			continue
		}
		host := t
		port := DefaultPort
		if h, p, ok := splitHostPort(t); ok {
			host, port = h, p
		}
		out = append(out, Target{Host: host, Port: port})
	}
	return out
}

// expandCIDR 把 IPv4 CIDR（如 "10.0.0.0/24"）展开为段内可探测主机地址；
// 非 CIDR 或非 IPv4 返回 nil（交由上层按单目标处理）。
// 掩码留有 ≥2 主机位时去掉网络号与广播号；展开数受 maxCIDRHosts 限制。
func expandCIDR(t string) []string {
	ip, ipnet, err := net.ParseCIDR(t)
	if err != nil || ip.To4() == nil {
		return nil
	}
	var all []net.IP
	for cur := ip.Mask(ipnet.Mask); ipnet.Contains(cur); cur = nextIP(cur) {
		dup := make(net.IP, len(cur))
		copy(dup, cur)
		all = append(all, dup)
		if len(all) > maxCIDRHosts+2 {
			break
		}
	}
	// 去网络号(首)与广播号(尾)：仅当掩码有 ≥2 主机位且未触发截断时。
	if ones, bits := ipnet.Mask.Size(); bits-ones >= 2 && len(all) > 2 && len(all) <= maxCIDRHosts+2 {
		all = all[1 : len(all)-1]
	}
	if len(all) > maxCIDRHosts {
		all = all[:maxCIDRHosts]
	}
	out := make([]string, 0, len(all))
	for _, ip := range all {
		out = append(out, ip.String())
	}
	return out
}

// nextIP 返回 ip 的下一个地址（大端 +1）。
func nextIP(ip net.IP) net.IP {
	n := make(net.IP, len(ip))
	copy(n, ip)
	for i := len(n) - 1; i >= 0; i-- {
		n[i]++
		if n[i] != 0 {
			break
		}
	}
	return n
}

// normalizeTarget 规整用户输入：兼容直接粘贴的完整网址。
//
// 例：https://host/path?q#f → host；http://10.0.0.1:8443/x → 10.0.0.1:8443。
// CIDR 写法（10.0.0.0/24）原样保留，避免被当作路径截断（由 ParseTargets 展开）。
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
