package remediate

import (
	"context"
	"net"
	"net/http"
	"net/url"
	"time"
)

// probeTimeout 单次连通性探测的超时。
const probeTimeout = 3 * time.Second

// ProbeResult 一次设备连通性探测的结果。
type ProbeResult struct {
	Online    bool   // 是否可达
	LatencyMs int    // 探测耗时（毫秒）
	Detail    string // 人类可读说明
}

// Probe 对设备 endpoint 做真实连通性探测。
//
// 优先 HTTP GET {endpoint}/healthz（任意 HTTP 响应即视为在线，连得上比状态码更重要）；
// 失败则退化为对 host:port 的 TCP 连接探测。两路均失败才判离线。
// 探测绝不 panic、不返回 error——离线是正常结果而非异常。
func Probe(ctx context.Context, endpoint string) ProbeResult {
	start := time.Now()

	if r, ok := probeHTTP(ctx, endpoint); ok {
		r.LatencyMs = int(time.Since(start).Milliseconds())
		return r
	}
	// HTTP 不通：退化到 TCP 连接探测。
	if r, ok := probeTCP(ctx, endpoint); ok {
		r.LatencyMs = int(time.Since(start).Milliseconds())
		return r
	}

	return ProbeResult{
		Online:    false,
		LatencyMs: int(time.Since(start).Milliseconds()),
		Detail:    "HTTP /healthz 与 TCP 连接均不可达",
	}
}

// probeHTTP 尝试 HTTP GET {endpoint}/healthz；任意响应视为在线。
func probeHTTP(ctx context.Context, endpoint string) (ProbeResult, bool) {
	if endpoint == "" {
		return ProbeResult{}, false
	}
	target := joinHealthz(endpoint)
	cctx, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(cctx, http.MethodGet, target, nil)
	if err != nil {
		return ProbeResult{}, false
	}
	client := &http.Client{Timeout: probeTimeout}
	resp, err := client.Do(req)
	if err != nil {
		return ProbeResult{}, false
	}
	defer resp.Body.Close()
	return ProbeResult{
		Online: true,
		Detail: "HTTP /healthz 可达，状态码 " + resp.Status,
	}, true
}

// probeTCP 对 endpoint 的 host:port 做 TCP 连接探测。
func probeTCP(ctx context.Context, endpoint string) (ProbeResult, bool) {
	host := hostPort(endpoint)
	if host == "" {
		return ProbeResult{}, false
	}
	d := net.Dialer{Timeout: probeTimeout}
	conn, err := d.DialContext(ctx, "tcp", host)
	if err != nil {
		return ProbeResult{}, false
	}
	_ = conn.Close()
	return ProbeResult{Online: true, Detail: "TCP 连接可达 " + host}, true
}

// joinHealthz 把 /healthz 拼到 endpoint 路径后。
func joinHealthz(endpoint string) string {
	if u, err := url.Parse(endpoint); err == nil && u.Host != "" {
		u.Path = singleSlash(u.Path) + "healthz"
		return u.String()
	}
	// 非标准 URL：直接拼接。
	return trimRightSlash(endpoint) + "/healthz"
}

// hostPort 从 endpoint 提取 host:port，缺端口时按 scheme 补默认端口。
func hostPort(endpoint string) string {
	u, err := url.Parse(endpoint)
	if err != nil || u.Host == "" {
		return ""
	}
	if u.Port() != "" {
		return u.Host
	}
	switch u.Scheme {
	case "https":
		return u.Hostname() + ":443"
	default:
		return u.Hostname() + ":80"
	}
}

func singleSlash(p string) string {
	if p == "" {
		return "/"
	}
	if p[len(p)-1] != '/' {
		return p + "/"
	}
	return p
}

func trimRightSlash(s string) string {
	for len(s) > 0 && s[len(s)-1] == '/' {
		s = s[:len(s)-1]
	}
	return s
}
