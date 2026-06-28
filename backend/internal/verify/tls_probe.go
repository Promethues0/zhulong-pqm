package verify

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"time"
)

// dialTimeout 单次握手超时（沿用 scan.TLSScanner 的 5s 口径）。
const dialTimeout = 5 * time.Second

// 混合 KEM 组的 IANA CurveID。Go 1.23 stdlib 未导出该常量名（1.24+ 才有
// tls.X25519MLKEM768），故按 IANA 码点显式定义；0x11ec 为正式 X25519MLKEM768，
// 0x6399 为早期 draft（x25519Kyber768Draft00），两者都接受以兼容不同对端栈。
const (
	curveX25519MLKEM768      tls.CurveID = 0x11ec
	curveX25519Kyber768Draft tls.CurveID = 0x6399
)

// probeOutcome 一次 TLS 探测的可观测结果。
//
// 诚实边界：Go 1.23 的 tls.ConnectionState 不暴露协商出的 KEM 组，故无法直接读出
// CurveID。改用「锁定 CurvePreferences 仅含目标组 + 握手成败」做可靠推断——
// 若仅提供混合组而握手成功，则对端必然协商了该组（TLS 1.3 从我方提供的组中选）。
type probeOutcome struct {
	Reachable    bool   // 是否完成 TCP 连接（不论握手成败）
	Handshake    bool   // TLS 握手是否成功
	TLSVersion   string // 协商出的 TLS 版本
	CipherSuite  string // 协商出的套件
	CertSubject  string // 叶证书主体
	CertVerified bool   // 在做信任校验时证书是否通过
	Err          string // 失败原因（握手/证书校验/拨号）
}

// probeHybrid 对 target 用「仅混合 KEM 组」握手：成功即证明对端协商了混合组。
// 用于 V-PROTO-01（混合握手）。
func probeHybrid(ctx context.Context, target string) probeOutcome {
	return dialTLS(ctx, target, &tls.Config{
		InsecureSkipVerify: true, // 此处只判组协商，不做信任决策
		MinVersion:         tls.VersionTLS13,
		CurvePreferences:   []tls.CurveID{curveX25519MLKEM768, curveX25519Kyber768Draft},
	})
}

// probeClassicOnly 对 target 仅以 X25519 握手：成功即证明向后兼容回退可用。
// 用于 V-PROTO-02（旧客户端回退）。剥离混合组后亦用于 V-SEC-01 的降级探测。
func probeClassicOnly(ctx context.Context, target string) probeOutcome {
	return dialTLS(ctx, target, &tls.Config{
		InsecureSkipVerify: true,
		CurvePreferences:   []tls.CurveID{tls.X25519},
	})
}

// probeVerified 对 target 做带信任校验的握手：证书验证失败即连接中止。
// 用于 V-SEC-03（伪造 ServerHello / 证书校验）。
func probeVerified(ctx context.Context, target string) probeOutcome {
	host := target
	if h, _, ok := splitHostPort(target); ok {
		host = h
	}
	return dialTLS(ctx, target, &tls.Config{
		InsecureSkipVerify: false,
		ServerName:         host,
	})
}

// dialTLS 执行一次带超时的 TLS 拨号握手并收敛为 probeOutcome。
func dialTLS(ctx context.Context, target string, cfg *tls.Config) probeOutcome {
	addr := normalizeTarget(target)
	dialer := &tls.Dialer{
		NetDialer: &net.Dialer{Timeout: dialTimeout},
		Config:    cfg,
	}
	ctx, cancel := context.WithTimeout(ctx, dialTimeout)
	defer cancel()

	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		out := probeOutcome{Err: err.Error()}
		// 区分「拨不通」与「握手/证书被拒」：含 certificate/handshake 关键字视为可达但握手失败。
		msg := strings.ToLower(err.Error())
		if strings.Contains(msg, "certificate") || strings.Contains(msg, "handshake") ||
			strings.Contains(msg, "tls") || strings.Contains(msg, "no cipher") ||
			strings.Contains(msg, "protocol version") {
			out.Reachable = true
		}
		return out
	}
	defer conn.Close()

	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		return probeOutcome{Reachable: true, Err: "非 TLS 连接"}
	}
	st := tlsConn.ConnectionState()
	out := probeOutcome{
		Reachable:    true,
		Handshake:    true,
		CertVerified: !cfg.InsecureSkipVerify,
		TLSVersion:   tlsVersionName(st.Version),
		CipherSuite:  tls.CipherSuiteName(st.CipherSuite),
	}
	if len(st.PeerCertificates) > 0 {
		out.CertSubject = st.PeerCertificates[0].Subject.CommonName
	}
	return out
}

// normalizeTarget 补默认端口 443。
func normalizeTarget(target string) string {
	target = strings.TrimSpace(target)
	if _, _, ok := splitHostPort(target); ok {
		return target
	}
	return net.JoinHostPort(target, "443")
}

// splitHostPort 解析 host:port（与 scan 包同口径，仅末段为合法端口才拆）。
func splitHostPort(s string) (string, int, bool) {
	if strings.Contains(s, "/") {
		return "", 0, false
	}
	idx := strings.LastIndex(s, ":")
	if idx < 0 || idx == len(s)-1 {
		return "", 0, false
	}
	portStr := s[idx+1:]
	port := 0
	for _, ch := range portStr {
		if ch < '0' || ch > '9' {
			return "", 0, false
		}
		port = port*10 + int(ch-'0')
	}
	if port < 1 || port > 65535 {
		return "", 0, false
	}
	return s[:idx], port, true
}

// tlsVersionName TLS 版本号转可读名（与 scan 包一致）。
func tlsVersionName(v uint16) string {
	switch v {
	case tls.VersionTLS13:
		return "TLS 1.3"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS10:
		return "TLS 1.0"
	default:
		return fmt.Sprintf("0x%04x", v)
	}
}
