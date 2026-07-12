package main

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"zhulong-pqm/internal/cryptoref"
	"zhulong-pqm/internal/model"
)

// listenerDialTimeout 本地握手探测的超时——只连本机地址，快速失败即可。
const listenerDialTimeout = 2 * time.Second

// discoverListeners 读 {fsRoot}/proc/net/tcp[6] 找本地 LISTEN 端口（含仅绑 127.0.0.1、
// 或被安全组挡在外部的端口——这类端口 Agentless 远程扫描完全看不到），逐个本地用
// crypto/tls.Dial 握手（仅连 127.0.0.1，真实网络操作但只触达本机；超时 2s；握手失败即
// 跳过，很多监听端口根本不是 TLS）。非 Linux（无 /proc/net/tcp）返回 nil。
func discoverListeners(fsRoot string) []model.CryptoAsset {
	ports := listenPorts(fsRoot)
	if len(ports) == 0 {
		return nil
	}
	var out []model.CryptoAsset
	for _, port := range ports {
		addr := fmt.Sprintf("127.0.0.1:%d", port)
		if asset, ok := probeLocalTLS(addr); ok {
			out = append(out, asset)
		}
	}
	return out
}

// listenPorts 解析 /proc/net/tcp 与 tcp6 里状态为 0A（TCP_LISTEN）的本地端口，去重。
func listenPorts(fsRoot string) []int {
	seen := map[int]bool{}
	for _, f := range []string{"tcp", "tcp6"} {
		parseListenFile(filepath.Join(fsRoot, "proc", "net", f), seen)
	}
	ports := make([]int, 0, len(seen))
	for p := range seen {
		ports = append(ports, p)
	}
	return ports
}

// parseListenFile 解析单个 /proc/net/tcp[6] 文件，把 LISTEN 状态行的本地端口写进 seen。
func parseListenFile(path string, seen map[int]bool) {
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	first := true
	for sc.Scan() {
		if first { // 首行是表头（sl local_address rem_address st ...）
			first = false
			continue
		}
		fields := strings.Fields(sc.Text())
		if len(fields) < 4 {
			continue
		}
		if !strings.EqualFold(fields[3], "0A") { // st 列，0A = TCP_LISTEN
			continue
		}
		parts := strings.Split(fields[1], ":") // local_address = "IP十六进制:PORT十六进制"
		if len(parts) != 2 {
			continue
		}
		portNum, err := strconv.ParseUint(parts[1], 16, 32)
		if err != nil {
			continue
		}
		seen[int(portNum)] = true
	}
}

// probeLocalTLS 本地 TLS 握手拿证书；非 TLS 端口/握手失败返回 ok=false（正常情况，跳过即可）。
func probeLocalTLS(addr string) (model.CryptoAsset, bool) {
	dialer := &net.Dialer{Timeout: listenerDialTimeout}
	conn, err := tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{InsecureSkipVerify: true}) // #nosec G402 -- 仅用于本机被动探测证书信息，非信任判断
	if err != nil {
		return model.CryptoAsset{}, false
	}
	defer conn.Close()
	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return model.CryptoAsset{}, false
	}
	leaf := state.PeerCertificates[0]
	algo, keySize := certPublicKeyInfo(leaf)
	notAfter := leaf.NotAfter
	return model.CryptoAsset{
		Name:            "本地监听服务 " + addr,
		Algorithm:       algo,
		KeySize:         keySize,
		Protocol:        tlsVersionName(state.Version),
		Endpoint:        addr,
		CertFingerprint: certFingerprint(leaf),
		CertNotAfter:    &notAfter,
		Layer:           model.LayerL1,
		Exposure:        model.ExposureInternal,
		AuthSafety:      cryptoref.AuthSafetyForAlgo(algo),
		RiskHint:        "本地握手探测（含仅绑 127.0.0.1 或被安全组拦截、Agentless 扫描不可见的端口）",
	}, true
}

// tlsVersionName TLS 协议版本常量 → 可读名。
func tlsVersionName(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "TLS1.0"
	case tls.VersionTLS11:
		return "TLS1.1"
	case tls.VersionTLS12:
		return "TLS1.2"
	case tls.VersionTLS13:
		return "TLS1.3"
	default:
		return fmt.Sprintf("TLS(0x%04x)", v)
	}
}
