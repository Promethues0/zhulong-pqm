package scan

import (
	"bufio"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"zhulong-pqm/internal/model"
)

// SSHDefaultPort SSH 默认端口。
const SSHDefaultPort = 22

// SSHScanner 审计 SSH 服务的密钥交换(KEX)与主机密钥算法。
//
// 实现说明：golang.org/x/crypto/ssh 高层 API 不暴露服务端协商的算法名列表，
// 故采用「最小协议实现」——读 banner 后直接解析服务端首个 SSH_MSG_KEXINIT
// 报文中的 KEX / host-key 名字列表（机读直证，置信度=高），不做完整握手、
// 不需凭据。无法读到 KEXINIT 时诚实降级，仅记录 banner。
type SSHScanner struct{}

// NewSSHScanner 构造 SSH 审计扫描器。
func NewSSHScanner() *SSHScanner { return &SSHScanner{} }

// Method 返回发现方式 M1（主动协议探测）。
func (s *SSHScanner) Method() string { return model.MethodM1ActiveTLS }

// Name 返回扫描器名 ssh。
func (s *SSHScanner) Name() string { return model.ScannerSSH }

// sshKexInit 解析出的 SSH 协商能力。
type sshKexInit struct {
	Banner       string
	KexAlgos     []string
	HostKeyAlgos []string
	simulated    bool
}

// Scan 完成一次 SSH 协议探测：读 banner + 解析 KEXINIT 名字列表。
func (s *SSHScanner) Scan(ctx context.Context, host string, port int) (*model.ScanResult, error) {
	if port == 0 {
		port = SSHDefaultPort
	}
	addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))

	dctx, cancel := context.WithTimeout(ctx, dialTimeout)
	defer cancel()

	d := &net.Dialer{Timeout: dialTimeout}
	conn, err := d.DialContext(dctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("ssh dial %s: %w", addr, err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(dialTimeout))

	info, err := readSSHKexInit(conn)
	if err != nil {
		return nil, fmt.Errorf("ssh probe %s: %w", addr, err)
	}

	hostKeyType := primaryHostKey(info.HostKeyAlgos)
	res := &model.ScanResult{
		Host:        host,
		Port:        port,
		TLSVersion:  info.Banner, // 复用字段承载 SSH banner（协议版本串）
		CipherSuite: strings.Join(info.KexAlgos, ","),
		KeyAlgo:     hostKeyType,
		SigAlgo:     hostKeyType,
	}

	raw, _ := json.Marshal(map[string]any{
		"banner":       info.Banner,
		"kexAlgos":     info.KexAlgos,
		"hostKeyAlgos": info.HostKeyAlgos,
		"simulated":    info.simulated,
	})
	res.Raw = string(raw)
	return res, nil
}

// Hits 实现 HitMatcher：从解析出的 KEX/host-key 列表命中 R-L1-05/R-L2-05。
func (s *SSHScanner) Hits(res *model.ScanResult) []model.RuleHit {
	kex := []string{}
	if res.CipherSuite != "" {
		kex = strings.Split(res.CipherSuite, ",")
	}
	return MatchSSHRules(res, kex, res.KeyAlgo)
}

// readSSHKexInit 读取 SSH 标识串与首个 KEXINIT 报文，解析 KEX/host-key 名字列表。
func readSSHKexInit(conn net.Conn) (sshKexInit, error) {
	var out sshKexInit
	br := bufio.NewReader(conn)

	// 1) 客户端先发标识串（RFC4253 4.2）。
	if _, err := conn.Write([]byte("SSH-2.0-ZhulongPQM-Audit\r\n")); err != nil {
		return out, err
	}
	// 2) 读服务端标识串（可能前置若干非 SSH- 行）。
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			return out, err
		}
		line = strings.TrimRight(line, "\r\n")
		if strings.HasPrefix(line, "SSH-") {
			out.Banner = line
			break
		}
	}

	// 3) 读二进制分组（RFC4253 6）：packet_length(4)|padding_length(1)|payload|padding。
	var lenBuf [4]byte
	if _, err := io.ReadFull(br, lenBuf[:]); err != nil {
		out.simulated = true
		return out, nil // 读不到 KEXINIT：诚实降级，仅留 banner。
	}
	pktLen := binary.BigEndian.Uint32(lenBuf[:])
	if pktLen < 2 || pktLen > 65535 {
		out.simulated = true
		return out, nil
	}
	pkt := make([]byte, pktLen)
	if _, err := io.ReadFull(br, pkt); err != nil {
		out.simulated = true
		return out, nil
	}
	padLen := int(pkt[0])
	payload := pkt[1:]
	if padLen < len(payload) {
		payload = payload[:len(payload)-padLen]
	}
	if len(payload) < 17 || payload[0] != 20 { // 20 = SSH_MSG_KEXINIT
		out.simulated = true
		return out, nil
	}
	// payload: msg(1) | cookie(16) | name-list × 10 ...
	p := payload[17:]
	lists, err := readNameLists(p, 2) // 仅需前两组：kex_algorithms, server_host_key_algorithms
	if err != nil {
		out.simulated = true
		return out, nil
	}
	out.KexAlgos = splitNameList(lists[0])
	out.HostKeyAlgos = splitNameList(lists[1])
	return out, nil
}

// readNameLists 顺序读取 n 个 SSH name-list（uint32 长度前缀 + UTF-8 逗号分隔串）。
func readNameLists(b []byte, n int) ([]string, error) {
	out := make([]string, 0, n)
	for i := 0; i < n; i++ {
		if len(b) < 4 {
			return nil, fmt.Errorf("name-list 截断")
		}
		l := binary.BigEndian.Uint32(b[:4])
		b = b[4:]
		if uint32(len(b)) < l {
			return nil, fmt.Errorf("name-list 长度越界")
		}
		out = append(out, string(b[:l]))
		b = b[l:]
	}
	return out, nil
}

func splitNameList(s string) []string {
	if s == "" {
		return nil
	}
	return strings.Split(s, ",")
}

// primaryHostKey 取首个主机密钥算法并归一为类型名（rsa/ecdsa/ed25519）。
func primaryHostKey(algos []string) string {
	if len(algos) == 0 {
		return ""
	}
	a := strings.ToLower(algos[0])
	switch {
	case strings.Contains(a, "ed25519"):
		return "Ed25519"
	case strings.Contains(a, "ecdsa"):
		return "ECDSA"
	case strings.Contains(a, "rsa"):
		return "RSA"
	case strings.Contains(a, "dss"):
		return "DSS"
	default:
		return algos[0]
	}
}
