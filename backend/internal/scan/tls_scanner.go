package scan

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"time"

	"zhulong-pqm/internal/model"
)

// certSHA256 计算证书 DER 的 SHA-256 指纹（十六进制，去重锚点输入）。
func certSHA256(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(sum[:])
}

// dialTimeout 单次握手的超时时间。
const dialTimeout = 5 * time.Second

// TLSScanner 通过完成 TLS 握手来探测目标端点的密码学特征。
//
// 使用 InsecureSkipVerify 以便对自签名/过期证书也能取到证书链；
// 这里只读取握手协商出的算法与证书元数据，不做信任决策。
type TLSScanner struct{}

// NewTLSScanner 构造一个 TLS 探测器。
func NewTLSScanner() *TLSScanner { return &TLSScanner{} }

// Method 返回发现方式标识 M1（主动 TLS 握手）。
func (s *TLSScanner) Method() string { return model.MethodM1ActiveTLS }

// Name 返回扫描器名。
func (s *TLSScanner) Name() string { return model.ScannerTLS }

// Scan 完成一次 TLS 握手并提取版本、套件、公钥与证书信息。
func (s *TLSScanner) Scan(ctx context.Context, host string, port int) (*model.ScanResult, error) {
	addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))

	dialer := &tls.Dialer{
		NetDialer: &net.Dialer{Timeout: dialTimeout},
		Config: &tls.Config{
			InsecureSkipVerify: true, // 仅取证书，不做信任校验
			ServerName:         host,
		},
	}

	ctx, cancel := context.WithTimeout(ctx, dialTimeout)
	defer cancel()

	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("tls dial %s: %w", addr, err)
	}
	defer conn.Close()

	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		return nil, fmt.Errorf("非 TLS 连接: %s", addr)
	}
	state := tlsConn.ConnectionState()

	res := &model.ScanResult{
		Host:        host,
		Port:        port,
		TLSVersion:  tlsVersionName(state.Version),
		CipherSuite: tls.CipherSuiteName(state.CipherSuite),
	}

	if len(state.PeerCertificates) > 0 {
		leaf := state.PeerCertificates[0]
		fillCertInfo(res, leaf)
	}

	// 留存原始快照供审计/前端展开。
	if raw, mErr := json.Marshal(map[string]any{
		"tlsVersion":  res.TLSVersion,
		"cipherSuite": res.CipherSuite,
		"keyAlgo":     res.KeyAlgo,
		"keySize":     res.KeySize,
		"sigAlgo":     res.SigAlgo,
		"subject":     res.CertSubject,
		"issuer":      res.CertIssuer,
	}); mErr == nil {
		res.Raw = string(raw)
	}

	return res, nil
}

// fillCertInfo 从叶证书提取公钥算法、密钥位数、签名算法与主体/签发者。
// PEM/证书导入路径（M5）复用同一函数。
func fillCertInfo(res *model.ScanResult, cert *x509.Certificate) {
	res.SigAlgo = cert.SignatureAlgorithm.String()
	res.CertSubject = cert.Subject.CommonName
	res.CertIssuer = cert.Issuer.CommonName
	res.CertFingerprint = certSHA256(cert)

	na := cert.NotAfter
	res.CertNotAfter = &na

	switch cert.PublicKeyAlgorithm {
	case x509.RSA:
		res.KeyAlgo = "RSA"
		if pub, ok := cert.PublicKey.(*rsa.PublicKey); ok {
			res.KeySize = pub.N.BitLen()
		}
	case x509.ECDSA:
		res.KeyAlgo = "ECDSA"
		if pub, ok := cert.PublicKey.(*ecdsa.PublicKey); ok {
			res.KeySize = pub.Curve.Params().BitSize
		}
	case x509.Ed25519:
		res.KeyAlgo = "Ed25519"
		res.KeySize = 256
	default:
		res.KeyAlgo = cert.PublicKeyAlgorithm.String()
	}
}

// tlsVersionName 将 TLS 版本号转为可读名称。
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
