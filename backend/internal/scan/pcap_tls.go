package scan

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"
)

// TLS 握手解析（M2 被动流量发现的 L7 提取）。
//
// 全部在【不可信的上传字节】上运行，故每一步都做边界检查，遇到截断/畸形即安全返回，
// 绝不 panic（越界 slice 会 panic → 必须自己守界）。

// tlsHandshake 从一段 TCP 载荷里提取的 TLS 握手要点。
type tlsHandshake struct {
	isClientHello bool
	isServerHello bool
	version       string   // 记录层/协商版本文案
	sni           string   // ClientHello SNI
	cipher        string   // ServerHello 协商套件名（或 ClientHello 首个非 GREASE 套件）
	keyAlgo       string   // 由套件推导的认证算法（RSA/ECDSA/SM2/DH），TLS1.3 留空待证书
	certAlgo      string   // Certificate 消息解析出的叶证书公钥算法
	certKeySize   int      // 叶证书密钥位数
	certFP        string   // 叶证书 SHA-256 指纹
	certSubject   string   // 叶证书 CN
}

// hsMsg 一条握手消息（类型 + 体，体已跨 TLS 记录/TCP 段拼接完整）。
type hsMsg struct {
	typ  byte
	body []byte
}

// handshakeMessages 从【已重组的 TCP 定向字节流】里抽取握手消息。
//
// 两步：① 把所有 handshake(type=22) TLS 记录的分片拼成握手字节流——这样跨 TLS 记录、
// 跨 TCP 段的 ClientHello / 大证书链都能被完整还原；② 按握手消息头(type+3字节长度)切分。
func handshakeMessages(stream []byte) []hsMsg {
	// ① 拼接所有 handshake 记录负载。
	var hsBuf []byte
	i := 0
	for i+5 <= len(stream) {
		ctype := stream[i]
		if stream[i+1] != 0x03 && stream[i+1] != 0x01 { // 非 TLS/TLCP 记录版本 → 非握手数据，停
			break
		}
		recLen := int(stream[i+3])<<8 | int(stream[i+4])
		if recLen <= 0 {
			break
		}
		start := i + 5
		end := start + recLen
		if end > len(stream) {
			end = len(stream) // 截断：取可见部分
		}
		if ctype == 0x16 { // handshake
			hsBuf = append(hsBuf, stream[start:end]...)
		} else if ctype != 0x14 { // 非 handshake/非 CCS(0x14)：握手已结束（AppData/Alert），停
			break
		}
		i = end
	}
	// ② 切分握手消息。
	var out []hsMsg
	j := 0
	for j+4 <= len(hsBuf) {
		typ := hsBuf[j]
		mlen := int(hsBuf[j+1])<<16 | int(hsBuf[j+2])<<8 | int(hsBuf[j+3])
		bstart := j + 4
		bend := bstart + mlen
		truncated := bend > len(hsBuf)
		if truncated {
			bend = len(hsBuf)
		}
		out = append(out, hsMsg{typ: typ, body: hsBuf[bstart:bend]})
		if truncated {
			break // 最后一条被截断，尽力解析后停止
		}
		j = bend
	}
	return out
}

// parseHandshakeMsg 解析一条完整握手消息为观测；非目标类型返回 nil。
func parseHandshakeMsg(typ byte, body []byte) *tlsHandshake {
	out := &tlsHandshake{}
	switch typ {
	case 0x01:
		out.isClientHello = true
		parseHello(body, out, true)
	case 0x02:
		out.isServerHello = true
		parseHello(body, out, false)
	case 0x0b:
		parseCertificate(body, out)
		if out.certAlgo == "" {
			return nil // Certificate 但没解出叶证书（截断），视为无效
		}
	default:
		return nil
	}
	return out
}

// parseHello 解析 ClientHello/ServerHello 共同前缀，client=true 时额外抓 SNI。
func parseHello(b []byte, out *tlsHandshake, client bool) {
	// version(2) random(32) session_id_len(1)+id
	if len(b) < 34 {
		return
	}
	// 握手体内的 version 字段比记录层版本更权威（记录层常年为 0x0301）。
	out.version = tlsRecordVersion(b[0], b[1])
	i := 34
	if i >= len(b) {
		return
	}
	sidLen := int(b[i])
	i += 1 + sidLen
	if client {
		// cipher_suites_len(2) + suites
		if i+2 > len(b) {
			return
		}
		csLen := int(b[i])<<8 | int(b[i+1])
		i += 2
		if i+csLen > len(b) {
			return
		}
		out.cipher, out.keyAlgo = firstMeaningfulSuite(b[i : i+csLen])
		i += csLen
		// compression_len(1)+methods
		if i >= len(b) {
			return
		}
		compLen := int(b[i])
		i += 1 + compLen
		// extensions
		out.sni = parseSNI(b, i)
	} else {
		// ServerHello: cipher_suite(2)
		if i+2 > len(b) {
			return
		}
		suite := int(b[i])<<8 | int(b[i+1])
		name, algo := suiteInfo(suite)
		out.cipher, out.keyAlgo = name, algo
		// 抓 supported_versions 扩展修正 TLS1.3 版本文案
		i += 3 // cipher(2)+compression(1)
		if v := parseSupportedVersion(b, i); v != "" {
			out.version = v
		}
	}
}

// parseSNI 从扩展区（extensions_len(2)+entries）里取 server_name(host_name)。
func parseSNI(b []byte, i int) string {
	if i+2 > len(b) {
		return ""
	}
	extLen := int(b[i])<<8 | int(b[i+1])
	i += 2
	end := i + extLen
	if end > len(b) {
		end = len(b)
	}
	for i+4 <= end {
		etype := int(b[i])<<8 | int(b[i+1])
		elen := int(b[i+2])<<8 | int(b[i+3])
		i += 4
		if i+elen > end {
			return ""
		}
		if etype == 0x0000 { // server_name
			e := b[i : i+elen]
			// server_name_list(2) + name_type(1) + host_name_len(2) + host
			if len(e) >= 5 && e[2] == 0x00 {
				hlen := int(e[3])<<8 | int(e[4])
				if 5+hlen <= len(e) {
					return string(e[5 : 5+hlen])
				}
			}
			return ""
		}
		i += elen
	}
	return ""
}

// parseSupportedVersion 在 ServerHello 扩展里找 supported_versions(0x002b) → TLS1.3。
func parseSupportedVersion(b []byte, i int) string {
	if i+2 > len(b) {
		return ""
	}
	extLen := int(b[i])<<8 | int(b[i+1])
	i += 2
	end := i + extLen
	if end > len(b) {
		end = len(b)
	}
	for i+4 <= end {
		etype := int(b[i])<<8 | int(b[i+1])
		elen := int(b[i+2])<<8 | int(b[i+3])
		i += 4
		if etype == 0x002b && i+2 <= end && b[i] == 0x03 && b[i+1] == 0x04 {
			return "TLS1.3"
		}
		i += elen
	}
	return ""
}

// parseCertificate 解析 Certificate 消息，取叶证书公钥算法/位数/指纹（尽力，跨段截断则放弃）。
func parseCertificate(b []byte, out *tlsHandshake) {
	// certificate_request_context 省略（TLS1.2 无此字段；TLS1.3 有 1 字节 ctx_len）。
	// 兼容：先按 TLS1.2 布局 certs_len(3)，失败再试 TLS1.3（ctx_len(1)+certs_len(3)）。
	for _, off := range []int{0, 1} {
		i := off
		if i+3 > len(b) {
			continue
		}
		if off == 1 {
			ctxLen := int(b[0])
			i = 1 + ctxLen
			if i+3 > len(b) {
				continue
			}
		}
		listLen := int(b[i])<<16 | int(b[i+1])<<8 | int(b[i+2])
		i += 3
		if listLen == 0 || i+3 > len(b) {
			continue
		}
		certLen := int(b[i])<<16 | int(b[i+1])<<8 | int(b[i+2])
		i += 3
		if certLen <= 0 || i+certLen > len(b) {
			continue // 叶证书跨段被截断，放弃
		}
		der := b[i : i+certLen]
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			continue
		}
		out.certAlgo = certPublicKeyAlgo(cert)
		out.certKeySize = certKeyBits(cert)
		sum := sha256.Sum256(der)
		out.certFP = hex.EncodeToString(sum[:])
		out.certSubject = cert.Subject.CommonName
		return
	}
}

// firstMeaningfulSuite 取客户端提供列表里首个非 GREASE 套件的名称与推导算法。
func firstMeaningfulSuite(b []byte) (string, string) {
	for i := 0; i+2 <= len(b); i += 2 {
		s := int(b[i])<<8 | int(b[i+1])
		if isGREASE(s) || s == 0x00ff { // GREASE / SCSV 跳过
			continue
		}
		return suiteInfo(s)
	}
	return "", ""
}

// isGREASE 判断是否 GREASE 占位值（0x0A0A、0x1A1A…0xFAFA）。
func isGREASE(s int) bool {
	return (s&0x0f0f) == 0x0a0a && (s>>8) == (s&0xff)
}

// suiteInfo 密码套件 → (名称, 认证算法)。认证算法用于 CryptoAsset.Algorithm 与后量子评分。
// TLS1.3 套件不编码认证算法（取决于证书），认证算法留空。
func suiteInfo(s int) (string, string) {
	if v, ok := cipherSuites[s]; ok {
		return v.name, v.algo
	}
	return fmt.Sprintf("0x%04X", s), ""
}

type suiteMeta struct {
	name string
	algo string
}

// cipherSuites 常见套件表（够覆盖 TLS1.2/1.3 + 国密 TLCP 的主流）。
var cipherSuites = map[int]suiteMeta{
	// RSA 密钥交换/认证
	0x000a: {"TLS_RSA_WITH_3DES_EDE_CBC_SHA", "RSA"},
	0x002f: {"TLS_RSA_WITH_AES_128_CBC_SHA", "RSA"},
	0x0035: {"TLS_RSA_WITH_AES_256_CBC_SHA", "RSA"},
	0x003c: {"TLS_RSA_WITH_AES_128_CBC_SHA256", "RSA"},
	0x009c: {"TLS_RSA_WITH_AES_128_GCM_SHA256", "RSA"},
	0x009d: {"TLS_RSA_WITH_AES_256_GCM_SHA384", "RSA"},
	// ECDHE_RSA（认证 RSA）
	0xc013: {"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA", "RSA"},
	0xc014: {"TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA", "RSA"},
	0xc02f: {"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "RSA"},
	0xc030: {"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", "RSA"},
	0xcca8: {"TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256", "RSA"},
	// ECDHE_ECDSA（认证 ECDSA）
	0xc009: {"TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA", "ECDSA"},
	0xc00a: {"TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA", "ECDSA"},
	0xc02b: {"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", "ECDSA"},
	0xc02c: {"TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384", "ECDSA"},
	0xcca9: {"TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256", "ECDSA"},
	// DHE_RSA（认证 RSA，交换 DH）
	0x0033: {"TLS_DHE_RSA_WITH_AES_128_CBC_SHA", "RSA"},
	0x0039: {"TLS_DHE_RSA_WITH_AES_256_CBC_SHA", "RSA"},
	0x009e: {"TLS_DHE_RSA_WITH_AES_128_GCM_SHA256", "RSA"},
	0x009f: {"TLS_DHE_RSA_WITH_AES_256_GCM_SHA384", "RSA"},
	// TLS 1.3（认证在证书里，algo 留空）
	0x1301: {"TLS_AES_128_GCM_SHA256", ""},
	0x1302: {"TLS_AES_256_GCM_SHA384", ""},
	0x1303: {"TLS_CHACHA20_POLY1305_SHA256", ""},
	0x1304: {"TLS_AES_128_CCM_SHA256", ""},
	0x1305: {"TLS_AES_128_CCM_8_SHA256", ""},
	// 国密 TLCP（认证 SM2）
	0xe011: {"ECDHE_SM4_CBC_SM3", "SM2"},
	0xe013: {"ECC_SM4_GCM_SM3", "SM2"},
	0xe051: {"ECDHE_SM4_GCM_SM3", "SM2"},
	0xe053: {"ECC_SM4_GCM_SM3", "SM2"},
}

// tlsRecordVersion TLS 记录层版本 → 文案。
func tlsRecordVersion(hi, lo byte) string {
	switch {
	case hi == 0x03 && lo == 0x01:
		return "TLS1.0"
	case hi == 0x03 && lo == 0x02:
		return "TLS1.1"
	case hi == 0x03 && lo == 0x03:
		return "TLS1.2" // 1.3 也用 0x0303 记录版本，由 supported_versions 修正
	case hi == 0x01 && lo == 0x01:
		return "TLCP1.1"
	default:
		return fmt.Sprintf("0x%02X%02X", hi, lo)
	}
}

// certPublicKeyAlgo x509 公钥算法 → 平台算法名。
func certPublicKeyAlgo(c *x509.Certificate) string {
	switch c.PublicKeyAlgorithm {
	case x509.RSA:
		return "RSA"
	case x509.ECDSA:
		return "ECDSA"
	case x509.Ed25519:
		return "Ed25519"
	case x509.DSA:
		return "DSA"
	default:
		return c.PublicKeyAlgorithm.String()
	}
}

// certKeyBits 叶证书密钥位数（RSA 模长 / ECDSA 曲线位）。
func certKeyBits(c *x509.Certificate) int {
	switch pk := c.PublicKey.(type) {
	case *rsa.PublicKey:
		return pk.N.BitLen()
	case *ecdsa.PublicKey:
		if pk.Curve != nil {
			return pk.Curve.Params().BitSize
		}
	}
	return 0
}
