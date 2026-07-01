package scan

import (
	"encoding/binary"
	"fmt"
	"net"
)

// M2 被动流量发现：解析上传的 classic libpcap 抓包，按 TCP 流提取 TLS 握手，
// 归并出每个服务端 endpoint 的密码学观测（协议版本 / 协商套件 / 认证算法 / 证书）。
//
// 纯 Go、无 CGO、无 libpcap 依赖——只读 classic .pcap 文件（tcpdump -w / Wireshark 另存）。
// pcapng（Wireshark 默认）请另存为 pcap。全程守界：畸形/截断的不可信输入不 panic。

// TLSObservation M2 观测到的一个服务端 TLS 端点。
type TLSObservation struct {
	Host    string // 服务端 IP
	Port    int    // 服务端端口
	SNI     string // ClientHello SNI（服务标识）
	Version string // 协商 TLS 版本
	Cipher  string // 协商密码套件
	Algo    string // 推导认证算法（证书优先，否则套件推导）
	KeySize int    // 证书密钥位数（抓到证书时）
	CertFP  string // 叶证书 SHA-256 指纹（抓到证书时）
	Subject string // 叶证书 CN（抓到证书时）
}

// PcapStats 解析统计（供审计/前端展示）。
type PcapStats struct {
	Packets    int `json:"packets"`
	TCPSegs    int `json:"tcpSegments"`
	Handshakes int `json:"handshakes"`
	Endpoints  int `json:"endpoints"`
}

const maxPcapPackets = 500000 // 处理包数上限，防超大文件

// ParsePCAP 解析 classic libpcap 字节流，返回服务端 TLS 观测与统计。
func ParsePCAP(data []byte) ([]TLSObservation, PcapStats, error) {
	var st PcapStats
	if len(data) >= 4 && data[0] == 0x0a && data[1] == 0x0d && data[2] == 0x0d && data[3] == 0x0a {
		return nil, st, fmt.Errorf("检测到 pcapng 格式，暂仅支持 classic .pcap；请用 tcpdump -w 或 Wireshark「另存为」pcap 后重试")
	}
	if len(data) < 24 {
		return nil, st, fmt.Errorf("不是有效的 pcap 文件（过短）")
	}
	var bo binary.ByteOrder
	switch magic := binary.BigEndian.Uint32(data[:4]); magic {
	case 0xa1b2c3d4, 0xa1b23c4d:
		bo = binary.BigEndian
	case 0xd4c3b2a1, 0x4d3cb2a1:
		bo = binary.LittleEndian
	default:
		return nil, st, fmt.Errorf("无法识别的 pcap 魔数 0x%08x（需 classic libpcap）", magic)
	}
	linkType := bo.Uint32(data[20:24])

	// 归并键 = 服务端 "ip:port"。
	byEndpoint := map[string]*TLSObservation{}
	get := func(ip string, port int) *TLSObservation {
		key := fmt.Sprintf("%s:%d", ip, port)
		o := byEndpoint[key]
		if o == nil {
			o = &TLSObservation{Host: ip, Port: port}
			byEndpoint[key] = o
		}
		return o
	}

	off := 24
	for off+16 <= len(data) && st.Packets < maxPcapPackets {
		inclLen := int(bo.Uint32(data[off+8 : off+12]))
		off += 16
		if inclLen <= 0 || off+inclLen > len(data) {
			break // 截断的最后一个包
		}
		pkt := data[off : off+inclLen]
		off += inclLen
		st.Packets++

		payload, l3 := stripLink(pkt, linkType)
		if payload == nil {
			continue
		}
		srcIP, dstIP, tcp := decodeIPTCP(payload, l3)
		if tcp == nil {
			continue
		}
		sp, dp, tpay := decodeTCP(tcp)
		if len(tpay) == 0 {
			continue
		}
		st.TCPSegs++
		hs := parseTLSPayload(tpay)
		if hs == nil {
			continue
		}
		st.Handshakes++
		switch {
		case hs.isClientHello:
			// 客户端 → 服务端：服务端 = dst。
			o := get(dstIP, dp)
			if hs.sni != "" {
				o.SNI = hs.sni
			}
			if o.Cipher == "" && hs.cipher != "" { // 仅在无 ServerHello 时暂用客户端首选
				o.Cipher, o.Algo = hs.cipher, hs.keyAlgo
			}
			if o.Version == "" {
				o.Version = hs.version
			}
		case hs.isServerHello:
			// 服务端 → 客户端：服务端 = src。ServerHello 权威覆盖套件/版本。
			o := get(srcIP, sp)
			o.Cipher = hs.cipher
			if hs.keyAlgo != "" {
				o.Algo = hs.keyAlgo
			}
			o.Version = hs.version
		case hs.certAlgo != "":
			// Certificate：服务端 = src。证书算法权威，覆盖套件推导。
			o := get(srcIP, sp)
			o.Algo = hs.certAlgo
			o.KeySize = hs.certKeySize
			o.CertFP = hs.certFP
			if o.Subject == "" {
				o.Subject = hs.certSubject
			}
		}
	}

	out := make([]TLSObservation, 0, len(byEndpoint))
	for _, o := range byEndpoint {
		out = append(out, *o)
	}
	st.Endpoints = len(out)
	return out, st, nil
}

// stripLink 按链路类型剥掉 L2，返回 L3 载荷与其 EtherType 提示（0x0800/0x86DD）。
func stripLink(pkt []byte, linkType uint32) ([]byte, uint16) {
	switch linkType {
	case 1: // Ethernet
		if len(pkt) < 14 {
			return nil, 0
		}
		et := binary.BigEndian.Uint16(pkt[12:14])
		i := 14
		for et == 0x8100 || et == 0x88a8 { // VLAN / QinQ
			if i+4 > len(pkt) {
				return nil, 0
			}
			et = binary.BigEndian.Uint16(pkt[i+2 : i+4])
			i += 4
		}
		return pkt[i:], et
	case 0: // NULL/loopback：4 字节地址族（host order，容错两端）
		if len(pkt) < 4 {
			return nil, 0
		}
		fam := pkt[0] // 小端时族在首字节
		switch fam {
		case 2:
			return pkt[4:], 0x0800
		case 24, 28, 30:
			return pkt[4:], 0x86DD
		}
		return pkt[4:], 0x0800
	case 101: // RAW IP
		return pkt, 0
	case 113: // LINUX_SLL
		if len(pkt) < 16 {
			return nil, 0
		}
		return pkt[16:], binary.BigEndian.Uint16(pkt[14:16])
	default:
		return nil, 0
	}
}

// decodeIPTCP 解 IPv4/IPv6，返回 src/dst IP 与 TCP 段（非 TCP 返回 nil）。
func decodeIPTCP(p []byte, et uint16) (string, string, []byte) {
	if len(p) < 1 {
		return "", "", nil
	}
	ver := p[0] >> 4
	if et == 0x86DD || ver == 6 {
		if len(p) < 40 || p[6] != 6 { // next_header=TCP（不追扩展头，MVP）
			return "", "", nil
		}
		src := net.IP(p[8:24]).String()
		dst := net.IP(p[24:40]).String()
		return src, dst, p[40:]
	}
	// IPv4
	if ver != 4 || len(p) < 20 {
		return "", "", nil
	}
	ihl := int(p[0]&0x0f) * 4
	if ihl < 20 || len(p) < ihl || p[9] != 6 { // protocol=TCP
		return "", "", nil
	}
	src := net.IP(p[12:16]).String()
	dst := net.IP(p[16:20]).String()
	return src, dst, p[ihl:]
}

// decodeTCP 返回 src/dst 端口与 TCP 载荷。
func decodeTCP(t []byte) (int, int, []byte) {
	if len(t) < 20 {
		return 0, 0, nil
	}
	sp := int(binary.BigEndian.Uint16(t[0:2]))
	dp := int(binary.BigEndian.Uint16(t[2:4]))
	dataOff := int(t[12]>>4) * 4
	if dataOff < 20 || len(t) < dataOff {
		return sp, dp, nil
	}
	return sp, dp, t[dataOff:]
}
