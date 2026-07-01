package scan

import (
	"encoding/binary"
	"fmt"
	"net"
)

// M2 被动流量发现：解析上传的抓包（classic .pcap 与 pcapng），按 TCP 流【重组】后
// 提取 TLS 握手，归并出每个服务端 endpoint 的密码学观测。
//
// 纯 Go、无 CGO、无 libpcap。重组支持跨 TCP 段的大 ClientHello 与多段证书链。
// 全程守界：畸形/截断的不可信输入不 panic。

// TLSObservation M2 观测到的一个服务端 TLS 端点。
type TLSObservation struct {
	Host    string `json:"host"`
	Port    int    `json:"port"`
	SNI     string `json:"sni"`
	Version string `json:"version"`
	Cipher  string `json:"cipher"`
	Algo    string `json:"algo"`
	KeySize int    `json:"keySize"`
	CertFP  string `json:"certFp"`
	Subject string `json:"subject"`
}

// PcapStats 解析统计（供审计/前端展示）。
type PcapStats struct {
	Format     string `json:"format"` // pcap / pcapng
	Packets    int    `json:"packets"`
	TCPSegs    int    `json:"tcpSegments"`
	Flows      int    `json:"flows"`
	Handshakes int    `json:"handshakes"`
	Endpoints  int    `json:"endpoints"`
}

const (
	maxPcapPackets = 500000     // 处理包数上限
	maxFlows       = 50000      // 跟踪的 TLS 流上限
	maxSegsPerFlow = 256        // 单流缓存段数上限（握手都在流首）
	maxReassembly  = 512 * 1024 // 单流重组缓冲上限
)

// fkey 定向 TCP 流键（src→dst，方向敏感）。
type fkey struct {
	sip, dip   string
	sport, dport int
}

type tcpSeg struct {
	seq  uint32
	data []byte
}

type tcpFlow struct {
	segs []tcpSeg
}

// ParsePCAP 解析抓包字节流（classic pcap 或 pcapng），返回服务端 TLS 观测与统计。
func ParsePCAP(data []byte) ([]TLSObservation, PcapStats, error) {
	var st PcapStats
	flows := map[fkey]*tcpFlow{}

	switch {
	case len(data) >= 4 && data[0] == 0x0a && data[1] == 0x0d && data[2] == 0x0d && data[3] == 0x0a:
		st.Format = "pcapng"
		if err := walkPcapng(data, &st, flows); err != nil {
			return nil, st, err
		}
	case len(data) >= 24:
		st.Format = "pcap"
		if err := walkClassic(data, &st, flows); err != nil {
			return nil, st, err
		}
	default:
		return nil, st, fmt.Errorf("不是有效的抓包文件（过短或格式未知）")
	}

	st.Flows = len(flows)
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

	for k, f := range flows {
		stream := reassemble(f.segs)
		for _, m := range handshakeMessages(stream) {
			hs := parseHandshakeMsg(m.typ, m.body)
			if hs == nil {
				continue
			}
			st.Handshakes++
			switch {
			case hs.isClientHello:
				o := get(k.dip, k.dport) // 客户端→服务端：服务端=dst
				if hs.sni != "" {
					o.SNI = hs.sni
				}
				if o.Cipher == "" && hs.cipher != "" {
					o.Cipher, o.Algo = hs.cipher, hs.keyAlgo
				}
				if o.Version == "" {
					o.Version = hs.version
				}
			case hs.isServerHello:
				o := get(k.sip, k.sport) // 服务端→客户端：服务端=src
				o.Cipher = hs.cipher
				if hs.keyAlgo != "" {
					o.Algo = hs.keyAlgo
				}
				o.Version = hs.version
			case hs.certAlgo != "":
				o := get(k.sip, k.sport)
				o.Algo = hs.certAlgo // 证书算法权威，覆盖套件推导
				o.KeySize = hs.certKeySize
				o.CertFP = hs.certFP
				if o.Subject == "" {
					o.Subject = hs.certSubject
				}
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

// looksTLS 判断 TCP 载荷是否以 TLS/TLCP 握手记录起始（用于识别 TLS 流首段）。
func looksTLS(p []byte) bool {
	return len(p) >= 3 && p[0] == 0x16 && (p[1] == 0x03 || p[1] == 0x01)
}

// processPacket 解一个链路帧，若属 TLS 流则把 TCP 段并入对应流缓存。
func processPacket(linkType uint32, pkt []byte, st *PcapStats, flows map[fkey]*tcpFlow) {
	if st.Packets >= maxPcapPackets {
		return
	}
	st.Packets++
	payload, et := stripLink(pkt, linkType)
	if payload == nil {
		return
	}
	sip, dip, tcp := decodeIPTCP(payload, et)
	if tcp == nil {
		return
	}
	sp, dp, seq, tpay := decodeTCP(tcp)
	if len(tpay) == 0 {
		return
	}
	st.TCPSegs++
	k := fkey{sip: sip, dip: dip, sport: sp, dport: dp}
	f := flows[k]
	if f == nil {
		if !looksTLS(tpay) || len(flows) >= maxFlows {
			return // 只跟踪以 TLS 握手起始的流，且限流上限
		}
		f = &tcpFlow{}
		flows[k] = f
	}
	if len(f.segs) < maxSegsPerFlow {
		f.segs = append(f.segs, tcpSeg{seq: seq, data: tpay})
	}
}

// reassemble 按序列号把定向流的 TCP 段重组为连续字节流（重传首写优先，越界截断）。
func reassemble(segs []tcpSeg) []byte {
	if len(segs) == 0 {
		return nil
	}
	base := segs[0].seq
	for _, s := range segs[1:] {
		if int32(s.seq-base) < 0 { // 环回安全的“更早”判定
			base = s.seq
		}
	}
	end := 0
	for _, s := range segs {
		off := int(s.seq - base)
		if off < 0 || off > maxReassembly {
			continue
		}
		if e := off + len(s.data); e > end {
			end = e
		}
	}
	if end > maxReassembly {
		end = maxReassembly
	}
	if end == 0 {
		return nil
	}
	buf := make([]byte, end)
	filled := make([]bool, end)
	for _, s := range segs {
		off := int(s.seq - base)
		if off < 0 || off >= end {
			continue
		}
		for i := 0; i < len(s.data) && off+i < end; i++ {
			if !filled[off+i] { // 首写优先，避免重传覆盖
				buf[off+i] = s.data[i]
				filled[off+i] = true
			}
		}
	}
	return buf
}

// walkClassic 解 classic libpcap，逐包送 processPacket。
func walkClassic(data []byte, st *PcapStats, flows map[fkey]*tcpFlow) error {
	var bo binary.ByteOrder
	switch magic := binary.BigEndian.Uint32(data[:4]); magic {
	case 0xa1b2c3d4, 0xa1b23c4d:
		bo = binary.BigEndian
	case 0xd4c3b2a1, 0x4d3cb2a1:
		bo = binary.LittleEndian
	default:
		return fmt.Errorf("无法识别的 pcap 魔数 0x%08x（需 classic libpcap 或 pcapng）", magic)
	}
	linkType := bo.Uint32(data[20:24])
	off := 24
	for off+16 <= len(data) {
		inclLen := int(bo.Uint32(data[off+8 : off+12]))
		off += 16
		if inclLen <= 0 || off+inclLen > len(data) {
			break
		}
		processPacket(linkType, data[off:off+inclLen], st, flows)
		off += inclLen
	}
	return nil
}

// walkPcapng 解 pcapng（块式：SHB/IDB/EPB/SPB），逐包送 processPacket。
func walkPcapng(data []byte, st *PcapStats, flows map[fkey]*tcpFlow) error {
	if len(data) < 12 {
		return fmt.Errorf("pcapng 过短")
	}
	var bo binary.ByteOrder
	switch binary.BigEndian.Uint32(data[8:12]) { // SHB byte-order magic 0x1A2B3C4D
	case 0x1a2b3c4d:
		bo = binary.BigEndian
	case 0x4d3c2b1a:
		bo = binary.LittleEndian
	default:
		return fmt.Errorf("无法识别的 pcapng 字节序魔数")
	}
	var linkTypes []uint16 // 按 IDB 顺序
	off := 0
	for off+12 <= len(data) {
		btype := bo.Uint32(data[off : off+4])
		blen := int(bo.Uint32(data[off+4 : off+8]))
		if blen < 12 || off+blen > len(data) {
			break
		}
		block := data[off : off+blen]
		switch btype {
		case 0x00000001: // IDB：link_type 在块内偏移 8（block_type,total_len 之后）
			if len(block) >= 10 {
				linkTypes = append(linkTypes, bo.Uint16(block[8:10]))
			}
		case 0x00000006: // EPB
			if len(block) >= 28 {
				ifid := int(bo.Uint32(block[8:12]))
				capLen := int(bo.Uint32(block[20:24]))
				if capLen > 0 && 28+capLen <= len(block) {
					lt := uint32(1)
					if ifid >= 0 && ifid < len(linkTypes) {
						lt = uint32(linkTypes[ifid])
					}
					processPacket(lt, block[28:28+capLen], st, flows)
				}
			}
		case 0x00000003: // SPB：packet_data 从偏移 12 起，长度=blen-16（去头12+尾4）
			if blen >= 16 {
				dlen := blen - 16
				if dlen > 0 && 12+dlen <= len(block) {
					lt := uint32(1)
					if len(linkTypes) > 0 {
						lt = uint32(linkTypes[0])
					}
					processPacket(lt, block[12:12+dlen], st, flows)
				}
			}
		}
		off += blen
	}
	return nil
}

// stripLink 按链路类型剥掉 L2，返回 L3 载荷与 EtherType 提示。
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
	case 0: // NULL/loopback：4 字节地址族
		if len(pkt) < 4 {
			return nil, 0
		}
		switch pkt[0] {
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
		if len(p) < 40 || p[6] != 6 {
			return "", "", nil
		}
		return net.IP(p[8:24]).String(), net.IP(p[24:40]).String(), p[40:]
	}
	if ver != 4 || len(p) < 20 {
		return "", "", nil
	}
	ihl := int(p[0]&0x0f) * 4
	if ihl < 20 || len(p) < ihl || p[9] != 6 {
		return "", "", nil
	}
	return net.IP(p[12:16]).String(), net.IP(p[16:20]).String(), p[ihl:]
}

// decodeTCP 返回 src/dst 端口、序列号与 TCP 载荷。
func decodeTCP(t []byte) (int, int, uint32, []byte) {
	if len(t) < 20 {
		return 0, 0, 0, nil
	}
	sp := int(binary.BigEndian.Uint16(t[0:2]))
	dp := int(binary.BigEndian.Uint16(t[2:4]))
	seq := binary.BigEndian.Uint32(t[4:8])
	dataOff := int(t[12]>>4) * 4
	if dataOff < 20 || len(t) < dataOff {
		return sp, dp, seq, nil
	}
	return sp, dp, seq, t[dataOff:]
}
