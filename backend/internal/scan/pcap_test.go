package scan

import (
	"encoding/binary"
	"testing"
)

// ---- 合成 pcap 构造器（动态回填长度，避免手算错） ----

func u16(v int) []byte { return []byte{byte(v >> 8), byte(v)} }

// tlsRecord 包一层 TLS 记录（type=22 handshake, ver=0x0301）。
func tlsRecord(hs []byte) []byte {
	rec := []byte{0x16, 0x03, 0x01}
	rec = append(rec, u16(len(hs))...)
	return append(rec, hs...)
}

// handshake 包一层握手头（type + 3 字节长度）。
func handshake(hsType byte, body []byte) []byte {
	h := []byte{hsType, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}
	return append(h, body...)
}

func clientHello(sni string, cipher int) []byte {
	var b []byte
	b = append(b, 0x03, 0x03)                 // client_version TLS1.2
	b = append(b, make([]byte, 32)...)        // random
	b = append(b, 0x00)                       // session_id_len
	b = append(b, u16(2)...)                   // cipher_suites_len
	b = append(b, u16(cipher)...)              // one cipher
	b = append(b, 0x01, 0x00)                 // compression: len1, null
	// SNI 扩展
	host := []byte(sni)
	entry := append([]byte{0x00}, u16(len(host))...)
	entry = append(entry, host...)
	snList := append(u16(len(entry)), entry...)
	ext := append([]byte{0x00, 0x00}, u16(len(snList))...)
	ext = append(ext, snList...)
	b = append(b, u16(len(ext))...) // extensions_len
	b = append(b, ext...)
	return tlsRecord(handshake(0x01, b))
}

func serverHello(cipher int) []byte {
	var b []byte
	b = append(b, 0x03, 0x03)          // server_version TLS1.2
	b = append(b, make([]byte, 32)...) // random
	b = append(b, 0x00)                // session_id_len
	b = append(b, u16(cipher)...)      // chosen cipher
	b = append(b, 0x00)                // compression null
	return tlsRecord(handshake(0x02, b))
}

// framePacket 把 TCP 载荷封成 Ethernet/IPv4/TCP 帧。
func framePacket(payload []byte, srcIP, dstIP [4]byte, srcPort, dstPort int) []byte {
	tcp := make([]byte, 20)
	binary.BigEndian.PutUint16(tcp[0:2], uint16(srcPort))
	binary.BigEndian.PutUint16(tcp[2:4], uint16(dstPort))
	tcp[12] = 5 << 4 // data offset = 20 bytes
	tcp = append(tcp, payload...)

	ip := make([]byte, 20)
	ip[0] = 0x45 // v4, IHL=5
	binary.BigEndian.PutUint16(ip[2:4], uint16(20+len(tcp)))
	ip[9] = 6 // TCP
	copy(ip[12:16], srcIP[:])
	copy(ip[16:20], dstIP[:])
	ip = append(ip, tcp...)

	eth := make([]byte, 14)
	binary.BigEndian.PutUint16(eth[12:14], 0x0800) // IPv4
	return append(eth, ip...)
}

// buildPcap 用 classic libpcap 大端头封装若干帧。
func buildPcap(frames [][]byte) []byte {
	out := make([]byte, 24)
	binary.BigEndian.PutUint32(out[0:4], 0xa1b2c3d4) // 大端 µs
	binary.BigEndian.PutUint32(out[20:24], 1)        // linktype Ethernet
	for _, f := range frames {
		hdr := make([]byte, 16)
		binary.BigEndian.PutUint32(hdr[8:12], uint32(len(f)))  // incl_len
		binary.BigEndian.PutUint32(hdr[12:16], uint32(len(f))) // orig_len
		out = append(out, hdr...)
		out = append(out, f...)
	}
	return out
}

func TestParsePCAP_TLSHandshake(t *testing.T) {
	client := [4]byte{10, 0, 0, 1}
	server := [4]byte{10, 0, 0, 2}
	// ClientHello: 提供 0xc02f(ECDHE_RSA)，SNI=example.com。
	ch := framePacket(clientHello("example.com", 0xc02f), client, server, 12345, 443)
	// ServerHello: 协商 0xc030(ECDHE_RSA_AES256_GCM) → 认证 RSA。
	sh := framePacket(serverHello(0xc030), server, client, 443, 12345)
	pcap := buildPcap([][]byte{ch, sh})

	obs, st, err := ParsePCAP(pcap)
	if err != nil {
		t.Fatalf("ParsePCAP err: %v", err)
	}
	if len(obs) != 1 {
		t.Fatalf("期望 1 个端点观测，实得 %d (%+v)", len(obs), obs)
	}
	o := obs[0]
	if o.Host != "10.0.0.2" || o.Port != 443 {
		t.Errorf("端点错: %s:%d", o.Host, o.Port)
	}
	if o.SNI != "example.com" {
		t.Errorf("SNI 错: %q", o.SNI)
	}
	if o.Algo != "RSA" {
		t.Errorf("认证算法应 RSA（ServerHello 0xc030 覆盖），实得 %q", o.Algo)
	}
	if o.Cipher != "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384" {
		t.Errorf("协商套件错: %q", o.Cipher)
	}
	if o.Version != "TLS1.2" {
		t.Errorf("版本错: %q", o.Version)
	}
	if st.Handshakes != 2 || st.Endpoints != 1 {
		t.Errorf("统计错: %+v", st)
	}
}

func TestParsePCAP_Rejects(t *testing.T) {
	// pcapng 魔数 → 友好报错。
	if _, _, err := ParsePCAP([]byte{0x0a, 0x0d, 0x0d, 0x0a, 0, 0, 0, 0}); err == nil {
		t.Error("pcapng 应报错")
	}
	// 垃圾 → 报错不 panic。
	if _, _, err := ParsePCAP([]byte("not a pcap at all, random bytes......")); err == nil {
		t.Error("非 pcap 应报错")
	}
	// 截断的记录不 panic。
	frame := framePacket([]byte{0x16, 0x03, 0x01, 0x00, 0xff, 0x01}, [4]byte{1, 1, 1, 1}, [4]byte{2, 2, 2, 2}, 1, 443)
	if _, _, err := ParsePCAP(buildPcap([][]byte{frame})); err != nil {
		t.Errorf("截断记录不应致错: %v", err)
	}
}
