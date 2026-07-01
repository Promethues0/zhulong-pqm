package scan

import (
	"encoding/binary"
	"testing"
)

// ---- 合成抓包构造器（动态回填长度，避免手算错） ----

func u16(v int) []byte { return []byte{byte(v >> 8), byte(v)} }

func tlsRecord(hs []byte) []byte {
	rec := []byte{0x16, 0x03, 0x01}
	rec = append(rec, u16(len(hs))...)
	return append(rec, hs...)
}

func handshake(hsType byte, body []byte) []byte {
	h := []byte{hsType, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}
	return append(h, body...)
}

func clientHello(sni string, cipher int) []byte {
	var b []byte
	b = append(b, 0x03, 0x03)
	b = append(b, make([]byte, 32)...)
	b = append(b, 0x00)
	b = append(b, u16(2)...)
	b = append(b, u16(cipher)...)
	b = append(b, 0x01, 0x00)
	host := []byte(sni)
	entry := append([]byte{0x00}, u16(len(host))...)
	entry = append(entry, host...)
	snList := append(u16(len(entry)), entry...)
	ext := append([]byte{0x00, 0x00}, u16(len(snList))...)
	ext = append(ext, snList...)
	b = append(b, u16(len(ext))...)
	b = append(b, ext...)
	return tlsRecord(handshake(0x01, b))
}

func serverHello(cipher int) []byte {
	var b []byte
	b = append(b, 0x03, 0x03)
	b = append(b, make([]byte, 32)...)
	b = append(b, 0x00)
	b = append(b, u16(cipher)...)
	b = append(b, 0x00)
	return tlsRecord(handshake(0x02, b))
}

// framePacket 把 TCP 载荷封成 Ethernet/IPv4/TCP 帧（可指定序列号）。
func framePacket(payload []byte, srcIP, dstIP [4]byte, srcPort, dstPort int, seq uint32) []byte {
	tcp := make([]byte, 20)
	binary.BigEndian.PutUint16(tcp[0:2], uint16(srcPort))
	binary.BigEndian.PutUint16(tcp[2:4], uint16(dstPort))
	binary.BigEndian.PutUint32(tcp[4:8], seq)
	tcp[12] = 5 << 4
	tcp = append(tcp, payload...)

	ip := make([]byte, 20)
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:4], uint16(20+len(tcp)))
	ip[9] = 6
	copy(ip[12:16], srcIP[:])
	copy(ip[16:20], dstIP[:])
	ip = append(ip, tcp...)

	eth := make([]byte, 14)
	binary.BigEndian.PutUint16(eth[12:14], 0x0800)
	return append(eth, ip...)
}

func buildPcap(frames [][]byte) []byte {
	out := make([]byte, 24)
	binary.BigEndian.PutUint32(out[0:4], 0xa1b2c3d4)
	binary.BigEndian.PutUint32(out[20:24], 1)
	for _, f := range frames {
		hdr := make([]byte, 16)
		binary.BigEndian.PutUint32(hdr[8:12], uint32(len(f)))
		binary.BigEndian.PutUint32(hdr[12:16], uint32(len(f)))
		out = append(out, hdr...)
		out = append(out, f...)
	}
	return out
}

// buildPcapng 用大端 pcapng（SHB + IDB(以太网) + 每帧一个 EPB）封装。
func buildPcapng(frames [][]byte) []byte {
	be := binary.BigEndian
	// SHB (28 字节)
	shb := make([]byte, 28)
	be.PutUint32(shb[0:4], 0x0A0D0D0A)
	be.PutUint32(shb[4:8], 28)
	be.PutUint32(shb[8:12], 0x1A2B3C4D)
	be.PutUint16(shb[12:14], 1)
	be.PutUint64(shb[16:24], 0xFFFFFFFFFFFFFFFF)
	be.PutUint32(shb[24:28], 28)
	// IDB (20 字节, linktype=1 以太网)
	idb := make([]byte, 20)
	be.PutUint32(idb[0:4], 0x00000001)
	be.PutUint32(idb[4:8], 20)
	be.PutUint16(idb[8:10], 1)
	be.PutUint32(idb[16:20], 20)
	out := append(append([]byte{}, shb...), idb...)
	// EPB 每帧
	for _, f := range frames {
		pad := (4 - len(f)%4) % 4
		total := 32 + len(f) + pad
		epb := make([]byte, 28)
		be.PutUint32(epb[0:4], 0x00000006)
		be.PutUint32(epb[4:8], uint32(total))
		be.PutUint32(epb[20:24], uint32(len(f))) // captured_len
		be.PutUint32(epb[24:28], uint32(len(f))) // original_len
		epb = append(epb, f...)
		epb = append(epb, make([]byte, pad)...)
		tail := make([]byte, 4)
		be.PutUint32(tail, uint32(total))
		epb = append(epb, tail...)
		out = append(out, epb...)
	}
	return out
}

func TestParsePCAP_TLSHandshake(t *testing.T) {
	client := [4]byte{10, 0, 0, 1}
	server := [4]byte{10, 0, 0, 2}
	ch := framePacket(clientHello("example.com", 0xc02f), client, server, 12345, 443, 0)
	sh := framePacket(serverHello(0xc030), server, client, 443, 12345, 0)
	obs, st, err := ParsePCAP(buildPcap([][]byte{ch, sh}))
	if err != nil {
		t.Fatalf("ParsePCAP err: %v", err)
	}
	if len(obs) != 1 {
		t.Fatalf("期望 1 端点，实得 %d (%+v)", len(obs), obs)
	}
	o := obs[0]
	if o.Host != "10.0.0.2" || o.Port != 443 || o.SNI != "example.com" || o.Algo != "RSA" ||
		o.Cipher != "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384" || o.Version != "TLS1.2" {
		t.Errorf("观测错: %+v", o)
	}
	if st.Format != "pcap" || st.Handshakes != 2 || st.Endpoints != 1 {
		t.Errorf("统计错: %+v", st)
	}
}

// TestParsePCAP_Reassembly 把一个 ClientHello 拆成两个 TCP 段（正确序列号），验证跨段重组。
func TestParsePCAP_Reassembly(t *testing.T) {
	client := [4]byte{10, 1, 1, 1}
	server := [4]byte{10, 1, 1, 2}
	full := clientHello("split.example.org", 0xc02f)
	cut := 20
	part1 := full[:cut]
	part2 := full[cut:]
	base := uint32(1000)
	f1 := framePacket(part1, client, server, 55555, 443, base)
	f2 := framePacket(part2, client, server, 55555, 443, base+uint32(len(part1)))
	obs, _, err := ParsePCAP(buildPcap([][]byte{f1, f2}))
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(obs) != 1 || obs[0].SNI != "split.example.org" {
		t.Fatalf("跨段重组未还原 ClientHello: %+v", obs)
	}
}

// TestParsePCAP_Pcapng 同样的握手放进 pcapng 容器，验证 pcapng 解析。
func TestParsePCAP_Pcapng(t *testing.T) {
	client := [4]byte{10, 2, 2, 1}
	server := [4]byte{10, 2, 2, 2}
	ch := framePacket(clientHello("ng.example.net", 0xc02b), client, server, 40000, 8443, 0)
	sh := framePacket(serverHello(0xc02b), server, client, 8443, 40000, 0)
	obs, st, err := ParsePCAP(buildPcapng([][]byte{ch, sh}))
	if err != nil {
		t.Fatalf("pcapng err: %v", err)
	}
	if st.Format != "pcapng" {
		t.Errorf("格式应识别为 pcapng: %+v", st)
	}
	if len(obs) != 1 || obs[0].SNI != "ng.example.net" || obs[0].Algo != "ECDSA" {
		t.Fatalf("pcapng 解析错: %+v", obs)
	}
}

func TestParsePCAP_Rejects(t *testing.T) {
	if _, _, err := ParsePCAP([]byte("not a pcap at all, random bytes......")); err == nil {
		t.Error("非抓包应报错")
	}
	// 截断记录不 panic。
	frame := framePacket([]byte{0x16, 0x03, 0x01, 0x00, 0xff, 0x01}, [4]byte{1, 1, 1, 1}, [4]byte{2, 2, 2, 2}, 1, 443, 0)
	if _, _, err := ParsePCAP(buildPcap([][]byte{frame})); err != nil {
		t.Errorf("截断记录不应致错: %v", err)
	}
}
