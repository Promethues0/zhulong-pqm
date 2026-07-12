package main

import (
	"encoding/binary"
	"errors"
	"os/exec"
	"testing"

	"zhulong-pqm/internal/model"
	"zhulong-pqm/internal/scan"
)

// serverHelloKeyShare 造一个 TLS ServerHello 记录，key_share 扩展选中 group（HRR 布局：仅 selected_group）。
func serverHelloKeyShare(group int) []byte {
	ks := []byte{0x00, 0x33, 0x00, 0x02, byte(group >> 8), byte(group)} // key_share ext, data=selected_group(2)
	body := []byte{0x03, 0x03}
	body = append(body, make([]byte, 32)...) // random
	body = append(body, 0x00)                // session_id_len
	body = append(body, 0x13, 0x01)          // cipher TLS_AES_128_GCM_SHA256
	body = append(body, 0x00)                // compression
	body = append(body, byte(len(ks)>>8), byte(len(ks)))
	body = append(body, ks...)
	hs := append([]byte{0x02, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}, body...)
	return append([]byte{0x16, 0x03, 0x03, byte(len(hs) >> 8), byte(len(hs))}, hs...)
}

// tlsFrame 把 TLS 负载封成 Ethernet+IPv4+TCP 帧（src=服务端）。长度全部计算，避免手写偏移出错。
func tlsFrame(payload []byte, src, dst [4]byte, sport, dport int) []byte {
	tcp := make([]byte, 20)
	binary.BigEndian.PutUint16(tcp[0:2], uint16(sport))
	binary.BigEndian.PutUint16(tcp[2:4], uint16(dport))
	binary.BigEndian.PutUint32(tcp[4:8], 1000) // seq
	tcp[12] = 0x50                             // data offset 5 words
	tcp[13] = 0x18                             // PSH+ACK
	binary.BigEndian.PutUint16(tcp[14:16], 0xffff)
	seg := append(tcp, payload...)
	ip := make([]byte, 20)
	ip[0] = 0x45 // ver4 IHL5
	ip[8] = 64   // TTL
	ip[9] = 6    // TCP
	binary.BigEndian.PutUint16(ip[2:4], uint16(20+len(seg)))
	copy(ip[12:16], src[:])
	copy(ip[16:20], dst[:])
	pkt := append(ip, seg...)
	eth := []byte{0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 1, 0x08, 0x00} // dst/src MAC + IPv4
	return append(eth, pkt...)
}

func TestWrapPcap_RoundTripThroughParsePCAP(t *testing.T) {
	frame := tlsFrame(serverHelloKeyShare(0x11EC), [4]byte{10, 0, 0, 5}, [4]byte{10, 0, 0, 9}, 443, 50000)
	pcapBytes := wrapPcap([][]byte{frame})

	obs, stats, err := scan.ParsePCAP(pcapBytes)
	if err != nil {
		t.Fatalf("ParsePCAP err: %v", err)
	}
	if stats.Format != "pcap" || stats.Packets != 1 {
		t.Fatalf("pcap 封装异常: format=%s packets=%d", stats.Format, stats.Packets)
	}
	if len(obs) != 1 {
		t.Fatalf("期望 1 个观测端点，得 %d (%+v)", len(obs), obs)
	}
	o := obs[0]
	if o.Host != "10.0.0.5" || o.Port != 443 {
		t.Errorf("端点 = %s:%d, want 10.0.0.5:443", o.Host, o.Port)
	}
	if o.KexGroup != "X25519MLKEM768" || o.KexSafety != "hybrid" {
		t.Errorf("协商组 = (%q,%q), want (X25519MLKEM768,hybrid)", o.KexGroup, o.KexSafety)
	}
}

func TestObservationsToAssets(t *testing.T) {
	obs := []scan.TLSObservation{{
		Host: "10.0.0.5", Port: 1443, SNI: "gw.internal", Version: "TLS1.3",
		Cipher: "TLS_AES_256_GCM_SHA384", Algo: "RSA", KeySize: 2048,
		CertFP: "abc123", KexGroup: "curveSM2MLKEM768", KexSafety: "hybrid",
	}}
	assets := observationsToAssets(obs)
	if len(assets) != 1 {
		t.Fatalf("期望 1 条资产，得 %d", len(assets))
	}
	a := assets[0]
	if a.Endpoint != "10.0.0.5:1443" {
		t.Errorf("Endpoint = %q, want 10.0.0.5:1443", a.Endpoint)
	}
	if a.KexGroup != "curveSM2MLKEM768" || a.KexSafety != "hybrid" {
		t.Errorf("KEX = (%q,%q), want (curveSM2MLKEM768,hybrid)", a.KexGroup, a.KexSafety)
	}
	if a.AuthSafety != "classical" { // RSA 证书 → 认证维经典
		t.Errorf("AuthSafety = %q, want classical", a.AuthSafety)
	}
	if a.Layer != model.LayerL1 {
		t.Errorf("Layer = %q, want L1", a.Layer)
	}
}

func TestAssetsFromPcap(t *testing.T) {
	frame := tlsFrame(serverHelloKeyShare(0x11EC), [4]byte{10, 0, 0, 7}, [4]byte{10, 0, 0, 9}, 8443, 40000)
	assets, stats, err := assetsFromPcap(wrapPcap([][]byte{frame}))
	if err != nil {
		t.Fatalf("assetsFromPcap err: %v", err)
	}
	if stats.Handshakes < 1 || len(assets) != 1 {
		t.Fatalf("stats=%+v assets=%d", stats, len(assets))
	}
	if assets[0].KexGroup != "X25519MLKEM768" {
		t.Errorf("KexGroup = %q, want X25519MLKEM768", assets[0].KexGroup)
	}
}

func TestCapture_ModeSelection(t *testing.T) {
	// mac(非 linux)：afpacket 强制 → captureAFPacket stub 返回 unavailable → Capture 报错（不回退）
	_, err := Capture(&Config{CaptureMode: "afpacket", Duration: 1})
	if err == nil || !errors.Is(err, errCaptureUnavailable) {
		t.Errorf("afpacket 强制在非 Linux 应报 errCaptureUnavailable，得 %v", err)
	}
	// tcpdump 强制但环境无 tcpdump → 也应是 errCaptureUnavailable
	if _, e := exec.LookPath("tcpdump"); e != nil {
		if _, ce := Capture(&Config{CaptureMode: "tcpdump", Duration: 1}); !errors.Is(ce, errCaptureUnavailable) {
			t.Errorf("无 tcpdump 时 tcpdump 强制应报 errCaptureUnavailable，得 %v", ce)
		}
	}
}
