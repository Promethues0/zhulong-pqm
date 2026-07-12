package scan

import (
	"encoding/binary"
	"fmt"
	"net"
	"time"
)

// 主动 PQC 枚举探针：构造只提供目标组、不带匹配 key_share 的 ClientHello，
// 逼服务端用 HelloRetryRequest（或 ServerHello）报出它选中的组——无需任何 PQC 密码运算。
//
// 全程只发一条 ClientHello、读一条响应记录，不完成握手。仅对授权目标使用。

// buildPQCClientHello 构造一条 TLS1.3 ClientHello 记录：supported_groups 放入 groups，
// key_share 只放一个 x25519 空壳（32 字节零），使服务端若选中某 PQC 组必回 HRR 报组。
func buildPQCClientHello(sni string, groups []int) []byte {
	var body []byte
	// legacy_version TLS1.2
	body = append(body, 0x03, 0x03)
	// random(32)
	body = append(body, make([]byte, 32)...)
	// legacy_session_id: 32 字节（兼容中间盒）
	body = append(body, 0x20)
	body = append(body, make([]byte, 32)...)
	// cipher_suites: TLS_AES_128_GCM_SHA256 + TLS_AES_256_GCM_SHA384
	body = append(body, 0x00, 0x04, 0x13, 0x01, 0x13, 0x02)
	// compression: null
	body = append(body, 0x01, 0x00)

	// ---- extensions ----
	var ext []byte
	ext = append(ext, extServerName(sni)...)
	ext = append(ext, extSupportedVersionsTLS13()...)
	ext = append(ext, extSupportedGroups(groups)...)
	ext = append(ext, extKeyShareX25519Empty()...)
	ext = append(ext, extSignatureAlgorithms()...)

	body = append(body, byte(len(ext)>>8), byte(len(ext)))
	body = append(body, ext...)

	// 握手消息头 type(1)=ClientHello + len(3)
	hs := []byte{0x01, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}
	hs = append(hs, body...)

	// 记录层 type(1)=handshake + version(2)=0x0301 + len(2)
	rec := []byte{0x16, 0x03, 0x01, byte(len(hs) >> 8), byte(len(hs))}
	rec = append(rec, hs...)
	return rec
}

func extServerName(sni string) []byte {
	if sni == "" {
		return nil
	}
	name := []byte(sni)
	// server_name_list: name_type(1)=0 + host_name_len(2) + host
	entry := append([]byte{0x00, byte(len(name) >> 8), byte(len(name))}, name...)
	list := append([]byte{byte(len(entry) >> 8), byte(len(entry))}, entry...)
	return extWrap(0x0000, list)
}

func extSupportedVersionsTLS13() []byte {
	// supported_versions: list_len(1)=2 + 0x0304
	return extWrap(0x002b, []byte{0x02, 0x03, 0x04})
}

func extSupportedGroups(groups []int) []byte {
	var list []byte
	for _, g := range groups {
		list = append(list, byte(g>>8), byte(g))
	}
	data := append([]byte{byte(len(list) >> 8), byte(len(list))}, list...)
	return extWrap(0x000a, data)
}

func extKeyShareX25519Empty() []byte {
	// key_share (client): client_shares_len(2) + [group=0x001D + len(2)=32 + 32 零字节]
	entry := append([]byte{0x00, 0x1D, 0x00, 0x20}, make([]byte, 32)...)
	data := append([]byte{byte(len(entry) >> 8), byte(len(entry))}, entry...)
	return extWrap(0x0033, data)
}

func extSignatureAlgorithms() []byte {
	// 覆盖经典 + PQC sigalg：ecdsa_secp256r1_sha256(0x0403)/rsa_pss(0x0804)/ed25519(0x0807)/ml-dsa-65(0x0905)
	sig := []byte{0x04, 0x03, 0x08, 0x04, 0x08, 0x07, 0x09, 0x05}
	data := append([]byte{byte(len(sig) >> 8), byte(len(sig))}, sig...)
	return extWrap(0x000d, data)
}

// extWrap 用 ext_type(2)+ext_len(2) 包一段扩展数据。
func extWrap(etype int, data []byte) []byte {
	out := []byte{byte(etype >> 8), byte(etype), byte(len(data) >> 8), byte(len(data))}
	return append(out, data...)
}

// ProbePQCGroups 逐组枚举：对每个目标组单独发一条只提供该组的 ClientHello，
// 若服务端 ServerHello/HRR 选中该组则计入 supported。返回服务端支持的 PQC/混合组码点。
func ProbePQCGroups(host string, port int, groups []int, timeout time.Duration) ([]int, error) {
	var supported []int
	for _, g := range groups {
		ok, err := probeOneGroup(host, port, g, timeout)
		if err != nil {
			continue // 单组失败不终止枚举（连接被拒/超时视为不支持）
		}
		if ok {
			supported = append(supported, g)
		}
	}
	return supported, nil
}

// probeOneGroup 发一条只提供组 g 的 ClientHello，读响应首条握手记录，判服务端是否选中 g。
func probeOneGroup(host string, port, g int, timeout time.Duration) (bool, error) {
	addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return false, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	ch := buildPQCClientHello(host, []int{g})
	if _, err := conn.Write(ch); err != nil {
		return false, err
	}

	// 读一条 TLS 记录头(5) + 体，尽量读满一条握手记录。
	hdr := make([]byte, 5)
	if _, err := readFull(conn, hdr); err != nil {
		return false, err
	}
	if hdr[0] != 0x16 { // 非 handshake（Alert=0x15 → 不支持）
		return false, nil
	}
	recLen := int(binary.BigEndian.Uint16(hdr[3:5]))
	if recLen <= 0 || recLen > 16384 {
		return false, nil
	}
	rec := make([]byte, recLen)
	if _, err := readFull(conn, rec); err != nil {
		return false, err
	}
	// rec 是握手消息流：type(1)+len(3)+body；ServerHello=0x02。复用 handshakeMessages 逻辑解 body。
	for _, m := range handshakeMessages(prependRecordFrame(rec)) {
		if m.typ != 0x02 { // 只看 ServerHello/HRR
			continue
		}
		out := &tlsHandshake{}
		parseHello(m.body, out, false)
		return out.negotiatedGroup == g, nil
	}
	return false, nil
}

// readFull 从 conn 读满 buf（DialTimeout 已设 deadline）。
func readFull(conn net.Conn, buf []byte) (int, error) {
	total := 0
	for total < len(buf) {
		n, err := conn.Read(buf[total:])
		if n > 0 {
			total += n
		}
		if err != nil {
			return total, err
		}
	}
	return total, nil
}

// prependRecordFrame 把裸握手记录体重新套上 handshake 记录头，喂给 handshakeMessages（它按记录切分）。
func prependRecordFrame(rec []byte) []byte {
	frame := []byte{0x16, 0x03, 0x03, byte(len(rec) >> 8), byte(len(rec))}
	return append(frame, rec...)
}
