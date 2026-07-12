package main

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// errCaptureUnavailable 标记「本机制在本环境不可用」（非 Linux / 无 CAP_NET_RAW / 缺 tcpdump），
// auto 模式据此在 AF_PACKET 与 tcpdump 间回退。
var errCaptureUnavailable = errors.New("capture mechanism unavailable")

// Capture 按 cfg.CaptureMode 选机制抓包，返回 pcap 字节流。
// auto：Linux 且能开 AF_PACKET → afpacket；否则回退 tcpdump；都不行 → 清晰错误。
func Capture(cfg *Config) ([]byte, error) {
	switch cfg.CaptureMode {
	case "afpacket":
		return captureAFPacket(cfg)
	case "tcpdump":
		return captureTcpdump(cfg)
	default: // auto
		b, err := captureAFPacket(cfg)
		if err == nil {
			return b, nil
		}
		if errors.Is(err, errCaptureUnavailable) {
			b2, err2 := captureTcpdump(cfg)
			if err2 == nil {
				return b2, nil
			}
			return nil, fmt.Errorf("AF_PACKET 不可用(%v)，tcpdump 回退也失败(%v)：请授 CAP_NET_RAW（setcap cap_net_raw+ep <binary>）或装 tcpdump", err, err2)
		}
		return nil, err
	}
}

// wrapPcap 把一组裸以太帧封成标准 classic pcap 字节流（linktype=1 Ethernet，大端）。
// 产物直接可喂 scan.ParsePCAP。纯函数，时间戳置 0（不影响解析，保测试确定性）。
func wrapPcap(frames [][]byte) []byte {
	// 全局头 24 字节：magic a1b2c3d4(大端) + ver 2.4 + zone/sigfigs 0 + snaplen 65535 + linktype 1
	out := []byte{
		0xa1, 0xb2, 0xc3, 0xd4,
		0x00, 0x02, 0x00, 0x04,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0xff, 0xff,
		0x00, 0x00, 0x00, 0x01,
	}
	var hdr [16]byte // ts_sec/ts_usec 置 0
	for _, f := range frames {
		binary.BigEndian.PutUint32(hdr[8:12], uint32(len(f)))  // incl_len
		binary.BigEndian.PutUint32(hdr[12:16], uint32(len(f))) // orig_len
		out = append(out, hdr[:]...)
		out = append(out, f...)
	}
	return out
}
