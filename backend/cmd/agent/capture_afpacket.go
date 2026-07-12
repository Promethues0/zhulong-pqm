//go:build linux

package main

import (
	"fmt"
	"net"
	"time"

	"golang.org/x/sys/unix"
)

// htons 主机序 → 网络序（16 位）。
func htons(v uint16) uint16 { return (v<<8)&0xff00 | (v>>8)&0x00ff }

// captureAFPacket 用 AF_PACKET/SOCK_RAW 原生套接字抓裸以太帧，到 duration 或 max-packets 停，
// 封成 pcap 字节流返回。需 root/CAP_NET_RAW，无权限时返回 errCaptureUnavailable 供 auto 回退。
func captureAFPacket(cfg *Config) ([]byte, error) {
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, int(htons(unix.ETH_P_ALL)))
	if err != nil {
		return nil, fmt.Errorf("开 AF_PACKET 套接字失败（需 CAP_NET_RAW）: %v: %w", err, errCaptureUnavailable)
	}
	defer unix.Close(fd)

	if cfg.Iface != "" {
		ifi, err := net.InterfaceByName(cfg.Iface)
		if err != nil {
			return nil, fmt.Errorf("网卡 %s 不存在: %v", cfg.Iface, err)
		}
		if err := unix.Bind(fd, &unix.SockaddrLinklayer{
			Protocol: htons(unix.ETH_P_ALL), Ifindex: ifi.Index,
		}); err != nil {
			return nil, fmt.Errorf("bind 网卡 %s 失败: %v", cfg.Iface, err)
		}
	}

	// 1 秒收超时，让 duration 到点能停（非阻塞死等）。
	_ = unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &unix.Timeval{Sec: 1})

	dur := cfg.Duration
	if dur <= 0 {
		dur = 30
	}
	maxPkts := cfg.MaxPackets
	if maxPkts <= 0 {
		maxPkts = 100000
	}
	deadline := time.Now().Add(time.Duration(dur) * time.Second)
	buf := make([]byte, 65536)
	var frames [][]byte
	for time.Now().Before(deadline) && len(frames) < maxPkts {
		n, _, err := unix.Recvfrom(fd, buf, 0)
		if err != nil {
			if err == unix.EAGAIN || err == unix.EWOULDBLOCK || err == unix.EINTR {
				continue // 收超时/中断，继续到 deadline
			}
			break
		}
		if n <= 0 {
			continue
		}
		f := make([]byte, n)
		copy(f, buf[:n])
		frames = append(frames, f)
	}
	return wrapPcap(frames), nil
}
