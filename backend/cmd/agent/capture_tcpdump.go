package main

import (
	"context"
	"fmt"
	"os/exec"
	"strconv"
	"time"
)

// captureTcpdump 调宿主机 tcpdump 抓包（-w - 输出 pcap 到 stdout）。到时用 ctx 杀进程，
// 已抓到的部分 pcap 仍可用。缺 tcpdump 返回 errCaptureUnavailable。
func captureTcpdump(cfg *Config) ([]byte, error) {
	if _, err := exec.LookPath("tcpdump"); err != nil {
		return nil, fmt.Errorf("未找到 tcpdump: %w", errCaptureUnavailable)
	}
	iface := cfg.Iface
	if iface == "" {
		iface = "any"
	}
	bpf := cfg.BPF
	if bpf == "" {
		bpf = "tcp"
	}
	dur := cfg.Duration
	if dur <= 0 {
		dur = 30
	}
	args := []string{"-i", iface, "-w", "-", "-U", "-q"}
	if cfg.MaxPackets > 0 {
		args = append(args, "-c", strconv.Itoa(cfg.MaxPackets))
	}
	args = append(args, bpf)

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(dur)*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "tcpdump", args...).Output()
	// 到时被 ctx 杀返回 err，但 stdout 已有 pcap 数据（≥24 字节全局头）即可用。
	if len(out) > 24 {
		return out, nil
	}
	if err != nil {
		return nil, fmt.Errorf("tcpdump 抓包失败（需 root/权限）: %v", err)
	}
	return out, nil // 空捕获（无匹配流量），非错
}
