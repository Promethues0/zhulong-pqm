//go:build !linux

package main

import "fmt"

// captureAFPacket 非 Linux 无 AF_PACKET，返回 unavailable 让 auto 回退 tcpdump。
func captureAFPacket(cfg *Config) ([]byte, error) {
	return nil, fmt.Errorf("AF_PACKET 仅 Linux 可用（当前非 Linux）: %w", errCaptureUnavailable)
}
