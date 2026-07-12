package main

import "testing"

func TestLoadConfig_ProbeFlags(t *testing.T) {
	cfg, err := loadConfig([]string{
		"--key", "zpqm-agent-x", "--role", "probe",
		"--iface", "eth0", "--duration", "15", "--max-packets", "5000",
		"--bpf", "tcp port 443", "--capture-mode", "afpacket",
	})
	if err != nil {
		t.Fatalf("loadConfig err: %v", err)
	}
	if cfg.Role != "probe" || cfg.Iface != "eth0" || cfg.Duration != 15 ||
		cfg.MaxPackets != 5000 || cfg.BPF != "tcp port 443" || cfg.CaptureMode != "afpacket" {
		t.Errorf("probe 配置解析错误: %+v", cfg)
	}
}

func TestLoadConfig_ProbeDefaults(t *testing.T) {
	cfg, err := loadConfig([]string{"--key", "k"})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if cfg.Duration != 30 || cfg.MaxPackets != 100000 || cfg.BPF != "tcp" || cfg.CaptureMode != "auto" {
		t.Errorf("默认值错误: %+v", cfg)
	}
}
