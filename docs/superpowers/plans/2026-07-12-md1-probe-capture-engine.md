# M-D1 探针拓包引擎 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 给 `zhulong-pqm-agent` 加 `--role=probe`：AF_PACKET（或 tcpdump 回退）实时抓包 → 包成 pcap → 复用 `scan.ParsePCAP` 边缘解析出 TLS+PQC 观测 → 经 M-B `/agent/assets/batch` 上报，只回传观测不回传原始包。

**Architecture:** 全在 `backend/cmd/agent/`。抓包机制两条路径（AF_PACKET 原生套接字为主、tcpdump 管道回退），统一产出标准 pcap 字节流，直接喂 M-A 已验证的 `scan.ParsePCAP`，把 `TLSObservation` 映射成 `model.CryptoAsset` 复用 M-C 的 `reportAssets` 上报。后端零改动。

**Tech Stack:** Go 1.24 纯 Go 免 CGO；`golang.org/x/sys/unix`(v0.41.0, AF_PACKET)；`os/exec`(tcpdump 回退)；复用 `internal/scan`(ParsePCAP)、`internal/cryptoref`、`internal/model`。

## Global Constraints

- **纯 Go 免 CGO 硬约束**：AF_PACKET 用 `golang.org/x/sys/unix`；tcpdump 走 `os/exec`；不得引入 libpcap/gopacket 等 CGO 依赖。
- **复用优先**：不重写任何 TLS/pcap 解析——一律经 `scan.ParsePCAP`（M-A 已验证）。
- **只回传观测**：探针绝不上传原始 pcap 字节，只上传解析出的 `CryptoAsset`（隐私）。
- **交叉编译必过**：`CGO_ENABLED=0 GOOS=linux GOARCH=amd64|arm64 go build ./cmd/agent` 双架构。
- **非 Linux 可编译可测**：AF_PACKET 真实实现用 `//go:build linux`；非 Linux 用 `//go:build !linux` stub 返回 unavailable，让 mac 上编译+测试。
- commit 前缀 `feat(agent):`，中文提交信息。工作分支 `feat/md1-probe`（当前 checkout `/Users/prometheus/Projects/zhulong-pqm`）。

## 已确认的既有签名（勿改）

- `scan.ParsePCAP(data []byte) ([]scan.TLSObservation, scan.PcapStats, error)`
- `scan.TLSObservation{Host string; Port int; SNI, Version, Cipher, Algo string; KeySize int; CertFP, Subject, KexGroup, KexSafety string}`
- `scan.PcapStats{Format string; Packets, TCPSegs, Flows, Handshakes, Endpoints int}`
- `reportAssets(cfg Config, assets []model.CryptoAsset) error`（POST `/api/v1/agent/assets/batch`，X-Agent-Key）
- `cryptoref.AuthSafetyForAlgo(algo string) string`
- `model.CryptoAsset` 字段：Name/Endpoint/Algorithm/KeySize/Protocol/CertFingerprint/KexGroup/KexSafety/AuthSafety/Layer/Exposure/RiskHint（M-A/M-B 已加）
- `model.LayerL1`、`model.ExposureInternal`、`model.AgentKindProbe="probe"`
- **classic pcap 格式**（ParsePCAP `walkClassic` 期望）：24 字节全局头 = magic(4) ver_maj(2) ver_min(2) zone(4) sigfigs(4) snaplen(4) linktype(4)；magic `0xa1b2c3d4`(大端)→大端读；linktype 在偏移 20；每包 16 字节头 = ts_sec(4) ts_usec(4) incl_len(4) orig_len(4)，`incl_len` 在包头偏移 8。

---

## File Structure

- **Create** `backend/cmd/agent/capture.go` — `wrapPcap`（裸帧→pcap 字节，纯函数）+ `Capture`（机制选择编排）+ `errCaptureUnavailable` 哨兵。
- **Create** `backend/cmd/agent/capture_afpacket.go`（`//go:build linux`）— `captureAFPacket` 真实 AF_PACKET 抓包。
- **Create** `backend/cmd/agent/capture_stub.go`（`//go:build !linux`）— `captureAFPacket` 返回 unavailable。
- **Create** `backend/cmd/agent/capture_tcpdump.go` — `captureTcpdump` 回退。
- **Create** `backend/cmd/agent/probe.go` — `observationsToAssets` + `assetsFromPcap` + `runProbe`。
- **Create** `backend/cmd/agent/capture_test.go` — wrapPcap 往返 + observationsToAssets + 机制选择测试。
- **Modify** `backend/cmd/agent/config.go` — 加 Iface/Duration/MaxPackets/BPF/CaptureMode 字段 + flags/env。
- **Modify** `backend/cmd/agent/main.go` — `runOnce` 按 `cfg.Role` 分派 host/probe。
- **Modify** `docs/主机Agent安装手册.md` + `CLAUDE.md` — 补探针模式一节。

---

## Task 1: 探针配置字段与 flag

**Files:**
- Modify: `backend/cmd/agent/config.go`（`Config` 结构 + `loadConfig`）
- Test: `backend/cmd/agent/config_test.go`（新建）

**Interfaces:**
- Produces: `Config.Iface string`、`Config.Duration int`、`Config.MaxPackets int`、`Config.BPF string`、`Config.CaptureMode string`

- [ ] **Step 1: Write the failing test**

新建 `backend/cmd/agent/config_test.go`：

```go
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd backend && go test ./cmd/agent/ -run TestLoadConfig_Probe -v`
Expected: FAIL — `Config` 无 `Iface` 等字段（编译错误）。

- [ ] **Step 3: 加字段与 flag**

在 `config.go` 的 `Config` 结构里追加：

```go
	// 探针模式（role=probe）配置
	Iface       string // 抓包网卡，空=全部/any
	Duration    int    // 抓包时长（秒）
	MaxPackets  int    // 抓包数上限
	BPF         string // tcpdump 回退时的 BPF 过滤表达式
	CaptureMode string // auto/afpacket/tcpdump
```

在 `loadConfig` 里，`--insecure` 那行之后、`fs.Parse` 之前追加：

```go
	fs.StringVar(&cfg.Iface, "iface", envOr("ZPQM_AGENT_IFACE", ""), "探针抓包网卡（空=全部/any）")
	fs.IntVar(&cfg.Duration, "duration", envIntOr("ZPQM_AGENT_DURATION", 30), "探针抓包时长（秒）")
	fs.IntVar(&cfg.MaxPackets, "max-packets", envIntOr("ZPQM_AGENT_MAX_PACKETS", 100000), "探针抓包数上限")
	fs.StringVar(&cfg.BPF, "bpf", envOr("ZPQM_AGENT_BPF", "tcp"), "tcpdump 回退时的 BPF 过滤表达式")
	fs.StringVar(&cfg.CaptureMode, "capture-mode", envOr("ZPQM_AGENT_CAPTURE_MODE", "auto"), "抓包机制：auto/afpacket/tcpdump")
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd backend && go test ./cmd/agent/ -run TestLoadConfig_Probe -v`
Expected: PASS。

- [ ] **Step 5: Commit**

```bash
cd backend && git add cmd/agent/config.go cmd/agent/config_test.go
git commit -m "feat(agent): 探针模式配置(iface/duration/max-packets/bpf/capture-mode)"
```

---

## Task 2: wrapPcap — 裸帧包成 pcap 字节

**Files:**
- Create: `backend/cmd/agent/capture.go`
- Test: `backend/cmd/agent/capture_test.go`

**Interfaces:**
- Consumes: `scan.ParsePCAP`（测试里验证往返）
- Produces: `func wrapPcap(frames [][]byte) []byte`；`var errCaptureUnavailable = errors.New(...)`

- [ ] **Step 1: Write the failing test**

新建 `backend/cmd/agent/capture_test.go`：

```go
package main

import (
	"encoding/binary"
	"testing"

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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd backend && go test ./cmd/agent/ -run TestWrapPcap -v`
Expected: FAIL — `wrapPcap` 未定义。

- [ ] **Step 3: Implement wrapPcap + 哨兵**

新建 `backend/cmd/agent/capture.go`：

```go
package main

import (
	"encoding/binary"
	"errors"
)

// errCaptureUnavailable 标记「本机制在本环境不可用」（非 Linux / 无 CAP_NET_RAW / 缺 tcpdump），
// auto 模式据此在 AF_PACKET 与 tcpdump 间回退。
var errCaptureUnavailable = errors.New("capture mechanism unavailable")

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
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd backend && go test ./cmd/agent/ -run TestWrapPcap -v`
Expected: PASS（往返出 hybrid 端点，证明 AF_PACKET 帧→pcap→ParsePCAP 路径正确）。

- [ ] **Step 5: Commit**

```bash
cd backend && git add cmd/agent/capture.go cmd/agent/capture_test.go
git commit -m "feat(agent): wrapPcap 裸帧封 pcap(复用 ParsePCAP，往返实测 hybrid 组识别)"
```

---

## Task 3: 观测→资产映射 + assetsFromPcap

**Files:**
- Create: `backend/cmd/agent/probe.go`
- Test: `backend/cmd/agent/capture_test.go`（追加）

**Interfaces:**
- Consumes: `scan.TLSObservation`、`scan.ParsePCAP`、`cryptoref.AuthSafetyForAlgo`、`model.CryptoAsset`
- Produces: `func observationsToAssets(obs []scan.TLSObservation) []model.CryptoAsset`；`func assetsFromPcap(pcapBytes []byte) ([]model.CryptoAsset, scan.PcapStats, error)`

- [ ] **Step 1: Write the failing test**

在 `capture_test.go` 追加：

```go
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
```

（`capture_test.go` 顶部 import 需含 `"zhulong-pqm/internal/model"`。）

- [ ] **Step 2: Run test to verify it fails**

Run: `cd backend && go test ./cmd/agent/ -run 'TestObservationsToAssets|TestAssetsFromPcap' -v`
Expected: FAIL — `observationsToAssets`/`assetsFromPcap` 未定义。

- [ ] **Step 3: Implement**

新建 `backend/cmd/agent/probe.go`：

```go
package main

import (
	"fmt"

	"zhulong-pqm/internal/cryptoref"
	"zhulong-pqm/internal/model"
	"zhulong-pqm/internal/scan"
)

// observationsToAssets 把探针解析出的 TLS 观测转成待上报的 CryptoAsset。
// KexGroup/KexSafety 由 ParsePCAP（M-A 引擎）填好直接带上；AuthSafety 由证书算法推导；
// 五维评分与 HNDL 由后端 upsertAgentAsset 补。网络端点按 host:port 走后端原生去重。
func observationsToAssets(obs []scan.TLSObservation) []model.CryptoAsset {
	out := make([]model.CryptoAsset, 0, len(obs))
	for _, o := range obs {
		name := o.Subject
		if name == "" {
			name = o.SNI
		}
		if name == "" {
			name = fmt.Sprintf("%s:%d", o.Host, o.Port)
		}
		out = append(out, model.CryptoAsset{
			Name:            name,
			Endpoint:        fmt.Sprintf("%s:%d", o.Host, o.Port),
			Algorithm:       o.Algo,
			KeySize:         o.KeySize,
			Protocol:        o.Version,
			CertFingerprint: o.CertFP,
			KexGroup:        o.KexGroup,
			KexSafety:       o.KexSafety,
			AuthSafety:      cryptoref.AuthSafetyForAlgo(o.Algo),
			Layer:           model.LayerL1,
			Exposure:        model.ExposureInternal,
			RiskHint:        "探针抓包边缘解析",
		})
	}
	return out
}

// assetsFromPcap 解析 pcap 字节流为待上报资产（复用 M-A 的 scan.ParsePCAP）。
func assetsFromPcap(pcapBytes []byte) ([]model.CryptoAsset, scan.PcapStats, error) {
	obs, stats, err := scan.ParsePCAP(pcapBytes)
	if err != nil {
		return nil, stats, err
	}
	return observationsToAssets(obs), stats, nil
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd backend && go test ./cmd/agent/ -run 'TestObservationsToAssets|TestAssetsFromPcap' -v`
Expected: PASS。

- [ ] **Step 5: Commit**

```bash
cd backend && git add cmd/agent/probe.go cmd/agent/capture_test.go
git commit -m "feat(agent): 观测→CryptoAsset 映射 + assetsFromPcap(复用 ParsePCAP)"
```

---

## Task 4: 抓包机制编排 + tcpdump 回退 + 非 Linux stub

**Files:**
- Modify: `backend/cmd/agent/capture.go`（加 `Capture`）
- Create: `backend/cmd/agent/capture_stub.go`（`//go:build !linux`）
- Create: `backend/cmd/agent/capture_tcpdump.go`
- Test: `backend/cmd/agent/capture_test.go`（追加）

**Interfaces:**
- Consumes: `captureAFPacket(cfg *Config) ([]byte, error)`（Task 5 在 linux 实现；本任务在 mac 用 stub 版）、`errCaptureUnavailable`
- Produces: `func Capture(cfg *Config) ([]byte, error)`；`func captureTcpdump(cfg *Config) ([]byte, error)`；stub 的 `captureAFPacket`

- [ ] **Step 1: Write the failing test**

在 `capture_test.go` 追加（mac 上 `!linux` stub 生效，afpacket 强制应报 unavailable）：

```go
import "errors" // 加到 capture_test.go 的 import 块

func TestCapture_ModeSelection(t *testing.T) {
	// mac(非 linux)：afpacket 强制 → captureAFPacket stub 返回 unavailable → Capture 报错（不回退）
	_, err := Capture(&Config{CaptureMode: "afpacket", Duration: 1})
	if err == nil || !errors.Is(err, errCaptureUnavailable) {
		t.Errorf("afpacket 强制在非 Linux 应报 errCaptureUnavailable，得 %v", err)
	}
	// tcpdump 强制但环境无 tcpdump（CI/mac 可能没有）→ 也应是 errCaptureUnavailable
	if _, err := exec.LookPath("tcpdump"); err != nil {
		if _, e := Capture(&Config{CaptureMode: "tcpdump", Duration: 1}); !errors.Is(e, errCaptureUnavailable) {
			t.Errorf("无 tcpdump 时 tcpdump 强制应报 errCaptureUnavailable，得 %v", e)
		}
	}
}
```

（`capture_test.go` import 加 `"os/exec"` 与 `"errors"`。）

- [ ] **Step 2: Run test to verify it fails**

Run: `cd backend && go test ./cmd/agent/ -run TestCapture_ModeSelection -v`
Expected: FAIL — `Capture`/`captureTcpdump`/stub `captureAFPacket` 未定义。

- [ ] **Step 3: Implement Capture 编排**

在 `capture.go` 末尾追加：

```go
import (
	"fmt"
	"os/exec"
)
// 注：capture.go 顶部 import 块合并为 "encoding/binary"/"errors"/"fmt"/"os/exec"

// Capture 按 cfg.CaptureMode 选机制抓包，返回 pcap 字节流。
// auto：Linux 且能开 AF_PACKET → afpacket；否则回退 tcpdump；都不行→清晰错误。
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
```

（把顶部 `import ( "encoding/binary"; "errors" )` 改为含 `"fmt"`、`"os/exec"`；`exec` 供后续引用。若 goimports 报未用，`exec` 由 tcpdump 文件用，本文件可不 import——按编译错误调整：`Capture` 本身只用 errors/fmt，`exec` 移到 capture_tcpdump.go。）

- [ ] **Step 4: Implement 非 Linux stub**

新建 `backend/cmd/agent/capture_stub.go`：

```go
//go:build !linux

package main

import "fmt"

// captureAFPacket 非 Linux 无 AF_PACKET，返回 unavailable 让 auto 回退 tcpdump。
func captureAFPacket(cfg *Config) ([]byte, error) {
	return nil, fmt.Errorf("AF_PACKET 仅 Linux 可用（当前非 Linux）: %w", errCaptureUnavailable)
}
```

- [ ] **Step 5: Implement tcpdump 回退**

新建 `backend/cmd/agent/capture_tcpdump.go`：

```go
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
```

- [ ] **Step 6: Run test to verify it passes**

Run: `cd backend && go build ./cmd/agent/ && go test ./cmd/agent/ -run TestCapture_ModeSelection -v`
Expected: PASS（若报 `exec`/import 未用，按编译提示把 `os/exec` 只留在 capture_tcpdump.go）。

- [ ] **Step 7: Commit**

```bash
cd backend && git add cmd/agent/capture.go cmd/agent/capture_stub.go cmd/agent/capture_tcpdump.go cmd/agent/capture_test.go
git commit -m "feat(agent): 抓包机制编排(auto 选择+tcpdump 回退+非 Linux stub)"
```

---

## Task 5: AF_PACKET 真实抓包（Linux）

**Files:**
- Create: `backend/cmd/agent/capture_afpacket.go`（`//go:build linux`）

**Interfaces:**
- Consumes: `golang.org/x/sys/unix`、`wrapPcap`、`errCaptureUnavailable`、`Config`
- Produces: `func captureAFPacket(cfg *Config) ([]byte, error)`（linux 版，与 stub 同签名）

- [ ] **Step 1: Implement（本任务无 mac 单测——AF_PACKET 需 root/Linux，靠交叉编译保证正确构建）**

新建 `backend/cmd/agent/capture_afpacket.go`：

```go
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
```

- [ ] **Step 2: 交叉编译验证（关键：AF_PACKET 真实路径的正确构建）**

Run:
```bash
cd backend && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /tmp/zpqm-agent-amd64 ./cmd/agent && \
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -o /tmp/zpqm-agent-arm64 ./cmd/agent && \
file /tmp/zpqm-agent-amd64 /tmp/zpqm-agent-arm64
```
Expected: 两个 ELF（x86-64 + aarch64）均构建成功。

- [ ] **Step 3: mac 上确认非 Linux stub 仍生效、全包编译**

Run: `cd backend && go build ./cmd/agent/ && go test ./cmd/agent/ -run TestCapture -v`
Expected: PASS（mac 用 stub，afpacket 强制报 unavailable）。

- [ ] **Step 4: Commit**

```bash
cd backend && git add cmd/agent/capture_afpacket.go
git commit -m "feat(agent): AF_PACKET 原生套接字抓包(Linux,纯 Go 免 CGO,双架构交叉编译过)"
```

---

## Task 6: 探针主流程接线 + role 分派 + 文档

**Files:**
- Modify: `backend/cmd/agent/probe.go`（加 `runProbe`）
- Modify: `backend/cmd/agent/main.go`（`runOnce` 按 role 分派）
- Modify: `docs/主机Agent安装手册.md`、`CLAUDE.md`

**Interfaces:**
- Consumes: `Capture`、`assetsFromPcap`、`reportAssets`、`model.AgentKindProbe`

- [ ] **Step 1: 加 runProbe**

在 `probe.go` 追加（import 加 `"fmt"` 已有）：

```go
// runProbe 探针主流程：抓包 → 边缘解析 → 上报（只回传观测，不回传原始包）。
func runProbe(cfg Config) error {
	pcapBytes, err := Capture(&cfg)
	if err != nil {
		return err
	}
	assets, stats, err := assetsFromPcap(pcapBytes)
	if err != nil {
		return fmt.Errorf("解析抓包失败: %v", err)
	}
	fmt.Printf("探针抓包：%s / %d 包 / %d 流 / %d 握手 → %d 观测\n",
		stats.Format, stats.Packets, stats.Flows, stats.Handshakes, len(assets))
	return reportAssets(cfg, assets)
}
```

- [ ] **Step 2: main.go 按 role 分派**

在 `main.go` 的 `runOnce := func() error {` 函数体最前面插入：

```go
		if cfg.Role == model.AgentKindProbe {
			return runProbe(cfg)
		}
```

（其余 host 逻辑不变；once/interval 循环对 probe 同样适用——常驻探针=周期抓包。）

- [ ] **Step 3: 全模块构建 + 测试 + 双架构交叉编译**

Run:
```bash
cd backend && go build ./... && go vet ./... && go test ./cmd/agent/ -v && \
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /tmp/a1 ./cmd/agent && \
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -o /tmp/a2 ./cmd/agent && echo "ALL GREEN"
```
Expected: 全绿 + 两架构编译过。

- [ ] **Step 4: 文档——安装手册加探针一节**

在 `docs/主机Agent安装手册.md` 末尾追加：

```markdown
---

## 8. 探针模式（role=probe，分布式抓包）

同一二进制加 `--role=probe` 即变**旁路抓包探针**：在镜像口/SPAN 口实时抓包，边缘解析出 TLS+后量子观测上报，**只回传观测、不回传原始包**（省带宽+隐私）。

```bash
# 需 root 或 CAP_NET_RAW（AF_PACKET 原生抓包）；无权限自动回退宿主机 tcpdump
sudo ZPQM_AGENT_SERVER=http://<平台>:8099 ZPQM_AGENT_KEY=zpqm-agent-.... \
  ./zhulong-pqm-agent --role=probe --iface=eth0 --duration=60

# 或授权后免 sudo：
sudo setcap cap_net_raw+ep ./zhulong-pqm-agent
```

| 参数 | 默认 | 说明 |
|---|---|---|
| `--iface` | 全部/any | 抓哪张网卡（镜像口） |
| `--duration` | 30 | 抓包时长（秒） |
| `--max-packets` | 100000 | 抓包数上限 |
| `--bpf` | `tcp` | tcpdump 回退时的过滤表达式 |
| `--capture-mode` | `auto` | `auto`(AF_PACKET 优先→tcpdump 回退)/`afpacket`/`tcpdump` |

常驻：`--interval 300` 每 5 分钟抓一轮。多探针=在各旁路点各部署一个 `--role=probe` 实例（各自注册取 Key）。到「密码使用点清单」按来源=agent 看，含协商组/后量子态。

> 服务端集中下发抓包任务（按网段分发给多探针、租约领任务）是下一里程碑 M-D2；本版探针为配置驱动。
```

在 `CLAUDE.md` 的 `backend/cmd/agent/` 架构行末尾补：`；--role=probe 为分布式抓包探针(AF_PACKET/tcpdump→ParsePCAP→观测上报,M-D1)`。

- [ ] **Step 5: Commit**

```bash
cd backend && git add cmd/agent/probe.go cmd/agent/main.go ../docs/主机Agent安装手册.md ../CLAUDE.md
git commit -m "feat(agent): 探针主流程接线(role=probe 抓包→解析→上报) + 安装手册探针节"
```

---

## Self-Review

**1. Spec coverage（对照 spec §1-§5）：**
- §1 架构数据流（AF_PACKET/tcpdump→pcap→ParsePCAP→观测→CryptoAsset→/agent/assets/batch）→ Task 2/3/4/5/6 ✓
- §2 组件文件（capture.go/capture_afpacket/capture_stub/capture_tcpdump/probe.go）→ Task 2/4/5/3 ✓
- §2 config/main 改动 → Task 1/6 ✓
- §3 错误处理（0 包非错、权限不足回退/报错、缺 tcpdump）→ Task 4（Capture 编排）+ capture_tcpdump/stub ✓
- §4 测试（wrapPcap 往返、observationsToAssets、capture-mode 选择、交叉编译）→ Task 2/3/4/5 ✓
- §5 文件清单 + 文档 → Task 6 ✓

**2. Placeholder scan：** 无 TBD/TODO；每个代码步给完整代码。Task 4 Step 3 有一处「按编译提示调整 import」的说明（`os/exec` 归属 capture_tcpdump.go）——非占位符而是明确的 import 归位指令。

**3. Type consistency：** `captureAFPacket(cfg *Config) ([]byte, error)` 在 stub(!linux) 与真实(linux) 两版签名一致；`Capture`/`captureTcpdump` 同签名；`wrapPcap([][]byte) []byte`、`observationsToAssets([]scan.TLSObservation) []model.CryptoAsset`、`assetsFromPcap([]byte)(…,scan.PcapStats,error)`、`runProbe(Config) error` 全链一致。`errCaptureUnavailable` 哨兵在 capture.go 定义，stub/tcpdump/afpacket 均 `%w` 包裹、Capture `errors.Is` 判。pcap 头字节与 ParsePCAP `walkClassic` 期望（magic 大端 a1b2c3d4/linktype 偏移 20/incl_len 偏移 8）逐一对齐。

**执行时注意（非阻塞）：** Task 4 的 `os/exec` import 归属可能触发 goimports「未用」——`Capture` 只用 errors/fmt，`exec.LookPath` 在 capture_tcpdump.go，按编译提示保证 `os/exec` 只在用它的文件 import。
