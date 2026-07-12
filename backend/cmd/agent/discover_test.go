package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"zhulong-pqm/internal/model"
)

const testdataDir = "testdata"

// ---- 1. 进程×加密库映射 ----

func TestDiscoverProcessLibs(t *testing.T) {
	assets := discoverProcessLibs(testdataDir)
	if len(assets) == 0 {
		t.Fatal("期望识别出 nginx 进程加载的密码库，得到 0 条")
	}

	var foundDisambiguated, foundAmbiguous bool
	for _, a := range assets {
		if a.Layer != model.LayerL4 {
			t.Errorf("Layer = %q，期望 L4（asset=%+v）", a.Layer, a)
		}
		if !strings.HasPrefix(a.Name, "进程 nginx 加载 ") {
			t.Errorf("Name = %q，期望以 \"进程 nginx 加载 \" 开头", a.Name)
		}
		if !strings.Contains(a.RiskHint, "pid=123") {
			t.Errorf("RiskHint = %q，期望含 pid=123（且不含在 Name 里）", a.RiskHint)
		}
		if strings.Contains(a.Name, "123") {
			t.Errorf("Name = %q 不应含 pid（否则合成锚点每次上报都变化，无法幂等）", a.Name)
		}
		switch {
		case strings.Contains(a.Algorithm, "OpenSSL 3.5"):
			foundDisambiguated = true
			if a.AuthSafety != "hybrid" {
				t.Errorf("OpenSSL 3.5.0（消歧后）AuthSafety = %q，期望 hybrid（PQCCapable）", a.AuthSafety)
			}
		case strings.Contains(a.Algorithm, "歧义"):
			foundAmbiguous = true
			if a.AuthSafety != "classical" {
				t.Errorf("未消歧的歧义库 AuthSafety = %q，期望 classical（保守）", a.AuthSafety)
			}
		}
	}
	if !foundDisambiguated {
		t.Error("未找到经版本串消歧为 OpenSSL 3.5.0 的资产（libssl.so.3 fixture 应含版本串）")
	}
	if !foundAmbiguous {
		t.Error("未找到仍处于歧义态的资产（libcrypto.so.3 无版本串 fixture，应保持保守 Ambiguous）")
	}
}

func TestDiscoverProcessLibsNoProc(t *testing.T) {
	if assets := discoverProcessLibs(t.TempDir()); assets != nil {
		t.Errorf("无 /proc 目录时期望 nil，得到 %+v", assets)
	}
}

// ---- 2. 磁盘证书 ----

func TestDiscoverDiskCerts(t *testing.T) {
	assets := discoverDiskCerts([]string{filepath.Join(testdataDir, "etc", "ssl")})
	if len(assets) != 1 {
		t.Fatalf("期望 1 条证书资产，得到 %d：%+v", len(assets), assets)
	}
	a := assets[0]
	if a.Name != "zpqm-agent-test" {
		t.Errorf("Name = %q，期望证书 CN zpqm-agent-test", a.Name)
	}
	if a.Algorithm != "RSA" {
		t.Errorf("Algorithm = %q，期望 RSA", a.Algorithm)
	}
	if a.KeySize != 2048 {
		t.Errorf("KeySize = %d，期望 2048", a.KeySize)
	}
	if len(a.CertFingerprint) != 64 {
		t.Errorf("CertFingerprint 长度 = %d，期望 64（SHA-256 hex）", len(a.CertFingerprint))
	}
	if a.CertNotAfter == nil || !a.CertNotAfter.After(time.Now()) {
		t.Errorf("CertNotAfter = %v，期望在未来（测试证书 3650 天有效期）", a.CertNotAfter)
	}
	if a.Layer != model.LayerL2 {
		t.Errorf("Layer = %q，期望 L2", a.Layer)
	}
	if a.AuthSafety != "classical" {
		t.Errorf("AuthSafety = %q，期望 classical（纯 RSA）", a.AuthSafety)
	}
}

func TestDiscoverDiskCertsNoRoot(t *testing.T) {
	if assets := discoverDiskCerts([]string{filepath.Join(testdataDir, "not-exist")}); assets != nil {
		t.Errorf("不存在的 root 期望 nil，得到 %+v", assets)
	}
}

// ---- 3. SSH 主机密钥 ----

func TestDiscoverSSHHostKeys(t *testing.T) {
	assets := discoverSSHHostKeys(filepath.Join(testdataDir, "etc", "ssh"))
	if len(assets) != 1 {
		t.Fatalf("期望 1 条 SSH 主机密钥资产，得到 %d：%+v", len(assets), assets)
	}
	a := assets[0]
	if a.Algorithm != "ssh-ed25519" {
		t.Errorf("Algorithm = %q，期望 ssh-ed25519", a.Algorithm)
	}
	if a.KeySize != 256 {
		t.Errorf("KeySize = %d，期望 256", a.KeySize)
	}
	if a.Protocol != "SSH" {
		t.Errorf("Protocol = %q，期望 SSH", a.Protocol)
	}
	if a.Layer != model.LayerL2 {
		t.Errorf("Layer = %q，期望 L2", a.Layer)
	}
	if a.AuthSafety != "classical" {
		t.Errorf("AuthSafety = %q，期望 classical（Ed25519 是经典算法）", a.AuthSafety)
	}
}

// ---- 4. 内核算法与包（dpkg） ----

func TestDiscoverDpkgPackages(t *testing.T) {
	assets := discoverDpkgPackages(testdataDir)
	if len(assets) == 0 {
		t.Fatal("期望解出至少 1 个密码库包，得到 0")
	}

	var foundOpenSSL, foundGnuTLS, foundNginx bool
	for _, a := range assets {
		if strings.Contains(a.Name, "nginx") {
			foundNginx = true
		}
		if strings.Contains(a.Algorithm, "OpenSSL 3.0.2") {
			foundOpenSSL = true
			if a.AuthSafety != "classical" {
				t.Errorf("OpenSSL 3.0.2（<3.5）AuthSafety = %q，期望 classical", a.AuthSafety)
			}
		}
		if strings.Contains(a.Algorithm, "GnuTLS") {
			foundGnuTLS = true
		}
		if a.Layer != model.LayerL4 {
			t.Errorf("Layer = %q，期望 L4", a.Layer)
		}
	}
	if !foundOpenSSL {
		t.Error("未解出 libssl3 包（应借 OpenSSL/铜锁歧义规则 + dpkg Version 消歧出 OpenSSL 3.0.2）")
	}
	if !foundGnuTLS {
		t.Error("未解出 libgnutls30 包")
	}
	if foundNginx {
		t.Error("nginx 包不应被当作密码库资产收录")
	}
}

// ---- 5. 监听服务：端口解析 ----

func TestListenPorts(t *testing.T) {
	ports := listenPorts(testdataDir)
	has := func(p int) bool {
		for _, x := range ports {
			if x == p {
				return true
			}
		}
		return false
	}
	if !has(0x4803) {
		t.Errorf("期望包含 LISTEN 端口 0x4803(18435)，得到 %v", ports)
	}
	if !has(22) {
		t.Errorf("期望包含 LISTEN 端口 22，得到 %v", ports)
	}
	if has(0xC350) {
		t.Errorf("状态非 LISTEN(01=ESTABLISHED) 的端口不应被收录，得到 %v", ports)
	}
}

// ---- 6. 监听服务：端到端本地 TLS 握手（真实起一个本机 TLS 监听器验证全链路）----

func TestDiscoverListenersIntegration(t *testing.T) {
	cert := generateSelfSignedCert(t)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Fatalf("起本地 TLS 监听失败: %v", err)
	}
	defer ln.Close()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				if tc, ok := c.(*tls.Conn); ok {
					_ = tc.Handshake()
				}
			}(conn)
		}
	}()
	port := ln.Addr().(*net.TCPAddr).Port

	tmp := t.TempDir()
	procNetDir := filepath.Join(tmp, "proc", "net")
	if err := os.MkdirAll(procNetDir, 0o755); err != nil {
		t.Fatal(err)
	}
	line := fmt.Sprintf("  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"+
		"   0: 0100007F:%04X 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1 1 0 100 0 0 10 0\n", port)
	if err := os.WriteFile(filepath.Join(procNetDir, "tcp"), []byte(line), 0o644); err != nil {
		t.Fatal(err)
	}

	assets := discoverListeners(tmp)
	if len(assets) != 1 {
		t.Fatalf("期望 1 条本地监听资产，得到 %d：%+v", len(assets), assets)
	}
	a := assets[0]
	wantEndpoint := fmt.Sprintf("127.0.0.1:%d", port)
	if a.Endpoint != wantEndpoint {
		t.Errorf("Endpoint = %q，期望 %q", a.Endpoint, wantEndpoint)
	}
	if a.Layer != model.LayerL1 {
		t.Errorf("Layer = %q，期望 L1", a.Layer)
	}
	if a.CertFingerprint == "" {
		t.Error("CertFingerprint 为空")
	}
	if a.Protocol == "" {
		t.Error("Protocol（TLS 版本）为空")
	}
}

func generateSelfSignedCert(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "zpqm-listener-test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// ---- 7. 字符串扫描（消歧用） ----

func TestExtractPrintableStrings(t *testing.T) {
	data := []byte{0x00, 0x01, 0x02}
	data = append(data, []byte("OpenSSL 3.5.0")...)
	data = append(data, 0x00, 0xff)
	text := extractPrintableStrings(data)
	if !strings.Contains(text, "OpenSSL 3.5.0") {
		t.Errorf("extractPrintableStrings(%v) = %q，期望含 OpenSSL 3.5.0", data, text)
	}
}

func TestReadVersionText(t *testing.T) {
	text := readVersionText(testdataDir, "/usr/lib/x86_64-linux-gnu/libssl.so.3")
	if !strings.Contains(text, "OpenSSL 3.5.0") {
		t.Errorf("readVersionText 未读到 fixture 里的版本串，got=%q", text)
	}
	if got := readVersionText(testdataDir, "/no/such/file.so"); got != "" {
		t.Errorf("不存在的文件期望空串，got=%q", got)
	}
}

// ---- 8. 配置加载 ----

func TestLoadConfigMissingKey(t *testing.T) {
	if _, err := loadConfig([]string{"--server", "http://x"}); err == nil {
		t.Error("缺少 --key 时期望报错")
	}
}

func TestLoadConfigFlagsAndDefaults(t *testing.T) {
	cfg, err := loadConfig([]string{"--key", "zpqm-agent-test-key", "--fsroot", "/fixture"})
	if err != nil {
		t.Fatalf("loadConfig 失败: %v", err)
	}
	if cfg.Server != "http://127.0.0.1:8099" {
		t.Errorf("Server 默认值 = %q", cfg.Server)
	}
	if cfg.FSRoot != "/fixture" {
		t.Errorf("FSRoot = %q，期望 /fixture", cfg.FSRoot)
	}
	if !cfg.Once {
		t.Error("默认 Once 期望 true")
	}
}

func TestLoadConfigIntervalImpliesNotOnce(t *testing.T) {
	cfg, err := loadConfig([]string{"--key", "k", "--interval", "30"})
	if err != nil {
		t.Fatalf("loadConfig 失败: %v", err)
	}
	if cfg.Once {
		t.Error("--interval > 0 时期望 Once=false")
	}
	if cfg.Interval != 30 {
		t.Errorf("Interval = %d，期望 30", cfg.Interval)
	}
}

func TestLoadConfigEnv(t *testing.T) {
	t.Setenv("ZPQM_AGENT_KEY", "env-key")
	t.Setenv("ZPQM_AGENT_SERVER", "http://env-server:9099")
	cfg, err := loadConfig(nil)
	if err != nil {
		t.Fatalf("loadConfig 失败: %v", err)
	}
	if cfg.Key != "env-key" {
		t.Errorf("Key = %q，期望取自 ZPQM_AGENT_KEY", cfg.Key)
	}
}
