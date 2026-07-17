package scan

import (
	"context"
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"zhulong-pqm/internal/model"
)

// applyProbeResult：命中多组时取表序第一个为主组，写 KexGroup/KexSafety + 证据。
func TestApplyProbeResult_PrimaryAndSafety(t *testing.T) {
	res := &model.ScanResult{}
	applyProbeResult(res, []int{0x11EE, 0x11EC}) // 国密在前 → 主组国密
	if res.KexGroup != "curveSM2MLKEM768" {
		t.Errorf("KexGroup = %q, want curveSM2MLKEM768", res.KexGroup)
	}
	if res.KexSafety != model.KexSafetyHybrid {
		t.Errorf("KexSafety = %q, want hybrid", res.KexSafety)
	}
	// 全部支持组应记进证据，便于审计（含次组码点文本）
	if !strings.Contains(res.EvidenceNote, "0x11EC") {
		t.Errorf("EvidenceNote 应记录全部支持组，缺 0x11EC: %q", res.EvidenceNote)
	}
}

// 纯 ML-KEM 组 → safe。
func TestApplyProbeResult_PureMLKEMSafe(t *testing.T) {
	res := &model.ScanResult{}
	applyProbeResult(res, []int{0x0201}) // MLKEM768 纯 PQC
	if res.KexGroup != "MLKEM768" || res.KexSafety != model.KexSafetySafe {
		t.Errorf("got %q/%q, want MLKEM768/safe", res.KexGroup, res.KexSafety)
	}
}

// 空枚举结果不动 res（经典目标不误判）。
func TestApplyProbeResult_EmptyLeavesUntouched(t *testing.T) {
	res := &model.ScanResult{KexGroup: "", KexSafety: ""}
	applyProbeResult(res, nil)
	if res.KexGroup != "" || res.KexSafety != "" {
		t.Errorf("空枚举不应写 KexGroup/KexSafety，得 %q/%q", res.KexGroup, res.KexSafety)
	}
}

// hostPort 从 httptest server URL 拆出 host 与 port。
func hostPort(t *testing.T, rawURL string) (string, int) {
	t.Helper()
	u := strings.TrimPrefix(rawURL, "https://")
	idx := strings.LastIndex(u, ":")
	port, _ := strconv.Atoi(u[idx+1:])
	return u[:idx], port
}

// 现代 Go(1.24+) TLS 服务端默认协商 X25519MLKEM768 混合组：
// 扫描器委托真握手拿证书 + 探针端到端枚举应检测到该 hybrid 组。这是真·正例。
func TestTLSPQCScanner_DetectsHybridOnModernGoServer(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()
	host, port := hostPort(t, srv.URL)

	sc := NewTLSPQCScanner()
	res, err := sc.Scan(context.Background(), host, port)
	if err != nil {
		t.Fatalf("Scan 真 TLS 服务失败: %v", err)
	}
	// 委托真握手拿到证书字段
	if res.CertFingerprint == "" || res.KeyAlgo == "" {
		t.Errorf("委托真握手应带证书字段，得 keyAlgo=%q fp=%q", res.KeyAlgo, res.CertFingerprint)
	}
	// 探针检测到现代 Go 默认支持的 X25519MLKEM768(0x11EC) hybrid
	if res.KexGroup != "X25519MLKEM768" || res.KexSafety != model.KexSafetyHybrid {
		t.Errorf("应检测到 X25519MLKEM768/hybrid，得 %q/%q", res.KexGroup, res.KexSafety)
	}
	if sc.Name() != "tls-pqc" || sc.Method() != model.MethodM1ActiveTLS {
		t.Errorf("Name/Method = %q/%q, want tls-pqc/M1", sc.Name(), sc.Method())
	}
}

// 显式只放经典曲线的 TLS 服务端：探针枚举 PQC 组全不支持 → KexGroup 空（经典目标不误判）。
func TestTLSPQCScanner_ClassicalServerNotMisjudged(t *testing.T) {
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	srv.TLS = &tls.Config{
		CurvePreferences: []tls.CurveID{tls.CurveP256, tls.X25519}, // 排除任何 MLKEM 混合组
	}
	srv.StartTLS()
	defer srv.Close()
	host, port := hostPort(t, srv.URL)

	sc := NewTLSPQCScanner()
	res, err := sc.Scan(context.Background(), host, port)
	if err != nil {
		t.Fatalf("Scan 经典 TLS 服务失败: %v", err)
	}
	if res.CertFingerprint == "" || res.KeyAlgo == "" {
		t.Errorf("委托真握手应带证书字段，得 keyAlgo=%q fp=%q", res.KeyAlgo, res.CertFingerprint)
	}
	if res.KexGroup != "" {
		t.Errorf("经典 TLS 目标 KexGroup 应空(枚举全不支持)，得 %q", res.KexGroup)
	}
}
