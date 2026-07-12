package remediate

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"zhulong-pqm/internal/model"
)

// 国密设备适配器：把不同厂商/协议的密码设备统一成 PQM 的【只读发现】与（后续）改造编排。
// 发现方法一律只读——绝不触发建密钥/下发配置等写接口（写接口只在编排改造且带确认闸门时调用）。

// adapterTimeout 单次设备 REST 调用的超时（发现要快，离线不该拖）。
const adapterTimeout = 6 * time.Second

// errUnreachable 标记【传输层】不可达（连不上/超时/连接重置）——只有它代表设备真离线。
// 应用层异常（HTTP 非 2xx、信封 code!=200/respValue!=0、响应体解析失败）不是离线，
// 设备是“在线但异常”，不应被误登记为 offline。用 errors.Is(err, errUnreachable) 判定。
var errUnreachable = errors.New("设备传输层不可达")

// unreachable 把传输层错误包成可被 errors.Is 识别的形态。
func unreachable(err error) error {
	return fmt.Errorf("%w: %v", errUnreachable, err)
}

// pqcTruthy 宽松判定后量子验签布尔结果：容 true/"true"/文档笔误"ture"/1/ok；显式 false/0/no 判否。
// 空串按调用方语义处理（HSM verify 恒返回 bool 故空判否；签名机 respValue==0 已表成功，走另一路）。
func pqcTruthy(raw []byte) bool {
	s := strings.ToLower(strings.Trim(strings.TrimSpace(string(raw)), `"`))
	switch s {
	case "true", "ture", "1", "ok", "success", "pass":
		return true
	case "", "false", "0", "no", "fail":
		return false
	}
	var b bool
	if json.Unmarshal(raw, &b) == nil {
		return b
	}
	return false
}

// clip 截断字符串用于证据展示（避免超长签名塞满 evidence）。
func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// DiscoveredAsset 只读发现出的一条密码资产线索，可登记进 CBOM。
type DiscoveredAsset struct {
	Kind        string // pubkey | cert | pqc-slot | capability
	Algorithm   string // SM2 / RSA / ML-DSA-65 / Aigis-sig(mode1) ...
	Ref         string // keyIndex / alias / certUsage
	Fingerprint string // 证书指纹（有则填）
	Raw         string // 原始 PEM/Base64，落 AssetEvidence
}

// DiscoverResult 只读发现的统一产物：在线状态 + 可登记进 CBOM 的资产/算法线索。
type DiscoverResult struct {
	Online     bool
	LatencyMs  int
	Detail     string            // 人类可读（含算法/证书摘要）
	Algorithms []string          // → Device.Capabilities / CryptoAsset.Algorithm（含 PQC 家族名）
	Assets     []DiscoveredAsset // → 逐条 CryptoAsset（后续 wave 自动登记）
	Evidence   map[string]string // → AssetEvidence.Raw（证书 PEM/公钥/健康串）
}

// DeviceAdapter 每类国密设备一个实现。Discover 只读，绝不触发写接口。
type DeviceAdapter interface {
	Discover(ctx context.Context, dev *model.Device, token string) DiscoverResult
}

// adapterFor 按设备类型选适配器；未知类型退化为通用连通性探测。
func adapterFor(t string) DeviceAdapter {
	switch t {
	case model.DeviceHSM:
		return hsmAdapter{}
	case model.DeviceSignServer:
		return signServerAdapter{}
	default:
		return genericAdapter{}
	}
}

// DiscoverDevice 是 API/编排层的统一入口：按设备类型只读发现。token 为解密后的接入凭据（可空）。
func DiscoverDevice(ctx context.Context, dev *model.Device, token string) DiscoverResult {
	if dev == nil {
		return DiscoverResult{Online: false, Detail: "设备为空"}
	}
	return adapterFor(dev.Type).Discover(ctx, dev, token)
}

// genericAdapter 通用适配器：复用既有 Probe（HTTP /healthz → TCP 兜底）。gateway/proxy/ca 走这条。
type genericAdapter struct{}

func (genericAdapter) Discover(ctx context.Context, dev *model.Device, _ string) DiscoverResult {
	r := Probe(ctx, dev.Endpoint)
	return DiscoverResult{Online: r.Online, LatencyMs: r.LatencyMs, Detail: r.Detail}
}

// deviceHTTPClient 面向内网密码设备的 HTTP 客户端。
//
// 这些设备走自签名证书（HTTPS 9443 / 443），无企业 PKI。安全策略分两档：
//   - pin 非空：钉住对端叶证书 SHA-256（VerifyPeerCertificate 强校验）——用于**携带凭据**
//     （如签名机 appCode）的请求，防中间人窃取已在库内加密的凭据。
//   - pin 为空：跳过证书校验，**仅允许无凭据的存活/证书探测**（不上行任何密文）。
//
// 调用方必须保证：pin 为空时绝不发送凭据（见 signServerAdapter）。
func deviceHTTPClient(pin string) *http.Client {
	tc := &tls.Config{InsecureSkipVerify: true} // #nosec G402 内网自签名，凭据路径改用下方 pin 强校验
	if p := normPin(pin); p != "" {
		tc.VerifyPeerCertificate = func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return errors.New("对端未提供证书")
			}
			sum := sha256.Sum256(rawCerts[0])
			if got := hex.EncodeToString(sum[:]); got != p {
				return fmt.Errorf("证书指纹不匹配（钉住 %s… 实得 %s…）", p[:min(12, len(p))], got[:min(12, len(got))])
			}
			return nil
		}
	}
	return &http.Client{
		Timeout:   adapterTimeout,
		Transport: &http.Transport{TLSClientConfig: tc},
	}
}

// normPin 规整证书指纹（小写、去空白与常见分隔符）。
func normPin(pin string) string {
	p := strings.ToLower(strings.TrimSpace(pin))
	p = strings.ReplaceAll(p, ":", "")
	p = strings.ReplaceAll(p, " ", "")
	return p
}

// tlsPinFrom 从设备能力清单解析 tlspin:<sha256hex>（对端叶证书指纹，用于凭据路径强校验）。
func tlsPinFrom(caps []string) string {
	for _, c := range caps {
		c = strings.TrimSpace(c)
		if strings.HasPrefix(c, "tlspin:") {
			return normPin(strings.TrimPrefix(c, "tlspin:"))
		}
	}
	return ""
}

// normBase 规整 endpoint 为可拼接的 base（去尾斜杠；缺 scheme 时补 http://）。
func normBase(endpoint string) string {
	e := strings.TrimSpace(endpoint)
	if e == "" {
		return ""
	}
	if !strings.HasPrefix(e, "http://") && !strings.HasPrefix(e, "https://") {
		e = "http://" + e
	}
	return strings.TrimRight(e, "/")
}

// MergeCaps 把发现到的算法能力并入既有 Capabilities（去重、稳定顺序，保留用户配置项如 keyslot:N）。
func MergeCaps(existing, discovered []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(existing)+len(discovered))
	for _, c := range existing {
		c = strings.TrimSpace(c)
		if c != "" && !seen[c] {
			seen[c] = true
			out = append(out, c)
		}
	}
	for _, c := range discovered {
		c = strings.TrimSpace(c)
		if c != "" && !seen[c] {
			seen[c] = true
			out = append(out, c)
		}
	}
	return out
}
