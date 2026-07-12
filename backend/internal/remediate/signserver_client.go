package remediate

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/emmansun/gmsm/smx509"

	"zhulong-pqm/internal/model"
)

// 安恒签名验签(+时间戳二合一)服务器适配器。
// baseUrl: https://ip/tsvsopenapi/api/...（默认 443）；HTTP 面默认关闭。
// 信封：请求 {version,reqType,reqTime(毫秒),request:{...}}；响应 {respond:{respValue,data,message}}，respValue==0 成功。
// 全 POST，无 GET，无 /health。鉴权 appCode 请求头（选传，存 Device.Token）。
// 本文件只实现【只读发现】：取服务器证书（存活+算法探针）+ 信任证书别名清单。签名/验签/时间戳签发等写/运算接口不在此。

const ssPathPrefix = "/tsvsopenapi/api"

type ssRespond struct {
	RespValue *int            `json:"respValue"`
	Data      json.RawMessage `json:"data"`
	Message   string          `json:"message"`
}

type ssEnvelope struct {
	Respond ssRespond `json:"respond"`
}

// ssDo 发一次签名机调用并校验 {respond:{respValue,data,message}} 信封（respValue==0 成功）。
// appCode 非空时作请求头（凭据，调用方须保证仅在已验证/钉证书的连接上传入）。
// out 非空时把 respond.data 解到 out。
func ssDo(ctx context.Context, client *http.Client, base, appCode, path, reqType string, request any, out any) error {
	env := map[string]any{
		"version": "1.0",
		"reqType": reqType,
		"reqTime": time.Now().UnixMilli(), // 签名机要求毫秒时间戳
		"request": request,
	}
	body, _ := json.Marshal(env)

	cctx, cancel := context.WithTimeout(ctx, adapterTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(cctx, http.MethodPost, base+ssPathPrefix+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if strings.TrimSpace(appCode) != "" {
		req.Header.Set("appCode", strings.TrimSpace(appCode))
	}
	resp, err := client.Do(req)
	if err != nil {
		return unreachable(err) // 传输层失败=真离线
	}
	defer resp.Body.Close()
	raw, rerr := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if rerr != nil {
		return unreachable(fmt.Errorf("读取响应体失败: %w", rerr))
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("签名机 %s 状态 %s", path, resp.Status) // 应用层：在线但异常
	}
	var e ssEnvelope
	if err := json.Unmarshal(raw, &e); err != nil {
		return fmt.Errorf("签名机响应非预期信封: %s", strings.TrimSpace(string(raw)))
	}
	if e.Respond.RespValue == nil || *e.Respond.RespValue != 0 {
		msg := e.Respond.Message
		if msg == "" {
			msg = "respValue!=0"
		}
		return fmt.Errorf("签名机拒绝: %s", msg)
	}
	if out != nil && len(e.Respond.Data) > 0 {
		return json.Unmarshal(e.Respond.Data, out)
	}
	return nil
}

// ssGetServerCertificate 取服务器证书（存活+算法能力探针）。certUsage: 0 签名证书 / 1 加密证书。
// 该接口取的是服务器自身证书，不需要 appCode 凭据，故一律不传 appCode（避免密文经未验证 TLS 外泄）。
// 单次请求：把 respond.data 收成 json.RawMessage，本地兼容三种形态——{cert:"..."} 对象、
// 裸 PEM 串、裸 base64 串（无 PEM 头，交由 ssParseCert→ensurePEM 补全），不再用 "CERTIFICATE" 子串前置过滤。
func ssGetServerCertificate(ctx context.Context, client *http.Client, base string, certUsage int) (string, error) {
	var data json.RawMessage
	if err := ssDo(ctx, client, base, "", "/cert/getServerCertificate", "getServerCertificate",
		map[string]int{"certUsage": certUsage}, &data); err != nil {
		return "", err // 含传输层 errUnreachable 或应用层异常，原样上抛
	}
	// 对象形态：{cert:"..."} / {certificate:"..."} / {data:"..."}。
	var obj map[string]any
	if json.Unmarshal(data, &obj) == nil {
		for _, k := range []string{"cert", "certificate", "certData", "data", "value"} {
			if v, ok := obj[k].(string); ok && strings.TrimSpace(v) != "" {
				return v, nil
			}
		}
	}
	// 字符串形态：裸 PEM 或裸 base64——任意非空即接受，是否为证书交下游 x509 解析判定。
	var s string
	if json.Unmarshal(data, &s) == nil && strings.TrimSpace(s) != "" {
		return s, nil
	}
	return "", fmt.Errorf("取到应答但无证书内容: %s", strings.TrimSpace(string(data)))
}

// ssStaticAlgorithms 签名机静态算法能力，含标准命名的后量子签名族（可直接对齐 CBOM）。
func ssStaticAlgorithms() []string {
	return []string{
		"SM2", "SM3", "SM4", "RSA", "SHA-256",
		"PQC:ML-DSA-44", "PQC:ML-DSA-65", "PQC:ML-DSA-87", // FIPS 204 Dilithium
		"PQC:FN-DSA-512", "PQC:FN-DSA-1024", // Falcon
		"PQC:SLH-DSA", // FIPS 205 SPHINCS+
	}
}

// signServerAdapter 签名验签服务器适配器。
type signServerAdapter struct{}

func (signServerAdapter) Discover(ctx context.Context, dev *model.Device, token string) DiscoverResult {
	base := normBase(dev.Endpoint)
	res := DiscoverResult{Evidence: map[string]string{}}
	if base == "" {
		res.Detail = "签名机地址为空"
		return res
	}
	// endpoint 若误带端口/路径，signserver 走 https 默认 443；normBase 已补 scheme。若给的是 http:// 明文口需 web 手动开启。
	// 凭据(appCode)只在钉了对端证书（tlspin:）的已验证连接上才允许上行，否则宁可不带，避免经未验证 TLS 被中间人窃取。
	pin := tlsPinFrom(dev.Capabilities)
	client := deviceHTTPClient(pin)
	start := time.Now()

	// 1) 存活+算法探针：取服务器签名证书（不带 appCode，无密文外泄）。
	pem0, err := ssGetServerCertificate(ctx, client, base, 0)
	if err != nil {
		res.LatencyMs = int(time.Since(start).Milliseconds())
		if errors.Is(err, errUnreachable) {
			res.Detail = "签名机不可达：" + err.Error() // 传输层失败=真离线
			return res
		}
		// 可达但应用层异常（状态/信封/无证书）→ 登记在线但降级，不谎报离线。
		res.Online = true
		res.Detail = "签名机在线但取证异常：" + err.Error()
		res.Algorithms = ssStaticAlgorithms()
		return res
	}
	res.Online = true
	res.Detail = "签名机在线，已取服务器签名证书"
	res.Algorithms = ssStaticAlgorithms()
	if a := ssParseCert(pem0, 0); a != nil {
		res.Assets = append(res.Assets, *a)
		res.Evidence["serverCert.sign"] = pem0
		fp := a.Fingerprint
		if fp != "" {
			fp = " " + fp[:min(16, len(fp))] + "…"
		}
		res.Detail += "（" + a.Algorithm + fp + "）"
	}

	// 2) 顺带取加密证书（只读，失败不致命）。
	if pem1, e := ssGetServerCertificate(ctx, client, base, 1); e == nil {
		if a := ssParseCert(pem1, 1); a != nil {
			res.Assets = append(res.Assets, *a)
			res.Evidence["serverCert.enc"] = pem1
		}
	}

	// 3) 凭据态提示：配了 appCode 但没钉证书 → 凭据路径不可用（本轮发现不上行凭据），提示运维补 tlspin。
	if strings.TrimSpace(token) != "" && pin == "" {
		res.Detail += "；注意：已配 appCode 但未钉证书(tlspin:)，为防中间人窃取凭据，本轮未使用 appCode 做实体级盘点"
	}
	res.LatencyMs = int(time.Since(start).Milliseconds())
	return res
}

// ssParseCert 解析 PEM/裸base64 证书，取公钥/签名算法与 SHA-256 指纹（纯计算只读）。
// 用 gmsm/smx509 解析——它兼容标准 x509 且能识别国密 SM2 证书（标准库 crypto/x509 会把 SM2 标成 unknown，
// 污染 CBOM 的算法登记）。certUsage 由调用点传入以正确标注 Ref（0 签名 / 1 加密）。
func ssParseCert(pemStr string, certUsage int) *DiscoveredAsset {
	ref := "certUsage=" + strconv.Itoa(certUsage)
	block, _ := pem.Decode([]byte(ensurePEM(pemStr)))
	if block == nil {
		return &DiscoveredAsset{Kind: "cert", Algorithm: "unknown", Ref: ref, Raw: pemStr}
	}
	sum := sha256.Sum256(block.Bytes)
	fp := hex.EncodeToString(sum[:])
	algo := "unknown"
	if c, err := smx509.ParseCertificate(block.Bytes); err == nil {
		// smx509 的 stringer 对 SM2 签名算法返回原始枚举数字（99），公钥算法标 ECDSA；显式归一为国密名。
		if c.SignatureAlgorithm == smx509.SM2WithSM3 {
			algo = "SM2/SM2-SM3"
		} else {
			algo = c.PublicKeyAlgorithm.String() + "/" + c.SignatureAlgorithm.String()
		}
	}
	return &DiscoveredAsset{Kind: "cert", Algorithm: algo, Ref: ref, Fingerprint: fp, Raw: pemStr}
}

// ---- 改造编排：写操作（仅工单 AllowWrite=true 时由 orchestrator 调用，绝不出现在 Discover）----

// ML-DSA 算法号（签名机 algId 映射，FIPS 204 Dilithium）。
const (
	algMLDSA44 = 459008
	algMLDSA65 = 459264
	algMLDSA87 = 459520
)

// PushSignServerMLDSASelfTest 编排签名机做 ML-DSA(Dilithium) 后量子签名自检。
// 用 external 族：生成外部密钥对 → 外部签名 → 外部验签，**纯计算不落服务器持久状态**（最安全的写路径）。
// 全通返回可入库证据；任一步失败返回 err（供诚实降级）。仅应由改造工单 AllowWrite=true 触发。
func PushSignServerMLDSASelfTest(endpoint, appCode, pin string) (map[string]string, error) {
	base := normBase(endpoint)
	if base == "" {
		return nil, fmt.Errorf("签名机地址为空")
	}
	client := deviceHTTPClient(pin)
	ctx := context.Background()
	algID := algMLDSA65 // ML-DSA-65（Dilithium3，均衡强度）

	// 1) 生成 ML-DSA 外部密钥对（返回公私钥，不落服务器状态）。
	var kp struct {
		KeySize    string `json:"keySize"`
		PublicKey  string `json:"publicKey"`
		PrivateKey string `json:"privateKey"`
	}
	if err := ssDo(ctx, client, base, appCode, "/quantum/generateExternalKeyPair", "generateExternalKeyPair",
		map[string]any{"algId": algID}, &kp); err != nil {
		return nil, fmt.Errorf("生成 ML-DSA 外部密钥对失败: %w", err)
	}
	if kp.PrivateKey == "" || kp.PublicKey == "" {
		return nil, fmt.Errorf("ML-DSA 密钥对返回为空")
	}
	// 2) 外部签名（inData 需 base64）。
	inData := base64.StdEncoding.EncodeToString([]byte("zhulong-pqm-pqc-selftest"))
	var sig string
	if err := ssDo(ctx, client, base, appCode, "/quantum/externalSign", "externalSign",
		map[string]any{"priKey": kp.PrivateKey, "inData": inData, "algId": algID}, &sig); err != nil {
		return nil, fmt.Errorf("ML-DSA 外部签名失败: %w", err)
	}
	// 3) 外部验签：签名机对无效签名会以 respValue!=0 返回，故 ssDo 无错即验签通过。
	var verRaw json.RawMessage
	if err := ssDo(ctx, client, base, appCode, "/quantum/externalVerify", "externalVerify",
		map[string]any{"pubKey": kp.PublicKey, "inData": inData, "sign": sig, "algId": algID}, &verRaw); err != nil {
		return nil, fmt.Errorf("ML-DSA 外部验签未通过: %w", err)
	}
	return map[string]string{
		"signServer": endpoint, "pqc-algo": "ML-DSA-65(Dilithium3)", "algId": strconv.Itoa(algID),
		"keySize": kp.KeySize, "selftest": "genKeyPair+sign+verify 通过",
		"signature": clip(sig, 24), "mode": "signserver-real",
	}, nil
}

// ensurePEM 给去了头尾的证书串补上 PEM 边界（签名机部分接口返回裸 base64）。
func ensurePEM(s string) string {
	s = strings.TrimSpace(s)
	if strings.Contains(s, "BEGIN CERTIFICATE") {
		return s
	}
	return "-----BEGIN CERTIFICATE-----\n" + s + "\n-----END CERTIFICATE-----\n"
}
