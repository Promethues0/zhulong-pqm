package remediate

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"zhulong-pqm/internal/model"
)

// 安恒服务器密码机（HSM）REST openApi 适配器。
// baseUrl: http://ip:9090 或 https://ip:9443；信封 {code:200,msg,data}；无鉴权，仅 Content-Type。
// 本文件只实现【只读发现】：健康探活 + 轻量心跳 + 按已知 keyIndex 导出公钥盘点。
// 写接口（/api/pqc/getKeyPair、/api/crypto/getAsymmetricKey 等）只在改造编排+确认闸门时调用，绝不在 Discover 里出现。

// hsmContentType 密码机要求带 charset。
const hsmContentType = "application/json;charset=UTF-8"

// hsmEnvelope 是密码机统一响应信封。data 为泛型，按接口自解。
type hsmEnvelope struct {
	Code *int            `json:"code"`
	Msg  string          `json:"msg"`
	Data json.RawMessage `json:"data"`
}

// hsmDo 发一次密码机 REST 调用并校验 {code,msg,data} 信封：
// code==200 为成功；out 非空时把 data 解到 out。method 通常 POST（健康检查用 GET）。
func hsmDo(ctx context.Context, client *http.Client, method, url string, body []byte, out any) error {
	cctx, cancel := context.WithTimeout(ctx, adapterTimeout)
	defer cancel()
	var rdr io.Reader
	if body != nil {
		rdr = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(cctx, method, url, rdr)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", hsmContentType)
	resp, err := client.Do(req)
	if err != nil {
		return unreachable(err) // 传输层失败=真离线
	}
	defer resp.Body.Close()
	raw, rerr := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if rerr != nil {
		return unreachable(fmt.Errorf("读取响应体失败: %w", rerr)) // 连接中断/截断，按不可达处理
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("HSM %s 状态 %s", url, resp.Status) // 应用层：在线但异常
	}
	var env hsmEnvelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return fmt.Errorf("HSM 响应非预期信封: %s", strings.TrimSpace(string(raw)))
	}
	if env.Code == nil || *env.Code != 200 {
		msg := env.Msg
		if msg == "" {
			msg = "code=" + itoaPtr(env.Code)
		}
		return fmt.Errorf("HSM 拒绝: %s", msg)
	}
	if out != nil && len(env.Data) > 0 {
		return json.Unmarshal(env.Data, out)
	}
	return nil
}

func itoaPtr(p *int) string {
	if p == nil {
		return "nil"
	}
	return strconv.Itoa(*p)
}

// hsmHealth 调 GET {base}/base/health。判定 code==200 **且健康值含 healthy**（大小写/包裹容错）。
// data 形态容错：可能是裸串 "healthy"、对象 {status:"healthy"}、或文档笔误——统一用 healthValueOf 归一，
// 不让 data 形态差异等价于“离线”。传输层错误(errUnreachable)才代表真离线。
func hsmHealth(ctx context.Context, client *http.Client, base string) (string, error) {
	var raw json.RawMessage
	if err := hsmDo(ctx, client, http.MethodGet, base+"/base/health", nil, &raw); err != nil {
		return "", err
	}
	v := healthValueOf(raw)
	if !strings.Contains(strings.ToLower(v), "healthy") {
		return v, fmt.Errorf("HSM 健康值非 healthy: %q", v)
	}
	return v, nil
}

// healthValueOf 从任意 data 形态提取健康字符串：裸串、{status|data|health|result:...} 包裹、或原样。
func healthValueOf(raw json.RawMessage) string {
	s := strings.TrimSpace(string(raw))
	if s == "" {
		return ""
	}
	var str string
	if json.Unmarshal(raw, &str) == nil {
		return str
	}
	var obj map[string]any
	if json.Unmarshal(raw, &obj) == nil {
		for _, k := range []string{"status", "data", "health", "result", "state"} {
			if v, ok := obj[k]; ok {
				return fmt.Sprintf("%v", v)
			}
		}
	}
	return strings.Trim(s, `"`) // 数字/布尔/未知：返回去引号原文
}

// hsmGenRandom 调 POST {base}/api/crypto/genRandom，作健康兜底心跳（不写密钥槽）。
// 成功与否只看“信封 code==200 且 data 非空”，不苛求 data 是裸串（形态差异不等于离线）。
func hsmGenRandom(ctx context.Context, client *http.Client, base string, length int) (string, error) {
	body, _ := json.Marshal(map[string]int{"length": length})
	var raw json.RawMessage
	if err := hsmDo(ctx, client, http.MethodPost, base+"/api/crypto/genRandom", body, &raw); err != nil {
		return "", err
	}
	if v := healthValueOf(raw); strings.TrimSpace(v) != "" {
		return v, nil
	}
	return "", fmt.Errorf("genRandom 返回空")
}

// hsmExportPublicKey 调 POST {base}/api/crypto/exportPublicKey，只读导出机内某 keyIndex 的公钥（不改状态）。
// typ: "encrypt" 或 "sign"。返回 Base64 公钥串。
func hsmExportPublicKey(ctx context.Context, client *http.Client, base, typ string, keyIndex int) (string, error) {
	body, _ := json.Marshal(map[string]any{"type": typ, "secretKey": keyIndex})
	var data string
	if err := hsmDo(ctx, client, http.MethodPost, base+"/api/crypto/exportPublicKey", body, &data); err != nil {
		return "", err
	}
	return data, nil
}

// hsmStaticAlgorithms 密码机静态算法能力（发现登记到 Device.Capabilities）。
// Aigis-sig 是后量子签名族，非 ML-DSA/Dilithium 命名，CBOM 里需单独标注。
func hsmStaticAlgorithms() []string {
	return []string{"SM1", "SM2", "SM3", "SM4", "SM9", "ECC", "HMAC-SM3", "PQC:Aigis-sig"}
}

// hsmAdapter 服务器密码机适配器。
type hsmAdapter struct{}

func (hsmAdapter) Discover(ctx context.Context, dev *model.Device, _ string) DiscoverResult {
	base := normBase(dev.Endpoint)
	res := DiscoverResult{Evidence: map[string]string{}}
	if base == "" {
		res.Detail = "密码机地址为空"
		return res
	}
	// HSM openApi 无凭据（仅 Content-Type），故即便走 https 也不上行密文；pin 可选强校验。
	client := deviceHTTPClient(tlsPinFrom(dev.Capabilities))
	start := time.Now()

	// 1) 首选健康探活；失败退化到 genRandom 心跳。
	//    在线判定：只要有一路应用层应答（哪怕业务异常），就是在线；仅两路都是传输层不可达才判离线。
	health, herr := hsmHealth(ctx, client, base)
	rnd, rerr := "", error(nil)
	switch {
	case herr == nil:
		res.Online = true
		res.Evidence["health"] = health
		res.Detail = "密码机健康：" + health
	default:
		rnd, rerr = hsmGenRandom(ctx, client, base, 16)
		switch {
		case rerr == nil:
			res.Online = true
			res.Evidence["entropy"] = "ok"
			res.Detail = "密码机在线（RNG 心跳可用；/base/health 异常：" + herr.Error() + "）"
			_ = rnd
		case errors.Is(herr, errUnreachable) && errors.Is(rerr, errUnreachable):
			// 两路都是传输层不可达 → 真离线。
			res.LatencyMs = int(time.Since(start).Milliseconds())
			res.Detail = "密码机不可达：" + rerr.Error()
			return res
		default:
			// 可达但应用层异常（信封/状态/健康值不对）→ 登记在线但降级，不谎报离线。
			res.Online = true
			res.Detail = "密码机在线但异常：health(" + herr.Error() + ")，RNG(" + rerr.Error() + ")"
		}
	}

	// 2) 在线：登记静态算法能力（含 PQC:Aigis-sig）。
	res.Algorithms = hsmStaticAlgorithms()

	// 3) 只读资产盘点：密码机无“列全部密钥”接口，按 Device.Capabilities 里配置的 keyslot:N 逐个导出公钥。
	for _, idx := range keyslotsFrom(dev.Capabilities) {
		for _, typ := range []string{"sign", "encrypt"} {
			pub, err := hsmExportPublicKey(ctx, client, base, typ, idx)
			if err != nil || strings.TrimSpace(pub) == "" {
				continue
			}
			res.Assets = append(res.Assets, DiscoveredAsset{
				// 密码机导出的是 64 字节 x||y 公钥，无法从导出接口区分 SM2 与 ECC-P256（都是 256 位经典椭圆曲线、
				// 同属抗量子脆弱类）。据实标注为该风险类，不臆断具体算法，避免污染 CBOM 的经典/后量子分类。
				Kind: "pubkey", Algorithm: "EC-256(SM2/P256,经典)", Ref: typ + ":keyIndex=" + strconv.Itoa(idx), Raw: pub,
			})
			res.Evidence[fmt.Sprintf("pubkey.%s.%d", typ, idx)] = pub
		}
	}
	if n := len(res.Assets); n > 0 {
		res.Detail += fmt.Sprintf("；盘点公钥 %d 项", n)
	}
	res.LatencyMs = int(time.Since(start).Milliseconds())
	return res
}

// ---- 改造编排：写操作（仅工单 AllowWrite=true 时由 orchestrator 调用，绝不出现在 Discover）----

// hsmPQCKeyIndex 密码机 PQC 自检专用密钥槽（默认 100，可 ZPQM_HSM_PQC_KEYINDEX 覆盖），
// 用高位专用槽避免覆盖生产密钥（keyslot:1 等）。
func hsmPQCKeyIndex() int {
	if v := strings.TrimSpace(os.Getenv("ZPQM_HSM_PQC_KEYINDEX")); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return 100
}

// PushHSMAigisSelfTest 编排密码机做 Aigis-sig 后量子签名自检：
// 生成PQC密钥对入专用槽(写) → 签名 → 验签。全通返回可入库证据；任一步失败返回 err（供诚实降级）。
// 这是真实写操作，只应由改造工单 AllowWrite=true 触发。
func PushHSMAigisSelfTest(endpoint, pin string) (map[string]string, error) {
	base := normBase(endpoint)
	if base == "" {
		return nil, fmt.Errorf("密码机地址为空")
	}
	client := deviceHTTPClient(pin)
	ctx := context.Background()
	mode := 1
	ki := hsmPQCKeyIndex()

	// 1) 生成 Aigis-sig 密钥对入专用槽（写操作）。
	genBody, _ := json.Marshal(map[string]any{"algorithmType": "Aigis-sig", "mode": mode, "keyIndex": ki})
	if err := hsmDo(ctx, client, http.MethodPost, base+"/api/pqc/getKeyPair", genBody, nil); err != nil {
		return nil, fmt.Errorf("生成 Aigis-sig 密钥对失败: %w", err)
	}
	// 2) 用机内私钥签名。
	data := "zhulong-pqm-pqc-selftest"
	signBody, _ := json.Marshal(map[string]any{"keyIndex": ki, "algorithmType": "Aigis-sig", "mode": mode, "data": data, "plainIsEncode": false})
	var sig string
	if err := hsmDo(ctx, client, http.MethodPost, base+"/api/pqc/sign", signBody, &sig); err != nil {
		return nil, fmt.Errorf("Aigis-sig 签名失败: %w", err)
	}
	// 3) 验签（返回布尔，容文档笔误 "ture"）。
	verBody, _ := json.Marshal(map[string]any{"keyIndex": ki, "algorithmType": "Aigis-sig", "mode": mode, "signature": sig, "data": data, "plainIsEncode": false})
	var verRaw json.RawMessage
	if err := hsmDo(ctx, client, http.MethodPost, base+"/api/pqc/verify", verBody, &verRaw); err != nil {
		return nil, fmt.Errorf("Aigis-sig 验签调用失败: %w", err)
	}
	if !pqcTruthy(verRaw) {
		return nil, fmt.Errorf("Aigis-sig 验签未通过")
	}
	return map[string]string{
		"hsm": endpoint, "pqc-algo": "Aigis-sig", "pqc-mode": strconv.Itoa(mode),
		"keyIndex": strconv.Itoa(ki), "selftest": "getKeyPair+sign+verify 通过",
		"signature": clip(sig, 24), "mode": "hsm-real",
	}, nil
}

// keyslotsFrom 从设备能力清单解析出 keyslot:N 的 keyIndex 列表（发现时按此清单只读探公钥）。
func keyslotsFrom(caps []string) []int {
	var out []int
	for _, c := range caps {
		c = strings.TrimSpace(c)
		if !strings.HasPrefix(c, "keyslot:") {
			continue
		}
		if n, err := strconv.Atoi(strings.TrimPrefix(c, "keyslot:")); err == nil {
			out = append(out, n)
		}
	}
	return out
}
