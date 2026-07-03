package remediate

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// gwEnvOr 读环境变量，缺省回落。
func gwEnvOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

// gwStepTimeout 真机联调时每一步 REST 调用的超时。
const gwStepTimeout = 8 * time.Second

// gwPolicy 是发往烛龙 IPSEC 网关的本地策略结构（不 import 网关模块，仅照其 REST 契约拼字段）。
type gwPolicy struct {
	Name        string `json:"name"`
	Enabled     bool   `json:"enabled"`
	Auth        string `json:"auth"`
	IKEVersion  string `json:"ikeVersion"`
	IKEMode     string `json:"ikeMode"`
	IKEEnc      string `json:"ikeEnc"`
	IKEAuth     string `json:"ikeAuth"`
	DHGroup     string `json:"dhGroup"`
	IKELifetime int    `json:"ikeLifetime"`
	ESPMode     string `json:"espMode"`
	Proto       string `json:"proto"`
	ESPEnc      string `json:"espEnc"`
	ESPAuth     string `json:"espAuth"`
	PFS         bool   `json:"pfs"`
	PQCGroup    string `json:"pqcGroup"`
	LocalAddr   string `json:"localAddr"`
	PeerAddr    string `json:"peerAddr"`
	SrcTS       string `json:"srcTs"`
	DstTS       string `json:"dstTs"`
	LocalID     string `json:"localId"`
	PeerID      string `json:"peerId"`
}

// PushHybridProposal 对在线的烛龙 IPSEC 网关执行真机联调：
// 依次 login → 建混合提议策略 → reload → 读 SAs，
// 成功返回可入库的 evidence map；任何一步失败返回 err（每步超时 8s）。
func PushHybridProposal(endpoint, username, password, name, pqcGroup string) (map[string]string, error) {
	if strings.TrimSpace(endpoint) == "" {
		return nil, fmt.Errorf("网关地址为空")
	}
	if strings.TrimSpace(username) == "" {
		username = "sysadmin"
	}
	if strings.TrimSpace(pqcGroup) == "" {
		pqcGroup = "mlkem768"
	}
	base := strings.TrimRight(endpoint, "/")

	token, err := gwLogin(base, username, password)
	if err != nil {
		return nil, fmt.Errorf("网关登录失败: %w", err)
	}

	policyName := gwPolicyName(name)
	policyID, err := gwCreatePolicy(base, token, policyName, pqcGroup)
	if err != nil {
		return nil, fmt.Errorf("下发策略失败: %w", err)
	}

	if err := gwReload(base, token); err != nil {
		return nil, fmt.Errorf("网关重载失败: %w", err)
	}

	sa := gwFirstSA(base, token)

	return map[string]string{
		"gateway":    endpoint,
		"policy":     policyName,
		"policyId":   policyID,
		"pqc":        "ke1_mlkem768",
		"auth":       "sm2",
		"ke-method":  "MLKEM_768+X25519",
		"sa":         sa,
	}, nil
}

// gwPolicyName 把资产名规整为网关接受的隧道名（仅字母数字 . _ -，≤64，加 pqm- 前缀）。
// 烛龙网关 createPolicy 会校验 `隧道名仅允许字母数字 . _ -`，中文/空格会被拒。
func gwPolicyName(raw string) string {
	var b strings.Builder
	prevDash := false
	for _, r := range raw {
		ok := (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') ||
			r == '.' || r == '_' || r == '-'
		if ok {
			b.WriteRune(r)
			prevDash = false
		} else if !prevDash {
			b.WriteByte('-')
			prevDash = true
		}
	}
	slug := strings.Trim(b.String(), "-._")
	if slug == "" {
		slug = "ke1mlkem"
	}
	name := "pqm-" + slug
	if len(name) > 64 {
		name = name[:64]
	}
	return name
}

// gwLogin 调 POST /api/auth/login，从信封 data.token 取令牌。
func gwLogin(base, username, password string) (string, error) {
	body, _ := json.Marshal(map[string]string{"username": username, "password": password})
	var data struct {
		Token string `json:"token"`
	}
	if err := gwDo(http.MethodPost, base+"/api/auth/login", "", body, &data); err != nil {
		return "", err
	}
	if data.Token == "" {
		return "", fmt.Errorf("响应未携带 token")
	}
	return data.Token, nil
}

// gwCreatePolicy 调 POST /api/ipsec/policies，返回新建策略 id（来自信封 data.id）。
func gwCreatePolicy(base, token, name, pqcGroup string) (string, error) {
	p := gwPolicy{
		Name:        name,
		Enabled:     true,
		Auth:        "sm2",
		IKEVersion:  "V2",
		IKEMode:     "main",
		// 传输密码套件：默认 AES256/SHA256（stock strongSwan 6.x 原生支持，配合 ml 插件
		// 可加载 ke1_mlkem 后量子混合）；国密网关(GM-patched strongSwan)可用
		// ZPQM_GW_ENC=SM4 ZPQM_GW_INTEG=SM3 切回 SM4/SM3。
		IKEEnc:      gwEnvOr("ZPQM_GW_ENC", "AES256"),
		IKEAuth:     gwEnvOr("ZPQM_GW_INTEG", "SHA256"),
		DHGroup:     "19",
		IKELifetime: 86400,
		ESPMode:     "tunnel",
		Proto:       "ESP",
		ESPEnc:      gwEnvOr("ZPQM_GW_ENC", "AES256"),
		ESPAuth:     gwEnvOr("ZPQM_GW_INTEG", "SHA256"),
		PFS:         true,
		PQCGroup:    pqcGroup,
		LocalAddr:   "0.0.0.0",
		PeerAddr:    "203.0.113.10",
		SrcTS:       "10.0.0.0/24",
		DstTS:       "10.1.0.0/24",
		LocalID:     "CN=zhulong-pqm-mgmt",
		PeerID:      "CN=zhulong-gateway-core",
	}
	body, _ := json.Marshal(p)
	var data struct {
		ID json.Number `json:"id"`
	}
	if err := gwDo(http.MethodPost, base+"/api/ipsec/policies", token, body, &data); err != nil {
		return "", err
	}
	id := data.ID.String()
	if id == "" {
		id = "0"
	}
	return id, nil
}

// gwReload 调 POST /api/ipsec/reload。
func gwReload(base, token string) error {
	return gwDo(http.MethodPost, base+"/api/ipsec/reload", token, []byte(`{}`), nil)
}

// gwFirstSA 调 GET /api/ipsec/sas，返回首条 SA 的 "<ike>/<proto>"；读不到返回空串（不致命）。
func gwFirstSA(base, token string) string {
	var data json.RawMessage
	if err := gwDo(http.MethodGet, base+"/api/ipsec/sas", token, nil, &data); err != nil {
		return ""
	}
	sas := extractSAList(data)
	if len(sas) == 0 {
		return ""
	}
	ike, _ := sas[0]["ike"].(string)
	proto, _ := sas[0]["proto"].(string)
	return strings.Trim(ike+"/"+proto, "/")
}

// extractSAList 兼容 data 为裸数组 [...] 或包裹形 {list:[...]}。
func extractSAList(raw json.RawMessage) []map[string]any {
	var arr []map[string]any
	if json.Unmarshal(raw, &arr) == nil && len(arr) > 0 {
		return arr
	}
	var wrap struct {
		List []map[string]any `json:"list"`
	}
	if json.Unmarshal(raw, &wrap) == nil && len(wrap.List) > 0 {
		return wrap.List
	}
	return nil
}

// gwDo 发一次带超时的请求，**统一校验烛龙网关的 {code,data,msg} 信封**：
// HTTP 非 2xx → 失败；code != 0 → 业务失败（带 msg，供编排诚实降级）；
// out 非 nil 时把 data 解到 out（无 data 字段则退化为整体解码）。
func gwDo(method, url, token string, body []byte, out any) error {
	ctx, cancel := context.WithTimeout(context.Background(), gwStepTimeout)
	defer cancel()
	var rdr io.Reader
	if body != nil {
		rdr = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, url, rdr)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := (&http.Client{Timeout: gwStepTimeout}).Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("%s 返回状态 %s", url, resp.Status)
	}
	// 烛龙网关信封：{"code":0,"data":...,"msg":""}；code!=0 即便 HTTP 200 也是失败。
	var env struct {
		Code *int            `json:"code"`
		Msg  string          `json:"msg"`
		Data json.RawMessage `json:"data"`
	}
	if json.Unmarshal(raw, &env) == nil && env.Code != nil {
		if *env.Code != 0 {
			msg := env.Msg
			if msg == "" {
				msg = fmt.Sprintf("code=%d", *env.Code)
			}
			return fmt.Errorf("网关拒绝: %s", msg)
		}
		if out != nil && len(env.Data) > 0 {
			return json.Unmarshal(env.Data, out)
		}
		return nil
	}
	// 非信封响应：直接解码。
	if out != nil {
		return json.Unmarshal(raw, out)
	}
	return nil
}
