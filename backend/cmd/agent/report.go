package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"zhulong-pqm/internal/model"
)

// maxBatchSize 单批上报的最大资产数（契约规定 ≤2000，Agent 端保守取 500 更利于失败重试）。
const maxBatchSize = 500

// batchReport 单批上报的响应体，字段对齐后端 agentAssetsBatch 的返回契约。
type batchReport struct {
	Created    int    `json:"created"`
	Updated    int    `json:"updated"`
	Total      int    `json:"total"`
	ReportedBy string `json:"reportedBy"`
}

// reportAssets 把 assets 按 maxBatchSize 分批 POST 到 {server}/api/v1/agent/assets/batch
// （X-Agent-Key 鉴权），逐批打印 created/updated；任一批失败立即返回清晰错误，不吞错。
func reportAssets(cfg Config, assets []model.CryptoAsset) error {
	if len(assets) == 0 {
		fmt.Println("本次未发现任何密码学使用点，跳过上报")
		return nil
	}
	client := &http.Client{Timeout: 30 * time.Second}
	if cfg.Insecure {
		client.Transport = &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}} // #nosec G402 -- 用户显式 --insecure 选择信任自签名服务器
	}

	endpoint := strings.TrimRight(cfg.Server, "/") + "/api/v1/agent/assets/batch"
	totalCreated, totalUpdated := 0, 0

	for start := 0; start < len(assets); start += maxBatchSize {
		end := start + maxBatchSize
		if end > len(assets) {
			end = len(assets)
		}
		batch := assets[start:end]

		body, err := json.Marshal(struct {
			Assets []model.CryptoAsset `json:"assets"`
		}{Assets: batch})
		if err != nil {
			return fmt.Errorf("序列化第 %d-%d 条资产失败: %w", start, end, err)
		}

		req, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(body))
		if err != nil {
			return fmt.Errorf("构造上报请求失败: %w", err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Agent-Key", cfg.Key)

		resp, err := client.Do(req)
		if err != nil {
			return fmt.Errorf("上报到 %s 失败（第 %d-%d 条）: %w", endpoint, start, end, err)
		}
		respBody, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("上报被拒绝（第 %d-%d 条），HTTP %d: %s", start, end, resp.StatusCode, strings.TrimSpace(string(respBody)))
		}

		var rep batchReport
		if err := json.Unmarshal(respBody, &rep); err != nil {
			return fmt.Errorf("解析上报响应失败（第 %d-%d 条）: %w，原始响应: %s", start, end, err, string(respBody))
		}
		totalCreated += rep.Created
		totalUpdated += rep.Updated
		fmt.Printf("[批次 %d-%d] 新建 %d / 更新 %d（Agent=%s）\n", start, end, rep.Created, rep.Updated, rep.ReportedBy)
	}
	fmt.Printf("上报完成：共 %d 条，新建 %d / 更新 %d\n", len(assets), totalCreated, totalUpdated)
	return nil
}
