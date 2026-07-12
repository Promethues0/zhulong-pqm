package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// agentHTTPClient 构造上报用 http 客户端（--insecure 时跳过 TLS 校验），与 report.go 同口径。
func agentHTTPClient(cfg Config) *http.Client {
	client := &http.Client{Timeout: 30 * time.Second}
	if cfg.Insecure {
		client.Transport = &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}} // #nosec G402 -- 用户显式 --insecure
	}
	return client
}

// captureFn 抓包函数（默认 Capture；测试可注入假实现）。
var captureFn = Capture

// leasedTask 服务端下发的抓包任务（GET /agent/tasks 的响应子集）。
type leasedTask struct {
	ID         uint   `json:"id"`
	Iface      string `json:"iface"`
	BPF        string `json:"bpf"`
	Duration   int    `json:"duration"`
	MaxPackets int    `json:"maxPackets"`
}

// runManagedProbe managed 探针主循环：轮询领任务→抓→上报→报完成；无任务则 sleep 再轮询。
func runManagedProbe(cfg Config) error {
	poll := cfg.TaskPoll
	if poll <= 0 {
		poll = 15
	}
	fmt.Printf("探针 managed 模式启动，每 %ds 轮询领任务\n", poll)
	for {
		ran, err := pollAndRunOne(cfg)
		if err != nil {
			fmt.Fprintln(os.Stderr, "本轮出错:", err)
		}
		if !ran {
			time.Sleep(time.Duration(poll) * time.Second)
		}
	}
}

// pollAndRunOne 领并执行一个任务。领到并跑完返回 (true,nil)；无任务返回 (false,nil)。
func pollAndRunOne(cfg Config) (bool, error) {
	task, ok, err := leaseTaskHTTP(cfg)
	if err != nil || !ok {
		return false, err
	}
	fmt.Printf("领到抓包任务 #%d（iface=%s bpf=%s dur=%ds）\n", task.ID, task.Iface, task.BPF, task.Duration)
	// 用任务参数覆盖抓包配置
	tcfg := cfg
	tcfg.Iface, tcfg.BPF, tcfg.Duration, tcfg.MaxPackets = task.Iface, task.BPF, task.Duration, task.MaxPackets
	// 心跳保活
	stop := make(chan struct{})
	go heartbeatLoop(cfg, task.ID, stop)

	pcapBytes, cerr := captureFn(&tcfg)
	close(stop)
	if cerr != nil {
		completeTaskHTTP(cfg, task.ID, 0, cerr.Error())
		return true, cerr
	}
	assets, stats, perr := assetsFromPcap(pcapBytes)
	if perr != nil {
		completeTaskHTTP(cfg, task.ID, 0, perr.Error())
		return true, perr
	}
	fmt.Printf("任务 #%d 抓包：%d 包 / %d 握手 → %d 观测\n", task.ID, stats.Packets, stats.Handshakes, len(assets))
	if rerr := reportAssets(cfg, assets); rerr != nil {
		completeTaskHTTP(cfg, task.ID, 0, rerr.Error())
		return true, rerr
	}
	return true, completeTaskHTTP(cfg, task.ID, len(assets), "")
}

func leaseTaskHTTP(cfg Config) (leasedTask, bool, error) {
	var t leasedTask
	req, _ := http.NewRequest(http.MethodGet, apiURL(cfg, "/api/v1/agent/tasks"), nil)
	req.Header.Set("X-Agent-Key", cfg.Key)
	resp, err := agentHTTPClient(cfg).Do(req)
	if err != nil {
		return t, false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNoContent {
		return t, false, nil
	}
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return t, false, fmt.Errorf("领任务 HTTP %d: %s", resp.StatusCode, string(b))
	}
	if err := json.NewDecoder(resp.Body).Decode(&t); err != nil {
		return t, false, err
	}
	return t, true, nil
}

func heartbeatLoop(cfg Config, id uint, stop chan struct{}) {
	tk := time.NewTicker(30 * time.Second)
	defer tk.Stop()
	for {
		select {
		case <-stop:
			return
		case <-tk.C:
			req, _ := http.NewRequest(http.MethodPost, apiURL(cfg, fmt.Sprintf("/api/v1/agent/tasks/%d/heartbeat", id)), nil)
			req.Header.Set("X-Agent-Key", cfg.Key)
			if resp, err := agentHTTPClient(cfg).Do(req); err == nil {
				resp.Body.Close()
			}
		}
	}
}

func completeTaskHTTP(cfg Config, id uint, resultCount int, errMsg string) error {
	body, _ := json.Marshal(map[string]any{"resultCount": resultCount, "error": errMsg})
	req, _ := http.NewRequest(http.MethodPost, apiURL(cfg, fmt.Sprintf("/api/v1/agent/tasks/%d/complete", id)), bytes.NewReader(body))
	req.Header.Set("X-Agent-Key", cfg.Key)
	req.Header.Set("Content-Type", "application/json")
	resp, err := agentHTTPClient(cfg).Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	return nil
}

func apiURL(cfg Config, path string) string { return strings.TrimRight(cfg.Server, "/") + path }
