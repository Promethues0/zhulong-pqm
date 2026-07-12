package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

func TestPollAndRunOne_LeaseCaptureReportComplete(t *testing.T) {
	var completed atomic.Bool
	var reported atomic.Int32

	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/agent/tasks", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"id": 42, "iface": "", "bpf": "tcp", "duration": 1, "maxPackets": 100})
	})
	mux.HandleFunc("/api/v1/agent/assets/batch", func(w http.ResponseWriter, r *http.Request) {
		reported.Add(1)
		json.NewEncoder(w).Encode(map[string]any{"created": 0, "updated": 0})
	})
	mux.HandleFunc("/api/v1/agent/tasks/42/complete", func(w http.ResponseWriter, r *http.Request) {
		completed.Store(true)
		json.NewEncoder(w).Encode(map[string]any{"ok": true, "status": "done"})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	// 注入假抓包：返回一个含 ServerHello(0x11EC) 的 pcap 字节流（复用 capture_test 里的 builder）
	captureFn = func(cfg *Config) ([]byte, error) {
		return wrapPcap([][]byte{tlsFrame(serverHelloKeyShare(0x11EC), [4]byte{10, 0, 0, 5}, [4]byte{10, 0, 0, 9}, 443, 40000)}), nil
	}
	defer func() { captureFn = Capture }()

	cfg := Config{Server: srv.URL, Key: "k", Role: "probe", Managed: true}
	got, err := pollAndRunOne(cfg)
	if err != nil {
		t.Fatalf("pollAndRunOne err: %v", err)
	}
	if !got {
		t.Fatal("应领到并执行一个任务")
	}
	if reported.Load() == 0 || !completed.Load() {
		t.Errorf("应上报观测且报完成: reported=%d completed=%v", reported.Load(), completed.Load())
	}
}
