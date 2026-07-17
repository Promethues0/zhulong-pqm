package scan

import (
	"testing"

	"zhulong-pqm/internal/model"
)

func TestNewScanner_TLSPQC(t *testing.T) {
	sc := NewScanner(model.ScannerTLSPQC)
	if sc.Name() != "tls-pqc" {
		t.Errorf("NewScanner(tls-pqc).Name() = %q, want tls-pqc", sc.Name())
	}
	if _, ok := sc.(*TLSPQCScanner); !ok {
		t.Errorf("NewScanner(tls-pqc) 类型 = %T, want *TLSPQCScanner", sc)
	}
	// 默认 tls 仍是 TLSScanner（无回归）
	if _, ok := NewScanner(model.ScannerTLS).(*TLSScanner); !ok {
		t.Error("NewScanner(tls) 应仍返回 *TLSScanner")
	}
}

// TestParseTargets_CIDRExpand 验证 CIDR 网段展开（去网络/广播号、上限保护）与单目标解析。
func TestParseTargets_CIDRExpand(t *testing.T) {
	cases := []struct {
		name     string
		in       []string
		wantLen  int
		contains []Target // 必须包含的样本
		absent   []string // 不应出现的 host（网络号/广播号）
	}{
		{
			name:     "/30 去网络与广播留 2 主机",
			in:       []string{"192.168.1.0/30"},
			wantLen:  2,
			contains: []Target{{Host: "192.168.1.1", Port: DefaultPort}, {Host: "192.168.1.2", Port: DefaultPort}},
			absent:   []string{"192.168.1.0", "192.168.1.3"},
		},
		{
			name:    "/24 展开 254 主机",
			in:      []string{"10.0.0.0/24"},
			wantLen: 254,
			absent:  []string{"10.0.0.0", "10.0.0.255"},
		},
		{
			name:     "/32 单主机保留",
			in:       []string{"10.1.2.3/32"},
			wantLen:  1,
			contains: []Target{{Host: "10.1.2.3", Port: DefaultPort}},
		},
		{
			name:     "普通 host:port 不受影响",
			in:       []string{"example.com:8443"},
			wantLen:  1,
			contains: []Target{{Host: "example.com", Port: 8443}},
		},
		{
			name:    "/8 触发上限截断",
			in:      []string{"10.0.0.0/8"},
			wantLen: maxCIDRHosts,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ParseTargets(tc.in)
			if len(got) != tc.wantLen {
				t.Fatalf("len=%d，期望 %d", len(got), tc.wantLen)
			}
			set := make(map[string]bool)
			for _, g := range got {
				set[g.Host] = true
			}
			for _, want := range tc.contains {
				found := false
				for _, g := range got {
					if g == want {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("缺少目标 %+v", want)
				}
			}
			for _, h := range tc.absent {
				if set[h] {
					t.Errorf("不应出现网络/广播号 %s", h)
				}
			}
		})
	}
}
