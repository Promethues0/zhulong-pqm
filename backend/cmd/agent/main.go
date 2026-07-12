// Command zhulong-pqm-agent 是烛龙 PQM 的主机 Agent（M-C）：纯 Go、免 CGO 单二进制，
// 在目标主机本地做全量密码学发现（进程×加密库、磁盘证书、SSH 主机密钥、本地监听服务
// TLS 握手、内核算法与包清单），经 M-B 的受限 Agent 通道（X-Agent-Key）批量上报。
//
// 信创（鲲鹏/飞腾）要求：CGO_ENABLED=0 GOOS=linux GOARCH=amd64|arm64 可交叉编译，
// 全部发现逻辑只用标准库，只读、绝不修改目标主机任何东西。
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"zhulong-pqm/internal/model"
)

func main() {
	cfg, err := loadConfig(os.Args[1:])
	if err != nil {
		fmt.Fprintln(os.Stderr, "配置错误:", err)
		os.Exit(1)
	}

	runOnce := func() error {
		assets := gatherAssets(cfg)
		fmt.Printf("发现完成：共 %d 条密码学使用点\n", len(assets))
		return reportAssets(cfg, assets)
	}

	if cfg.Once {
		if err := runOnce(); err != nil {
			fmt.Fprintln(os.Stderr, "上报失败:", err)
			os.Exit(1)
		}
		return
	}

	// 常驻模式：按 Interval 周期跑；单轮失败只打印错误，不终止进程（下一轮再试）。
	interval := time.Duration(cfg.Interval) * time.Second
	fmt.Printf("常驻模式启动，每 %s 采集一次\n", interval)
	for {
		if err := runOnce(); err != nil {
			fmt.Fprintln(os.Stderr, "本轮上报失败:", err)
		}
		time.Sleep(interval)
	}
}

// gatherAssets 编排全部发现模块，汇总为待上报的 CryptoAsset 列表。
func gatherAssets(cfg Config) []model.CryptoAsset {
	var out []model.CryptoAsset
	out = append(out, discoverProcessLibs(cfg.FSRoot)...)
	out = append(out, discoverDiskCerts(defaultCertRoots(cfg.FSRoot))...)
	out = append(out, discoverSSHHostKeys(joinRoot(cfg.FSRoot, cfg.SSHDir))...)
	out = append(out, discoverListeners(cfg.FSRoot)...)
	out = append(out, discoverOSCrypto(cfg.FSRoot)...)
	return out
}

// joinRoot 把可能已是绝对路径的 sub 挂到 fsRoot 下：fsRoot="/" 时 filepath.Join 幂等
// （Join("/", "/etc/ssh") == "/etc/ssh"），fsRoot=测试/容器根目录时正确前缀。
func joinRoot(fsRoot, sub string) string {
	return filepath.Join(fsRoot, sub)
}

// defaultCertRoots 磁盘证书发现的默认目录集合（常见证书存放位置），fsRoot 前缀 + glob 展开。
func defaultCertRoots(fsRoot string) []string {
	patterns := []string{
		"/etc/ssl",
		"/etc/pki",
		"/etc/pki/tls",
		"/etc/nginx",
		"/opt/*/etc",
	}
	var out []string
	for _, p := range patterns {
		full := joinRoot(fsRoot, p)
		if strings.Contains(full, "*") {
			matches, _ := filepath.Glob(full)
			out = append(out, matches...)
			continue
		}
		out = append(out, full)
	}
	return out
}
