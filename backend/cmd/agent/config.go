package main

import (
	"flag"
	"fmt"
	"os"
)

// Config 主机 Agent 运行配置：flag 优先，env（ZPQM_AGENT_*）兜底默认值。
type Config struct {
	Server   string // 平台地址，如 http://127.0.0.1:8099
	Key      string // X-Agent-Key（注册 Agent 时平台一次性下发的 apiKey）
	Role     string // host（本轮实现）/ probe（M-D 预留)
	Once     bool   // true=采一次即退出；false 常驻按 Interval 轮询
	Interval int    // 秒，Once=false 时的轮询间隔；0 视同 Once
	FSRoot   string // 发现根目录，默认 "/"；容器/测试注入 fixture 目录
	SSHDir   string // SSH 主机密钥目录，默认 /etc/ssh
	Insecure bool   // 跳过服务器 TLS 证书校验（自签名场景）

	// 探针模式（role=probe）配置
	Iface       string // 抓包网卡，空=全部/any
	Duration    int    // 抓包时长（秒）
	MaxPackets  int    // 抓包数上限
	BPF         string // tcpdump 回退时的 BPF 过滤表达式
	CaptureMode string // auto/afpacket/tcpdump
}

// envOr 取环境变量，缺省时回落 def。
func envOr(key, def string) string {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		return v
	}
	return def
}

// envBoolOr 取布尔环境变量（"1"/"true"/"yes" 为真，大小写不敏感），缺省回落 def。
func envBoolOr(key string, def bool) bool {
	v, ok := os.LookupEnv(key)
	if !ok || v == "" {
		return def
	}
	switch v {
	case "1", "true", "TRUE", "True", "yes", "YES":
		return true
	case "0", "false", "FALSE", "False", "no", "NO":
		return false
	default:
		return def
	}
}

// envIntOr 取整数环境变量，缺省或解析失败回落 def。
func envIntOr(key string, def int) int {
	v, ok := os.LookupEnv(key)
	if !ok || v == "" {
		return def
	}
	n := 0
	neg := false
	for i, ch := range v {
		if i == 0 && ch == '-' {
			neg = true
			continue
		}
		if ch < '0' || ch > '9' {
			return def
		}
		n = n*10 + int(ch-'0')
	}
	if neg {
		n = -n
	}
	return n
}

// loadConfig 解析 flag（默认值取自 env），返回配置。err 非空即参数不合法。
func loadConfig(args []string) (Config, error) {
	fs := flag.NewFlagSet("zhulong-pqm-agent", flag.ContinueOnError)
	cfg := Config{}
	fs.StringVar(&cfg.Server, "server", envOr("ZPQM_AGENT_SERVER", "http://127.0.0.1:8099"), "烛龙 PQM 平台地址")
	fs.StringVar(&cfg.Key, "key", envOr("ZPQM_AGENT_KEY", ""), "Agent API Key（X-Agent-Key，注册 Agent 时一次性下发）")
	fs.StringVar(&cfg.Role, "role", envOr("ZPQM_AGENT_ROLE", "host"), "Agent 角色：host（主机全量发现，本轮实现）/ probe（预留）")
	fs.BoolVar(&cfg.Once, "once", envBoolOr("ZPQM_AGENT_ONCE", true), "true=采集一次即退出；false 常驻按 --interval 轮询")
	fs.IntVar(&cfg.Interval, "interval", envIntOr("ZPQM_AGENT_INTERVAL", 0), "常驻模式轮询间隔（秒），0 视同 --once")
	fs.StringVar(&cfg.FSRoot, "fsroot", envOr("ZPQM_AGENT_FSROOT", "/"), "发现根目录（测试/容器注入 fixture 目录）")
	fs.StringVar(&cfg.SSHDir, "ssh-dir", envOr("ZPQM_AGENT_SSH_DIR", "/etc/ssh"), "SSH 主机密钥目录")
	fs.BoolVar(&cfg.Insecure, "insecure", envBoolOr("ZPQM_AGENT_INSECURE", false), "跳过平台 TLS 证书校验（自签名场景）")
	fs.StringVar(&cfg.Iface, "iface", envOr("ZPQM_AGENT_IFACE", ""), "探针抓包网卡（空=全部/any）")
	fs.IntVar(&cfg.Duration, "duration", envIntOr("ZPQM_AGENT_DURATION", 30), "探针抓包时长（秒）")
	fs.IntVar(&cfg.MaxPackets, "max-packets", envIntOr("ZPQM_AGENT_MAX_PACKETS", 100000), "探针抓包数上限")
	fs.StringVar(&cfg.BPF, "bpf", envOr("ZPQM_AGENT_BPF", "tcp"), "tcpdump 回退时的 BPF 过滤表达式")
	fs.StringVar(&cfg.CaptureMode, "capture-mode", envOr("ZPQM_AGENT_CAPTURE_MODE", "auto"), "抓包机制：auto/afpacket/tcpdump")

	if err := fs.Parse(args); err != nil {
		return cfg, err
	}
	if cfg.Interval > 0 {
		cfg.Once = false
	}
	if cfg.Key == "" {
		return cfg, fmt.Errorf("缺少 Agent Key：请先在控制台注册 Agent 获取 apiKey，再用 --key 或 ZPQM_AGENT_KEY 提供")
	}
	return cfg, nil
}
