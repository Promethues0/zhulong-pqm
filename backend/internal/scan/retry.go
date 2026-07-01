package scan

import (
	"context"
	"errors"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"zhulong-pqm/internal/model"
)

// scanEnvInt 读非负整型环境变量，缺省/非法时回落。
func scanEnvInt(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			return n
		}
	}
	return def
}

// RetryPolicy 扫描瞬态失败的退避重试策略。
type RetryPolicy struct {
	MaxRetries  int           // 额外重试次数（0=不重试）
	BaseBackoff time.Duration // 首次退避，之后指数翻倍
}

// defaultRetryPolicy 从环境变量构造：
// ZPQM_SCAN_RETRIES（默认 2）、ZPQM_SCAN_BACKOFF_MS（默认 300）。
func defaultRetryPolicy() RetryPolicy {
	return RetryPolicy{
		MaxRetries:  scanEnvInt("ZPQM_SCAN_RETRIES", 2),
		BaseBackoff: time.Duration(scanEnvInt("ZPQM_SCAN_BACKOFF_MS", 300)) * time.Millisecond,
	}
}

// isRetryable 仅对【瞬态网络失败】重试：超时 / 连接重置 / 临时错误。
//
// 确定性失败一律不重试——徒增耗时且结论不会变：
// 拒绝连接（端口关闭）、无路由、DNS 不存在、TLS 协议 / 证书错误（非 TLS 服务或版本不匹配）。
// 上下文取消（任务被取消）也不重试。
func isRetryable(err error) bool {
	if err == nil || errors.Is(err, context.Canceled) {
		return false
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return true
	}
	s := strings.ToLower(err.Error())
	switch {
	case strings.Contains(s, "connection refused"),
		strings.Contains(s, "no route to host"),
		strings.Contains(s, "no such host"),
		strings.Contains(s, "tls:"),
		strings.Contains(s, "x509"):
		return false
	case strings.Contains(s, "i/o timeout"),
		strings.Contains(s, "deadline exceeded"),
		strings.Contains(s, "connection reset"),
		strings.Contains(s, "broken pipe"):
		return true
	}
	return false
}

// scanWithRetry 对瞬态失败做有上限的指数退避重试；退避期间响应 ctx 取消。
func scanWithRetry(ctx context.Context, sc Scanner, host string, port int, pol RetryPolicy) (*model.ScanResult, error) {
	var res *model.ScanResult
	var err error
	for attempt := 0; ; attempt++ {
		res, err = sc.Scan(ctx, host, port)
		if err == nil || attempt >= pol.MaxRetries || !isRetryable(err) {
			return res, err
		}
		backoff := pol.BaseBackoff << attempt // base * 2^attempt
		select {
		case <-ctx.Done():
			return res, err
		case <-time.After(backoff):
		}
	}
}
