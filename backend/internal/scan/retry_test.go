package scan

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"zhulong-pqm/internal/model"
)

// retryFakeScanner 前 fails 次返回 err，之后成功；记录调用次数。
type retryFakeScanner struct {
	fails int32
	err   error
	calls int32
}

func (f *retryFakeScanner) Scan(_ context.Context, host string, port int) (*model.ScanResult, error) {
	n := atomic.AddInt32(&f.calls, 1)
	if n <= f.fails {
		return nil, f.err
	}
	return &model.ScanResult{Host: host, Port: port}, nil
}
func (f *retryFakeScanner) Method() string { return model.MethodM1ActiveTLS }
func (f *retryFakeScanner) Name() string   { return "fake" }

func TestScanWithRetry(t *testing.T) {
	pol := RetryPolicy{MaxRetries: 2, BaseBackoff: time.Millisecond}

	t.Run("瞬态超时重试后成功", func(t *testing.T) {
		f := &retryFakeScanner{fails: 2, err: errors.New("dial tcp 1.2.3.4:443: i/o timeout")}
		res, err := scanWithRetry(context.Background(), f, "h", 443, pol)
		if err != nil || res == nil {
			t.Fatalf("应重试到成功，err=%v", err)
		}
		if f.calls != 3 {
			t.Errorf("应调用 3 次（1 + 2 重试），实际 %d", f.calls)
		}
	})

	t.Run("拒绝连接不重试", func(t *testing.T) {
		f := &retryFakeScanner{fails: 9, err: errors.New("dial tcp 1.2.3.4:443: connect: connection refused")}
		if _, err := scanWithRetry(context.Background(), f, "h", 443, pol); err == nil {
			t.Fatal("应失败")
		}
		if f.calls != 1 {
			t.Errorf("确定性失败不应重试，实际调用 %d", f.calls)
		}
	})

	t.Run("TLS 协议错误不重试", func(t *testing.T) {
		f := &retryFakeScanner{fails: 9, err: errors.New("tls: first record does not look like a TLS handshake")}
		if _, err := scanWithRetry(context.Background(), f, "h", 443, pol); err == nil {
			t.Fatal("应失败")
		}
		if f.calls != 1 {
			t.Errorf("TLS 协议错误不应重试，实际调用 %d", f.calls)
		}
	})

	t.Run("超过上限仍失败", func(t *testing.T) {
		f := &retryFakeScanner{fails: 99, err: errors.New("i/o timeout")}
		if _, err := scanWithRetry(context.Background(), f, "h", 443, pol); err == nil {
			t.Fatal("应失败")
		}
		if f.calls != 3 {
			t.Errorf("应调用 1 + 2 次后放弃，实际 %d", f.calls)
		}
	})
}

func TestScanWithRetry_CtxCancel(t *testing.T) {
	pol := RetryPolicy{MaxRetries: 5, BaseBackoff: 50 * time.Millisecond}
	f := &retryFakeScanner{fails: 99, err: errors.New("i/o timeout")}
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // 立即取消：退避 select 应立刻返回，不再重试
	if _, err := scanWithRetry(ctx, f, "h", 443, pol); err == nil {
		t.Fatal("应返回失败")
	}
	if f.calls != 1 {
		t.Errorf("取消后应停止重试，实际调用 %d", f.calls)
	}
}
