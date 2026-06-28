package scan

import (
	"context"
	"fmt"

	"zhulong-pqm/internal/model"
)

// PlaceholderScanner 占位扫描器（IKE/RDP 等未实现协议）。
//
// 只注册元数据，规则库可见但探测返回「未实现」，不阻塞主流程（深化蓝图 ①）。
type PlaceholderScanner struct {
	name        string
	defaultPort int
}

// NewPlaceholderScanner 构造占位扫描器。
func NewPlaceholderScanner(name string, defaultPort int) *PlaceholderScanner {
	return &PlaceholderScanner{name: name, defaultPort: defaultPort}
}

// Method 占位扫描器统一标 M1（主动协议）。
func (s *PlaceholderScanner) Method() string { return model.MethodM1ActiveTLS }

// Name 返回扫描器名。
func (s *PlaceholderScanner) Name() string { return s.name }

// Scan 返回未实现错误（诚实标注，不产生伪造结果）。
func (s *PlaceholderScanner) Scan(ctx context.Context, host string, port int) (*model.ScanResult, error) {
	return nil, fmt.Errorf("%s 扫描器尚未实现（占位）", s.name)
}
