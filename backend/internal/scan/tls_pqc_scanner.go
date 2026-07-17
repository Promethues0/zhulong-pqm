package scan

import (
	"context"
	"fmt"
	"strings"

	"zhulong-pqm/internal/cryptoref"
	"zhulong-pqm/internal/model"
)

// TLSPQCScanner 组合式主动扫描器：先委托 TLSScanner 真握手拿证书/认证维，
// 再用 ProbePQCGroups 逐组枚举补密钥交换维，合并进同一 ScanResult。opt-in（scannerType=tls-pqc）。
type TLSPQCScanner struct {
	tls *TLSScanner
}

// NewTLSPQCScanner 构造组合扫描器。
func NewTLSPQCScanner() *TLSPQCScanner {
	return &TLSPQCScanner{tls: NewTLSScanner()}
}

// Method 仍是 M1（主动 TLS 握手）——枚举探针不改变发现方式语义。
func (s *TLSPQCScanner) Method() string { return model.MethodM1ActiveTLS }

// Name 返回扫描器名。
func (s *TLSPQCScanner) Name() string { return "tls-pqc" }

// Scan 真握手拿证书 + 逐组枚举 PQC 组，合并成一条结果。
func (s *TLSPQCScanner) Scan(ctx context.Context, host string, port int) (*model.ScanResult, error) {
	res, err := s.tls.Scan(ctx, host, port)
	if err != nil {
		return nil, err // 无证书=无资产，与现有语义一致（Runner 记 failed 结果）
	}
	// 逐组枚举；单组失败探针内部已 continue 容错，返回服务端支持的 PQC/混合组码点。
	supported, _ := ProbePQCGroups(host, port, cryptoref.PQCGroupCodepoints(), dialTimeout)
	applyProbeResult(res, supported)
	return res, nil
}

// applyProbeResult 把枚举到的支持组合并进 res：取表序第一个为主组填 KexGroup/KexSafety，
// 全部支持组记进 EvidenceNote 留证。supported 空则不动 res（经典目标 KexGroup 留空，不误判）。
func applyProbeResult(res *model.ScanResult, supported []int) {
	if len(supported) == 0 {
		return
	}
	primary := supported[0]
	name, kind, _, _ := cryptoref.ClassifyGroup(primary)
	res.KexGroup = name
	res.KexSafety = cryptoref.SafetyFromKind(kind)

	codes := make([]string, len(supported))
	for i, cp := range supported {
		codes[i] = fmt.Sprintf("0x%04X", cp)
	}
	note := fmt.Sprintf("主动枚举 PQC 支持组: %s（主组 %s/%s）",
		strings.Join(codes, " "), name, res.KexSafety)
	if res.EvidenceNote == "" {
		res.EvidenceNote = note
	} else {
		res.EvidenceNote += "; " + note
	}
}
