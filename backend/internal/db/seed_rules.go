package db

import (
	"fmt"
	"log"

	"gorm.io/gorm"

	"zhulong-pqm/internal/model"
)

// ruleSeedErr 规则种子自检错误。
func ruleSeedErr(format string, a ...any) error {
	return fmt.Errorf("seed scan rules: "+format, a...)
}

// seedRuleSpec 描述一条内置扫描规则（PRD 文件 1-1 的 30 条规则库）。
type seedRuleSpec struct {
	RuleID      string
	CheckItem   string
	Layer       string
	AlgoFeature string
	Tools       string
	RiskHint    string   // 极高/高/中
	Confidence  string   // 高/中/低
	Methods     []string // 默认发现方式
	Priority    string   // P1/P2/P3
}

// builtinRules 内置 30 条规则：L1×8 / L2×8 / L3×8 / L4×6。
//
// 统计契约（FR-3.4.1，db 自检与 /rules 统计头共同保证）：
//   total=30、极高(RiskHint=极高)=7、P1 高优(Priority=P1)=14、按层 8/8/8/6。
//
// 七条极高规则号硬编码：R-L2-01/03/04/08、R-L3-03/07、R-L4-03（model.CriticalRuleIDs）。
// 文案取 PRD/深化蓝图 ① 命中表与 L1-L4 分层清单。
var builtinRules = []seedRuleSpec{
	// ---- L1 应用/会话层（8 条；P1=3，极高=0）----
	{"R-L1-01", "对外 TLS 版本清单", model.LayerL1, "TLS1.0/1.1/1.2 弱版本", "nmap/sslyze/testssl.sh", model.RiskHintMedium, model.ConfHigh, []string{model.MethodM1ActiveTLS, model.MethodM2Passive}, model.LevelP1},
	{"R-L1-02", "密钥协商套件审计", model.LayerL1, "RSA/ECDH/DHE 经典 KEX（非混合/PQC）", "sslyze/testssl.sh", model.RiskHintHigh, model.ConfHigh, []string{model.MethodM1ActiveTLS}, model.LevelP1},
	{"R-L1-03", "证书签名算法审计", model.LayerL1, "RSA-PKCS1/ECDSA/Ed25519 签名", "openssl/sslyze", model.RiskHintHigh, model.ConfHigh, []string{model.MethodM1ActiveTLS, model.MethodM5Cert}, model.LevelP1},
	{"R-L1-04", "HTTPS API 网关加密栈", model.LayerL1, "对外 API 经典握手", "nmap/sslyze", model.RiskHintMedium, model.ConfMedium, []string{model.MethodM1ActiveTLS}, model.LevelP2},
	{"R-L1-05", "SSH KEX 算法审计", model.LayerL1, "经典 DH/ECDH（curve25519 不命中）", "ssh-audit", model.RiskHintMedium, model.ConfHigh, []string{model.MethodM1ActiveTLS}, model.LevelP2},
	{"R-L1-06", "邮件/SMTP STARTTLS 加密", model.LayerL1, "SMTP/IMAP 经典 TLS", "testssl.sh/nmap", model.RiskHintMedium, model.ConfMedium, []string{model.MethodM1ActiveTLS, model.MethodM2Passive}, model.LevelP3},
	{"R-L1-07", "Web 应用 JWT/会话签名", model.LayerL1, "RS256/ES256 经典签名", "代码审计/M3 Agent", model.RiskHintMedium, model.ConfMedium, []string{model.MethodM3Agent, model.MethodM6Config}, model.LevelP3},
	{"R-L1-08", "客户端 mTLS 双向认证", model.LayerL1, "客户端证书 RSA/ECDSA", "sslyze/抓包", model.RiskHintMedium, model.ConfMedium, []string{model.MethodM1ActiveTLS, model.MethodM2Passive}, model.LevelP2},

	// ---- L2 协议/传输层（8 条；P1=5，极高=4：R-L2-01/03/04/08）----
	{"R-L2-01", "根/中间 CA 证书算法", model.LayerL2, "自签 CA：RSA/SM2 且 IsCA", "openssl/PKI 巡检/PEM 导入", model.RiskHintCritical, model.ConfHigh, []string{model.MethodM5Cert, model.MethodM3Agent}, model.LevelP1},
	{"R-L2-02", "服务器叶证书算法", model.LayerL2, "服务器证书 RSA/ECDSA", "openssl/sslyze/PEM 导入", model.RiskHintHigh, model.ConfHigh, []string{model.MethodM1ActiveTLS, model.MethodM5Cert}, model.LevelP1},
	{"R-L2-03", "IPSec/IKEv2 网关 KEX", model.LayerL2, "IKEv2 经典 DH 组（非 ke1_mlkem 混合）", "ike-scan/网关配置审计", model.RiskHintCritical, model.ConfMedium, []string{model.MethodM6Config, model.MethodM3Agent}, model.LevelP1},
	{"R-L2-04", "VPN 隧道密钥交换", model.LayerL2, "SSL/IPSec VPN 经典密钥协商", "网关配置审计/抓包", model.RiskHintCritical, model.ConfMedium, []string{model.MethodM6Config, model.MethodM2Passive}, model.LevelP1},
	{"R-L2-05", "SSH 主机密钥算法", model.LayerL2, "主机密钥 RSA/ECDSA", "ssh-audit", model.RiskHintMedium, model.ConfHigh, []string{model.MethodM1ActiveTLS}, model.LevelP2},
	{"R-L2-06", "私有协议 TLS 封装", model.LayerL2, "中间件/消息总线经典 TLS", "抓包/配置审计", model.RiskHintMedium, model.ConfMedium, []string{model.MethodM6Config, model.MethodM2Passive}, model.LevelP3},
	{"R-L2-07", "负载均衡 SSL 卸载", model.LayerL2, "LB 终结点经典套件", "sslyze/配置审计", model.RiskHintHigh, model.ConfMedium, []string{model.MethodM1ActiveTLS, model.MethodM6Config}, model.LevelP2},
	{"R-L2-08", "PKI 信任链完整审计", model.LayerL2, "证书链全经典签名（根→叶）", "openssl/PKI 巡检", model.RiskHintCritical, model.ConfHigh, []string{model.MethodM5Cert, model.MethodM3Agent}, model.LevelP1},

	// ---- L3 数据存储层（8 条；P1=4，极高=2：R-L3-03/07）----
	{"R-L3-01", "数据库静态加密(TDE)", model.LayerL3, "DB TDE AES + RSA 包裹密钥", "M3 Agent/配置审计", model.RiskHintHigh, model.ConfMedium, []string{model.MethodM3Agent, model.MethodM6Config}, model.LevelP1},
	{"R-L3-02", "字段级/列加密", model.LayerL3, "应用层字段加密经典封装", "代码审计/M3", model.RiskHintMedium, model.ConfMedium, []string{model.MethodM3Agent}, model.LevelP3},
	{"R-L3-03", "长效合规档案加密", model.LayerL3, "10 年+ 归档 RSA 封装（HNDL 高危）", "M3 Agent/资产清册", model.RiskHintCritical, model.ConfMedium, []string{model.MethodM3Agent, model.MethodM7Manual}, model.LevelP1},
	{"R-L3-04", "备份/磁带加密", model.LayerL3, "备份介质经典密钥包裹", "M3 Agent/配置审计", model.RiskHintHigh, model.ConfMedium, []string{model.MethodM3Agent, model.MethodM6Config}, model.LevelP1},
	{"R-L3-05", "对象存储 SSE 加密", model.LayerL3, "SSE-KMS 经典主密钥", "M3 Agent/云配置审计", model.RiskHintMedium, model.ConfMedium, []string{model.MethodM3Agent, model.MethodM6Config}, model.LevelP3},
	{"R-L3-06", "文件系统/卷加密", model.LayerL3, "全盘加密密钥封装", "M3 Agent", model.RiskHintMedium, model.ConfMedium, []string{model.MethodM3Agent}, model.LevelP3},
	{"R-L3-07", "密钥管理系统(KMS)主密钥", model.LayerL3, "KMS 根/主密钥 RSA 包裹（核心信任）", "KMS 审计/M3", model.RiskHintCritical, model.ConfMedium, []string{model.MethodM3Agent, model.MethodM6Config}, model.LevelP1},
	{"R-L3-08", "消息队列/日志静态加密", model.LayerL3, "MQ/日志落盘经典加密", "M3 Agent/配置审计", model.RiskHintMedium, model.ConfMedium, []string{model.MethodM3Agent}, model.LevelP2},

	// ---- L4 硬件/根信任层（6 条；P1=2，极高=1：R-L4-03）----
	{"R-L4-01", "加密库版本(ML-KEM 支持)", model.LayerL4, "OpenSSL<3.5/LibreSSL/mbedTLS 不支持 ML-KEM", "syft/cdxgen/SBOM 导入", model.RiskHintMedium, model.ConfHigh, []string{model.MethodM4SBOM}, model.LevelP2},
	{"R-L4-02", "HSM/加密机算法能力", model.LayerL4, "HSM 仅支持经典算法固件", "HSM 巡检/M3", model.RiskHintHigh, model.ConfMedium, []string{model.MethodM3Agent, model.MethodM7Manual}, model.LevelP2},
	{"R-L4-03", "硬件根信任(TPM/安全芯片)", model.LayerL4, "TPM/安全芯片固化经典根密钥不可 OTA", "硬件清册/M7 申报", model.RiskHintCritical, model.ConfLow, []string{model.MethodM7Manual, model.MethodM3Agent}, model.LevelP1},
	{"R-L4-04", "IoT/工控设备证书", model.LayerL4, "5–10 年长效证书无 OTA 升级", "资产清册/M7", model.RiskHintHigh, model.ConfLow, []string{model.MethodM7Manual, model.MethodM3Agent}, model.LevelP1},
	{"R-L4-05", "第三方密码库依赖", model.LayerL4, "外部依赖加密组件（供应链）", "syft/cdxgen/SBOM 导入", model.RiskHintMedium, model.ConfHigh, []string{model.MethodM4SBOM}, model.LevelP3},
	{"R-L4-06", "固件/Bootloader 签名", model.LayerL4, "固件镜像经典签名验证", "固件审计/M7", model.RiskHintHigh, model.ConfLow, []string{model.MethodM7Manual, model.MethodM3Agent}, model.LevelP2},
}

// seedScanRules 在规则表为空时植入 30 条内置规则，并自检统计契约（FR-3.4.1）。
func seedScanRules(gdb *gorm.DB) error {
	var count int64
	gdb.Model(&model.ScanRule{}).Count(&count)
	if count > 0 {
		return nil
	}

	// 自检：种子常量必须满足 total=30、极高=7、P1=14、按层 8/8/8/6。
	if err := validateBuiltinRules(); err != nil {
		return err
	}

	for _, r := range builtinRules {
		rule := model.ScanRule{
			RuleID:         r.RuleID,
			CheckItem:      r.CheckItem,
			Layer:          r.Layer,
			AlgoFeature:    r.AlgoFeature,
			Tools:          r.Tools,
			RiskHint:       r.RiskHint,
			BaseConfidence: r.Confidence,
			MethodsJSON:    MarshalStrings(r.Methods),
			Priority:       r.Priority,
			Builtin:        true,
			Enabled:        true,
		}
		if err := gdb.Create(&rule).Error; err != nil {
			return err
		}
	}
	log.Printf("seed: 已创建 %d 条内置扫描规则（L1×8/L2×8/L3×8/L4×6，极高 7/P1 高优 14）", len(builtinRules))
	return nil
}

// validateBuiltinRules 编译期之后的运行期自检，防止后续误改 seed 破坏验收口径。
func validateBuiltinRules() error {
	if len(builtinRules) != 30 {
		return ruleSeedErr("规则总数应为 30，实为 %d", len(builtinRules))
	}
	byLayer := map[string]int{}
	critical, p1 := 0, 0
	seen := map[string]bool{}
	for _, r := range builtinRules {
		if seen[r.RuleID] {
			return ruleSeedErr("规则号重复：%s", r.RuleID)
		}
		seen[r.RuleID] = true
		byLayer[r.Layer]++
		if r.RiskHint == model.RiskHintCritical {
			critical++
		}
		if r.Priority == model.LevelP1 {
			p1++
		}
	}
	if byLayer["L1"] != 8 || byLayer["L2"] != 8 || byLayer["L3"] != 8 || byLayer["L4"] != 6 {
		return ruleSeedErr("分层数量应为 L1:8/L2:8/L3:8/L4:6，实为 L1:%d/L2:%d/L3:%d/L4:%d",
			byLayer["L1"], byLayer["L2"], byLayer["L3"], byLayer["L4"])
	}
	if critical != 7 {
		return ruleSeedErr("极高规则数应为 7，实为 %d", critical)
	}
	if p1 != 14 {
		return ruleSeedErr("P1 高优规则数应为 14，实为 %d", p1)
	}
	// 七条极高规则号必须与硬编码常量一致。
	for _, id := range model.CriticalRuleIDs {
		if !seen[id] {
			return ruleSeedErr("缺少极高规则号 %s", id)
		}
		for _, r := range builtinRules {
			if r.RuleID == id && r.RiskHint != model.RiskHintCritical {
				return ruleSeedErr("规则 %s 应为极高风险", id)
			}
		}
	}
	return nil
}
