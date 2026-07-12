// Package remediate 提供 R2 改造主线：以编排外部设备为主线，把资产迁移到后量子算法。
//
// 它由两部分组成：静态的剧本库（Playbook）描述每条改造轨道的标准步骤与交付/验收口径；
// 以及异步执行器（Orchestrator），按剧本逐步编排设备并实时回写工单进度（模式照抄 scan.Runner）。
package remediate

// Playbook 一条改造轨道的剧本：标准步骤、交付物与验收口径。
//
// 剧本是静态知识，不入库；建工单时按剧本快照 Deliverable/Acceptance/Steps，
// 之后剧本演进不影响历史工单。
type Playbook struct {
	Key        string   `json:"key"`        // 唯一键（tls-hybrid 等）
	Name       string   `json:"name"`       // 中文名
	DeviceType string   `json:"deviceType"` // 适配设备类型（gateway/hsm/ca）
	TargetAlgo string   `json:"targetAlgo"` // 默认建议目标算法
	Steps      []string `json:"steps"`      // 标准步骤名（有序）
	Deliverable string  `json:"deliverable"` // 交付物
	Acceptance  string  `json:"acceptance"`  // 验收标准
}

// playbooks 剧本库。文案与设计规范严格对齐，单测可据此锁定。
var playbooks = []Playbook{
	{
		Key:        "tls-hybrid",
		Name:       "外部TLS混合KEM",
		DeviceType: "gateway",
		TargetAlgo: "X25519+ML-KEM-768",
		Steps: []string{
			"设备连通性校验",
			"下发混合KEM提议(X25519MLKEM768)",
			"灰度发布5→20→50→100%",
			"混合握手验收",
		},
		Deliverable: "对外TLS混合KEM上线",
		Acceptance:  "openssl s_client -groups X25519MLKEM768 握手成功",
	},
	{
		Key:        "root-ca-hybrid",
		Name:       "根CA/PKI混合根CA",
		DeviceType: "hsm",
		TargetAlgo: "ML-DSA-65",
		Steps: []string{
			"HSM连通性与槽位校验",
			"HSM内生成混合根CA密钥对",
			"签发混合根CA自签名证书",
			"签发混合中间CA",
			"信任锚分发(GPO/MDM)",
			"证书链验收",
		},
		Deliverable: "混合根CA+中间CA+信任锚",
		Acceptance:  "openssl verify 证书链通过",
	},
	{
		Key:        "ssl-vpn-hybrid",
		Name:       "SSL VPN混合KEM",
		DeviceType: "gateway",
		TargetAlgo: "ke1_mlkem(MLKEM_768+X25519)",
		Steps: []string{
			"VPN固件PQC能力校验",
			"下发混合IKEv2提议(ke1_mlkem)",
			"客户端强制升级推送",
			"swanctl SA验收",
		},
		Deliverable: "VPN混合KEM上线",
		Acceptance:  "swanctl --list-sas ke-method MLKEM_768+X25519",
	},
	{
		Key:        "code-signing",
		Name:       "代码签名双签名",
		DeviceType: "sign-server", // 签名机执行 ML-DSA(Dilithium) 后量子签名（原 ca 占位，改指真实签名验签服务器）
		TargetAlgo: "RSA+ML-DSA-87",
		Steps: []string{
			"代码签名基础设施审计",
			"部署RSA+ML-DSA双签名",
			"TSA时间戳服务协调",
			"双签名验收",
		},
		Deliverable: "RSA+ML-DSA双签名",
		Acceptance:  "双签名均有效",
	},
	{
		Key:        "gm-hybrid",
		Name:       "国密融合SM2+ML-KEM",
		DeviceType: "gateway",
		TargetAlgo: "SM2+ML-KEM/SM2+ML-DSA",
		Steps: []string{
			"国密网关能力校验",
			"下发SM2+ML-KEM混合提议",
			"灰度发布",
			"国密混合握手验收",
		},
		Deliverable: "国密混合上线",
		Acceptance:  "SM2+ML-KEM混合协商成功",
	},
}

// Playbooks 返回全部改造剧本（静态副本）。
func Playbooks() []Playbook {
	out := make([]Playbook, len(playbooks))
	copy(out, playbooks)
	return out
}

// PlaybookByKey 按 Key 查找剧本，未命中返回 (Playbook{}, false)。
func PlaybookByKey(key string) (Playbook, bool) {
	for _, p := range playbooks {
		if p.Key == key {
			return p, true
		}
	}
	return Playbook{}, false
}
