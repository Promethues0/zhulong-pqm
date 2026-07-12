package model

import "time"

// Agent 主机 Agent / 分布式探针的身份档案（M-B）。
//
// 告别「Agent 拿 admin 密码换 token」：管理员注册一个 Agent 得到一次性 API Key，
// Agent 用该 Key 上报，平台按 AgentID 归属资产（CryptoAsset.ReportedBy）。
// Key 仅存哈希（KeyHash），明文只在注册那一刻返回一次。
type Agent struct {
	ID         uint       `gorm:"primaryKey" json:"id"`
	AgentID    string     `gorm:"uniqueIndex;not null" json:"agentId"` // 对外公开标识，如 agent-7f3a2c
	Hostname   string     `json:"hostname"`
	Kind       string     `gorm:"default:host" json:"kind"` // host/probe/both
	LabelsJSON string     `gorm:"column:labels;type:text" json:"-"`
	Labels     []string   `gorm:"-" json:"labels"` // 网段/机房/业务标签，供任务分发（M-D）与筛选
	Version    string     `json:"version"`
	Status     string     `gorm:"default:active" json:"status"` // active/revoked
	KeyHash    string     `json:"-"`                            // API Key 的 SHA-256(hex)，绝不回传
	OS         string     `json:"os"`
	LastSeenAt *time.Time `json:"lastSeenAt"`
	EnrolledAt time.Time  `json:"enrolledAt"`
	CreatedAt  time.Time  `json:"createdAt"`
	UpdatedAt  time.Time  `json:"updatedAt"`
}

// Agent 种类。
const (
	AgentKindHost  = "host"  // 主机全量密码学发现
	AgentKindProbe = "probe" // 分布式抓包探针（M-D）
	AgentKindBoth  = "both"
)

// Agent 状态。
const (
	AgentActive  = "active"
	AgentRevoked = "revoked"
)

// SourceAgent 主机 Agent 上报的资产来源（区别于 scan/manual/import）。
const SourceAgent = "agent"
