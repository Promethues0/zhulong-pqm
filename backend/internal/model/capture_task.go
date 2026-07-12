package model

import "time"

// CaptureTask 分布式抓包任务（M-D2）：控制台建任务，按标签选择器分发给探针，拉取式租约领取。
type CaptureTask struct {
	ID                uint       `gorm:"primaryKey" json:"id"`
	Name              string     `gorm:"not null" json:"name"`
	LabelSelectorJSON string     `gorm:"column:label_selector;type:text" json:"-"`
	LabelSelector     []string   `gorm:"-" json:"labelSelector"` // 空=任意探针可领
	Iface             string     `json:"iface"`
	BPF               string     `gorm:"default:tcp" json:"bpf"`
	Duration          int        `gorm:"default:30" json:"duration"`
	MaxPackets        int        `gorm:"default:100000" json:"maxPackets"`
	Status            string     `gorm:"default:pending" json:"status"`
	LeasedBy          string     `json:"leasedBy"`
	LeaseExpiresAt    *time.Time `json:"leaseExpiresAt"`
	StartedAt         *time.Time `json:"startedAt"`
	FinishedAt        *time.Time `json:"finishedAt"`
	ResultCount       int        `json:"resultCount"`
	RunCount          int        `json:"runCount"`
	Error             string     `json:"error"`
	Schedule          string     `json:"schedule"` // cron，空=一次性
	ScheduleEnabled   bool       `json:"scheduleEnabled"`
	NextRunAt         *time.Time `json:"nextRunAt"`
	LastRunAt         *time.Time `json:"lastRunAt"`
	CreatedBy         string     `json:"createdBy"`
	CreatedAt         time.Time  `json:"createdAt"`
	UpdatedAt         time.Time  `json:"updatedAt"`
}

// 抓包任务状态。
const (
	CapturePending   = "pending"
	CaptureLeased    = "leased"
	CaptureDone      = "done"
	CaptureFailed    = "failed"
	CaptureCancelled = "cancelled"
)

// SubsetOf 判 sel 是否是 labels 的子集（sel 每个标签都在 labels 里）。空 sel 恒真（任意探针可领）。
func SubsetOf(sel, labels []string) bool {
	if len(sel) == 0 {
		return true
	}
	set := make(map[string]struct{}, len(labels))
	for _, l := range labels {
		set[l] = struct{}{}
	}
	for _, s := range sel {
		if _, ok := set[s]; !ok {
			return false
		}
	}
	return true
}
