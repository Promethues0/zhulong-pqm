package scan

import (
	"strings"
	"time"
)

// 复扫周期口径（最小自实现 cron，私有化离线无外部 cron 依赖；与 monitor 同口径）。
const (
	cronQuarterDur = 90 * 24 * time.Hour
	cronMonthDur   = 30 * 24 * time.Hour
	cronWeekDur    = 7 * 24 * time.Hour
	cronDayDur     = 24 * time.Hour
)

// CronToInterval 把 cron 表达式粗粒度映射为复扫间隔（覆盖季度/月/周/日）。
// 无法识别回退季度（PRD 默认）。供 ① 周期扫描调度复用。
func CronToInterval(cron string) time.Duration {
	c := strings.TrimSpace(cron)
	switch {
	case c == "":
		return cronQuarterDur
	case strings.Contains(c, "*/3 *"):
		return cronQuarterDur
	case strings.Contains(c, "*/1 *"), strings.HasSuffix(c, " * *"):
		return cronMonthDur
	case strings.Contains(c, "* * 0"), strings.Contains(c, "* * 1"):
		return cronWeekDur
	case strings.Contains(c, "*/1 * *"):
		return cronDayDur
	default:
		return cronQuarterDur
	}
}

// NextCronRun 据 cron 表达式从当前时刻计算下次执行时间（供前端展示）。
func NextCronRun(cron string) *time.Time {
	t := time.Now().Add(CronToInterval(cron))
	return &t
}
