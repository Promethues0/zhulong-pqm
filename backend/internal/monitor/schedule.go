package monitor

import (
	"context"
	"log"
	"strings"
	"time"

	"gorm.io/gorm"

	"zhulong-pqm/internal/model"
	"zhulong-pqm/internal/scan"
)

// 复扫周期口径（最小自实现 cron 判断，私有化离线无外部 cron 依赖）：
// 仅识别常见周期字段，映射为 time.Duration 注册到统一调度框架（B0-5 scan.Scheduler）。
// 默认季度 0 0 3 1 */3 *。
const (
	quarterDur = 90 * 24 * time.Hour
	monthDur   = 30 * 24 * time.Hour
	weekDur    = 7 * 24 * time.Hour
	dayDur     = 24 * time.Hour
)

// cronToInterval 把 cron 表达式粗粒度映射为复扫间隔（自实现，覆盖季度/月/周/日）。
// 无法识别时回退季度（与 PRD 默认一致）。
func cronToInterval(cron string) time.Duration {
	c := strings.TrimSpace(cron)
	switch {
	case c == "" :
		return quarterDur
	case strings.Contains(c, "*/3 *"): // 每 3 月（季度）
		return quarterDur
	case strings.Contains(c, "*/1 *"), strings.HasSuffix(c, " * *"): // 每月
		return monthDur
	case strings.Contains(c, "* * 0"), strings.Contains(c, "* * 1"): // 每周（星期字段）
		return weekDur
	default:
		return quarterDur
	}
}

// nextRunAfter 据策略 cron 与基准时刻计算下次复扫时间（供前端展示 NextRunAt）。
func nextRunAfter(p *model.MonitorPolicy, from time.Time) *time.Time {
	next := from.Add(cronToInterval(p.RescanCron))
	return &next
}

// NextRunAfterPublic 导出版 nextRunAfter，供 API 层填充展示用 NextRunAt（不落库）。
func NextRunAfterPublic(p *model.MonitorPolicy, from time.Time) *time.Time {
	return nextRunAfter(p, from)
}

// schedulerJobName 策略在统一调度框架内的注册名（按策略 ID 唯一）。
func schedulerJobName(policyID uint) string {
	return "monitor-rescan-" + uintToStr(policyID)
}

// RegisterPolicies 把所有启用策略注册到统一调度框架（B0-5）。
// 每个 enabled 策略按其 cron 间隔注册一个复扫 JobFunc；调度器到点在 goroutine 内调 Runner.Run。
// main.go 启动后调用一次；策略增删改后由 API 调 SyncPolicy/Unregister 增量维护。
func RegisterPolicies(sched *scan.Scheduler, gdb *gorm.DB) {
	if sched == nil {
		return
	}
	var policies []model.MonitorPolicy
	gdb.Where("enabled = ?", true).Find(&policies)
	for i := range policies {
		SyncPolicy(sched, gdb, &policies[i])
	}
	log.Printf("monitor: 已注册 %d 条监测复扫策略到统一调度", len(policies))
}

// SyncPolicy 注册/刷新单条策略的周期复扫任务；禁用则注销。
func SyncPolicy(sched *scan.Scheduler, gdb *gorm.DB, p *model.MonitorPolicy) {
	if sched == nil || p == nil {
		return
	}
	name := schedulerJobName(p.ID)
	if !p.Enabled {
		sched.Unregister(name)
		return
	}
	pid := p.ID
	interval := cronToInterval(p.RescanCron)
	sched.Register(name, interval, func(ctx context.Context) {
		NewRunner(gdb, nil).Run(ctx, pid)
	})
	// 计算并落库 NextRunAt（供前端展示）。
	next := nextRunAfter(p, time.Now())
	gdb.Model(&model.MonitorPolicy{}).Where("id = ?", pid).Update("next_run_at", next)
}

// UnregisterPolicy 注销一条策略的周期复扫任务（删除策略时调用）。
func UnregisterPolicy(sched *scan.Scheduler, policyID uint) {
	if sched == nil {
		return
	}
	sched.Unregister(schedulerJobName(policyID))
}

// uintToStr 无 strconv 依赖的 uint→string（避免引入额外 import 噪声）。
func uintToStr(v uint) string {
	if v == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for v > 0 {
		i--
		buf[i] = byte('0' + v%10)
		v /= 10
	}
	return string(buf[i:])
}
