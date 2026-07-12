package api

import (
	"testing"
	"time"

	"zhulong-pqm/internal/db"
	"zhulong-pqm/internal/model"
)

func TestLeaseTask_AtomicAndLabelMatch(t *testing.T) {
	gdb, err := db.Open(":memory:")
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	s := &Server{db: gdb}
	mk := func(name string, sel []string) {
		gdb.Create(&model.CaptureTask{Name: name, LabelSelectorJSON: db.MarshalStrings(sel),
			Status: model.CapturePending, Duration: 10})
	}
	mk("任意", nil)
	mk("机房A专用", []string{"机房A"})
	mk("机房B专用", []string{"机房B"})

	// 探针 labels=[机房A] → 可领 "任意" 或 "机房A专用"，不可领 "机房B专用"
	got, ok := s.leaseTask("agent-1", []string{"机房A"})
	if !ok || (got.Name != "任意" && got.Name != "机房A专用") {
		t.Fatalf("机房A 探针领到 %+v ok=%v", got, ok)
	}
	if got.Status != model.CaptureLeased || got.LeasedBy != "agent-1" {
		t.Errorf("租约状态错: %+v", got)
	}

	// 把剩下的 pending 都设为 [机房B]，机房A 探针应领不到
	gdb.Model(&model.CaptureTask{}).Where("status = ?", model.CapturePending).
		Update("label_selector", db.MarshalStrings([]string{"机房B"}))
	if _, ok := s.leaseTask("agent-1", []string{"机房A"}); ok {
		t.Error("机房A 探针不应领到 机房B 任务")
	}
	if _, ok := s.leaseTask("agent-2", []string{"机房B"}); !ok {
		t.Error("机房B 探针应能领到")
	}
}

func TestLeaseTask_LeaseDuration(t *testing.T) {
	if d := leaseDuration(&model.CaptureTask{Duration: 10}); d < 120*time.Second {
		t.Errorf("短任务租约应≥120s，得 %v", d)
	}
	if d := leaseDuration(&model.CaptureTask{Duration: 300}); d < 600*time.Second {
		t.Errorf("长任务租约应≥2×时长，得 %v", d)
	}
}

func TestCompleteTask_OneShotAndRecurring(t *testing.T) {
	gdb, _ := db.Open(":memory:")
	s := &Server{db: gdb}

	one := model.CaptureTask{Name: "一次性", Status: model.CaptureLeased, LeasedBy: "a1"}
	gdb.Create(&one)
	s.applyComplete(&one, "a1", 7)
	if one.Status != model.CaptureDone || one.ResultCount != 7 || one.RunCount != 1 {
		t.Errorf("一次性完成态错: %+v", one)
	}

	rec := model.CaptureTask{Name: "周期", Status: model.CaptureLeased, LeasedBy: "a1",
		ScheduleEnabled: true, Schedule: "0 * * * *"}
	gdb.Create(&rec)
	s.applyComplete(&rec, "a1", 3)
	if rec.Status != model.CapturePending || rec.NextRunAt == nil || rec.LeasedBy != "" {
		t.Errorf("周期完成应回 pending+NextRunAt+清 LeasedBy: %+v", rec)
	}
}

func TestReclaimAndReschedule(t *testing.T) {
	gdb, _ := db.Open(":memory:")
	past := time.Now().Add(-time.Hour)
	expired := model.CaptureTask{Name: "过期", Status: model.CaptureLeased, LeasedBy: "a1", LeaseExpiresAt: &past}
	gdb.Create(&expired)
	due := model.CaptureTask{Name: "到点", Status: model.CaptureDone, ScheduleEnabled: true, Schedule: "0 * * * *", NextRunAt: &past}
	gdb.Create(&due)
	future := time.Now().Add(time.Hour)
	notdue := model.CaptureTask{Name: "未到", Status: model.CaptureDone, ScheduleEnabled: true, Schedule: "0 * * * *", NextRunAt: &future}
	gdb.Create(&notdue)

	reclaimAndReschedule(gdb)

	var e, d, n model.CaptureTask
	gdb.First(&e, expired.ID)
	gdb.First(&d, due.ID)
	gdb.First(&n, notdue.ID)
	if e.Status != model.CapturePending || e.LeasedBy != "" {
		t.Errorf("过期租约应回 pending 清 LeasedBy: %+v", e)
	}
	if d.Status != model.CapturePending {
		t.Errorf("到点周期任务应回 pending: %+v", d)
	}
	if n.Status != model.CaptureDone {
		t.Errorf("未到点周期任务不应动: %+v", n)
	}
}
