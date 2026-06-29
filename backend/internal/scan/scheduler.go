package scan

import (
	"context"
	"log"
	"sync"
	"time"
)

// Scheduler 进程内统一调度框架（C1 合一）：单 time.Ticker 驱动，
// 暴露注册入口供 ① 周期扫描与 ⑤ 监测复扫共用，避免双 ticker / 双 cron 口径漂移。
//
// Wave A 仅落框架与启动；① 周期扫描在 Wave B 接入，⑤ 复扫注册由 ⑤ agent 接。
// 每个 Job 声明一个执行周期（time.Duration）；Scheduler 每 tick（默认 60s）
// 检查各 Job 是否到期（now >= NextRunAt），到期则在独立 goroutine 内触发其 Run。
type Scheduler struct {
	interval time.Duration

	mu      sync.Mutex
	jobs    map[string]*scheduledJob
	running map[string]bool // 手动触发的进程内互斥集合（无对应 scheduledJob 时也可单飞）

	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// JobFunc 一个被调度的周期任务体。ctx 在 Scheduler 停止时被取消。
type JobFunc func(ctx context.Context)

type scheduledJob struct {
	name    string
	every   time.Duration
	run     JobFunc
	nextAt  time.Time
	running bool
}

// NewScheduler 构造调度器；tick 为基础轮询周期（<=0 取默认 60s）。
func NewScheduler(tick time.Duration) *Scheduler {
	if tick <= 0 {
		tick = 60 * time.Second
	}
	return &Scheduler{
		interval: tick,
		jobs:     make(map[string]*scheduledJob),
		running:  make(map[string]bool),
	}
}

// TryRun 原子地占用名为 name 的执行槽用于手动触发：未占用返回 true 并置位（调用方跑完须调 DoneRun 复位）；
// 已在运行（手动占用或对应周期任务在跑）返回 false，供调用方做再入保护（如手动复扫 409）。
func (s *Scheduler) TryRun(name string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.running[name] {
		return false
	}
	if j, ok := s.jobs[name]; ok && j.running {
		return false
	}
	s.running[name] = true
	return true
}

// DoneRun 释放 TryRun 占用的执行槽（与 TryRun 成对调用）。
func (s *Scheduler) DoneRun(name string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.running, name)
}

// Register 注册（或覆盖）一个周期任务。every<=0 的任务被忽略（视为禁用）。
// 注册后首次到期时间为 now+every。线程安全，可在运行中注册。
func (s *Scheduler) Register(name string, every time.Duration, run JobFunc) {
	if run == nil || every <= 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.jobs[name] = &scheduledJob{
		name:   name,
		every:  every,
		run:    run,
		nextAt: time.Now().Add(every),
	}
	log.Printf("scheduler: 已注册周期任务 %q（每 %s）", name, every)
}

// Unregister 注销一个周期任务。
func (s *Scheduler) Unregister(name string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.jobs, name)
}

// Start 启动调度循环（非阻塞，内部起 goroutine）。重复调用安全（仅首次生效）。
func (s *Scheduler) Start(parent context.Context) {
	s.mu.Lock()
	if s.cancel != nil {
		s.mu.Unlock()
		return
	}
	ctx, cancel := context.WithCancel(parent)
	s.cancel = cancel
	s.mu.Unlock()

	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		ticker := time.NewTicker(s.interval)
		defer ticker.Stop()
		log.Printf("scheduler: 已启动（tick=%s）", s.interval)
		for {
			select {
			case <-ctx.Done():
				log.Println("scheduler: 已停止")
				return
			case now := <-ticker.C:
				s.tick(ctx, now)
			}
		}
	}()
}

// tick 检查所有到期任务并触发执行。
func (s *Scheduler) tick(ctx context.Context, now time.Time) {
	s.mu.Lock()
	due := make([]*scheduledJob, 0)
	for _, j := range s.jobs {
		if j.running || s.running[j.name] || now.Before(j.nextAt) {
			continue
		}
		j.running = true
		j.nextAt = now.Add(j.every)
		due = append(due, j)
	}
	s.mu.Unlock()

	for _, j := range due {
		s.wg.Add(1)
		go func(job *scheduledJob) {
			defer s.wg.Done()
			defer func() {
				s.mu.Lock()
				job.running = false
				s.mu.Unlock()
				if r := recover(); r != nil {
					log.Printf("scheduler: 任务 %q panic: %v", job.name, r)
				}
			}()
			job.run(ctx)
		}(j)
	}
}

// Stop 停止调度并等待在途任务收尾。
func (s *Scheduler) Stop() {
	s.mu.Lock()
	cancel := s.cancel
	s.cancel = nil
	s.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	s.wg.Wait()
}
