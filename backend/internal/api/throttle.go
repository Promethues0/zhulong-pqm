package api

import (
	"sync"
	"time"
)

// 登录暴力破解防护：按「用户名+客户端IP」限流，窗口内失败超阈值即临时锁定。
// 纯内存、进程级；配合已有的登录审计（事后可查）形成实时拦截。

const (
	loginMaxFails = 7               // 窗口内最多失败次数
	loginWindow   = 5 * time.Minute // 失败窗口 / 锁定时长
	limiterCap    = 4096            // 惰性清理阈值，防内存无界增长
)

type attemptRec struct {
	count int
	until time.Time
}

type attemptLimiter struct {
	mu sync.Mutex
	m  map[string]*attemptRec
}

var loginLimiter = &attemptLimiter{m: make(map[string]*attemptRec)}

// allow 判断该 key 是否允许再次尝试；被锁定时返回剩余秒数。
func (l *attemptLimiter) allow(key string) (bool, int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	r := l.m[key]
	now := time.Now()
	if r == nil || now.After(r.until) {
		return true, 0
	}
	if r.count >= loginMaxFails {
		return false, int(time.Until(r.until).Seconds()) + 1
	}
	return true, 0
}

// fail 记一次失败（过期则重置计数），并顺带惰性清理过期项。
func (l *attemptLimiter) fail(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	r := l.m[key]
	if r == nil || now.After(r.until) {
		r = &attemptRec{}
		l.m[key] = r
	}
	r.count++
	r.until = now.Add(loginWindow)
	if len(l.m) > limiterCap {
		for k, v := range l.m {
			if now.After(v.until) {
				delete(l.m, k)
			}
		}
	}
}

// reset 登录成功后清除该 key 的失败记录。
func (l *attemptLimiter) reset(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.m, key)
}
