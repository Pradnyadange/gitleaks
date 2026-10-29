package audit

import (
	"context"
	"sync"
	"time"
)

type RateLimiter struct {
	mu       sync.Mutex
	interval time.Duration
	next     time.Time
}

func NewRateLimiter(rpm int) *RateLimiter {
	if rpm <= 0 {
		return nil
	}
	return &RateLimiter{
		interval: time.Minute / time.Duration(rpm),
		next:     time.Now(),
	}
}

func (rl *RateLimiter) Wait(ctx context.Context) error {
	if rl == nil {
		return nil
	}

	rl.mu.Lock()
	now := time.Now()
	waitDuration := time.Duration(0)
	if now.Before(rl.next) {
		waitDuration = rl.next.Sub(now)
		rl.next = rl.next.Add(rl.interval)
	} else {
		rl.next = now.Add(rl.interval)
	}
	rl.mu.Unlock()

	if waitDuration <= 0 {
		return nil
	}

	timer := time.NewTimer(waitDuration)
	defer timer.Stop()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

