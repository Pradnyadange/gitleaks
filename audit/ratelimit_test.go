package audit

import (
	"context"
	"testing"
	"time"
)

func TestRateLimiterSpacing(t *testing.T) {
	// 600 RPM = 1 request every 100ms
	rl := NewRateLimiter(600)
	ctx := context.Background()

	start := time.Now()
	if err := rl.Wait(ctx); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	t1 := time.Now()

	if err := rl.Wait(ctx); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	t2 := time.Now()

	diff := t2.Sub(t1)
	// Allow slight timing tolerance
	if diff < 50*time.Millisecond {
		t.Errorf("expected rate limiter to space requests, got interval %v", diff)
	}
	_ = start
}

