package main

import (
	"sync"
	"time"
)

// RateLimiter is a minimal per-key fixed-window limiter. It guards the write
// path of a public, unauthenticated endpoint against a single host flooding
// the in-memory store. Reads are intentionally not limited.
type RateLimiter struct {
	mu     sync.Mutex
	count  map[string]*window
	limit  int
	window time.Duration
	now    func() time.Time
}

type window struct {
	start time.Time
	hits  int
}

// NewRateLimiter allows `limit` events per `per` window per key. limit < 1
// disables limiting.
func NewRateLimiter(limit int, per time.Duration) *RateLimiter {
	return &RateLimiter{
		count:  make(map[string]*window),
		limit:  limit,
		window: per,
		now:    time.Now,
	}
}

// Allow reports whether the key may proceed, recording the hit if so.
func (r *RateLimiter) Allow(key string) bool {
	if r.limit < 1 {
		return true
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.now()
	w, ok := r.count[key]
	if !ok || now.Sub(w.start) >= r.window {
		r.count[key] = &window{start: now, hits: 1}
		r.reapLocked(now)
		return true
	}
	if w.hits >= r.limit {
		return false
	}
	w.hits++
	return true
}

// reapLocked drops windows that have fully elapsed so the map can't grow
// unbounded under churn of distinct keys.
func (r *RateLimiter) reapLocked(now time.Time) {
	if len(r.count) < 1024 {
		return
	}
	for k, w := range r.count {
		if now.Sub(w.start) >= r.window {
			delete(r.count, k)
		}
	}
}
