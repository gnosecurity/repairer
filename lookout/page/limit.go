package page

import (
	"sync"
	"time"
)

// limiter hands out tokens per key: a key starts with burst of them and gets one back every period. It keeps
// at most maxKeys keys; a full bucket is forgotten when the map is swept, since a new one would be the same.
type limiter struct {
	mu      sync.Mutex
	burst   float64
	every   time.Duration
	buckets map[string]*bucket
	swept   time.Time
}

type bucket struct {
	tokens float64
	at     time.Time
}

const maxKeys = 50000

func newLimiter(burst int, every time.Duration) *limiter {
	return &limiter{burst: float64(burst), every: every, buckets: map[string]*bucket{}}
}

// take spends one of key's tokens at now. With none left it reports false and how long until the next one.
func (l *limiter) take(key string, now time.Time) (bool, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if now.Sub(l.swept) > 10*time.Minute || len(l.buckets) >= maxKeys {
		l.sweep(now)
	}
	b := l.buckets[key]
	if b == nil {
		if len(l.buckets) >= maxKeys {
			return false, time.Minute
		}
		b = &bucket{tokens: l.burst, at: now}
		l.buckets[key] = b
	}
	b.tokens = l.refilled(b, now)
	b.at = now
	if b.tokens >= 1 {
		b.tokens--
		return true, 0
	}
	return false, time.Duration((1 - b.tokens) * float64(l.every))
}

func (l *limiter) refilled(b *bucket, now time.Time) float64 {
	gained := float64(now.Sub(b.at)) / float64(l.every)
	if gained < 0 {
		gained = 0
	}
	return min(l.burst, b.tokens+gained)
}

func (l *limiter) sweep(now time.Time) {
	for k, b := range l.buckets {
		if l.refilled(b, now) >= l.burst {
			delete(l.buckets, k)
		}
	}
	l.swept = now
}
