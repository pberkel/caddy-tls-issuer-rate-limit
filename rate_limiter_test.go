// Copyright 2026 Pieter Berkel
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package ratelimitissuer

import (
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
)

// --- slidingWindow ----------------------------------------------------------

func TestSlidingWindow_EmptyCount(t *testing.T) {
	var w slidingWindow
	if n := w.count(time.Now(), time.Hour); n != 0 {
		t.Errorf("empty window count = %d, want 0", n)
	}
}

func TestSlidingWindow_CountWithinWindow(t *testing.T) {
	var w slidingWindow
	now := time.Now()
	w.add(now.Add(-30*time.Minute), time.Hour)
	w.add(now.Add(-10*time.Minute), time.Hour)
	if n := w.count(now, time.Hour); n != 2 {
		t.Errorf("count = %d, want 2", n)
	}
}

func TestSlidingWindow_ExpiredEntriesTrimmed(t *testing.T) {
	var w slidingWindow
	now := time.Now()
	w.add(now.Add(-2*time.Hour), time.Hour) // expired
	w.add(now.Add(-30*time.Minute), time.Hour)
	if n := w.count(now, time.Hour); n != 1 {
		t.Errorf("count = %d, want 1 (expired entry should be trimmed)", n)
	}
}

func TestSlidingWindow_AllExpired(t *testing.T) {
	var w slidingWindow
	now := time.Now()
	w.add(now.Add(-2*time.Hour), time.Hour)
	w.add(now.Add(-90*time.Minute), time.Hour)
	if n := w.count(now, time.Hour); n != 0 {
		t.Errorf("count = %d, want 0 after all entries expire", n)
	}
}

func TestSlidingWindow_AddTrimsExpired(t *testing.T) {
	var w slidingWindow
	now := time.Now()
	w.add(now.Add(-2*time.Hour), time.Hour) // will be expired
	w.add(now, time.Hour)
	if len(w.timestamps) != 1 {
		t.Errorf("timestamps len = %d, want 1 after add trims expired", len(w.timestamps))
	}
}

func TestSlidingWindow_ExactBoundary(t *testing.T) {
	var w slidingWindow
	now := time.Now()
	// Exactly at the boundary: now - duration is the cutoff, entries must be strictly After.
	w.timestamps = []time.Time{now.Add(-time.Hour)} // exactly at boundary — should be excluded
	if n := w.count(now, time.Hour); n != 0 {
		t.Errorf("entry at exact boundary should be excluded, count = %d", n)
	}
}

// --- rateLimitState ---------------------------------------------------------

func newTestRateLimiter(globalLimit, perDomainLimit *RateLimit, now func() time.Time) *rateLimitState {
	s := &rateLimitState{
		domains: make(map[string][]*slidingWindow),
		now:     now,
	}
	if globalLimit != nil {
		s.globalLimits = []*RateLimit{globalLimit}
		s.globals = []*slidingWindow{{}}
	}
	if perDomainLimit != nil {
		s.perDomainLimits = []*RateLimit{perDomainLimit}
	}
	return s
}

func TestRateLimiter_GlobalCheckBeforeLimit(t *testing.T) {
	rl := newTestRateLimiter(makeRateLimit(3, time.Hour), nil, time.Now)
	rl.recordGlobal() // 1
	rl.recordGlobal() // 2
	if err := rl.checkGlobal(); err != nil {
		t.Errorf("expected no error at 2/3, got: %v", err)
	}
}

func TestRateLimiter_GlobalCheckAtLimit(t *testing.T) {
	rl := newTestRateLimiter(makeRateLimit(3, time.Hour), nil, time.Now)
	rl.recordGlobal()
	rl.recordGlobal()
	rl.recordGlobal()
	if err := rl.checkGlobal(); err == nil {
		t.Error("expected error at 3/3")
	}
}

func TestRateLimiter_GlobalWindowExpiry(t *testing.T) {
	start := time.Now()
	rl := newTestRateLimiter(makeRateLimit(1, time.Hour), nil, func() time.Time { return start })
	rl.recordGlobal()

	// Advance past the window — the recorded entry should no longer count.
	rl.now = func() time.Time { return start.Add(time.Hour + time.Second) }
	if err := rl.checkGlobal(); err != nil {
		t.Errorf("expired entries should not be counted, got: %v", err)
	}
}

func TestRateLimiter_PerDomainCheckBeforeLimit(t *testing.T) {
	rl := newTestRateLimiter(nil, makeRateLimit(2, time.Hour), time.Now)
	rl.recordDomain("example.com")
	if err := rl.checkDomain("example.com"); err != nil {
		t.Errorf("expected no error at 1/2, got: %v", err)
	}
}

func TestRateLimiter_PerDomainCheckAtLimit(t *testing.T) {
	rl := newTestRateLimiter(nil, makeRateLimit(2, time.Hour), time.Now)
	rl.recordDomain("example.com")
	rl.recordDomain("example.com")
	if err := rl.checkDomain("example.com"); err == nil {
		t.Error("expected error at 2/2")
	}
}

func TestRateLimiter_PerDomainCheckUnknownDomain(t *testing.T) {
	rl := newTestRateLimiter(nil, makeRateLimit(2, time.Hour), time.Now)
	if err := rl.checkDomain("unknown.com"); err != nil {
		t.Errorf("unknown domain should not be rate-limited, got: %v", err)
	}
}

func TestRateLimiter_PerDomainEvictsExpiredEntry(t *testing.T) {
	start := time.Now()
	rl := newTestRateLimiter(nil, makeRateLimit(1, time.Hour), func() time.Time { return start })
	rl.recordDomain("example.com")

	// Advance past the window.
	rl.now = func() time.Time { return start.Add(time.Hour + time.Second) }
	if err := rl.checkDomain("example.com"); err != nil {
		t.Errorf("expired domain entry should not be rate-limited, got: %v", err)
	}
	rl.mu.Lock()
	_, still := rl.domains["example.com"]
	rl.mu.Unlock()
	if still {
		t.Error("expired domain window should have been evicted")
	}
}

func TestRateLimiter_DifferentDomainsIndependent(t *testing.T) {
	rl := newTestRateLimiter(nil, makeRateLimit(1, time.Hour), time.Now)
	rl.recordDomain("foo.com")
	if err := rl.checkDomain("bar.com"); err != nil {
		t.Errorf("different domain should not be limited, got: %v", err)
	}
}

// --- RateLimit.resolve & validate -------------------------------------------

func TestRateLimit_ResolveNilIsNoop(t *testing.T) {
	var rl *RateLimit
	if err := rl.resolve(caddy.NewReplacer(), "test"); err != nil {
		t.Errorf("nil resolve should be noop, got: %v", err)
	}
}

func TestRateLimit_ResolveEmptyRawIsNoop(t *testing.T) {
	rl := &RateLimit{Limit: 5, Duration: caddy.Duration(time.Hour)}
	if err := rl.resolve(caddy.NewReplacer(), "test"); err != nil {
		t.Errorf("empty LimitRaw should be noop, got: %v", err)
	}
	if rl.Limit != 5 {
		t.Error("Limit should be unchanged")
	}
}

func TestRateLimit_ResolveRaw(t *testing.T) {
	rl := &RateLimit{LimitRaw: "10", DurationRaw: "1h"}
	if err := rl.resolve(caddy.NewReplacer(), "test"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rl.Limit != 10 {
		t.Errorf("Limit = %d, want 10", rl.Limit)
	}
	if time.Duration(rl.Duration) != time.Hour {
		t.Errorf("Duration = %v, want 1h", time.Duration(rl.Duration))
	}
}

func TestRateLimit_ResolveInvalidLimit(t *testing.T) {
	rl := &RateLimit{LimitRaw: "notanumber", DurationRaw: "1h"}
	if err := rl.resolve(caddy.NewReplacer(), "test"); err == nil {
		t.Error("expected error for non-integer limit")
	}
}

func TestRateLimit_ResolveInvalidDuration(t *testing.T) {
	rl := &RateLimit{LimitRaw: "10", DurationRaw: "notaduration"}
	if err := rl.resolve(caddy.NewReplacer(), "test"); err == nil {
		t.Error("expected error for invalid duration")
	}
}

func TestRateLimit_ValidateNilIsNoop(t *testing.T) {
	var rl *RateLimit
	if err := rl.validate("test"); err != nil {
		t.Errorf("nil validate should be noop, got: %v", err)
	}
}

func TestRateLimit_ValidateZeroLimit(t *testing.T) {
	rl := &RateLimit{Limit: 0, Duration: caddy.Duration(time.Hour)}
	if err := rl.validate("test"); err == nil {
		t.Error("expected error for zero limit")
	}
}

func TestRateLimit_ValidateNegativeLimit(t *testing.T) {
	rl := &RateLimit{Limit: -1, Duration: caddy.Duration(time.Hour)}
	if err := rl.validate("test"); err == nil {
		t.Error("expected error for negative limit")
	}
}

func TestRateLimit_ValidateZeroDuration(t *testing.T) {
	rl := &RateLimit{Limit: 5, Duration: 0}
	if err := rl.validate("test"); err == nil {
		t.Error("expected error for zero duration")
	}
}

func TestRateLimit_ValidateValid(t *testing.T) {
	rl := &RateLimit{Limit: 5, Duration: caddy.Duration(time.Hour)}
	if err := rl.validate("test"); err != nil {
		t.Errorf("unexpected error for valid config: %v", err)
	}
}
