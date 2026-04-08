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
	"fmt"
	"sync"
	"time"

	"github.com/caddyserver/caddy/v2"
)

// RateLimit defines an exact sliding-window rate limit: at most Limit
// issuances within any rolling Duration window.
type RateLimit struct {
	// Maximum number of certificate issuances within Duration.
	Limit int `json:"limit,omitempty"`
	// Rolling time window for the rate limit.
	Duration caddy.Duration `json:"duration,omitempty"`
}

// rateLimitState holds in-memory exact sliding-window counters for global and
// per-domain rate limits. Each configured rate limit has its own window so
// that multiple tiered limits can be enforced simultaneously.
type rateLimitState struct {
	mu              sync.Mutex
	totals          []*slidingWindow
	domains         map[string][]*slidingWindow
	totalLimits     []*RateLimit
	perDomainLimits []*RateLimit
	now             func() time.Time
}

// slidingWindow tracks exact issuance timestamps within a rolling time window.
// Timestamps are always appended in chronological order, so expired entries
// are always a contiguous prefix. A zero-value slidingWindow is ready to use.
type slidingWindow struct {
	timestamps []time.Time
}

// trim removes timestamps older than d from the front of the window.
// Timestamps are always appended in chronological order, so expired entries
// are always a contiguous prefix. Compaction is done in-place to release
// the backing array slots occupied by expired entries.
func (w *slidingWindow) trim(now time.Time, d time.Duration) {
	cutoff := now.Add(-d)
	i := 0
	for i < len(w.timestamps) && !w.timestamps[i].After(cutoff) {
		i++
	}
	if i > 0 {
		w.timestamps = w.timestamps[:copy(w.timestamps, w.timestamps[i:])]
	}
}

// count returns the exact number of issuances within the past d.
func (w *slidingWindow) count(now time.Time, d time.Duration) int {
	w.trim(now, d)
	return len(w.timestamps)
}

// add records a new issuance at now, trimming expired entries first.
func (w *slidingWindow) add(now time.Time, d time.Duration) {
	w.trim(now, d)
	w.timestamps = append(w.timestamps, now)
}

// checkTotal returns an error if any global rate limit window is exceeded.
func (s *rateLimitState) checkTotal() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	for i, rl := range s.totalLimits {
		if s.totals[i].count(now, time.Duration(rl.Duration)) >= rl.Limit {
			return fmt.Errorf("global certificate issuance rate limit exceeded")
		}
	}
	return nil
}

// recordTotal increments all global issuance windows.
func (s *rateLimitState) recordTotal() {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	for i, rl := range s.totalLimits {
		s.totals[i].add(now, time.Duration(rl.Duration))
	}
}

// checkDomain returns an error if any per-domain rate limit window is exceeded
// for the given registrable domain. Expired domain windows are evicted lazily.
func (s *rateLimitState) checkDomain(domain string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	windows, ok := s.domains[domain]
	if !ok {
		return nil
	}
	now := s.now()
	allEmpty := true
	for i, rl := range s.perDomainLimits {
		d := time.Duration(rl.Duration)
		n := windows[i].count(now, d)
		if n > 0 {
			allEmpty = false
		}
		if n >= rl.Limit {
			return fmt.Errorf("per-domain certificate issuance rate limit exceeded for %s", domain)
		}
	}
	if allEmpty {
		delete(s.domains, domain)
	}
	return nil
}

// recordDomain increments all per-domain issuance windows for domain.
func (s *rateLimitState) recordDomain(domain string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	windows, ok := s.domains[domain]
	if !ok {
		windows = make([]*slidingWindow, len(s.perDomainLimits))
		for i := range windows {
			windows[i] = &slidingWindow{}
		}
		s.domains[domain] = windows
	}
	now := s.now()
	for i, rl := range s.perDomainLimits {
		windows[i].add(now, time.Duration(rl.Duration))
	}
}

// validate returns an error if the rate limit configuration is invalid.
// It is a no-op when rl is nil.
func (rl *RateLimit) validate() error {
	if rl == nil {
		return nil
	}
	if rl.Limit <= 0 {
		return fmt.Errorf("limit must be greater than 0, got %d", rl.Limit)
	}
	if time.Duration(rl.Duration) <= 0 {
		return fmt.Errorf("duration must be greater than 0")
	}
	return nil
}
