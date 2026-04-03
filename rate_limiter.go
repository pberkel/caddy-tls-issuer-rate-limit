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
	"strconv"
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

	// LimitRaw and DurationRaw hold raw string values set during Caddyfile
	// parsing; they may contain Caddy placeholders resolved at provisioning
	// time. When non-empty, they take precedence over Limit and Duration and
	// must survive JSON serialization so that the Caddyfile → JSON → provision
	// round-trip preserves placeholder expressions.
	LimitRaw    string `json:"limit_raw,omitempty"`
	DurationRaw string `json:"duration_raw,omitempty"`
}

// rateLimitState holds in-memory exact sliding-window counters for global and
// per-domain rate limits. Each configured rate limit has its own window so
// that multiple tiered limits can be enforced simultaneously.
type rateLimitState struct {
	mu              sync.Mutex
	globals         []*slidingWindow
	domains         map[string][]*slidingWindow
	globalLimits    []*RateLimit
	perDomainLimits []*RateLimit
	now             func() time.Time
}

// slidingWindow tracks exact issuance timestamps within a rolling time window.
// Timestamps are always appended in chronological order, so trimming expired
// entries is a binary search from the front. A zero-value slidingWindow is
// ready to use.
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

// checkGlobal returns an error if any global rate limit window is exceeded.
func (s *rateLimitState) checkGlobal() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	for i, rl := range s.globalLimits {
		if s.globals[i].count(now, time.Duration(rl.Duration)) >= rl.Limit {
			return fmt.Errorf("global certificate issuance rate limit exceeded")
		}
	}
	return nil
}

// recordGlobal increments all global issuance windows.
func (s *rateLimitState) recordGlobal() {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	for i, rl := range s.globalLimits {
		s.globals[i].add(now, time.Duration(rl.Duration))
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

// resolve replaces Caddy placeholders in LimitRaw and DurationRaw and stores
// the parsed values in Limit and Duration. It is a no-op when rl is nil or
// LimitRaw is empty.
func (rl *RateLimit) resolve(replacer *caddy.Replacer, name string) error {
	if rl == nil || rl.LimitRaw == "" {
		return nil
	}
	limitStr := replacer.ReplaceAll(rl.LimitRaw, "")
	limit, err := strconv.Atoi(limitStr)
	if err != nil {
		return fmt.Errorf("invalid integer value for %s limit: %s", name, limitStr)
	}
	durStr := replacer.ReplaceAll(rl.DurationRaw, "")
	dur, err := caddy.ParseDuration(durStr)
	if err != nil {
		return fmt.Errorf("invalid duration value for %s: %s", name, durStr)
	}
	rl.Limit = limit
	rl.Duration = caddy.Duration(dur)
	return nil
}

// validate returns an error if the rate limit configuration is invalid.
// It is a no-op when rl is nil.
func (rl *RateLimit) validate(name string) error {
	if rl == nil {
		return nil
	}
	if rl.Limit <= 0 {
		return fmt.Errorf("%s limit must be greater than 0, got %d", name, rl.Limit)
	}
	if time.Duration(rl.Duration) <= 0 {
		return fmt.Errorf("%s duration must be greater than 0", name)
	}
	return nil
}
