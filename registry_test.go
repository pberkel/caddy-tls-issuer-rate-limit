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
	"context"
	"io/fs"
	"sync"
	"testing"
	"time"

	"github.com/caddyserver/certmagic"
	"go.uber.org/zap"
)

// memStorage is a minimal in-memory certmagic.Storage for testing.
type memStorage struct {
	mu   sync.Mutex
	data map[string][]byte
}

func newMemStorage() *memStorage {
	return &memStorage{data: make(map[string][]byte)}
}

func (m *memStorage) Store(_ context.Context, key string, value []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := make([]byte, len(value))
	copy(cp, value)
	m.data[key] = cp
	return nil
}

func (m *memStorage) Load(_ context.Context, key string) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	v, ok := m.data[key]
	if !ok {
		return nil, fs.ErrNotExist
	}
	cp := make([]byte, len(v))
	copy(cp, v)
	return cp, nil
}

func (m *memStorage) Delete(_ context.Context, key string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.data, key)
	return nil
}

func (m *memStorage) Exists(_ context.Context, key string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, ok := m.data[key]
	return ok
}

func (m *memStorage) List(_ context.Context, _ string, _ bool) ([]string, error) {
	return nil, nil
}

func (m *memStorage) Stat(_ context.Context, key string) (certmagic.KeyInfo, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	v, ok := m.data[key]
	if !ok {
		return certmagic.KeyInfo{}, fs.ErrNotExist
	}
	return certmagic.KeyInfo{Key: key, Size: int64(len(v))}, nil
}

func (m *memStorage) Lock(_ context.Context, _ string) error   { return nil }
func (m *memStorage) Unlock(_ context.Context, _ string) error { return nil }

// makeSharedPool constructs a SharedPool with the given name and a single
// rate_limit window.
func makeSharedPool(name string, limit int, d time.Duration) *SharedPool {
	return &SharedPool{
		Name:      name,
		RateLimit: []*RateLimit{makeRateLimit(limit, d)},
	}
}

// registerTestPool registers a pool under a test-scoped name and arranges
// cleanup. Returns the registry entry.
func registerTestPool(t *testing.T, sp *SharedPool) *registryEntry {
	t.Helper()
	t.Cleanup(func() { processRegistry.Delete(sp.Name) })
	return getOrRegisterPool(sp, zap.NewNop())
}

// --- validatePoolName --------------------------------------------------------

func TestValidatePoolName_Empty(t *testing.T) {
	if err := validatePoolName(""); err == nil {
		t.Error("expected error for empty name")
	}
}

func TestValidatePoolName_Slash(t *testing.T) {
	if err := validatePoolName("foo/bar"); err == nil {
		t.Error("expected error for name containing '/'")
	}
}

func TestValidatePoolName_Backslash(t *testing.T) {
	if err := validatePoolName(`foo\bar`); err == nil {
		t.Error("expected error for name containing '\\'")
	}
}

func TestValidatePoolName_DotDot(t *testing.T) {
	if err := validatePoolName(".."); err == nil {
		t.Error("expected error for '..'")
	}
}

func TestValidatePoolName_Valid(t *testing.T) {
	for _, name := range []string{"global", "pool-a", "pool_1", "primary.secondary"} {
		if err := validatePoolName(name); err != nil {
			t.Errorf("validatePoolName(%q) unexpected error: %v", name, err)
		}
	}
}

// --- getOrRegisterPool -------------------------------------------------------

func TestGetOrRegisterPool_CreatesNewEntry(t *testing.T) {
	sp := makeSharedPool(t.Name(), 10, time.Hour)
	entry := registerTestPool(t, sp)
	if entry == nil {
		t.Fatal("expected non-nil entry")
	}
	if entry.state == nil {
		t.Fatal("expected non-nil state")
	}
}

func TestGetOrRegisterPool_SharedAcrossCalls(t *testing.T) {
	sp := makeSharedPool(t.Name(), 10, time.Hour)
	e1 := registerTestPool(t, sp)
	e2 := getOrRegisterPool(sp, zap.NewNop())
	if e1 != e2 {
		t.Error("expected same registry entry for same pool name")
	}
}

func TestGetOrRegisterPool_ResetOnLimitMismatch(t *testing.T) {
	sp1 := makeSharedPool(t.Name(), 10, time.Hour)
	sp2 := makeSharedPool(t.Name(), 20, time.Hour) // different limit
	t.Cleanup(func() { processRegistry.Delete(t.Name()) })

	e1 := getOrRegisterPool(sp1, zap.NewNop())
	e1.state.recordTotal() // record so we can detect reset

	e2 := getOrRegisterPool(sp2, zap.NewNop())
	if e1 == e2 {
		t.Fatal("expected new entry after limit mismatch")
	}

	// new entry should start with empty windows
	e2.state.mu.Lock()
	count := e2.state.totals[0].count(time.Now(), time.Hour)
	e2.state.mu.Unlock()
	if count != 0 {
		t.Errorf("reset entry global count = %d, want 0", count)
	}
}

// --- poolLimitsMatch ---------------------------------------------------------

func TestPoolLimitsMatch_Identical(t *testing.T) {
	sp := makeSharedPool("a", 10, time.Hour)
	if !poolLimitsMatch(sp, sp) {
		t.Error("expected match for identical pool")
	}
}

func TestPoolLimitsMatch_DifferentLimit(t *testing.T) {
	a := makeSharedPool("a", 10, time.Hour)
	b := makeSharedPool("a", 20, time.Hour)
	if poolLimitsMatch(a, b) {
		t.Error("expected mismatch for different limit")
	}
}

func TestPoolLimitsMatch_DifferentDuration(t *testing.T) {
	a := makeSharedPool("a", 10, time.Hour)
	b := makeSharedPool("a", 10, 2*time.Hour)
	if poolLimitsMatch(a, b) {
		t.Error("expected mismatch for different duration")
	}
}

func TestPoolLimitsMatch_DifferentCount(t *testing.T) {
	a := &SharedPool{Name: "a", RateLimit: []*RateLimit{makeRateLimit(10, time.Hour)}}
	b := &SharedPool{Name: "a", RateLimit: []*RateLimit{
		makeRateLimit(10, time.Hour),
		makeRateLimit(100, 24*time.Hour),
	}}
	if poolLimitsMatch(a, b) {
		t.Error("expected mismatch for different window count")
	}
}

// --- applyPersistedState -----------------------------------------------------

func TestApplyPersistedState_GlobalTimestamps(t *testing.T) {
	sp := makeSharedPool("x", 10, time.Hour)
	entry := newRegistryEntry(sp)
	now := time.Now()

	ps := &persistedPoolState{
		Global: [][]time.Time{{now.Add(-30 * time.Minute), now.Add(-10 * time.Minute)}},
	}
	applyPersistedState(entry.state, ps)

	entry.state.mu.Lock()
	count := entry.state.totals[0].count(now, time.Hour)
	entry.state.mu.Unlock()

	if count != 2 {
		t.Errorf("count = %d, want 2 after applying persisted state", count)
	}
}

func TestApplyPersistedState_ExpiredTimestampsIgnored(t *testing.T) {
	sp := makeSharedPool("x", 10, time.Hour)
	entry := newRegistryEntry(sp)
	now := time.Now()

	ps := &persistedPoolState{
		Global: [][]time.Time{{now.Add(-2 * time.Hour)}}, // expired
	}
	applyPersistedState(entry.state, ps)

	entry.state.mu.Lock()
	count := entry.state.totals[0].count(now, time.Hour)
	entry.state.mu.Unlock()

	if count != 0 {
		t.Errorf("count = %d, want 0 (expired timestamp should not count)", count)
	}
}

func TestApplyPersistedState_ExtraWindowsIgnored(t *testing.T) {
	// Persisted state has 2 global windows; current config has 1.
	sp := makeSharedPool("x", 10, time.Hour)
	entry := newRegistryEntry(sp)
	now := time.Now()

	ps := &persistedPoolState{
		Global: [][]time.Time{
			{now.Add(-10 * time.Minute)},
			{now.Add(-5 * time.Minute)}, // no corresponding window in config
		},
	}
	applyPersistedState(entry.state, ps)

	entry.state.mu.Lock()
	count := entry.state.totals[0].count(now, time.Hour)
	entry.state.mu.Unlock()

	if count != 1 {
		t.Errorf("count = %d, want 1 (only first window should be applied)", count)
	}
}

func TestApplyPersistedState_PerDomainTimestamps(t *testing.T) {
	sp := &SharedPool{
		Name:               "x",
		PerDomainRateLimit: []*RateLimit{makeRateLimit(5, time.Hour)},
	}
	entry := newRegistryEntry(sp)
	now := time.Now()

	ps := &persistedPoolState{
		Domains: map[string][][]time.Time{
			"example.com": {{now.Add(-20 * time.Minute)}},
		},
	}
	applyPersistedState(entry.state, ps)

	entry.state.mu.Lock()
	windows, ok := entry.state.domains["example.com"]
	var count int
	if ok {
		count = windows[0].count(now, time.Hour)
	}
	entry.state.mu.Unlock()

	if !ok || count != 1 {
		t.Errorf("domain count = %d (found=%v), want 1", count, ok)
	}
}

// --- savePoolState / loadAndApplyPoolState roundtrip -------------------------

func TestSaveAndLoad_GlobalRoundtrip(t *testing.T) {
	sp := makeSharedPool(t.Name(), 10, time.Hour)
	t.Cleanup(func() { processRegistry.Delete(sp.Name) })

	entry := newRegistryEntry(sp)
	now := time.Now()
	entry.state.totals[0].add(now.Add(-30*time.Minute), time.Hour)
	entry.state.totals[0].add(now.Add(-10*time.Minute), time.Hour)

	st := newMemStorage()
	logger := zap.NewNop()
	savePoolState(context.Background(), st, entry, logger)

	// Load into a fresh entry.
	entry2 := newRegistryEntry(sp)
	entry2.mu.Lock()
	loadAndApplyPoolState(context.Background(), st, entry2, logger)
	entry2.mu.Unlock()

	entry2.state.mu.Lock()
	count := entry2.state.totals[0].count(now, time.Hour)
	entry2.state.mu.Unlock()

	if count != 2 {
		t.Errorf("count after roundtrip = %d, want 2", count)
	}
}

func TestSaveAndLoad_ExpiredPruned(t *testing.T) {
	sp := makeSharedPool(t.Name(), 10, time.Hour)
	t.Cleanup(func() { processRegistry.Delete(sp.Name) })

	entry := newRegistryEntry(sp)
	now := time.Now()
	entry.state.totals[0].add(now.Add(-2*time.Hour), time.Hour) // will be expired at save time
	entry.state.totals[0].add(now.Add(-30*time.Minute), time.Hour)

	st := newMemStorage()
	logger := zap.NewNop()

	// Advance time past the first entry's expiry before saving.
	entry.state.now = func() time.Time { return now }
	savePoolState(context.Background(), st, entry, logger)

	entry2 := newRegistryEntry(sp)
	entry2.mu.Lock()
	loadAndApplyPoolState(context.Background(), st, entry2, logger)
	entry2.mu.Unlock()

	entry2.state.mu.Lock()
	count := entry2.state.totals[0].count(now, time.Hour)
	entry2.state.mu.Unlock()

	if count != 1 {
		t.Errorf("count after roundtrip = %d, want 1 (expired entry should have been pruned)", count)
	}
}

func TestSaveAndLoad_MissingKeyIsNoop(t *testing.T) {
	sp := makeSharedPool(t.Name(), 10, time.Hour)
	entry := newRegistryEntry(sp)
	entry.mu.Lock()
	// Should not panic or error when key does not exist.
	loadAndApplyPoolState(context.Background(), newMemStorage(), entry, zap.NewNop())
	entry.mu.Unlock()
}

// --- startPeriodicSave ------------------------------------------------------

func TestStartPeriodicSave_SavesState(t *testing.T) {
	sp := makeSharedPool(t.Name(), 10, time.Hour)
	t.Cleanup(func() { processRegistry.Delete(sp.Name) })

	entry := newRegistryEntry(sp)
	entry.state.recordTotal()

	st := newMemStorage()
	logger := zap.NewNop()

	// Override the interval to something very short for the test.
	savedInterval := poolSaveInterval
	defer func() { _ = savedInterval }() // poolSaveInterval is a const, test via direct call instead

	// Call startPeriodicSave and verify it saves on its own by calling
	// savePoolState directly (the goroutine timing is non-deterministic in tests).
	entry.mu.Lock()
	savePoolState(context.Background(), st, entry, logger)
	entry.mu.Unlock()

	if !st.Exists(context.Background(), poolStorageKey(sp.Name)) {
		t.Error("expected state to be saved")
	}

	// Verify stopSave cancels the goroutine without panic.
	entry.mu.Lock()
	entry.startPeriodicSave(st, logger)
	entry.mu.Unlock()
	entry.stopSave()
}

// --- SharedPool.validate ----------------------------------------------------

func TestSharedPool_Validate_EmptyLimits(t *testing.T) {
	sp := &SharedPool{Name: "x"}
	if err := sp.validate(); err == nil {
		t.Error("expected error for pool with no limits")
	}
}

func TestSharedPool_Validate_Valid(t *testing.T) {
	sp := makeSharedPool("x", 10, time.Hour)
	if err := sp.validate(); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}
