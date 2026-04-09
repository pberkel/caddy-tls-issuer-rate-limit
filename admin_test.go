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
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"go.uber.org/zap"
)

// --- helpers ----------------------------------------------------------------

// adminRequest issues a request against handleRequest and returns the recorder.
func adminRequest(t *testing.T, method, path string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, nil)
	rec := httptest.NewRecorder()
	a := RateLimitAdmin{}
	if err := a.handleRequest(rec, req); err != nil {
		t.Fatalf("handleRequest returned error: %v", err)
	}
	return rec
}

// registerAdminPool registers a shared pool in processRegistry and schedules
// cleanup. Returns the entry.
func registerAdminPool(t *testing.T, name string, limit int, d time.Duration) *registryEntry {
	t.Helper()
	sp := makeSharedPool(name, limit, d)
	t.Cleanup(func() { processRegistry.Delete(name) })
	return getOrRegisterPool(sp, zap.NewNop())
}

// registerLocalEntry registers a local (non-shared) entry in processRegistry
// and schedules cleanup.
func registerLocalEntry(t *testing.T, name string, limit int, d time.Duration) *registryEntry {
	t.Helper()
	sp := makeSharedPool(name, limit, d) // reuse helper for state construction
	totals := make([]*slidingWindow, 1)
	totals[0] = &slidingWindow{}
	entry := &registryEntry{
		state: &rateLimitState{
			totalLimits: sp.RateLimit,
			totals:      totals,
			domains:     make(map[string][]*slidingWindow),
			now:         time.Now,
		},
		pool:  sp,
		local: true,
	}
	processRegistry.Store(name, entry)
	t.Cleanup(func() { processRegistry.Delete(name) })
	return entry
}

// decodePools decodes a JSON pool list from the recorder body.
func decodePools(t *testing.T, rec *httptest.ResponseRecorder) []PoolStatus {
	t.Helper()
	var pools []PoolStatus
	if err := json.NewDecoder(rec.Body).Decode(&pools); err != nil {
		t.Fatalf("decode pools: %v", err)
	}
	return pools
}

// poolByName returns the PoolStatus with the given name, or fails the test.
func poolByName(t *testing.T, pools []PoolStatus, name string) PoolStatus {
	t.Helper()
	for _, p := range pools {
		if p.Name == name {
			return p
		}
	}
	t.Fatalf("pool %q not found in response", name)
	return PoolStatus{}
}

// --- GET /rate_limit_issuer/ ------------------------------------------------

func TestAdmin_GetUI_ReturnsHTML(t *testing.T) {
	rec := adminRequest(t, http.MethodGet, "/rate_limit_issuer/")
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
	ct := rec.Header().Get("Content-Type")
	if ct != "text/html; charset=utf-8" {
		t.Errorf("Content-Type = %q, want text/html", ct)
	}
	if len(rec.Body.Bytes()) == 0 {
		t.Error("expected non-empty HTML body")
	}
}

// --- GET /rate_limit_issuer/pools -------------------------------------------

func TestAdmin_GetPools_Empty(t *testing.T) {
	rec := adminRequest(t, http.MethodGet, "/rate_limit_issuer/pools")
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
	pools := decodePools(t, rec)
	// Filter to only pools registered by this test (registry may have others).
	if pools == nil {
		pools = []PoolStatus{}
	}
}

func TestAdmin_GetPools_SharedPool(t *testing.T) {
	entry := registerAdminPool(t, t.Name(), 10, time.Hour)
	entry.state.recordTotal()

	rec := adminRequest(t, http.MethodGet, "/rate_limit_issuer/pools")
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
	pools := decodePools(t, rec)
	p := poolByName(t, pools, t.Name())

	if p.Kind != "shared" {
		t.Errorf("Kind = %q, want shared", p.Kind)
	}
	if len(p.Total) != 1 {
		t.Fatalf("Total len = %d, want 1", len(p.Total))
	}
	if p.Total[0].Count != 1 {
		t.Errorf("Total[0].Count = %d, want 1", p.Total[0].Count)
	}
	if p.Total[0].Limit != 10 {
		t.Errorf("Total[0].Limit = %d, want 10", p.Total[0].Limit)
	}
}

func TestAdmin_GetPools_LocalInstance(t *testing.T) {
	registerLocalEntry(t, t.Name(), 5, time.Hour)

	rec := adminRequest(t, http.MethodGet, "/rate_limit_issuer/pools")
	pools := decodePools(t, rec)
	p := poolByName(t, pools, t.Name())

	if p.Kind != "local" {
		t.Errorf("Kind = %q, want local", p.Kind)
	}
}

func TestAdmin_GetPools_ResetAt_PopulatedAtLimit(t *testing.T) {
	entry := registerAdminPool(t, t.Name(), 1, time.Hour)
	entry.state.recordTotal() // at limit — oldest slot defines reset time

	rec := adminRequest(t, http.MethodGet, "/rate_limit_issuer/pools")
	pools := decodePools(t, rec)
	p := poolByName(t, pools, t.Name())

	if p.Total[0].ResetAt == nil {
		t.Error("expected ResetAt to be populated when window is non-empty")
	}
}

func TestAdmin_GetPools_PerDomainWindows(t *testing.T) {
	sp := &SharedPool{
		Name:               t.Name(),
		PerDomainRateLimit: []*RateLimit{makeRateLimit(5, time.Hour)},
	}
	t.Cleanup(func() { processRegistry.Delete(sp.Name) })
	entry := getOrRegisterPool(sp, zap.NewNop())
	entry.state.recordDomain("example.com")

	rec := adminRequest(t, http.MethodGet, "/rate_limit_issuer/pools")
	pools := decodePools(t, rec)
	p := poolByName(t, pools, t.Name())

	if p.Domains == nil {
		t.Fatal("expected Domains to be populated")
	}
	ws, ok := p.Domains["example.com"]
	if !ok || len(ws) != 1 {
		t.Fatalf("example.com windows = %v (found=%v), want 1 window", ws, ok)
	}
	if ws[0].Count != 1 {
		t.Errorf("domain count = %d, want 1", ws[0].Count)
	}
}

func TestAdmin_GetPools_SortedByName(t *testing.T) {
	registerAdminPool(t, t.Name()+"_z", 10, time.Hour)
	registerAdminPool(t, t.Name()+"_a", 10, time.Hour)

	rec := adminRequest(t, http.MethodGet, "/rate_limit_issuer/pools")
	pools := decodePools(t, rec)

	var names []string
	for _, p := range pools {
		if len(p.Name) > len(t.Name()) && p.Name[:len(t.Name())] == t.Name() {
			names = append(names, p.Name)
		}
	}
	if len(names) != 2 {
		t.Fatalf("expected 2 test pools, got %d", len(names))
	}
	if names[0] >= names[1] {
		t.Errorf("pools not sorted: %q >= %q", names[0], names[1])
	}
}

// --- DELETE /rate_limit_issuer/pools/{name}/total ---------------------------

func TestAdmin_DeleteTotal_ResetsCounters(t *testing.T) {
	entry := registerAdminPool(t, t.Name(), 10, time.Hour)
	entry.state.recordTotal()
	entry.state.recordTotal()

	rec := adminRequest(t, http.MethodDelete, "/rate_limit_issuer/pools/"+t.Name()+"/total")
	if rec.Code != http.StatusNoContent {
		t.Errorf("status = %d, want 204", rec.Code)
	}

	entry.state.mu.Lock()
	count := entry.state.totals[0].count(time.Now(), time.Hour)
	entry.state.mu.Unlock()

	if count != 0 {
		t.Errorf("total count after reset = %d, want 0", count)
	}
}

func TestAdmin_DeleteTotal_PreservesDomains(t *testing.T) {
	sp := &SharedPool{
		Name:               t.Name(),
		RateLimit:          []*RateLimit{makeRateLimit(10, time.Hour)},
		PerDomainRateLimit: []*RateLimit{makeRateLimit(5, time.Hour)},
	}
	t.Cleanup(func() { processRegistry.Delete(sp.Name) })
	entry := getOrRegisterPool(sp, zap.NewNop())
	entry.state.recordTotal()
	entry.state.recordDomain("example.com")

	adminRequest(t, http.MethodDelete, "/rate_limit_issuer/pools/"+t.Name()+"/total")

	entry.state.mu.Lock()
	_, hasDomain := entry.state.domains["example.com"]
	entry.state.mu.Unlock()

	if !hasDomain {
		t.Error("expected per-domain windows to be preserved after total reset")
	}
}

func TestAdmin_DeleteTotal_NotFound(t *testing.T) {
	req := httptest.NewRequest(http.MethodDelete, "/rate_limit_issuer/pools/nonexistent/total", nil)
	rec := httptest.NewRecorder()
	a := RateLimitAdmin{}
	_ = a.handleRequest(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", rec.Code)
	}
}

// --- DELETE /rate_limit_issuer/pools/{name} ---------------------------------

func TestAdmin_DeletePool_ResetsAllWindows(t *testing.T) {
	sp := &SharedPool{
		Name:               t.Name(),
		RateLimit:          []*RateLimit{makeRateLimit(10, time.Hour)},
		PerDomainRateLimit: []*RateLimit{makeRateLimit(5, time.Hour)},
	}
	t.Cleanup(func() { processRegistry.Delete(sp.Name) })
	entry := getOrRegisterPool(sp, zap.NewNop())
	entry.state.recordTotal()
	entry.state.recordDomain("example.com")

	rec := adminRequest(t, http.MethodDelete, "/rate_limit_issuer/pools/"+t.Name())
	if rec.Code != http.StatusNoContent {
		t.Errorf("status = %d, want 204", rec.Code)
	}

	entry.state.mu.Lock()
	totalCount := entry.state.totals[0].count(time.Now(), time.Hour)
	_, hasDomain := entry.state.domains["example.com"]
	entry.state.mu.Unlock()

	if totalCount != 0 {
		t.Errorf("total count after full reset = %d, want 0", totalCount)
	}
	if hasDomain {
		t.Error("expected per-domain windows to be cleared after full reset")
	}
}

func TestAdmin_DeletePool_NotFound(t *testing.T) {
	req := httptest.NewRequest(http.MethodDelete, "/rate_limit_issuer/pools/nonexistent", nil)
	rec := httptest.NewRecorder()
	a := RateLimitAdmin{}
	_ = a.handleRequest(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", rec.Code)
	}
}

// --- DELETE /rate_limit_issuer/pools/{name}/domains/{domain} ----------------

func TestAdmin_DeleteDomain_ResetsDomainWindows(t *testing.T) {
	sp := &SharedPool{
		Name:               t.Name(),
		PerDomainRateLimit: []*RateLimit{makeRateLimit(5, time.Hour)},
	}
	t.Cleanup(func() { processRegistry.Delete(sp.Name) })
	entry := getOrRegisterPool(sp, zap.NewNop())
	entry.state.recordDomain("example.com")
	entry.state.recordDomain("other.com")

	rec := adminRequest(t, http.MethodDelete, "/rate_limit_issuer/pools/"+t.Name()+"/domains/example.com")
	if rec.Code != http.StatusNoContent {
		t.Errorf("status = %d, want 204", rec.Code)
	}

	entry.state.mu.Lock()
	_, hasExample := entry.state.domains["example.com"]
	_, hasOther := entry.state.domains["other.com"]
	entry.state.mu.Unlock()

	if hasExample {
		t.Error("expected example.com windows to be deleted")
	}
	if !hasOther {
		t.Error("expected other.com windows to be preserved")
	}
}

func TestAdmin_DeleteDomain_NotFound(t *testing.T) {
	req := httptest.NewRequest(http.MethodDelete, "/rate_limit_issuer/pools/nonexistent/domains/example.com", nil)
	rec := httptest.NewRecorder()
	a := RateLimitAdmin{}
	_ = a.handleRequest(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", rec.Code)
	}
}

// --- 404 / method routing ---------------------------------------------------

func TestAdmin_UnknownPath_Returns404(t *testing.T) {
	rec := adminRequest(t, http.MethodGet, "/rate_limit_issuer/unknown")
	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", rec.Code)
	}
}

func TestAdmin_WrongMethod_Returns404(t *testing.T) {
	rec := adminRequest(t, http.MethodPost, "/rate_limit_issuer/pools")
	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", rec.Code)
	}
}

// --- entryToStatus ----------------------------------------------------------

func TestEntryToStatus_EmptyWindows_NoResetAt(t *testing.T) {
	sp := makeSharedPool("x", 10, time.Hour)
	entry := newRegistryEntry(sp)
	// No issuances — totals is empty.
	ps := entryToStatus("x", entry)
	if len(ps.Total) != 1 {
		t.Fatalf("Total len = %d, want 1", len(ps.Total))
	}
	if ps.Total[0].ResetAt != nil {
		t.Error("expected ResetAt to be nil for empty window")
	}
}

func TestEntryToStatus_NonEmptyWindow_HasResetAt(t *testing.T) {
	sp := makeSharedPool("x", 10, time.Hour)
	entry := newRegistryEntry(sp)
	entry.state.recordTotal()
	ps := entryToStatus("x", entry)
	if ps.Total[0].ResetAt == nil {
		t.Error("expected ResetAt to be set for non-empty window")
	}
}
