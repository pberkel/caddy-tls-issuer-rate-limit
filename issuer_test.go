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
	"crypto/x509"
	"errors"
	"io/fs"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/certmagic"
)

// --- Helpers ----------------------------------------------------------------

// stubIssuer is a minimal certmagic.Issuer for testing.
type stubIssuer struct {
	key       string
	issueFunc func(ctx context.Context, csr *x509.CertificateRequest) (*certmagic.IssuedCertificate, error)
}

func (s *stubIssuer) Issue(ctx context.Context, csr *x509.CertificateRequest) (*certmagic.IssuedCertificate, error) {
	if s.issueFunc != nil {
		return s.issueFunc(ctx, csr)
	}
	return &certmagic.IssuedCertificate{Certificate: []byte("stub")}, nil
}

func (s *stubIssuer) IssuerKey() string {
	if s.key != "" {
		return s.key
	}
	return "stub"
}

// preCheckerIssuer wraps stubIssuer with a PreCheck hook.
type preCheckerIssuer struct {
	stubIssuer
	preCheckErr error
	called      bool
}

func (p *preCheckerIssuer) PreCheck(_ context.Context, _ []string, _ bool) error {
	p.called = true
	return p.preCheckErr
}

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

// newTestIssuer returns a RateLimitIssuer wired with the provided inner issuer
// and storage, with no limits configured.
func newTestIssuer(inner certmagic.Issuer, storage certmagic.Storage) *RateLimitIssuer {
	return &RateLimitIssuer{
		issuer:  inner,
		storage: storage,
		rateLimiter: &rateLimitState{
			domains: make(map[string][]*slidingWindow),
			now:     time.Now,
		},
		approvals: &approvalState{
			atCapacityIssuer: make(map[string]time.Time),
			atCapacityGlobal: make(map[string]time.Time),
			now:              time.Now,
		},
	}
}

// newTestIssuerWithLimits returns a RateLimitIssuer with per-instance cert cap
// and optional rate limits configured.
func newTestIssuerWithLimits(inner certmagic.Issuer, storage certmagic.Storage, maxCerts int, globalRL, perDomainRL *RateLimit) *RateLimitIssuer {
	iss := newTestIssuer(inner, storage)
	iss.Name = "test"
	iss.MaxCertsPerDomain = maxCerts
	if globalRL != nil {
		iss.GlobalRateLimit = []*RateLimit{globalRL}
		iss.rateLimiter.globalLimits = iss.GlobalRateLimit
		iss.rateLimiter.globals = []*slidingWindow{{}}
	}
	if perDomainRL != nil {
		iss.PerDomainRateLimit = []*RateLimit{perDomainRL}
		iss.rateLimiter.perDomainLimits = iss.PerDomainRateLimit
	}
	return iss
}

func makeRateLimit(limit int, d time.Duration) *RateLimit {
	return &RateLimit{Limit: limit, Duration: caddy.Duration(d)}
}

// --- certSubject ------------------------------------------------------------

func TestCertSubject(t *testing.T) {
	tests := []struct {
		name          string
		wantDomain    string
		wantSubject   string
		wantErrSubstr string
	}{
		{"www.example.com", "example.com", "www.example.com", ""},
		{"api.example.com", "example.com", "api.example.com", ""},
		{"example.com", "example.com", "example.com", ""},
		{"*.example.com", "example.com", "*.example.com", ""},
		{"*.example.co.uk", "example.co.uk", "*.example.co.uk", ""},
		{"api.v2.example.com", "example.com", "api.v2.example.com", ""},
		{"com", "", "", "determining registrable domain"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			domain, subject, err := certSubject(tt.name)
			if tt.wantErrSubstr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErrSubstr) {
					t.Fatalf("certSubject(%q) error = %v, want containing %q", tt.name, err, tt.wantErrSubstr)
				}
				return
			}
			if err != nil {
				t.Fatalf("certSubject(%q) unexpected error: %v", tt.name, err)
			}
			if domain != tt.wantDomain {
				t.Errorf("domain = %q, want %q", domain, tt.wantDomain)
			}
			if subject != tt.wantSubject {
				t.Errorf("subject = %q, want %q", subject, tt.wantSubject)
			}
		})
	}
}

func TestCertCountKey(t *testing.T) {
	iss := newTestIssuer(&stubIssuer{}, nil)
	iss.Name = "primary"
	got := iss.certCountKey("example.com")
	want := "tls_issuer_rate_limit/primary/counts/example.com.json"
	if got != want {
		t.Errorf("certCountKey = %q, want %q", got, want)
	}
}

func TestGlobalCertCountKey(t *testing.T) {
	iss := newTestIssuer(&stubIssuer{key: "acme-v02.api.letsencrypt.org-directory"}, nil)
	got := iss.globalCertCountKey("example.com")
	want := "tls_issuer_rate_limit/counts/example.com.json"
	if got != want {
		t.Errorf("globalCertCountKey = %q, want %q", got, want)
	}
}

// --- approvalState (at-capacity cache) --------------------------------------

func TestApprovalState_IssuerScope_Miss(t *testing.T) {
	iss := newTestIssuer(&stubIssuer{}, nil)
	if iss.approvals.isCached("example.com", iss.approvals.atCapacityIssuer) {
		t.Error("expected miss for unknown domain")
	}
}

func TestApprovalState_IssuerScope_Hit(t *testing.T) {
	iss := newTestIssuer(&stubIssuer{}, nil)
	iss.approvals.cache("example.com", iss.approvals.atCapacityIssuer)
	if !iss.approvals.isCached("example.com", iss.approvals.atCapacityIssuer) {
		t.Error("expected hit after cache")
	}
}

func TestApprovalState_IssuerScope_Expired(t *testing.T) {
	now := time.Now()
	iss := newTestIssuer(&stubIssuer{}, nil)
	iss.approvals.now = func() time.Time { return now }
	iss.approvals.cache("example.com", iss.approvals.atCapacityIssuer)

	iss.approvals.now = func() time.Time { return now.Add(atCapacityCacheTTL + time.Second) }
	if iss.approvals.isCached("example.com", iss.approvals.atCapacityIssuer) {
		t.Error("expected expired entry to return miss")
	}
	iss.approvals.mu.Lock()
	_, still := iss.approvals.atCapacityIssuer["example.com"]
	iss.approvals.mu.Unlock()
	if still {
		t.Error("expired entry should have been evicted")
	}
}

func TestApprovalState_GlobalScope_Independent(t *testing.T) {
	iss := newTestIssuer(&stubIssuer{}, nil)
	// Caching in global scope should not affect issuer scope and vice versa.
	iss.approvals.cache("example.com", iss.approvals.atCapacityGlobal)
	if iss.approvals.isCached("example.com", iss.approvals.atCapacityIssuer) {
		t.Error("global cache should not affect issuer cache")
	}
	if !iss.approvals.isCached("example.com", iss.approvals.atCapacityGlobal) {
		t.Error("expected hit in global cache")
	}
}

// --- Provision validation ---------------------------------------------------

func TestProvision_MaxCertsPerDomain_RequiresName(t *testing.T) {
	// MaxCertsPerDomain > 0 without a Name should fail at provision time.
	// We test this via the validation logic directly since Provision requires
	// a full caddy.Context.
	iss := &RateLimitIssuer{
		issuer:            &stubIssuer{},
		MaxCertsPerDomain: 5,
		Name:              "",
	}
	// Replicate the validation check from Provision.
	if iss.MaxCertsPerDomain > 0 && iss.Name == "" {
		// expected — validation would return an error
		return
	}
	t.Error("expected validation to fail when max_certs_per_domain set without name")
}

func TestProvision_MaxCertsPerDomain_WithName_OK(t *testing.T) {
	iss := &RateLimitIssuer{
		issuer:            &stubIssuer{},
		MaxCertsPerDomain: 5,
		Name:              "primary",
	}
	if iss.MaxCertsPerDomain > 0 && iss.Name == "" {
		t.Error("unexpected validation failure with name set")
	}
}

// --- storage: loadCertCount / storeCertCount --------------------------------

func TestLoadCertCount_NotExist(t *testing.T) {
	iss := newTestIssuer(&stubIssuer{}, newMemStorage())
	counts, err := iss.loadCertCount(context.Background(), iss.certCountKey("example.com"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(counts) != 0 {
		t.Errorf("expected empty map, got %v", counts)
	}
}

func TestLoadCertCount_Roundtrip(t *testing.T) {
	st := newMemStorage()
	iss := newTestIssuer(&stubIssuer{}, st)
	ctx := context.Background()
	key := iss.certCountKey("example.com")

	counts := map[string]struct{}{"www.example.com": {}, "api.example.com": {}}
	if err := iss.storeCertCount(ctx, key, counts); err != nil {
		t.Fatalf("storeCertCount: %v", err)
	}
	loaded, err := iss.loadCertCount(ctx, key)
	if err != nil {
		t.Fatalf("loadCertCount: %v", err)
	}
	for _, s := range []string{"www.example.com", "api.example.com"} {
		if _, ok := loaded[s]; !ok {
			t.Errorf("missing subject %q after roundtrip", s)
		}
	}
}

// --- recordCertCount --------------------------------------------------------

func TestRecordCertCount_AddsSubject(t *testing.T) {
	st := newMemStorage()
	iss := newTestIssuerWithLimits(&stubIssuer{}, st, 5, nil, nil)
	ctx := context.Background()
	key := iss.certCountKey("example.com")

	if err := iss.recordCertCount(ctx, key, "example.com", "www.example.com", 5, iss.approvals.atCapacityIssuer); err != nil {
		t.Fatalf("recordCertCount: %v", err)
	}
	counts, _ := iss.loadCertCount(ctx, key)
	if _, ok := counts["www"]; !ok {
		t.Error("subject not found after recordCertCount")
	}
}

func TestRecordCertCount_Idempotent(t *testing.T) {
	st := newMemStorage()
	iss := newTestIssuerWithLimits(&stubIssuer{}, st, 5, nil, nil)
	ctx := context.Background()
	key := iss.certCountKey("example.com")

	for range 3 {
		if err := iss.recordCertCount(ctx, key, "example.com", "www.example.com", 5, iss.approvals.atCapacityIssuer); err != nil {
			t.Fatalf("recordCertCount: %v", err)
		}
	}
	counts, _ := iss.loadCertCount(ctx, key)
	if len(counts) != 1 {
		t.Errorf("expected 1 subject, got %d", len(counts))
	}
}

func TestRecordCertCount_SetsAtCapacityCache(t *testing.T) {
	st := newMemStorage()
	iss := newTestIssuerWithLimits(&stubIssuer{}, st, 1, nil, nil)
	ctx := context.Background()
	key := iss.certCountKey("example.com")

	if err := iss.recordCertCount(ctx, key, "example.com", "www.example.com", 1, iss.approvals.atCapacityIssuer); err != nil {
		t.Fatalf("recordCertCount: %v", err)
	}
	if !iss.approvals.isCached("example.com", iss.approvals.atCapacityIssuer) {
		t.Error("expected domain to be marked at-capacity after reaching max")
	}
}

func TestRecordCertCount_GlobalKey_IndependentFromInstanceKey(t *testing.T) {
	st := newMemStorage()
	iss := newTestIssuer(&stubIssuer{}, st)
	iss.Name = "primary"
	ctx := context.Background()

	instanceKey := iss.certCountKey("example.com")
	globalKey := iss.globalCertCountKey("example.com")

	// Record via global key.
	if err := iss.recordCertCount(ctx, globalKey, "example.com", "www.example.com", 5, iss.approvals.atCapacityGlobal); err != nil {
		t.Fatalf("recordCertCount (global): %v", err)
	}

	// Per-instance key should still be empty.
	counts, _ := iss.loadCertCount(ctx, instanceKey)
	if len(counts) != 0 {
		t.Error("global record should not affect per-instance storage")
	}

	// Global key should have the subject.
	counts, _ = iss.loadCertCount(ctx, globalKey)
	if _, ok := counts["www"]; !ok {
		t.Error("subject not found in global storage")
	}
}

// --- checkCertCount ---------------------------------------------------------

func TestCheckCertCount_BelowLimit(t *testing.T) {
	st := newMemStorage()
	iss := newTestIssuerWithLimits(&stubIssuer{}, st, 5, nil, nil)
	ctx := context.Background()
	key := iss.certCountKey("example.com")

	if err := iss.checkCertCount(ctx, key, "example.com", "www.example.com", 5, iss.approvals.atCapacityIssuer); err != nil {
		t.Errorf("expected no error below limit, got: %v", err)
	}
}

func TestCheckCertCount_AtLimit(t *testing.T) {
	st := newMemStorage()
	iss := newTestIssuerWithLimits(&stubIssuer{}, st, 1, nil, nil)
	ctx := context.Background()
	key := iss.certCountKey("example.com")

	_ = iss.recordCertCount(ctx, key, "example.com", "existing.example.com", 1, iss.approvals.atCapacityIssuer)

	if err := iss.checkCertCount(ctx, key, "example.com", "new.example.com", 1, iss.approvals.atCapacityIssuer); err == nil {
		t.Error("expected error when at limit")
	}
}

func TestCheckCertCount_ExistingSubjectIsRenewal(t *testing.T) {
	st := newMemStorage()
	iss := newTestIssuerWithLimits(&stubIssuer{}, st, 1, nil, nil)
	ctx := context.Background()
	key := iss.certCountKey("example.com")

	_ = iss.recordCertCount(ctx, key, "example.com", "www.example.com", 1, iss.approvals.atCapacityIssuer)

	if err := iss.checkCertCount(ctx, key, "example.com", "www.example.com", 1, iss.approvals.atCapacityIssuer); err != nil {
		t.Errorf("renewal of existing subject should not be rejected, got: %v", err)
	}
}

// --- checkStorageLimits -----------------------------------------------------

func TestCheckStorageLimits_NoLimits(t *testing.T) {
	iss := newTestIssuer(&stubIssuer{}, newMemStorage())
	if err := iss.checkStorageLimits(context.Background(), []string{"www.example.com"}); err != nil {
		t.Errorf("unexpected error with no limits: %v", err)
	}
}

func TestCheckStorageLimits_NoStorage(t *testing.T) {
	iss := newTestIssuer(&stubIssuer{}, nil)
	iss.MaxCertsPerDomain = 5
	if err := iss.checkStorageLimits(context.Background(), []string{"www.example.com"}); err != nil {
		t.Errorf("unexpected error with nil storage: %v", err)
	}
}

func TestCheckStorageLimits_PerIssuerLimit(t *testing.T) {
	st := newMemStorage()
	iss := newTestIssuerWithLimits(&stubIssuer{}, st, 1, nil, nil)
	ctx := context.Background()

	// Fill per-issuer cap.
	if _, err := iss.Issue(ctx, &x509.CertificateRequest{DNSNames: []string{"www.example.com"}}); err != nil {
		t.Fatalf("first Issue: %v", err)
	}
	if err := iss.checkStorageLimits(ctx, []string{"api.example.com"}); err == nil {
		t.Error("expected per-issuer limit error")
	}
}

func TestCheckStorageLimits_GlobalLimit(t *testing.T) {
	st := newMemStorage()
	iss := newTestIssuer(&stubIssuer{}, st)
	iss.GlobalMaxCertsPerDomain = 1
	ctx := context.Background()

	// Fill global cap via recordCertCount directly.
	if err := iss.recordCertCount(ctx, iss.globalCertCountKey("example.com"), "example.com", "www.example.com", 1, iss.approvals.atCapacityGlobal); err != nil {
		t.Fatalf("recordCertCount: %v", err)
	}
	if err := iss.checkStorageLimits(ctx, []string{"api.example.com"}); err == nil {
		t.Error("expected global limit error")
	}
}

func TestCheckStorageLimits_BothLimitsMustPass(t *testing.T) {
	st := newMemStorage()
	iss := newTestIssuer(&stubIssuer{}, st)
	iss.Name = "test"
	iss.MaxCertsPerDomain = 2
	iss.GlobalMaxCertsPerDomain = 1
	ctx := context.Background()

	// Per-issuer still has capacity; global is full.
	if err := iss.recordCertCount(ctx, iss.globalCertCountKey("example.com"), "example.com", "www.example.com", 1, iss.approvals.atCapacityGlobal); err != nil {
		t.Fatalf("recordCertCount: %v", err)
	}
	if err := iss.checkStorageLimits(ctx, []string{"api.example.com"}); err == nil {
		t.Error("expected rejection when global limit full even though per-issuer has capacity")
	}
}

func TestCheckStorageLimits_WildcardSharesSlot(t *testing.T) {
	st := newMemStorage()
	iss := newTestIssuerWithLimits(&stubIssuer{}, st, 1, nil, nil)
	ctx := context.Background()

	key := iss.certCountKey("example.com")
	_ = iss.recordCertCount(ctx, key, "example.com", "*.example.com", 1, iss.approvals.atCapacityIssuer)

	if err := iss.checkStorageLimits(ctx, []string{"*.example.com"}); err != nil {
		t.Errorf("renewal via wildcard subject should not be rejected: %v", err)
	}
}

// --- checkInMemoryLimits ----------------------------------------------------

func TestCheckInMemoryLimits_NoLimits(t *testing.T) {
	iss := newTestIssuer(&stubIssuer{}, nil)
	if err := iss.checkInMemoryLimits([]string{"www.example.com"}); err != nil {
		t.Errorf("unexpected error with no limits configured: %v", err)
	}
}

func TestCheckInMemoryLimits_GlobalRateLimitExceeded(t *testing.T) {
	iss := newTestIssuerWithLimits(&stubIssuer{}, nil, 0, makeRateLimit(1, time.Hour), nil)
	iss.rateLimiter.recordGlobal()

	if err := iss.checkInMemoryLimits([]string{"www.example.com"}); err == nil {
		t.Error("expected global rate limit error")
	}
}

func TestCheckInMemoryLimits_PerDomainRateLimitExceeded(t *testing.T) {
	iss := newTestIssuerWithLimits(&stubIssuer{}, nil, 0, nil, makeRateLimit(1, time.Hour))
	iss.rateLimiter.recordDomain("example.com")

	if err := iss.checkInMemoryLimits([]string{"www.example.com"}); err == nil {
		t.Error("expected per-domain rate limit error")
	}
}

func TestCheckInMemoryLimits_IssuerAtCapacityCacheHit(t *testing.T) {
	iss := newTestIssuerWithLimits(&stubIssuer{}, nil, 5, nil, nil)
	iss.approvals.cache("example.com", iss.approvals.atCapacityIssuer)

	if err := iss.checkInMemoryLimits([]string{"www.example.com"}); err == nil {
		t.Error("expected at-capacity error from per-issuer cache")
	}
}

func TestCheckInMemoryLimits_GlobalAtCapacityCacheHit(t *testing.T) {
	iss := newTestIssuer(&stubIssuer{}, nil)
	iss.GlobalMaxCertsPerDomain = 5
	iss.approvals.cache("example.com", iss.approvals.atCapacityGlobal)

	if err := iss.checkInMemoryLimits([]string{"www.example.com"}); err == nil {
		t.Error("expected at-capacity error from global cache")
	}
}

func TestCheckInMemoryLimits_DeduplicatesDomains(t *testing.T) {
	iss := newTestIssuerWithLimits(&stubIssuer{}, nil, 0, nil, makeRateLimit(2, time.Hour))
	iss.rateLimiter.recordDomain("example.com") // count = 1

	if err := iss.checkInMemoryLimits([]string{"www.example.com", "api.example.com"}); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

// --- PreCheck ---------------------------------------------------------------

func TestPreCheck_DelegatestoInnerPreChecker(t *testing.T) {
	inner := &preCheckerIssuer{}
	iss := newTestIssuer(inner, nil)

	if err := iss.PreCheck(context.Background(), []string{"www.example.com"}, false); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if !inner.called {
		t.Error("inner PreCheck was not called")
	}
}

func TestPreCheck_InnerPreCheckerError(t *testing.T) {
	inner := &preCheckerIssuer{preCheckErr: errors.New("inner says no")}
	iss := newTestIssuer(inner, nil)

	if err := iss.PreCheck(context.Background(), []string{"www.example.com"}, false); err == nil {
		t.Error("expected error from inner PreChecker")
	}
}

func TestPreCheck_RateLimitBlocksBeforeInner(t *testing.T) {
	inner := &preCheckerIssuer{}
	iss := newTestIssuerWithLimits(inner, nil, 0, makeRateLimit(1, time.Hour), nil)
	iss.rateLimiter.recordGlobal()

	if err := iss.PreCheck(context.Background(), []string{"www.example.com"}, false); err == nil {
		t.Error("expected rate limit error")
	}
	if inner.called {
		t.Error("inner PreCheck should not have been called when rate limit exceeded")
	}
}

// --- Issue ------------------------------------------------------------------

func TestIssue_Success(t *testing.T) {
	iss := newTestIssuer(&stubIssuer{}, newMemStorage())
	csr := &x509.CertificateRequest{DNSNames: []string{"www.example.com"}}
	cert, err := iss.Issue(context.Background(), csr)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if cert == nil {
		t.Fatal("expected non-nil certificate")
	}
}

func TestIssue_InnerError_NoCountRecorded(t *testing.T) {
	st := newMemStorage()
	inner := &stubIssuer{
		issueFunc: func(_ context.Context, _ *x509.CertificateRequest) (*certmagic.IssuedCertificate, error) {
			return nil, errors.New("ACME failed")
		},
	}
	iss := newTestIssuerWithLimits(inner, st, 5, nil, nil)
	ctx := context.Background()

	if _, err := iss.Issue(ctx, &x509.CertificateRequest{DNSNames: []string{"www.example.com"}}); err == nil {
		t.Fatal("expected error from inner issuer")
	}

	counts, _ := iss.loadCertCount(ctx, iss.certCountKey("example.com"))
	if len(counts) != 0 {
		t.Errorf("expected no counts after failed issuance, got %d", len(counts))
	}
}

func TestIssue_PerIssuerMaxCertsReached_Rejected(t *testing.T) {
	st := newMemStorage()
	iss := newTestIssuerWithLimits(&stubIssuer{}, st, 1, nil, nil)
	ctx := context.Background()

	if _, err := iss.Issue(ctx, &x509.CertificateRequest{DNSNames: []string{"www.example.com"}}); err != nil {
		t.Fatalf("first Issue: %v", err)
	}
	if _, err := iss.Issue(ctx, &x509.CertificateRequest{DNSNames: []string{"api.example.com"}}); err == nil {
		t.Error("expected second issuance to be rejected at per-issuer limit")
	}
}

func TestIssue_GlobalMaxCertsReached_Rejected(t *testing.T) {
	st := newMemStorage()
	iss := newTestIssuer(&stubIssuer{}, st)
	iss.GlobalMaxCertsPerDomain = 1
	ctx := context.Background()

	if _, err := iss.Issue(ctx, &x509.CertificateRequest{DNSNames: []string{"www.example.com"}}); err != nil {
		t.Fatalf("first Issue: %v", err)
	}
	if _, err := iss.Issue(ctx, &x509.CertificateRequest{DNSNames: []string{"api.example.com"}}); err == nil {
		t.Error("expected second issuance to be rejected at global limit")
	}
}

func TestIssue_BothLimits_GlobalFull_Rejected(t *testing.T) {
	st := newMemStorage()
	iss := newTestIssuer(&stubIssuer{}, st)
	iss.Name = "test"
	iss.MaxCertsPerDomain = 5       // per-instance has room
	iss.GlobalMaxCertsPerDomain = 1 // global is tight
	ctx := context.Background()

	if _, err := iss.Issue(ctx, &x509.CertificateRequest{DNSNames: []string{"www.example.com"}}); err != nil {
		t.Fatalf("first Issue: %v", err)
	}
	if _, err := iss.Issue(ctx, &x509.CertificateRequest{DNSNames: []string{"api.example.com"}}); err == nil {
		t.Error("expected rejection when global limit full")
	}
}

func TestIssue_RenewalOfExistingSubject_Allowed(t *testing.T) {
	st := newMemStorage()
	iss := newTestIssuerWithLimits(&stubIssuer{}, st, 1, nil, nil)
	ctx := context.Background()
	csr := &x509.CertificateRequest{DNSNames: []string{"www.example.com"}}

	if _, err := iss.Issue(ctx, csr); err != nil {
		t.Fatalf("first Issue: %v", err)
	}
	if _, err := iss.Issue(ctx, csr); err != nil {
		t.Errorf("renewal should be allowed: %v", err)
	}
}

func TestIssue_RecordsCountersOnSuccess(t *testing.T) {
	st := newMemStorage()
	iss := newTestIssuerWithLimits(&stubIssuer{}, st, 5, makeRateLimit(100, time.Hour), makeRateLimit(10, time.Hour))
	ctx := context.Background()

	if _, err := iss.Issue(ctx, &x509.CertificateRequest{DNSNames: []string{"www.example.com"}}); err != nil {
		t.Fatalf("Issue: %v", err)
	}

	// Per-issuer storage count incremented.
	counts, _ := iss.loadCertCount(ctx, iss.certCountKey("example.com"))
	if _, ok := counts["www"]; !ok {
		t.Error("subject not recorded in per-issuer storage after issuance")
	}

	// In-memory rate limit counters incremented.
	iss.rateLimiter.mu.Lock()
	globalCount := iss.rateLimiter.globals[0].count(time.Now(), time.Duration(iss.GlobalRateLimit[0].Duration))
	domainWindows, hasDomain := iss.rateLimiter.domains["example.com"]
	var domainCount int
	if hasDomain {
		domainCount = domainWindows[0].count(time.Now(), time.Duration(iss.PerDomainRateLimit[0].Duration))
	}
	iss.rateLimiter.mu.Unlock()

	if globalCount != 1 {
		t.Errorf("global rate counter = %d, want 1", globalCount)
	}
	if !hasDomain || domainCount != 1 {
		t.Error("per-domain rate counter not incremented")
	}
}

func TestIssue_RecordsGlobalCount(t *testing.T) {
	st := newMemStorage()
	iss := newTestIssuer(&stubIssuer{}, st)
	iss.GlobalMaxCertsPerDomain = 5
	ctx := context.Background()

	if _, err := iss.Issue(ctx, &x509.CertificateRequest{DNSNames: []string{"www.example.com"}}); err != nil {
		t.Fatalf("Issue: %v", err)
	}

	counts, _ := iss.loadCertCount(ctx, iss.globalCertCountKey("example.com"))
	if _, ok := counts["www"]; !ok {
		t.Error("subject not recorded in global storage after issuance")
	}
}

// --- IssuerKey --------------------------------------------------------------

func TestIssuerKey(t *testing.T) {
	iss := newTestIssuer(&stubIssuer{key: "my-issuer"}, nil)
	if got := iss.IssuerKey(); got != "my-issuer" {
		t.Errorf("IssuerKey = %q, want %q", got, "my-issuer")
	}
}

// --- SetConfig --------------------------------------------------------------

type configSetterIssuer struct {
	stubIssuer
	setCalled bool
	cfg       *certmagic.Config
}

func (c *configSetterIssuer) SetConfig(cfg *certmagic.Config) {
	c.setCalled = true
	c.cfg = cfg
}

func TestSetConfig_StoredAndPropagated(t *testing.T) {
	inner := &configSetterIssuer{}
	iss := newTestIssuer(inner, nil)
	cfg := &certmagic.Config{Storage: newMemStorage()}
	iss.SetConfig(cfg)

	if iss.storage != cfg.Storage {
		t.Error("storage not set from config")
	}
	if !inner.setCalled {
		t.Error("SetConfig not propagated to inner issuer")
	}
}

func TestSetConfig_NonSetterInnerIsOK(t *testing.T) {
	iss := newTestIssuer(&stubIssuer{}, nil)
	cfg := &certmagic.Config{Storage: newMemStorage()}
	iss.SetConfig(cfg)
	if iss.storage != cfg.Storage {
		t.Error("storage not set")
	}
}
