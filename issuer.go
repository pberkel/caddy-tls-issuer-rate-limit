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

// Package ratelimitissuer provides a Caddy TLS issuer module
// (tls.issuance.rate_limit) that wraps any inner certmagic.Issuer and enforces
// configurable rate limits and per-domain certificate caps at issuance time.
//
// Because limits are enforced after certmagic's SubjectTransformer has run,
// they apply to the effective certificate subject rather than the raw hostname
// from the TLS handshake. This means hostnames that share a wildcard cert
// (e.g. www.example.com and api.example.com both mapping to *.example.com)
// correctly consume only one slot rather than one each.
package ratelimitissuer

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/caddyserver/certmagic"
	"go.uber.org/zap"
	"golang.org/x/net/publicsuffix"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddytls"
)

func init() {
	caddy.RegisterModule(RateLimitIssuer{})
}

// RateLimitIssuer is a TLS issuer (module ID: tls.issuance.rate_limit) that
// wraps an inner certmagic.Issuer and enforces configurable issuance rate
// limits and per-domain certificate caps.
//
// Limits are enforced at issuance time, after certmagic's SubjectTransformer
// has run, so counts apply to the effective certificate subject — not the raw
// hostname from the TLS handshake. This makes RateLimitIssuer correct when
// used with tls.issuance.opportunistic, where multiple hostnames may map to
// the same wildcard certificate.
//
// # Certificate count scopes
//
// Two independent certificate count limits are available and may be configured
// simultaneously; both must be satisfied for issuance to proceed.
//
// max_certs_per_domain is scoped per inner issuer: counts are stored under a
// key derived from the inner issuer's IssuerKey(), so two RateLimitIssuer
// instances wrapping different inner issuers maintain independent counts. Two
// instances wrapping the same inner issuer share counts — the cap applies to
// the total number of certificates issued by that issuer regardless of which
// policy triggered the issuance.
//
// global_max_certs_per_domain is scoped globally across all inner issuers:
// counts are stored in a shared namespace so that certificates issued through
// any inner issuer all count toward the same cap. This is useful when the
// inner issuer is a load balancer or proxy that may distribute requests across
// multiple underlying ACME issuers.
//
// # Multiple instances
//
// When multiple RateLimitIssuer instances are loaded into the same Caddy
// server (e.g. across different automation policies), each instance maintains
// independent in-memory rate limit windows. A certificate issuance recorded by
// one instance does not advance the sliding window of another, so the effective
// combined rate may be higher than the configured per-instance limit.
//
// EXPERIMENTAL: Subject to change.
type RateLimitIssuer struct {
	// The inner issuer to delegate certificate issuance to.
	// Any tls.issuance module is accepted. Required.
	IssuerRaw json.RawMessage `json:"issuer,omitempty" caddy:"namespace=tls.issuance inline_key=module"`

	// Name uniquely identifies this rate_limit issuer instance and is used to
	// namespace per-instance certificate counts in storage. Required when
	// max_certs_per_domain is set; ignored otherwise.
	Name string `json:"name,omitempty"`

	// Maximum number of unique certificates that may be issued per registrable
	// domain (eTLD+1), scoped to this rate_limit issuer instance. Requires
	// Name to be set. 0 or unset means no limit.
	MaxCertsPerDomain int `json:"max_certs_per_domain,omitempty"`

	// Raw string value for max_certs_per_domain; may contain Caddy
	// placeholders resolved at provisioning time. When non-empty, takes
	// precedence over MaxCertsPerDomain.
	MaxCertsPerDomainRaw string `json:"max_certs_per_domain_raw,omitempty"`

	// Maximum number of unique certificates that may be issued per registrable
	// domain (eTLD+1), counted globally across all inner issuers. 0 or unset
	// means no limit.
	GlobalMaxCertsPerDomain int `json:"global_max_certs_per_domain,omitempty"`

	// Raw string value for global_max_certs_per_domain; may contain Caddy
	// placeholders resolved at provisioning time. When non-empty, takes
	// precedence over GlobalMaxCertsPerDomain.
	GlobalMaxCertsPerDomainRaw string `json:"global_max_certs_per_domain_raw,omitempty"`

	// Global issuance rate limit across all domains. Limits the total number
	// of new certificates issued within a rolling time window.
	GlobalRateLimit *RateLimit `json:"global_rate_limit,omitempty"`

	// Per registrable domain issuance rate limit. Limits the number of new
	// certificates issued for a single domain within a rolling time window.
	PerDomainRateLimit *RateLimit `json:"per_domain_rate_limit,omitempty"`

	issuer      certmagic.Issuer
	logger      *zap.Logger
	storage     certmagic.Storage
	rateLimiter *rateLimitState
	approvals   *approvalState
}

// approvalState holds short-lived in-memory caches of domains known to be at
// their certificate cap, avoiding repeated storage reads for already-full
// domains. Separate caches are maintained for per-issuer and global scopes.
type approvalState struct {
	mu               sync.Mutex
	atCapacityIssuer map[string]time.Time
	atCapacityGlobal map[string]time.Time
	now              func() time.Time
}

// storedCertCount is the on-disk representation of issued certificate subjects
// per registrable domain.
type storedCertCount struct {
	Subjects []string `json:"subjects"`
}

const (
	atCapacityCacheTTL = 2 * time.Minute
	storageKeyPrefix   = "tls_issuer_rate_limit"
)

// CaddyModule returns the Caddy module information.
func (RateLimitIssuer) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "tls.issuance.rate_limit",
		New: func() caddy.Module { return new(RateLimitIssuer) },
	}
}

// Provision sets up the module.
func (iss *RateLimitIssuer) Provision(ctx caddy.Context) error {
	iss.logger = ctx.Logger()

	repl := caddy.NewReplacer()

	if iss.MaxCertsPerDomainRaw != "" {
		resolved := repl.ReplaceAll(iss.MaxCertsPerDomainRaw, "")
		n, err := fmt.Sscanf(resolved, "%d", &iss.MaxCertsPerDomain)
		if n != 1 || err != nil {
			return fmt.Errorf("invalid max_certs_per_domain value: %q", resolved)
		}
	}
	if iss.GlobalMaxCertsPerDomainRaw != "" {
		resolved := repl.ReplaceAll(iss.GlobalMaxCertsPerDomainRaw, "")
		n, err := fmt.Sscanf(resolved, "%d", &iss.GlobalMaxCertsPerDomain)
		if n != 1 || err != nil {
			return fmt.Errorf("invalid global_max_certs_per_domain value: %q", resolved)
		}
	}
	if err := iss.GlobalRateLimit.resolve(repl, "global_rate_limit"); err != nil {
		return err
	}
	if err := iss.PerDomainRateLimit.resolve(repl, "per_domain_rate_limit"); err != nil {
		return err
	}
	if err := iss.GlobalRateLimit.validate("global_rate_limit"); err != nil {
		return err
	}
	if err := iss.PerDomainRateLimit.validate("per_domain_rate_limit"); err != nil {
		return err
	}
	if iss.MaxCertsPerDomain > 0 && iss.Name == "" {
		return fmt.Errorf("name is required when max_certs_per_domain is set")
	}

	iss.rateLimiter = &rateLimitState{
		globalLimit:    iss.GlobalRateLimit,
		perDomainLimit: iss.PerDomainRateLimit,
		domains:        make(map[string]*slidingWindow),
		now:            time.Now,
	}
	iss.approvals = &approvalState{
		atCapacityIssuer: make(map[string]time.Time),
		atCapacityGlobal: make(map[string]time.Time),
		now:              time.Now,
	}

	if iss.IssuerRaw != nil {
		val, err := ctx.LoadModule(iss, "IssuerRaw")
		if err != nil {
			return fmt.Errorf("loading inner issuer module: %v", err)
		}
		iss.issuer = val.(certmagic.Issuer)
	}
	if iss.issuer == nil {
		return fmt.Errorf("inner issuer is required")
	}

	return nil
}

// SetConfig implements caddytls.ConfigSetter. It obtains certmagic storage
// and propagates the config to the inner issuer.
func (iss *RateLimitIssuer) SetConfig(cfg *certmagic.Config) {
	iss.storage = cfg.Storage
	if cs, ok := iss.issuer.(caddytls.ConfigSetter); ok {
		cs.SetConfig(cfg)
	}
}

// PreCheck implements certmagic.PreChecker. It performs fast in-memory limit
// checks to reject requests early — before the inner issuer sets up challenge
// infrastructure — then delegates to the inner issuer's PreCheck if present.
func (iss *RateLimitIssuer) PreCheck(ctx context.Context, names []string, interactive bool) error {
	if err := iss.checkInMemoryLimits(names); err != nil {
		return err
	}
	if pc, ok := iss.issuer.(certmagic.PreChecker); ok {
		return pc.PreCheck(ctx, names, interactive)
	}
	return nil
}

// Issue obtains a certificate via the inner issuer. Authoritative storage-
// backed limit checks run before the inner issuer is called so that a
// rejected request never triggers certificate issuance. Counters are recorded
// only on successful issuance; a failed issuance does not consume a slot.
func (iss *RateLimitIssuer) Issue(ctx context.Context, csr *x509.CertificateRequest) (*certmagic.IssuedCertificate, error) {
	if err := iss.checkStorageLimits(ctx, csr.DNSNames); err != nil {
		return nil, err
	}
	cert, err := iss.issuer.Issue(ctx, csr)
	if err != nil {
		return nil, err
	}
	iss.recordIssuance(ctx, csr.DNSNames)
	return cert, nil
}

// IssuerKey delegates to the inner issuer's key for certificate storage namespacing.
func (iss *RateLimitIssuer) IssuerKey() string {
	return iss.issuer.IssuerKey()
}

// checkInMemoryLimits performs fast, non-storage limit checks suitable for
// early rejection in PreCheck. Only in-memory rate limit counters and the
// at-capacity domain caches are consulted; no storage reads are performed.
func (iss *RateLimitIssuer) checkInMemoryLimits(names []string) error {
	if iss.GlobalRateLimit != nil {
		if err := iss.rateLimiter.checkGlobal(); err != nil {
			return err
		}
	}
	for _, ds := range iss.uniqueSubjects(names) {
		if iss.PerDomainRateLimit != nil {
			if err := iss.rateLimiter.checkDomain(ds.domain); err != nil {
				return err
			}
		}
		if iss.MaxCertsPerDomain > 0 && iss.approvals.isCached(ds.domain, iss.approvals.atCapacityIssuer) {
			return fmt.Errorf("certificate limit reached for %s", ds.domain)
		}
		if iss.GlobalMaxCertsPerDomain > 0 && iss.approvals.isCached(ds.domain, iss.approvals.atCapacityGlobal) {
			return fmt.Errorf("global certificate limit reached for %s", ds.domain)
		}
	}
	return nil
}

// checkStorageLimits performs authoritative storage-backed limit checks for
// both per-instance and global certificate caps. Checks are read-only; subjects
// are recorded in recordIssuance after successful issuance.
func (iss *RateLimitIssuer) checkStorageLimits(ctx context.Context, names []string) error {
	if iss.storage == nil {
		return nil
	}
	for _, ds := range iss.uniqueSubjects(names) {
		if iss.MaxCertsPerDomain > 0 {
			if err := iss.checkCertCount(ctx, iss.certCountKey(ds.domain), ds.domain, ds.subject, iss.MaxCertsPerDomain, iss.approvals.atCapacityIssuer); err != nil {
				return err
			}
		}
		if iss.GlobalMaxCertsPerDomain > 0 {
			if err := iss.checkCertCount(ctx, iss.globalCertCountKey(ds.domain), ds.domain, ds.subject, iss.GlobalMaxCertsPerDomain, iss.approvals.atCapacityGlobal); err != nil {
				return err
			}
		}
	}
	return nil
}

// checkCertCount reads the cert count at storageKey and returns an error if
// adding subject would exceed limit. It populates the given at-capacity cache
// map when the domain reaches its cap.
func (iss *RateLimitIssuer) checkCertCount(ctx context.Context, storageKey, domain, subject string, limit int, atCapacity map[string]time.Time) error {
	if err := iss.storage.Lock(ctx, storageKey); err != nil {
		return fmt.Errorf("locking cert count for %s: %w", domain, err)
	}
	unlockCtx := context.WithoutCancel(ctx)
	defer func() {
		if err := iss.storage.Unlock(unlockCtx, storageKey); err != nil {
			iss.logger.Error("unlocking cert count", zap.String("domain", domain), zap.Error(err))
		}
	}()

	counts, err := iss.loadCertCount(ctx, storageKey)
	if err != nil {
		return err
	}
	if _, ok := counts[subject]; ok {
		// Subject already counted — this issuance will be a no-op or renewal.
		return nil
	}
	if len(counts) >= limit {
		iss.approvals.cache(domain, atCapacity)
		return fmt.Errorf("certificate limit of %d reached for %s", limit, domain)
	}
	return nil
}

// recordIssuance records a successful certificate issuance in all counters.
// Errors from storage operations are logged but do not fail the issuance.
func (iss *RateLimitIssuer) recordIssuance(ctx context.Context, names []string) {
	if iss.GlobalRateLimit != nil {
		iss.rateLimiter.recordGlobal()
	}
	for _, ds := range iss.uniqueSubjects(names) {
		if iss.PerDomainRateLimit != nil {
			iss.rateLimiter.recordDomain(ds.domain)
		}
		if iss.storage != nil {
			if iss.MaxCertsPerDomain > 0 {
				if err := iss.recordCertCount(ctx, iss.certCountKey(ds.domain), ds.domain, ds.subject, iss.MaxCertsPerDomain, iss.approvals.atCapacityIssuer); err != nil {
					iss.logger.Error("recording per-issuer cert count after issuance",
						zap.String("domain", ds.domain),
						zap.String("subject", ds.subject),
						zap.Error(err))
				}
			}
			if iss.GlobalMaxCertsPerDomain > 0 {
				if err := iss.recordCertCount(ctx, iss.globalCertCountKey(ds.domain), ds.domain, ds.subject, iss.GlobalMaxCertsPerDomain, iss.approvals.atCapacityGlobal); err != nil {
					iss.logger.Error("recording global cert count after issuance",
						zap.String("domain", ds.domain),
						zap.String("subject", ds.subject),
						zap.Error(err))
				}
			}
		}
	}
}

// domainSubject pairs a registrable domain with its certificate subject key.
type domainSubject struct {
	domain  string
	subject string
}

// uniqueSubjects extracts unique (domain, subject) pairs from names, one per
// registrable domain. Names that cannot be parsed are skipped with a warning.
func (iss *RateLimitIssuer) uniqueSubjects(names []string) []domainSubject {
	seen := make(map[string]struct{}, len(names))
	result := make([]domainSubject, 0, len(names))
	for _, name := range names {
		domain, subject, err := certSubject(name)
		if err != nil {
			iss.logger.Warn("skipping unparseable certificate name",
				zap.String("name", name),
				zap.Error(err))
			continue
		}
		if _, ok := seen[domain]; ok {
			continue
		}
		seen[domain] = struct{}{}
		result = append(result, domainSubject{domain: domain, subject: subject})
	}
	return result
}

// recordCertCount adds subject to the persisted cert count at storageKey.
func (iss *RateLimitIssuer) recordCertCount(ctx context.Context, storageKey, domain, subject string, limit int, atCapacity map[string]time.Time) error {
	if err := iss.storage.Lock(ctx, storageKey); err != nil {
		return fmt.Errorf("locking cert count for %s: %w", domain, err)
	}
	unlockCtx := context.WithoutCancel(ctx)
	defer func() {
		if err := iss.storage.Unlock(unlockCtx, storageKey); err != nil {
			iss.logger.Error("unlocking cert count", zap.String("domain", domain), zap.Error(err))
		}
	}()

	counts, err := iss.loadCertCount(ctx, storageKey)
	if err != nil {
		return err
	}
	if _, ok := counts[subject]; ok {
		return nil // already recorded
	}
	counts[subject] = struct{}{}
	if err := iss.storeCertCount(ctx, storageKey, counts); err != nil {
		return err
	}
	if len(counts) >= limit {
		iss.approvals.cache(domain, atCapacity)
	}
	return nil
}

// loadCertCount reads the persisted cert count set from storageKey.
func (iss *RateLimitIssuer) loadCertCount(ctx context.Context, storageKey string) (map[string]struct{}, error) {
	data, err := iss.storage.Load(ctx, storageKey)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return make(map[string]struct{}), nil
		}
		return nil, fmt.Errorf("loading cert count from %s: %w", storageKey, err)
	}
	var stored storedCertCount
	if err := json.Unmarshal(data, &stored); err != nil {
		return nil, fmt.Errorf("decoding cert count from %s: %w", storageKey, err)
	}
	counts := make(map[string]struct{}, len(stored.Subjects))
	for _, s := range stored.Subjects {
		counts[s] = struct{}{}
	}
	return counts, nil
}

// storeCertCount persists the cert count set to storageKey.
func (iss *RateLimitIssuer) storeCertCount(ctx context.Context, storageKey string, counts map[string]struct{}) error {
	subjects := make([]string, 0, len(counts))
	for s := range counts {
		subjects = append(subjects, s)
	}
	slices.Sort(subjects)
	data, err := json.Marshal(storedCertCount{Subjects: subjects})
	if err != nil {
		return fmt.Errorf("encoding cert count for %s: %w", storageKey, err)
	}
	if err := iss.storage.Store(ctx, storageKey, data); err != nil {
		return fmt.Errorf("storing cert count to %s: %w", storageKey, err)
	}
	return nil
}

// isCached returns true if domain is known to be at capacity in the given map.
// Expired entries are evicted lazily.
func (a *approvalState) isCached(domain string, m map[string]time.Time) bool {
	now := a.now()
	a.mu.Lock()
	defer a.mu.Unlock()
	expiresAt, ok := m[domain]
	if !ok {
		return false
	}
	if now.After(expiresAt) {
		delete(m, domain)
		return false
	}
	return true
}

// cache marks domain as at-capacity in the given map.
func (a *approvalState) cache(domain string, m map[string]time.Time) {
	a.mu.Lock()
	defer a.mu.Unlock()
	m[domain] = a.now().Add(atCapacityCacheTTL)
}

// certSubject extracts the registrable domain (eTLD+1) and the subject key
// used for cert counting from a certificate name.
//
// The subject key is the name itself, which correctly deduplicates certificates:
// all requests for *.example.com share the subject "*.example.com", while
// www.example.com and api.example.com each have their own subject key.
func certSubject(name string) (domain, subject string, err error) {
	lookup := strings.TrimPrefix(name, "*.")
	domain, err = publicsuffix.EffectiveTLDPlusOne(lookup)
	if err != nil {
		return "", "", fmt.Errorf("determining registrable domain for %q: %w", name, err)
	}
	return domain, name, nil
}

// certCountKey returns the per-instance storage key for the cert count of a
// registrable domain, namespaced under the instance Name.
func (iss *RateLimitIssuer) certCountKey(domain string) string {
	return path.Join(storageKeyPrefix, iss.Name, "counts", domain+".json")
}

// globalCertCountKey returns the global storage key for the cert count of a
// registrable domain, shared across all inner issuers.
func (iss *RateLimitIssuer) globalCertCountKey(domain string) string {
	return path.Join(storageKeyPrefix, "counts", domain+".json")
}

// Interface guards
var (
	_ caddy.Module          = (*RateLimitIssuer)(nil)
	_ caddy.Provisioner     = (*RateLimitIssuer)(nil)
	_ certmagic.Issuer      = (*RateLimitIssuer)(nil)
	_ certmagic.PreChecker  = (*RateLimitIssuer)(nil)
	_ caddytls.ConfigSetter = (*RateLimitIssuer)(nil)
)
