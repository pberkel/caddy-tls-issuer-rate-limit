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
// configurable certificate issuance rate limits.
//
// Because limits are enforced after certmagic's SubjectTransformer has run,
// they apply to the effective certificate subject rather than the raw hostname
// from the TLS handshake. This means hostnames that share a wildcard cert
// (e.g. www.example.com and api.example.com both mapping to *.example.com)
// correctly count as one issuance rather than two.
package ratelimitissuer

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/caddyserver/certmagic"
	"github.com/mholt/acmez/v3/acme"
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
// limits.
//
// Limits are enforced at issuance time, after certmagic's SubjectTransformer
// has run, so counts apply to the effective certificate subject — not the raw
// hostname from the TLS handshake. This makes RateLimitIssuer correct when
// used with tls.issuance.opportunistic, where multiple hostnames may map to
// the same wildcard certificate.
//
// # Local limits
//
// RateLimit and PerDomainRateLimit are local to this instance — each
// RateLimitIssuer maintains independent in-memory windows.
//
// # Shared pools
//
// SharedPools allows multiple RateLimitIssuer instances within the same Caddy
// process to share rate limit state. Instances referencing the same pool name
// share in-memory sliding windows. Shared pool state is persisted to Caddy's
// configured storage backend and restored on startup.
type RateLimitIssuer struct {
	// The inner issuer to delegate certificate issuance to.
	// Any tls.issuance module is accepted. Required.
	IssuerRaw json.RawMessage `json:"issuer,omitempty" caddy:"namespace=tls.issuance inline_key=module"`

	// Local issuance rate limits across all domains, scoped to this instance.
	// Each entry enforces an independent sliding window; all windows must have
	// capacity for issuance to proceed. Multiple entries allow tiered limits
	// (e.g. 100/hour and 500/day simultaneously).
	RateLimit []*RateLimit `json:"rate_limit,omitempty"`

	// Local per registrable domain issuance rate limits, scoped to this
	// instance. Each entry enforces an independent sliding window per domain;
	// all windows must have capacity. Multiple entries allow tiered limits.
	PerDomainRateLimit []*RateLimit `json:"per_domain_rate_limit,omitempty"`

	// Named shared pools whose rate limit state is shared across all
	// RateLimitIssuer instances referencing the same pool name. State is
	// persisted across restarts.
	SharedPools []*SharedPool `json:"shared_pools,omitempty"`

	// Optional stable identifier for this instance, used as the key in the
	// admin registry. If omitted, a UUID is generated at provision time.
	// Useful for distinguishing multiple local instances in the admin UI.
	InstanceID string `json:"instance_id,omitempty"`

	issuer         certmagic.Issuer
	logger         *zap.Logger
	rateLimiter    *rateLimitState           // local limiter
	sharedLimiters map[string]*registryEntry // keyed by pool name
	storage        certmagic.Storage         // for shared pool persistence
	instanceID     string                    // admin registry key, set at Provision
}

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

	// Validate local rate limit configs.
	for _, rl := range iss.RateLimit {
		if err := rl.validate(); err != nil {
			return fmt.Errorf("rate_limit: %w", err)
		}
	}
	for _, rl := range iss.PerDomainRateLimit {
		if err := rl.validate(); err != nil {
			return fmt.Errorf("per_domain_rate_limit: %w", err)
		}
	}

	// Initialise local in-memory sliding windows (one per configured limit).
	totalWindows := make([]*slidingWindow, len(iss.RateLimit))
	for i := range totalWindows {
		totalWindows[i] = &slidingWindow{}
	}
	iss.rateLimiter = &rateLimitState{
		totalLimits:     iss.RateLimit,
		perDomainLimits: iss.PerDomainRateLimit,
		totals:          totalWindows,
		domains:         make(map[string][]*slidingWindow),
		now:             time.Now,
	}

	// Start background eviction of expired per-domain entries.
	if len(iss.PerDomainRateLimit) > 0 {
		iss.rateLimiter.startEviction(time.Hour)
	}

	// Validate shared pool configs and obtain (or create) their registry entries.
	seen := make(map[string]struct{}, len(iss.SharedPools))
	iss.sharedLimiters = make(map[string]*registryEntry, len(iss.SharedPools))
	for _, sp := range iss.SharedPools {
		if err := sp.validate(); err != nil {
			return err
		}
		if _, dup := seen[sp.Name]; dup {
			return fmt.Errorf("duplicate shared pool name %q", sp.Name)
		}
		seen[sp.Name] = struct{}{}
		iss.sharedLimiters[sp.Name] = getOrRegisterPool(sp, iss.logger)
	}

	// Load and wire up the inner issuer module.
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

	// Register local limiter in the admin registry so the admin handler can
	// expose it alongside shared pools. Use the configured InstanceID if
	// provided, otherwise generate a UUID.
	if len(iss.RateLimit) > 0 || len(iss.PerDomainRateLimit) > 0 {
		entry := &registryEntry{
			state: iss.rateLimiter,
			local: true,
		}
		if iss.InstanceID != "" {
			if _, loaded := processRegistry.LoadOrStore(iss.InstanceID, entry); loaded {
				return fmt.Errorf("instance_id %q is already in use by another rate_limit instance", iss.InstanceID)
			}
			iss.instanceID = iss.InstanceID
		} else {
			for {
				id := newUUID()
				if _, loaded := processRegistry.LoadOrStore(id, entry); !loaded {
					iss.instanceID = id
					break
				}
			}
		}
	}

	poolNames := make([]string, 0, len(iss.SharedPools))
	for _, sp := range iss.SharedPools {
		poolNames = append(poolNames, sp.Name)
	}
	iss.logger.Info("rate_limit issuer ready",
		zap.Int("rate_limits", len(iss.RateLimit)),
		zap.Int("per_domain_rate_limits", len(iss.PerDomainRateLimit)),
		zap.Strings("shared_pools", poolNames),
	)

	return nil
}

// SetConfig implements caddytls.ConfigSetter. It propagates the certmagic
// config to the inner issuer and, on first call with a non-nil storage backend,
// loads persisted state for any configured shared pools and starts a background
// goroutine to periodically save state.
func (iss *RateLimitIssuer) SetConfig(cfg *certmagic.Config) {
	if cs, ok := iss.issuer.(caddytls.ConfigSetter); ok {
		cs.SetConfig(cfg)
	}
	if cfg.Storage == nil || len(iss.sharedLimiters) == 0 {
		return
	}
	iss.storage = cfg.Storage
	ctx := context.Background()
	for _, entry := range iss.sharedLimiters {
		entry.mu.Lock()
		if !entry.loaded {
			if !entry.pool.Ephemeral {
				loadAndApplyPoolState(ctx, cfg.Storage, entry, iss.logger)
			}
			entry.loaded = true
		}
		if !entry.saving {
			entry.startBackground(cfg.Storage, iss.logger)
			entry.saving = true
		}
		entry.mu.Unlock()
	}
}

// Cleanup implements caddy.CleanerUpper. It removes the local limiter entry
// from processRegistry and persists shared pool state to storage. Errors are
// logged but do not prevent cleanup.
func (iss *RateLimitIssuer) Cleanup() error {
	if iss.rateLimiter.stopEviction != nil {
		iss.rateLimiter.stopEviction()
	}
	if iss.instanceID != "" {
		processRegistry.Delete(iss.instanceID)
	}
	if iss.storage == nil || len(iss.sharedLimiters) == 0 {
		return nil
	}
	ctx := context.Background()
	for _, entry := range iss.sharedLimiters {
		if !entry.pool.Ephemeral {
			savePoolState(ctx, iss.storage, entry, iss.logger)
		}
	}
	return nil
}

// PreCheck implements certmagic.PreChecker. It performs fast in-memory rate
// limit checks to reject requests early — before the inner issuer sets up
// challenge infrastructure — then delegates to the inner issuer's PreCheck if
// present.
//
// Renewals (certificates already present in storage) bypass rate limit checks
// entirely and are never blocked or counted.
//
// Rate limit errors are wrapped in certmagic.ErrNoRetry so that the TLS
// handshake fails immediately rather than blocking in certmagic's obtain loop.
func (iss *RateLimitIssuer) PreCheck(ctx context.Context, names []string, interactive bool) error {
	if !iss.isRenewal(ctx, names) {
		if err := iss.checkRateLimits(names); err != nil {
			return certmagic.ErrNoRetry{Err: err}
		}
	}
	if pc, ok := iss.issuer.(certmagic.PreChecker); ok {
		return pc.PreCheck(ctx, names, interactive)
	}
	return nil
}

// Issue obtains a certificate via the inner issuer. Rate limit counters are
// recorded only on successful new issuances; renewals and failed issuances do
// not consume a slot.
func (iss *RateLimitIssuer) Issue(ctx context.Context, csr *x509.CertificateRequest) (*certmagic.IssuedCertificate, error) {
	renewal := iss.isRenewal(ctx, csr.DNSNames)
	cert, err := iss.issuer.Issue(ctx, csr)
	if err != nil {
		return nil, err
	}
	if !renewal {
		iss.recordIssuance(csr.DNSNames)
	}
	return cert, nil
}

// isRenewal reports whether a certificate already exists in storage for any of
// the given names under this issuer, indicating that the upcoming issuance is a
// renewal rather than a first-time request. When storage is unavailable the
// result is false — the conservative default is to treat unknown state as new.
func (iss *RateLimitIssuer) isRenewal(ctx context.Context, names []string) bool {
	if iss.storage == nil {
		return false
	}
	issuerKey := iss.issuer.IssuerKey()
	for _, name := range names {
		if iss.storage.Exists(ctx, certmagic.StorageKeys.SiteCert(issuerKey, name)) {
			return true
		}
	}
	return false
}

// IssuerKey delegates to the inner issuer's key for certificate storage namespacing.
func (iss *RateLimitIssuer) IssuerKey() string {
	return iss.issuer.IssuerKey()
}

// ErrNotSupported is returned by GetRenewalInfo and Revoke when the inner
// issuer does not implement the corresponding optional interface.
var ErrNotSupported = fmt.Errorf("operation not supported by inner issuer")

// GetRenewalInfo delegates to the inner issuer if it implements
// certmagic.RenewalInfoGetter (ARI, RFC 8739). Returns ErrNotSupported
// otherwise.
//
// Note: because RateLimitIssuer has this method, certmagic will always
// type-assert it as a RenewalInfoGetter and call through. If the inner issuer
// does not support ARI, certmagic will log the returned ErrNotSupported at
// ERROR level and continue — this is certmagic's standard handling for ARI
// errors and does not affect certificate renewal.
func (iss *RateLimitIssuer) GetRenewalInfo(ctx context.Context, cert certmagic.Certificate) (acme.RenewalInfo, error) {
	if rig, ok := iss.issuer.(certmagic.RenewalInfoGetter); ok {
		return rig.GetRenewalInfo(ctx, cert)
	}
	return acme.RenewalInfo{}, ErrNotSupported
}

// Revoke delegates to the inner issuer if it implements certmagic.Revoker.
// Returns ErrNotSupported otherwise.
func (iss *RateLimitIssuer) Revoke(ctx context.Context, cert certmagic.CertificateResource, reason int) error {
	if r, ok := iss.issuer.(certmagic.Revoker); ok {
		return r.Revoke(ctx, cert, reason)
	}
	return ErrNotSupported
}

// checkRateLimits checks all rate limit windows — local and shared.
func (iss *RateLimitIssuer) checkRateLimits(names []string) error {
	if err := iss.checkLimiter(iss.rateLimiter, names); err != nil {
		return err
	}
	for _, entry := range iss.sharedLimiters {
		if err := iss.checkLimiter(entry.state, names); err != nil {
			return err
		}
	}
	return nil
}

// checkLimiter checks all windows in a single rateLimitState.
func (iss *RateLimitIssuer) checkLimiter(s *rateLimitState, names []string) error {
	if len(s.totalLimits) > 0 {
		if err := s.checkTotal(); err != nil {
			return err
		}
	}
	if len(s.perDomainLimits) > 0 {
		for _, domain := range iss.uniqueDomains(names) {
			if err := s.checkDomain(domain); err != nil {
				return err
			}
		}
	}
	return nil
}

// recordIssuance records a successful certificate issuance in all rate limit
// counters — local and shared.
func (iss *RateLimitIssuer) recordIssuance(names []string) {
	iss.recordLimiter(iss.rateLimiter, names)
	for _, entry := range iss.sharedLimiters {
		iss.recordLimiter(entry.state, names)
	}
}

// recordLimiter records an issuance in a single rateLimitState.
func (iss *RateLimitIssuer) recordLimiter(s *rateLimitState, names []string) {
	if len(s.totalLimits) > 0 {
		s.recordTotal()
	}
	if len(s.perDomainLimits) > 0 {
		for _, domain := range iss.uniqueDomains(names) {
			s.recordDomain(domain)
		}
	}
}

// uniqueDomains extracts unique registrable domains (eTLD+1) from names.
// Names that cannot be parsed are skipped with a warning.
func (iss *RateLimitIssuer) uniqueDomains(names []string) []string {
	seen := make(map[string]struct{}, len(names))
	result := make([]string, 0, len(names))
	for _, name := range names {
		domain, err := certDomain(name)
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
		result = append(result, domain)
	}
	return result
}

// certDomain returns the registrable domain (eTLD+1) for a certificate name.
func certDomain(name string) (string, error) {
	lookup := strings.TrimPrefix(name, "*.")
	domain, err := publicsuffix.EffectiveTLDPlusOne(lookup)
	if err != nil {
		return "", fmt.Errorf("determining registrable domain for %q: %w", name, err)
	}
	return domain, nil
}

// Interface guards
// Note: certmagic.Revoker and certmagic.RenewalInfoGetter are intentionally
// omitted — these are conditionally delegated to the inner issuer and are not
// unconditionally satisfied by RateLimitIssuer.
var (
	_ caddy.Module          = (*RateLimitIssuer)(nil)
	_ caddy.Provisioner     = (*RateLimitIssuer)(nil)
	_ caddy.CleanerUpper    = (*RateLimitIssuer)(nil)
	_ certmagic.Issuer      = (*RateLimitIssuer)(nil)
	_ certmagic.PreChecker  = (*RateLimitIssuer)(nil)
	_ caddytls.ConfigSetter = (*RateLimitIssuer)(nil)
)
