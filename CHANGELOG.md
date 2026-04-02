# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `tls.issuance.rate_limit` Caddy module wrapping any inner `tls.issuance` issuer
- Global sliding-window rate limit (`global_rate_limit`) capping total certificate issuances across all domains within a rolling time window
- Per-domain sliding-window rate limit (`per_domain_rate_limit`) capping issuances per registrable domain (eTLD+1) within a rolling time window
- Per-instance certificate cap (`max_certs_per_domain`) limiting unique certificates per registrable domain, scoped to a named `rate_limit` instance and persisted to Caddy storage
- Global certificate cap (`global_max_certs_per_domain`) limiting unique certificates per registrable domain across all `rate_limit` instances, persisted to Caddy storage
- Both certificate caps may be configured simultaneously; issuance must satisfy both to proceed
- Exact sliding-window rate limiter using per-timestamp accounting (no approximation)
- In-memory at-capacity cache (2-minute TTL) to avoid repeated storage reads for domains already at their certificate cap
- Distributed-safe storage locking via `certmagic.Storage.Lock`/`Unlock` for certificate count reads and writes
- Counters recorded only on successful issuance; a failed or rejected issuance does not consume a slot
- ARI support (`GetRenewalInfo`) delegating to the inner issuer (RFC 8739).
- Caddyfile support with inline instance name: `issuer rate_limit [<name>] { ... }`
- Caddy placeholder support in all numeric and duration configuration values
- `PreCheck` fast-path rejects requests before the inner issuer sets up challenge infrastructure
- Storage keys namespaced under `tls_issuer_rate_limit/`
