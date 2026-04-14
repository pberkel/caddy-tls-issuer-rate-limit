# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.1] - 2026-04-14

### Added
- `debug` configuration option. When `true`, per-request rate limit evaluation details (renewal bypass, limit check results, and issuance recording) are emitted at info level regardless of the global Caddy log level. When `false` (the default), the same details are only emitted when Caddy's global log level is set to debug.

---

## [1.0.0] - 2026-04-10

### Added

- `tls.issuance.rate_limit` Caddy module wrapping any inner `tls.issuance` issuer
- Sliding-window rate limit (`rate_limit`) capping total certificate issuances across all domains within a rolling time window
- Per-domain sliding-window rate limit (`per_domain_rate_limit`) capping issuances per registrable domain (eTLD+1) within a rolling time window
- Both rate limit types support multiple entries per block for tiered limits; all windows must have capacity for issuance to proceed
- Exact sliding-window rate limiter using per-timestamp accounting (no approximation)
- Counters recorded only on successful issuance; a failed or rejected issuance does not consume a slot
- Renewals (certificate already present in storage) bypass all rate limit checks and are never blocked or counted
- Rate limit errors wrapped in `certmagic.ErrNoRetry` to fail TLS handshakes immediately rather than blocking in certmagic's obtain loop
- `local [<name>] { ... }` block scopes rate limits to a single issuer instance; the optional name is used as a stable identifier in the admin API (defaults to a UUID generated at provision time)
- `shared <name> { ... }` block defines a named pool shared across all `rate_limit` instances referencing the same name within a process; in-memory sliding windows are shared so an issuance recorded by one instance is visible to all others
- Shared pool state is persisted to Caddy's configured storage backend on shutdown and config reload, and restored on startup; state is also saved periodically every 5 minutes to bound data loss on an unclean exit (storage key: `tls_issuer_rate_limit/pools/<name>.json`)
- Persisted pool state is discarded on startup if the stored rate limit configuration differs from the current config, preventing stale timestamps from being applied to windows with different capacities; a warning is logged when this occurs
- `ephemeral` flag on a shared pool disables persistence entirely for that pool; windows reset to zero on every process restart
- Per-domain sliding windows are evicted by a background goroutine running hourly once all timestamps in the window have expired, keeping memory usage proportional to active issuance activity
- `PreCheck` fast-path rejects requests before the inner issuer sets up challenge infrastructure
- ARI support (`GetRenewalInfo`) delegating to the inner issuer (RFC 8739)
- Revocation support (`Revoke`) delegating to the inner issuer
- Admin API handler (`admin.api.rate_limit_tls_issuer`) exposing rate limit state for all local instances and shared pools; routes: `GET /rate_limit_tls_issuer/` (web UI), `GET /rate_limit_tls_issuer/pools` (JSON status), `DELETE /rate_limit_tls_issuer/pools/<name>` (reset all windows), `DELETE /rate_limit_tls_issuer/pools/<name>/total` (reset total windows), `DELETE /rate_limit_tls_issuer/pools/<name>/domains/<domain>` (reset per-domain windows)
- Caddy placeholder support in all numeric and duration configuration values
