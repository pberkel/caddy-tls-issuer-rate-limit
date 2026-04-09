# caddy-issuer-rate-limit

A [Caddy](https://caddyserver.com) TLS issuer module (`tls.issuance.rate_limit`) that wraps any inner issuer and enforces configurable certificate issuance rate limits.

> **Experimental:** The configuration interface may change before a stable release.

## Why this module exists

Caddy's on-demand TLS permission module runs before `SubjectTransformer` is applied, meaning it operates on raw hostnames from the TLS handshake rather than actual certificate subjects. For deployments that use wildcard subject transformation (e.g. via [`caddy-issuer-opportunistic`](https://github.com/pberkel/caddy-issuer-opportunistic)), this causes over-counting: `www.example.com` and `api.example.com` each consume a slot even though both result in a single `*.example.com` certificate.

This module enforces limits at issuance time — after `SubjectTransformer` has run — so counts always reflect actual certificates issued. Hostnames that map to the same wildcard certificate share a single slot rather than each consuming one.

## How it works

The module wraps an inner issuer and intercepts the issuance lifecycle at two points:

1. **`PreCheck`** — checks whether the request is a renewal (certificate already present in storage) or a new issuance. Renewals bypass all rate limit checks and are never blocked. For new issuances, fast in-memory checks reject requests before the inner issuer sets up challenge infrastructure. Rate limit errors are wrapped in `certmagic.ErrNoRetry` so the TLS handshake fails immediately rather than blocking in certmagic's obtain loop.
2. **`Issue`** — delegates to the inner issuer. Counters are recorded **only on successful new issuances**; renewals and failed issuances do not consume a slot.

Other certmagic interfaces are delegated to the inner issuer transparently:

- **ARI** (`GetRenewalInfo`) — ACME Renewal Information (RFC 8739) is forwarded if the inner issuer supports it.
- **Revocation** (`Revoke`) — certificate revocation is forwarded if the inner issuer supports it.

## Installation

Build Caddy with this module using [`xcaddy`](https://github.com/caddyserver/xcaddy):

```sh
xcaddy build \
  --with github.com/pberkel/caddy-issuer-rate-limit
```

## Configuration

### Caddyfile

```caddyfile
{
    on_demand_tls {
        permission http {
            endpoint https://auth.example.internal/check
        }
    }
}

:443 {
    tls {
        on_demand
        issuer rate_limit {
            issuer acme {
                dir https://acme-v02.api.letsencrypt.org/directory
            }
            local {                         # local to this instance
                rate_limit             30 10m
                rate_limit            300 24h
                per_domain_rate_limit   5 6h
                per_domain_rate_limit  20 24h
            }
            shared global {                 # shared across all instances
                rate_limit            500 24h
                per_domain_rate_limit  50 24h
            }
        }
    }
    reverse_proxy localhost:8080
}
```

#### Syntax

```
issuer rate_limit {
    issuer <module> { ... }
    local [<name>] {
        rate_limit <limit> <duration>
        per_domain_rate_limit <limit> <duration>
    }
    shared <name> {
        rate_limit <limit> <duration>
        per_domain_rate_limit <limit> <duration>
    }
}
```

#### Subdirectives

| Subdirective | Required | Description |
|---|---|---|
| `issuer <module> { ... }` | Yes | Inner issuer to delegate certificate issuance to. Any `tls.issuance` module is accepted. |
| `local [<name>] { ... }` | No | Local rate limits scoped to this instance. The optional `<name>` is a stable identifier used as the key in the admin registry (see [Admin API](#admin-api)); if omitted, a UUID is generated at provision time. May appear at most once. |
| `shared <name> { ... }` | No | Named shared pool. Rate limit state is shared across all `rate_limit` instances referencing the same name and persisted across restarts. May be repeated for multiple pools. See [Shared pools](#shared-pools) below. |

#### `local` block subdirectives

| Subdirective | Description |
|---|---|
| `rate_limit <limit> <duration>` | Maximum new certificates across all domains within a rolling time window (e.g. `100 1h`). May be repeated for tiered limits; all windows must have capacity. |
| `per_domain_rate_limit <limit> <duration>` | Maximum new certificates per registrable domain within a rolling time window (e.g. `5 6h`). May be repeated for tiered limits. |

#### `shared` block subdirectives

| Subdirective | Description |
|---|---|
| `rate_limit <limit> <duration>` | Maximum new certificates across all domains within a rolling window for this pool. May be repeated for tiered limits. |
| `per_domain_rate_limit <limit> <duration>` | Maximum new certificates per registrable domain within a rolling window for this pool. May be repeated for tiered limits. |

### JSON

```json
{
  "apps": {
    "tls": {
      "automation": {
        "on_demand": {
          "permission": {
            "module": "http",
            "endpoint": "https://auth.example.internal/check"
          }
        },
        "policies": [
          {
            "on_demand": true,
            "issuers": [
              {
                "module": "rate_limit",
                "instance_id": "primary",
                "issuer": {
                  "module": "acme",
                  "ca": "https://acme-v02.api.letsencrypt.org/directory"
                },
                "rate_limit": [
                  { "limit": 30,  "duration": 600000000000 },
                  { "limit": 300, "duration": 86400000000000 }
                ],
                "per_domain_rate_limit": [
                  { "limit": 5,  "duration": 21600000000000 },
                  { "limit": 20, "duration": 86400000000000 }
                ],
                "shared_pools": [
                  {
                    "name": "global",
                    "rate_limit": [
                      { "limit": 500, "duration": 86400000000000 }
                    ],
                    "per_domain_rate_limit": [
                      { "limit": 50, "duration": 86400000000000 }
                    ]
                  }
                ]
              }
            ]
          }
        ]
      }
    }
  }
}
```

Duration values are in nanoseconds.

## Rate limit behaviour

Rate limits apply only to **new certificate issuances**. Renewals — requests where a certificate for the subject already exists in Caddy's storage — bypass all checks and are never blocked or counted. This ensures that rate limit exhaustion from a burst of new domains cannot prevent existing certificates from renewing.

Rate limits are enforced per registrable domain (eTLD+1). Because limits apply after `SubjectTransformer` has run, hostnames that map to the same wildcard certificate share a single slot:

- `www.example.com` and `api.example.com` both transforming to `*.example.com` count as one issuance against the `example.com` per-domain limit.
- `www.example.com` and `api.example.com` issued without transformation each count independently under `example.com`.

### Tiered limits

Both `rate_limit` and `per_domain_rate_limit` may be specified multiple times. Each entry defines an independent sliding window — an issuance must fit within **all** configured windows to proceed. This enables tiered constraints such as "no more than 5 per domain per 6 hours, and no more than 20 per domain per day".

### Memory management

Per-domain sliding windows are held in memory for the duration of their configured window. A background goroutine runs hourly to evict entries whose windows have fully expired, keeping memory usage proportional to the number of domains with recent issuance activity.

## Shared pools

Named shared pools (`shared <name> { ... }`) allow multiple `rate_limit` instances within the same Caddy process to enforce a common rate limit. All instances referencing the same pool name share in-memory sliding windows — an issuance recorded by one instance is visible to all others.

Use the conventional name `global` to create a process-wide limit that all instances participate in:

```caddyfile
shared global {
    rate_limit            500 24h
    per_domain_rate_limit  50 24h
}
```

**Multiple instances:** an issuance must satisfy **all** configured limits — local and shared — to proceed.

**Limit changes:** if a pool's limits are changed across a config reload, the in-memory state is reset and a warning is logged.

**Persistence:** shared pool state is saved to Caddy's configured storage backend on shutdown and config reload, and restored on startup. State is also saved periodically every 5 minutes, bounding the data lost on an unclean exit (OOM kill, SIGKILL). Storage key: `tls_issuer_rate_limit/pools/<name>.json`. Expired timestamps are pruned before saving.

## Admin API

This module registers an admin API handler (`admin.api.rate_limit_issuer`) that exposes rate limit state for all local instances and shared pools in the process.

### Routes

| Method | Path | Description |
|---|---|---|
| `GET` | `/rate_limit_issuer/` | Self-contained web interface |
| `GET` | `/rate_limit_issuer/pools` | JSON status of all instances and pools |
| `DELETE` | `/rate_limit_issuer/pools/<name>/total` | Reset total (cross-domain) windows |
| `DELETE` | `/rate_limit_issuer/pools/<name>/domains/<domain>` | Reset per-domain windows for one domain |
| `DELETE` | `/rate_limit_issuer/pools/<name>` | Reset all windows (total and per-domain) |

The `<name>` for a local instance is the name given in the `local` block (or `instance_id` in JSON config), or the auto-generated UUID if none was set.

### Accessing the admin UI via a site block

Caddy's admin API listens on `localhost:2019` by default and is not directly exposed. To proxy it through a site block with authentication:

```caddyfile
{
    admin localhost:2019 {
        origins admin.example.com
    }
}

admin.example.com {
    handle_path /admin/* {
        basic_auth {
            alice $2a$14$...
        }
        reverse_proxy localhost:2019 {
            header_up Host admin.example.com
        }
    }
}
```

`handle_path` strips the `/admin` prefix before proxying, so `/admin/rate_limit_issuer/` is forwarded as `/rate_limit_issuer/`. The `origins` directive allows the admin API to accept requests with that `Host` header.

## Recommended usage with caddy-tls-permission-policy

For on-demand TLS deployments, use [`caddy-tls-permission-policy`](https://github.com/pberkel/caddy-tls-permission-policy) for admission control (DNS resolution checks, IP filtering, hostname pattern matching) and this module for issuance rate limiting:

```caddyfile
{
    on_demand_tls {
        permission policy {
            resolves_to your-server.example.com
            max_subdomain_depth 3
        }
    }
}

:443 {
    tls {
        on_demand
        issuer rate_limit {
            issuer acme {
                dir https://acme-v02.api.letsencrypt.org/directory
            }
            local {
                rate_limit             30 10m
                rate_limit            300 24h
                per_domain_rate_limit   5 6h
                per_domain_rate_limit  20 24h
            }
            shared global {
                rate_limit            500 24h
                per_domain_rate_limit  50 24h
            }
        }
    }
}
```

This separation of concerns keeps admission (is this hostname allowed?) distinct from lifecycle (how many certificates have been issued?).

## License

Apache 2.0 — see [LICENSE](LICENSE).
