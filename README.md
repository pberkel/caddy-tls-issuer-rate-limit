# caddy-issuer-rate-limit

A [Caddy](https://caddyserver.com) TLS issuer module (`tls.issuance.rate_limit`) that wraps any inner issuer and enforces configurable certificate issuance rate limits and per-domain certificate caps.

> **Experimental:** The configuration interface may change before a stable release.

## Why this module exists

Caddy's on-demand TLS permission module runs before `SubjectTransformer` is applied, meaning it operates on raw hostnames from the TLS handshake rather than actual certificate subjects. For deployments that use wildcard subject transformation (e.g. via [`caddy-issuer-opportunistic`](https://github.com/pberkel/caddy-issuer-opportunistic)), this causes over-counting: `www.example.com` and `api.example.com` each consume a slot even though both result in a single `*.example.com` certificate.

This module enforces limits at issuance time — after `SubjectTransformer` has run — so counts always reflect actual certificates issued. Hostnames that map to the same wildcard certificate share a single slot rather than each consuming one.

## How it works

The module wraps an inner issuer and intercepts the issuance lifecycle at two points:

1. **`PreCheck`** — fast in-memory checks (rate limit windows, at-capacity domain cache) reject requests before the inner issuer sets up challenge infrastructure.
2. **`Issue`** — authoritative storage-backed checks run before delegating to the inner issuer. Counters are recorded **only on successful issuance**; a failed issuance does not consume a slot.

Certificate counts are persisted to Caddy's configured storage backend (the same storage used for certificate data), making limits consistent across restarts and, when a distributed storage backend is used, across multiple Caddy instances.

## Installation

Build Caddy with this module using [`xcaddy`](https://github.com/caddyserver/xcaddy):

```sh
xcaddy build \
  --with github.com/pberkel/caddy-issuer-rate-limit
```

To use with the opportunistic issuer:

```sh
xcaddy build \
  --with github.com/pberkel/caddy-issuer-rate-limit \
  --with github.com/pberkel/caddy-issuer-opportunistic \
  --with github.com/caddy-dns/<your-dns-provider>
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
        issuer rate_limit primary {
            issuer opportunistic {
                primary acme {
                    dir https://acme-v02.api.letsencrypt.org/directory
                    dns <provider> {
                        # provider-specific credentials
                    }
                    dns_challenge_override_domain acme.example.net
                }
                fallback acme {
                    dir https://acme-v02.api.letsencrypt.org/directory
                }
            }
            global_max_certs_per_domain 50
            max_certs_per_domain        20
            global_rate_limit           100 1h
            per_domain_rate_limit       5   6h
        }
    }
    reverse_proxy localhost:8080
}
```

#### Syntax

```
issuer rate_limit [<name>] {
    ...
}
```

`<name>` is an optional instance identifier. It is required when `max_certs_per_domain` is set; omit it when only rate limits or `global_max_certs_per_domain` are configured.

#### Subdirectives

| Subdirective | Required | Description |
|---|---|---|
| `issuer <module> { ... }` | Yes | Inner issuer to delegate certificate issuance to. Any `tls.issuance` module is accepted. |
| `max_certs_per_domain <n>` | No | Maximum unique certificates per registrable domain (eTLD+1), scoped to this `rate_limit` instance. Requires `<name>`. Counts are persisted across restarts. |
| `global_max_certs_per_domain <n>` | No | Maximum unique certificates per registrable domain (eTLD+1), counted globally across all `rate_limit` instances. Counts are persisted across restarts. |
| `global_rate_limit <limit> <duration>` | No | Maximum new certificates across all domains within a rolling time window (e.g. `100 1h`). |
| `per_domain_rate_limit <limit> <duration>` | No | Maximum new certificates per registrable domain within a rolling time window (e.g. `5 6h`). |

Both `max_certs_per_domain` and `global_max_certs_per_domain` may be configured simultaneously; an issuance must satisfy both caps to proceed.

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
                "name": "primary",
                "issuer": {
                  "module": "opportunistic",
                  "primary": {
                    "module": "acme",
                    "ca": "https://acme-v02.api.letsencrypt.org/directory",
                    "challenges": {
                      "dns": {
                        "provider": { "name": "<provider>" },
                        "override_domain": "acme.example.net"
                      }
                    }
                  },
                  "fallback": {
                    "module": "acme",
                    "ca": "https://acme-v02.api.letsencrypt.org/directory"
                  }
                },
                "max_certs_per_domain": 20,
                "global_max_certs_per_domain": 50,
                "global_rate_limit": {
                  "limit": 100,
                  "duration": 3600000000000
                },
                "per_domain_rate_limit": {
                  "limit": 5,
                  "duration": 21600000000000
                }
              }
            ]
          }
        ]
      }
    }
  }
}
```

## Counting behaviour

Certificate subjects are counted per registrable domain (eTLD+1). The subject key used for deduplication is the certificate name as presented to the issuer — after any subject transformation. This has two important consequences:

- **Wildcard certificates:** `www.example.com` and `api.example.com` both transform to `*.example.com` before reaching this module. Both consume the same `*.example.com` slot — one certificate, one count.
- **Specific certificates:** `www.example.com` and `api.example.com` issued without transformation each consume their own slot under `example.com`.

| Certificate subject | Registrable domain | Slot key |
|---|---|---|
| `*.example.com` | `example.com` | `*.example.com` |
| `www.example.com` | `example.com` | `www.example.com` |
| `api.v2.example.com` | `example.com` | `api.v2.example.com` |
| `*.example.co.uk` | `example.co.uk` | `*.example.co.uk` |

### Certificate count scopes

`max_certs_per_domain` and `global_max_certs_per_domain` enforce the same per-domain cap but with different storage scopes:

| Subdirective | Storage key | Scope |
|---|---|---|
| `max_certs_per_domain` | `tls_issuer_rate_limit/<name>/counts/<domain>.json` | Per `rate_limit` instance, identified by `<name>`. Two instances with different names maintain independent counts; two instances with the same name share counts. |
| `global_max_certs_per_domain` | `tls_issuer_rate_limit/counts/<domain>.json` | Shared across all `rate_limit` instances regardless of name. |

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
        issuer rate_limit primary {
            issuer opportunistic { ... }
            max_certs_per_domain        20
            global_max_certs_per_domain 50
            global_rate_limit           100 1h
            per_domain_rate_limit       5   6h
        }
    }
}
```

This separation of concerns keeps admission (is this hostname allowed?) distinct from lifecycle (how many certificates have been issued?).

## License

Apache 2.0 — see [LICENSE](LICENSE).
