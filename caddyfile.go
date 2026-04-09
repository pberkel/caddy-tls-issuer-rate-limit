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
	"strconv"

	"github.com/caddyserver/certmagic"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
)

// UnmarshalCaddyfile populates RateLimitIssuer from Caddyfile tokens.
//
// Syntax:
//
//	issuer rate_limit {
//	    issuer <module> { ... }
//	    local [<name>] {
//	        rate_limit <limit> <duration>
//	        per_domain_rate_limit <limit> <duration>
//	    }
//	    shared <name> {
//	        rate_limit <limit> <duration>
//	        per_domain_rate_limit <limit> <duration>
//	    }
//	}
//
// issuer is required. local and shared blocks are optional and may each be
// repeated. Multiple local blocks accumulate into a single local limiter —
// useful for splitting total and per-domain limits across separate blocks.
// rate_limit and per_domain_rate_limit may be repeated within any block for
// tiered limits; all windows must have capacity for issuance to proceed.
//
// The optional <name> in any local block is a stable identifier used as the
// key in the admin registry. At most one local block may specify a name; if
// omitted across all local blocks, a UUID is generated at provision time.
//
// Example:
//
//	issuer rate_limit {
//	    issuer acme {
//	        dir https://acme-v02.api.letsencrypt.org/directory
//	    }
//	    local my-issuer {
//	        rate_limit   100 1h
//	        rate_limit   500 24h
//	        per_domain_rate_limit 5  6h
//	        per_domain_rate_limit 20 24h
//	    }
//	    shared global {
//	        rate_limit            500 24h
//	        per_domain_rate_limit  50 24h
//	    }
//	}
func (iss *RateLimitIssuer) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	d.Next() // consume "rate_limit"
	if d.NextArg() {
		return d.ArgErr()
	}

	for nesting := d.Nesting(); d.NextBlock(nesting); {
		switch d.Val() {
		case "issuer":
			if iss.IssuerRaw != nil {
				return d.Err("inner issuer already specified")
			}
			raw, err := unmarshalIssuer(d)
			if err != nil {
				return err
			}
			iss.IssuerRaw = raw

		case "local":
			if d.NextArg() {
				if iss.InstanceID != "" {
					return d.Err("local name already specified by a previous local block")
				}
				iss.InstanceID = d.Val()
				if d.NextArg() {
					return d.ArgErr()
				}
			}
			for nesting := d.Nesting(); d.NextBlock(nesting); {
				switch d.Val() {
				case "rate_limit":
					args := d.RemainingArgs()
					if len(args) != 2 {
						return d.Err("rate_limit requires exactly two arguments: <limit> <duration>")
					}
					rl, err := makeCaddyRateLimit(d, args[0], args[1])
					if err != nil {
						return err
					}
					iss.RateLimit = append(iss.RateLimit, rl)
				case "per_domain_rate_limit":
					args := d.RemainingArgs()
					if len(args) != 2 {
						return d.Err("per_domain_rate_limit requires exactly two arguments: <limit> <duration>")
					}
					rl, err := makeCaddyRateLimit(d, args[0], args[1])
					if err != nil {
						return err
					}
					iss.PerDomainRateLimit = append(iss.PerDomainRateLimit, rl)
				default:
					return d.Errf("unknown subdirective '%s'", d.Val())
				}
			}

		case "shared":
			if !d.NextArg() {
				return d.ArgErr()
			}
			sp := &SharedPool{Name: d.Val()}
			if d.NextArg() {
				return d.ArgErr()
			}
			for nesting := d.Nesting(); d.NextBlock(nesting); {
				switch d.Val() {
				case "rate_limit":
					args := d.RemainingArgs()
					if len(args) != 2 {
						return d.Err("rate_limit requires exactly two arguments: <limit> <duration>")
					}
					rl, err := makeCaddyRateLimit(d, args[0], args[1])
					if err != nil {
						return err
					}
					sp.RateLimit = append(sp.RateLimit, rl)
				case "per_domain_rate_limit":
					args := d.RemainingArgs()
					if len(args) != 2 {
						return d.Err("per_domain_rate_limit requires exactly two arguments: <limit> <duration>")
					}
					rl, err := makeCaddyRateLimit(d, args[0], args[1])
					if err != nil {
						return err
					}
					sp.PerDomainRateLimit = append(sp.PerDomainRateLimit, rl)
				case "ephemeral":
					if d.NextArg() {
						switch d.Val() {
						case "true":
							sp.Ephemeral = true
						case "false":
							sp.Ephemeral = false
						default:
							return d.Errf("ephemeral must be true or false, got %q", d.Val())
						}
						if d.NextArg() {
							return d.ArgErr()
						}
					} else {
						sp.Ephemeral = true
					}
				default:
					return d.Errf("unknown subdirective '%s'", d.Val())
				}
			}
			iss.SharedPools = append(iss.SharedPools, sp)

		default:
			return d.Errf("unknown subdirective '%s'", d.Val())
		}
	}

	return nil
}

// unmarshalIssuer reads the next module name token, delegates Caddyfile
// parsing to that module, and returns the JSON-encoded module object.
func unmarshalIssuer(d *caddyfile.Dispenser) ([]byte, error) {
	if !d.NextArg() {
		return nil, d.ArgErr()
	}
	modName := d.Val()
	modID := "tls.issuance." + modName

	unm, err := caddyfile.UnmarshalModule(d, modID)
	if err != nil {
		return nil, err
	}
	issuer, ok := unm.(certmagic.Issuer)
	if !ok {
		return nil, d.Errf("module %s (%T) is not a certmagic.Issuer", modID, unm)
	}
	return caddyconfig.JSONModuleObject(issuer, "module", modName, nil), nil
}

// makeCaddyRateLimit constructs a RateLimit from Caddyfile token strings,
// parsing the limit and duration immediately.
func makeCaddyRateLimit(d *caddyfile.Dispenser, limitVal, durationVal string) (*RateLimit, error) {
	n, err := strconv.Atoi(limitVal)
	if err != nil {
		return nil, d.Errf("invalid limit %q: expected a positive integer", limitVal)
	}
	dur, err := caddy.ParseDuration(durationVal)
	if err != nil {
		return nil, d.Errf("invalid duration %q: %v", durationVal, err)
	}
	return &RateLimit{Limit: n, Duration: caddy.Duration(dur)}, nil
}

// Interface guards
var (
	_ caddyfile.Unmarshaler = (*RateLimitIssuer)(nil)
)
