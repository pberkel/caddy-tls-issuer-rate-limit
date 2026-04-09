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
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
)

// parse runs UnmarshalCaddyfile on the given text and returns the resulting
// RateLimitIssuer and any error. The text should begin with "rate_limit",
// matching what the dispenser would be positioned at when Caddy calls the
// unmarshaller.
func parse(text string) (*RateLimitIssuer, error) {
	d := caddyfile.NewTestDispenser(text)
	var iss RateLimitIssuer
	err := iss.UnmarshalCaddyfile(d)
	return &iss, err
}

// --- outer block ------------------------------------------------------------

func TestCaddyfile_EmptyBlock(t *testing.T) {
	iss, err := parse("rate_limit {\n}")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(iss.RateLimit) != 0 || len(iss.PerDomainRateLimit) != 0 || len(iss.SharedPools) != 0 {
		t.Error("expected empty issuer for empty block")
	}
}

func TestCaddyfile_UnknownOuterSubdirective(t *testing.T) {
	if _, err := parse(`rate_limit { foo bar }`); err == nil {
		t.Error("expected error for unknown subdirective")
	}
}

func TestCaddyfile_ExtraOuterArg(t *testing.T) {
	if _, err := parse(`rate_limit extra {}`); err == nil {
		t.Error("expected error for extra outer argument")
	}
}

// --- local block ------------------------------------------------------------

func TestCaddyfile_LocalBlock_RateLimit(t *testing.T) {
	iss, err := parse(`rate_limit {
		local {
			rate_limit 100 1h
		}
	}`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(iss.RateLimit) != 1 {
		t.Fatalf("RateLimit len = %d, want 1", len(iss.RateLimit))
	}
	if iss.RateLimit[0].Limit != 100 {
		t.Errorf("Limit = %d, want 100", iss.RateLimit[0].Limit)
	}
	if time.Duration(iss.RateLimit[0].Duration) != time.Hour {
		t.Errorf("Duration = %v, want 1h", iss.RateLimit[0].Duration)
	}
}

func TestCaddyfile_LocalBlock_PerDomainRateLimit(t *testing.T) {
	iss, err := parse(`rate_limit {
		local {
			per_domain_rate_limit 5 6h
		}
	}`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(iss.PerDomainRateLimit) != 1 {
		t.Fatalf("PerDomainRateLimit len = %d, want 1", len(iss.PerDomainRateLimit))
	}
	if iss.PerDomainRateLimit[0].Limit != 5 {
		t.Errorf("Limit = %d, want 5", iss.PerDomainRateLimit[0].Limit)
	}
}

func TestCaddyfile_LocalBlock_WithName(t *testing.T) {
	iss, err := parse(`rate_limit {
		local my-instance {
			rate_limit 10 1h
		}
	}`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if iss.InstanceID != "my-instance" {
		t.Errorf("InstanceID = %q, want %q", iss.InstanceID, "my-instance")
	}
}

func TestCaddyfile_LocalBlock_TieredLimits(t *testing.T) {
	iss, err := parse(`rate_limit {
		local {
			rate_limit 30  10m
			rate_limit 300 24h
			per_domain_rate_limit 5  6h
			per_domain_rate_limit 20 24h
		}
	}`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(iss.RateLimit) != 2 {
		t.Errorf("RateLimit len = %d, want 2", len(iss.RateLimit))
	}
	if len(iss.PerDomainRateLimit) != 2 {
		t.Errorf("PerDomainRateLimit len = %d, want 2", len(iss.PerDomainRateLimit))
	}
}

func TestCaddyfile_MultipleLocalBlocks_Accumulate(t *testing.T) {
	iss, err := parse(`rate_limit {
		local {
			rate_limit 100 1h
		}
		local {
			per_domain_rate_limit 5 6h
		}
	}`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(iss.RateLimit) != 1 {
		t.Errorf("RateLimit len = %d, want 1", len(iss.RateLimit))
	}
	if len(iss.PerDomainRateLimit) != 1 {
		t.Errorf("PerDomainRateLimit len = %d, want 1", len(iss.PerDomainRateLimit))
	}
}

func TestCaddyfile_MultipleLocalBlocks_NameInFirst(t *testing.T) {
	iss, err := parse(`rate_limit {
		local primary {
			rate_limit 100 1h
		}
		local {
			per_domain_rate_limit 5 6h
		}
	}`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if iss.InstanceID != "primary" {
		t.Errorf("InstanceID = %q, want %q", iss.InstanceID, "primary")
	}
}

func TestCaddyfile_MultipleLocalBlocks_DuplicateName(t *testing.T) {
	if _, err := parse(`rate_limit {
		local alpha {
			rate_limit 10 1h
		}
		local beta {
			rate_limit 20 1h
		}
	}`); err == nil {
		t.Error("expected error for duplicate local name")
	}
}

func TestCaddyfile_LocalBlock_UnknownSubdirective(t *testing.T) {
	if _, err := parse(`rate_limit {
		local { unknown_key foo }
	}`); err == nil {
		t.Error("expected error for unknown local subdirective")
	}
}

func TestCaddyfile_LocalBlock_RateLimitMissingArgs(t *testing.T) {
	if _, err := parse(`rate_limit {
		local { rate_limit 100 }
	}`); err == nil {
		t.Error("expected error for rate_limit with only one argument")
	}
}

func TestCaddyfile_LocalBlock_InvalidLimit(t *testing.T) {
	if _, err := parse(`rate_limit {
		local { rate_limit notanumber 1h }
	}`); err == nil {
		t.Error("expected error for non-integer limit")
	}
}

func TestCaddyfile_LocalBlock_InvalidDuration(t *testing.T) {
	if _, err := parse(`rate_limit {
		local { rate_limit 10 notaduration }
	}`); err == nil {
		t.Error("expected error for invalid duration")
	}
}

func TestCaddyfile_LocalBlock_ExtraNameArg(t *testing.T) {
	if _, err := parse(`rate_limit {
		local name extra {}
	}`); err == nil {
		t.Error("expected error for extra argument after local name")
	}
}

// --- shared block -----------------------------------------------------------

func TestCaddyfile_SharedBlock_Basic(t *testing.T) {
	iss, err := parse(`rate_limit {
		shared global {
			rate_limit 500 24h
		}
	}`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(iss.SharedPools) != 1 {
		t.Fatalf("SharedPools len = %d, want 1", len(iss.SharedPools))
	}
	sp := iss.SharedPools[0]
	if sp.Name != "global" {
		t.Errorf("pool Name = %q, want %q", sp.Name, "global")
	}
	if len(sp.RateLimit) != 1 || sp.RateLimit[0].Limit != 500 {
		t.Errorf("pool RateLimit = %v, want [{500, 24h}]", sp.RateLimit)
	}
}

func TestCaddyfile_SharedBlock_PerDomain(t *testing.T) {
	iss, err := parse(`rate_limit {
		shared global {
			per_domain_rate_limit 50 24h
		}
	}`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(iss.SharedPools[0].PerDomainRateLimit) != 1 {
		t.Errorf("PerDomainRateLimit len = %d, want 1", len(iss.SharedPools[0].PerDomainRateLimit))
	}
}

func TestCaddyfile_SharedBlock_Ephemeral_Bare(t *testing.T) {
	iss, err := parse(`rate_limit {
		shared tmp {
			rate_limit 100 1h
			ephemeral
		}
	}`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !iss.SharedPools[0].Ephemeral {
		t.Error("expected Ephemeral = true for bare ephemeral directive")
	}
}

func TestCaddyfile_SharedBlock_Ephemeral_True(t *testing.T) {
	iss, err := parse(`rate_limit {
		shared tmp {
			rate_limit 100 1h
			ephemeral true
		}
	}`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !iss.SharedPools[0].Ephemeral {
		t.Error("expected Ephemeral = true")
	}
}

func TestCaddyfile_SharedBlock_Ephemeral_False(t *testing.T) {
	iss, err := parse(`rate_limit {
		shared tmp {
			rate_limit 100 1h
			ephemeral false
		}
	}`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if iss.SharedPools[0].Ephemeral {
		t.Error("expected Ephemeral = false")
	}
}

func TestCaddyfile_SharedBlock_Ephemeral_Invalid(t *testing.T) {
	if _, err := parse(`rate_limit {
		shared tmp {
			rate_limit 100 1h
			ephemeral maybe
		}
	}`); err == nil {
		t.Error("expected error for invalid ephemeral value")
	}
}

func TestCaddyfile_SharedBlock_MultipleBlocks(t *testing.T) {
	iss, err := parse(`rate_limit {
		shared pool-a {
			rate_limit 100 1h
		}
		shared pool-b {
			rate_limit 200 24h
		}
	}`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(iss.SharedPools) != 2 {
		t.Errorf("SharedPools len = %d, want 2", len(iss.SharedPools))
	}
	if iss.SharedPools[0].Name != "pool-a" || iss.SharedPools[1].Name != "pool-b" {
		t.Errorf("pool names = %q, %q", iss.SharedPools[0].Name, iss.SharedPools[1].Name)
	}
}

func TestCaddyfile_SharedBlock_MissingName(t *testing.T) {
	if _, err := parse(`rate_limit {
		shared { rate_limit 100 1h }
	}`); err == nil {
		t.Error("expected error for shared block with no name")
	}
}

func TestCaddyfile_SharedBlock_ExtraNameArg(t *testing.T) {
	if _, err := parse(`rate_limit {
		shared pool extra { rate_limit 100 1h }
	}`); err == nil {
		t.Error("expected error for extra argument after shared name")
	}
}

func TestCaddyfile_SharedBlock_UnknownSubdirective(t *testing.T) {
	if _, err := parse(`rate_limit {
		shared pool { unknown_key foo }
	}`); err == nil {
		t.Error("expected error for unknown shared subdirective")
	}
}

// --- makeCaddyRateLimit -----------------------------------------------------

func TestMakeCaddyRateLimit_Valid(t *testing.T) {
	d := caddyfile.NewTestDispenser(`rate_limit {}`)
	d.Next()
	rl, err := makeCaddyRateLimit(d, "10", "1h")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rl.Limit != 10 {
		t.Errorf("Limit = %d, want 10", rl.Limit)
	}
	if time.Duration(rl.Duration) != time.Hour {
		t.Errorf("Duration = %v, want 1h", rl.Duration)
	}
}

func TestMakeCaddyRateLimit_InvalidLimit(t *testing.T) {
	d := caddyfile.NewTestDispenser(`rate_limit {}`)
	d.Next()
	if _, err := makeCaddyRateLimit(d, "bad", "1h"); err == nil {
		t.Error("expected error for non-integer limit")
	}
}

func TestMakeCaddyRateLimit_InvalidDuration(t *testing.T) {
	d := caddyfile.NewTestDispenser(`rate_limit {}`)
	d.Next()
	if _, err := makeCaddyRateLimit(d, "10", "bad"); err == nil {
		t.Error("expected error for invalid duration")
	}
}

// --- caddy.Duration parsing sanity ------------------------------------------

func TestCaddyfile_DurationUnits(t *testing.T) {
	tests := []struct {
		input string
		want  time.Duration
	}{
		{"10m", 10 * time.Minute},
		{"24h", 24 * time.Hour},
		{"30s", 30 * time.Second},
	}
	for _, tt := range tests {
		iss, err := parse("rate_limit {\n\tlocal {\n\t\trate_limit 1 " + tt.input + "\n\t}\n}")
		if err != nil {
			t.Errorf("input %q: unexpected error: %v", tt.input, err)
			continue
		}
		if got := time.Duration(iss.RateLimit[0].Duration); got != tt.want {
			t.Errorf("input %q: Duration = %v, want %v", tt.input, got, tt.want)
		}
	}
}
