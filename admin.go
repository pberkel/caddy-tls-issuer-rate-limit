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
	"sort"
	"strings"
	"time"

	"github.com/caddyserver/caddy/v2"
)

func init() {
	caddy.RegisterModule(RateLimitAdmin{})
}

// RateLimitAdmin registers admin API routes for inspecting and resetting
// shared rate limit pool state. It is loaded automatically by Caddy's admin
// server when this package is imported.
//
// Routes:
//
//	GET    /rate_limit_issuer/          - HTML web interface
//	GET    /rate_limit_issuer/pools     - JSON status of all shared pools
//	DELETE /rate_limit_issuer/pools/{name}                  - reset all windows for a pool
//	DELETE /rate_limit_issuer/pools/{name}/domains/{domain} - reset per-domain windows
type RateLimitAdmin struct{}

// CaddyModule returns the Caddy module information.
func (RateLimitAdmin) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "admin.api.rate_limit_issuer",
		New: func() caddy.Module { return new(RateLimitAdmin) },
	}
}

// Routes implements caddy.AdminRouter.
func (a RateLimitAdmin) Routes() []caddy.AdminRoute {
	return []caddy.AdminRoute{
		{
			Pattern: "/rate_limit_issuer/",
			Handler: caddy.AdminHandlerFunc(a.handleRequest),
		},
	}
}

// handleRequest dispatches incoming admin requests by method and path.
func (a RateLimitAdmin) handleRequest(w http.ResponseWriter, r *http.Request) error {
	// Strip the registered prefix to get the local path.
	local := strings.TrimPrefix(r.URL.Path, "/rate_limit_issuer")
	local = strings.TrimPrefix(local, "/")
	local = strings.TrimSuffix(local, "/")

	switch {
	case local == "" && r.Method == http.MethodGet:
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, err := w.Write([]byte(adminHTML))
		return err

	case local == "pools" && r.Method == http.MethodGet:
		return a.handleGetPools(w, r)

	case strings.HasPrefix(local, "pools/") && r.Method == http.MethodDelete:
		rest := strings.TrimPrefix(local, "pools/")
		if i := strings.Index(rest, "/domains/"); i >= 0 {
			return a.handleDeletePool(w, r, rest[:i], rest[i+len("/domains/"):])
		}
		if strings.HasSuffix(rest, "/total") {
			return a.handleDeleteTotal(w, r, strings.TrimSuffix(rest, "/total"))
		}
		return a.handleDeletePool(w, r, rest, "")

	default:
		http.Error(w, "not found", http.StatusNotFound)
		return nil
	}
}

// WindowStatus is the serialisable view of a single sliding window.
type WindowStatus struct {
	Limit    int        `json:"limit"`
	Duration string     `json:"duration"`
	Count    int        `json:"count"`
	ResetAt  *time.Time `json:"reset_at,omitempty"`
}

// PoolStatus is the serialisable view of a pool entry. Kind is "shared" for
// named shared pools and "local" for per-instance local limiters.
type PoolStatus struct {
	Name    string                    `json:"name"`
	Kind    string                    `json:"kind"`
	Total   []WindowStatus            `json:"total,omitempty"`
	Domains map[string][]WindowStatus `json:"domains,omitempty"`
}

// handleGetPools writes a JSON array of PoolStatus for all entries in
// processRegistry (both shared pools and local instances), sorted by name.
func (a RateLimitAdmin) handleGetPools(w http.ResponseWriter, r *http.Request) error {
	var pools []PoolStatus
	processRegistry.Range(func(key, value any) bool {
		pools = append(pools, entryToStatus(key.(string), value.(*registryEntry)))
		return true
	})
	sort.Slice(pools, func(i, j int) bool { return pools[i].Name < pools[j].Name })
	w.Header().Set("Content-Type", "application/json")
	return json.NewEncoder(w).Encode(pools)
}

// handleDeleteTotal resets only the total (cross-domain) windows for the named pool.
func (a RateLimitAdmin) handleDeleteTotal(w http.ResponseWriter, r *http.Request, name string) error {
	val, ok := processRegistry.Load(name)
	if !ok {
		http.Error(w, "pool not found", http.StatusNotFound)
		return nil
	}
	s := val.(*registryEntry).state
	s.mu.Lock()
	for i := range s.totals {
		s.totals[i].timestamps = nil
	}
	s.mu.Unlock()
	w.WriteHeader(http.StatusNoContent)
	return nil
}

// handleDeletePool resets windows for the named pool or, when domain is
// non-empty, resets only that domain's windows within the pool.
func (a RateLimitAdmin) handleDeletePool(w http.ResponseWriter, r *http.Request, name, domain string) error {
	val, ok := processRegistry.Load(name)
	if !ok {
		http.Error(w, "pool not found", http.StatusNotFound)
		return nil
	}
	s := val.(*registryEntry).state
	if domain == "" {
		s.mu.Lock()
		for i := range s.totals {
			s.totals[i].timestamps = nil
		}
		s.domains = make(map[string][]*slidingWindow)
		s.mu.Unlock()
	} else {
		s.mu.Lock()
		delete(s.domains, domain)
		s.mu.Unlock()
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

// entryToStatus snapshots the current window counts for a registry entry.
// The state mutex is held for the duration to keep the snapshot consistent and
// to satisfy the locking contract of slidingWindow.count().
func entryToStatus(name string, entry *registryEntry) PoolStatus {
	s := entry.state
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()

	kind := "shared"
	if entry.local {
		kind = "local"
	}
	ps := PoolStatus{Name: name, Kind: kind}

	for i, rl := range s.totalLimits {
		d := time.Duration(rl.Duration)
		_ = s.totals[i].count(now, d) // trim before resetAt
		ws := WindowStatus{
			Limit:    rl.Limit,
			Duration: d.String(),
			Count:    len(s.totals[i].timestamps),
		}
		if t := s.totals[i].resetAt(d); !t.IsZero() {
			ws.ResetAt = &t
		}
		ps.Total = append(ps.Total, ws)
	}

	if len(s.domains) > 0 {
		ps.Domains = make(map[string][]WindowStatus, len(s.domains))
		for domain, windows := range s.domains {
			ws := make([]WindowStatus, len(s.perDomainLimits))
			for i, rl := range s.perDomainLimits {
				d := time.Duration(rl.Duration)
				_ = windows[i].count(now, d) // trim before resetAt
				ws[i] = WindowStatus{
					Limit:    rl.Limit,
					Duration: d.String(),
					Count:    len(windows[i].timestamps),
				}
				if t := windows[i].resetAt(d); !t.IsZero() {
					ws[i].ResetAt = &t
				}
			}
			ps.Domains[domain] = ws
		}
	}

	return ps
}

// Interface guard
var _ caddy.AdminRouter = RateLimitAdmin{}

// adminHTML is the self-contained web interface served at /rate_limit_issuer/.
const adminHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Rate Limit Issuer</title>
<style>
* { box-sizing: border-box; }
body { font-family: system-ui, sans-serif; margin: 0; background: #f0f2f5; color: #222; }
header { background: #1a1a2e; color: #fff; padding: 1rem 2rem; display: flex; justify-content: space-between; align-items: center; }
header h1 { margin: 0; font-size: 1.2rem; font-weight: 500; letter-spacing: 0.02em; }
#refresh-status { font-size: 0.8rem; color: #aaa; }
main { padding: 2rem; max-width: 960px; margin: 0 auto; }
h2 { font-size: 0.9rem; text-transform: uppercase; letter-spacing: 0.08em; color: #555; margin: 0 0 1rem; }
.pool { background: #fff; border-radius: 8px; padding: 1.25rem 1.5rem; margin-bottom: 1.25rem; box-shadow: 0 1px 4px rgba(0,0,0,.08); }
.pool-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 1rem; }
.pool-name { font-size: 1.05rem; font-weight: 600; }
.pool-id { font-size: 0.8rem; color: #999; font-weight: normal; margin-left: 0.5rem; }
.section-label { font-size: 0.72rem; text-transform: uppercase; letter-spacing: 0.07em; color: #888; margin: 1rem 0 0.4rem; }
table { width: 100%; border-collapse: collapse; font-size: 0.9rem; }
th { text-align: left; color: #666; font-weight: 500; padding: 5px 8px; border-bottom: 2px solid #eee; }
td { padding: 6px 8px; border-bottom: 1px solid #f2f2f2; vertical-align: middle; }
tr:last-child td { border-bottom: none; }
.bar-wrap { min-width: 80px; }
.bar { background: #e8e8e8; border-radius: 4px; height: 6px; overflow: hidden; }
.bar-fill { height: 6px; border-radius: 4px; transition: width .4s, background .4s; background: #4caf50; }
.bar-fill.warn { background: #ff9800; }
.bar-fill.crit { background: #f44336; }
.count-cell { white-space: nowrap; }
button { padding: 4px 12px; border: 1px solid #ddd; border-radius: 5px; background: #fff; cursor: pointer; font-size: 0.82rem; color: #444; transition: background .15s; }
button:hover { background: #f7f7f7; }
button.danger { border-color: #e53935; color: #e53935; }
button.danger:hover { background: #fff5f5; }
td.action { text-align: right; }
.group { margin-bottom: 2rem; }
.empty { color: #bbb; font-size: 0.9rem; padding: 0.5rem 0 1.5rem; }
</style>
</head>
<body>
<header>
  <h1>Rate Limit Issuer</h1>
  <span id="refresh-status">Loading&hellip;</span>
</header>
<main>
  <div class="group">
    <h2>Shared Pools</h2>
    <div id="shared"></div>
  </div>
  <div class="group">
    <h2>Local Instances</h2>
    <div id="local"></div>
  </div>
</main>
<script>
const base = window.location.pathname.replace(/\/+$/, '');

function esc(s) {
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
}
// jsonAttr JSON-encodes v and HTML-escapes the result for use inside a
// double-quoted HTML attribute (e.g. onclick="fn(jsonAttr(v))").
function jsonAttr(v) {
  return JSON.stringify(v).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}
function barClass(count, limit) {
  const p = count / limit;
  return p >= 1 ? 'crit' : p >= 0.8 ? 'warn' : '';
}
function mostConstrained(windows) {
  return windows.reduce((a, b) => (b.count / b.limit > a.count / a.limit ? b : a), windows[0]);
}
function windowBar(windows) {
  const w = mostConstrained(windows);
  const cls = barClass(w.count, w.limit);
  const pct = Math.min(100, Math.round(w.count / w.limit * 100));
  return '<div class="bar-wrap"><div class="bar"><div class="bar-fill ' + cls + '" style="width:' + pct + '%"></div></div></div>';
}
function fmtReset(iso) {
  if (!iso) return '\u2014';
  const diff = new Date(iso) - Date.now();
  if (diff <= 0) return 'now';
  const s = Math.ceil(diff / 1000);
  if (s < 60) return 'in ' + s + 's';
  const m = Math.ceil(s / 60);
  if (m < 60) return 'in ' + m + 'm';
  return 'in ' + Math.ceil(m / 60) + 'h';
}
function renderGlobal(name, windows) {
  if (!windows || windows.length === 0) return '';
  const row = '<tr>' +
    '<td class="count-cell">' + windows.map(w => w.count+'/'+w.limit).join(', ') + '</td>' +
    '<td>' + windows.map(w => esc(w.duration)).join(', ') + '</td>' +
    '<td>' + windowBar(windows) + '</td>' +
    '<td>' + windows.map(w => fmtReset(w.reset_at)).join(', ') + '</td>' +
    '<td class="action"><button onclick="resetTotal(' + jsonAttr(name) + ')">Reset</button></td></tr>';
  return '<div class="section-label">Total</div>' +
    '<table><thead><tr><th>Count / Limit</th><th>Window</th><th></th><th>Resets</th><th></th></tr></thead><tbody>' + row + '</tbody></table>';
}
function renderDomains(name, domains) {
  if (!domains || Object.keys(domains).length === 0) return '';
  const sorted = Object.entries(domains).sort((a, b) => a[0].localeCompare(b[0]));
  const rows = sorted.map(([domain, windows]) => {
    return '<tr><td>' + esc(domain) + '</td>' +
      '<td class="count-cell">' + windows.map(w => w.count+'/'+w.limit).join(', ') + '</td>' +
      '<td>' + windows.map(w => esc(w.duration)).join(', ') + '</td>' +
      '<td>' + windowBar(windows) + '</td>' +
      '<td>' + windows.map(w => fmtReset(w.reset_at)).join(', ') + '</td>' +
      '<td class="action"><button onclick="resetDomain(' + jsonAttr(name) + ',' + jsonAttr(domain) + ')">Reset</button></td></tr>';
  }).join('');
  return '<div class="section-label">Per Domain</div>' +
    '<table><thead><tr><th>Domain</th><th>Count / Limit</th><th>Window</th><th></th><th>Resets</th><th></th></tr></thead><tbody>' + rows + '</tbody></table>';
}
function renderGroup(items, containerID, emptyMsg) {
  const el = document.getElementById(containerID);
  if (!items || items.length === 0) {
    el.innerHTML = '<p class="empty">' + emptyMsg + '</p>';
    return;
  }
  el.innerHTML = items.map(item =>
    '<div class="pool">' +
    '<div class="pool-header"><span class="pool-name">' + esc(item.name) + '</span>' +
    '<button class="danger" onclick="resetAll(' + jsonAttr(item.name) + ')">Reset all</button></div>' +
    renderGlobal(item.name, item.total) +
    renderDomains(item.name, item.domains) +
    '</div>'
  ).join('');
}

async function load() {
  try {
    const r = await fetch(base + '/pools');
    if (!r.ok) throw new Error('HTTP ' + r.status);
    const all = await r.json();
    renderGroup(all.filter(p => p.kind === 'shared'), 'shared', 'No shared pools registered.');
    renderGroup(all.filter(p => p.kind === 'local'),  'local',  'No local instances registered.');
    document.getElementById('refresh-status').textContent = 'Updated ' + new Date().toLocaleTimeString();
  } catch (e) {
    document.getElementById('refresh-status').textContent = 'Error: ' + e.message;
  }
}

async function resetAll(name) {
  if (!confirm('Reset all windows for \u201c' + name + '\u201d?')) return;
  const r = await fetch(base + '/pools/' + encodeURIComponent(name), {method: 'DELETE'});
  if (!r.ok) alert('Reset failed: HTTP ' + r.status);
  await load();
}

async function resetTotal(name) {
  if (!confirm('Reset total windows for \u201c' + name + '\u201d?')) return;
  const r = await fetch(base + '/pools/' + encodeURIComponent(name) + '/total', {method: 'DELETE'});
  if (!r.ok) alert('Reset failed: HTTP ' + r.status);
  await load();
}

async function resetDomain(name, domain) {
  if (!confirm('Reset domain \u201c' + domain + '\u201d in \u201c' + name + '\u201d?')) return;
  const r = await fetch(
    base + '/pools/' + encodeURIComponent(name) + '/domains/' + encodeURIComponent(domain),
    {method: 'DELETE'}
  );
  if (!r.ok) alert('Reset failed: HTTP ' + r.status);
  await load();
}

load();
setInterval(load, 5000);
</script>
</body>
</html>`
