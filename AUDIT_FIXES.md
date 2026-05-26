# v2.2 Audit & Fixes

A full code review found 16 blunders across discovery, probing, and templating. This document explains each one and how it was fixed. All fixes are covered by unit tests (19 passing).

## Discovery Layer (most severe)

### #1 — crt.sh URL construction was fragile
**Before:** `fmt.Sprintf("https://crt.sh/?q=%%25.%s", url.QueryEscape(domain))`
- The `url.QueryEscape` of `example.com` doesn't touch dots, but combined with `%%25` it was unnecessarily complex.

**Fix:** Direct string concat with the literal SQL wildcard `%25.` plus per-request UA. Added a lenient newline-delimited JSON fallback for crt.sh's occasional non-JSON responses, expanded retry timing, and now include the apex domain in results.

### #2 — Scope filter used `strings.Contains` (allowed sneaky matches)
**Before:** `if sub == "" || !strings.Contains(sub, domain)`
- `"evilexample.com"` matches `"example.com"` ← false positive!
- `"notexample.com.attacker.io"` matches `"example.com"` ← scope injection!

**Fix:** New `inScope(host, domain)` uses `strings.HasSuffix(host, "."+domain) || host == domain`. Demonstrated with:

```
Host "evilexample.com" with target "example.com":
  OLD contains-check: true  (BAD - false positive!)
  NEW suffix-check:   false (CORRECT)
```

Covered by `TestInScope` with 10 cases.

### #3 — Chaos double-suffixed FQDNs
**Before:** `add(s+"."+domain, ...)` — if Chaos returns full FQDNs (some endpoints do), this produced `api.example.com.example.com` which then got rejected.

**Fix:** Defensive: if response item already contains a dot, treat as FQDN; otherwise concat with domain.

### #4 — Wayback returned external URLs that contained the domain in path/query
The old contains-check would let `https://attacker.com/?ref=example.com` through. Now blocked by the new `inScope` filter (#2).

### #5 — Shodan parser was fundamentally broken
The real format (from shodan-python's `__main__.py`) is fixed-width:
```
<subdomain padded 32 chars> <TYPE padded 14 chars> <value>[ Ports: p1, p2, ...]
```

The old parser:
- Assumed column 0 was always a subdomain (apex domains have empty subdomain → column 0 is the TYPE).
- Used `!strings.Contains(fields[0], ".")` as the "is it a prefix" test — fails for CNAME values that are hostnames.
- Treated `MX` `value` as a hostname when it actually has a priority prefix (`10 mx1.example.com`).
- Ignored ANSI color escapes — the CLI emits them in many environments.
- Discarded all the port enrichment data from `-D`.
- Didn't capture stderr where header sometimes goes.

**Fix:** Complete rewrite as a proper struct-returning function `parseShodanOutput()` that:
- Strips ANSI escapes (`\x1b[...]`) before parsing.
- Uses fixed-width columns (offsets 0-32, 32-46, 46+) to correctly identify apex domain rows where subdomain is empty.
- Has a lenient whitespace-fallback for shorter lines.
- Strips MX priority numbers.
- Captures ports from `Ports: 22, 80, 443, 9000` suffix.
- Skips error/header/diagnostic lines.
- Now also captures TXT, NS, SOA, PTR record types (not just A/CNAME).

Covered by 6 tests including realistic fixtures with ANSI colors, CRLF endings, no-details mode, error outputs, TXT records with spaces, and short-line fallbacks.

### #6 — Port info from Shodan was ignored
You called this out specifically. Now:
- `fetchShodan` runs with `-D` to get port info.
- Each subdomain's discovered ports get stored in `subExtraPorts`.
- `generateURLs` produces probe URLs for those extra ports — both `http://` and `https://` variants — while skipping the defaults (80/443) to avoid duplicates.
- For known TLS ports (8443, 9443, 4443), https is tried first.
- The dedup map is now keyed by `hostname:port` so the same host on different ports stays distinct in results.

Covered by `TestGenerateURLs_WithExtraPorts`.

### #7 — Wayback used http (not https) and had brittle header detection
**Before:** Plain http, skipped row index 0 unconditionally.

**Fix:** Now uses https, detects the header by content (`row[0] == "original"`), logs HTTP error codes, and properly URL-encodes the domain in the query.

### Shodan auth/init errors with exit code 0
The shodan CLI exits 0 even when uninitialized, printing `Error: Please run "shodan init..."`. The new `isShodanFatalError()` detects these patterns and surfaces a real Go error to the caller, which then logs `[shodan] error: ...` clearly.

## Probing Layer

### #8 — http won dedup, even when https was better
**Before:** First-arrival-wins dedup at hostname level.

**Fix:** Dedup key is now `hostname:port` and the dedup map stores `Result` values. When a duplicate arrives, https replaces http. The flat slice is emitted after all probes finish.

### #9 — Misleading commandExists / env check
**Before:** Shodan skip message implied `SHODAN_API_KEY` was needed, but the CLI uses `~/.shodan/api_key` from `shodan init`. The env var was actually never used.

**Fix:** Removed the misleading env check; we now run the CLI and detect init errors with `isShodanFatalError`.

### #10 — Total timeout caused premature aborts on slow servers
Acknowledged but kept as-is for now: 10s default is reasonable, configurable via `-timeout`, and applies fairly to both connect and body read. Adding a separate `ResponseHeaderTimeout` would help but adds complexity.

## Year Regex

### #11 — Missing HTML entity variants
**Before:** Only matched literal `©`, `&copy;`, "copyright", "copr.".

**Fix:** Now also matches `&#169;`, `&#0169;`, `&#xa9;`, `&#x00A9;` (decimal and hex HTML entities for ©). Added `/` and `,` as range separators alongside `-` and em-dash variants.

Covered by `TestYearRegex_Variants` with 11 cases including HTML entities, year ranges with slash separators, and out-of-range filtering.

### #13 — Title extraction grabs SVG `<title>` etc.
Acknowledged minor bug, kept as-is — pages with valid copyright in body that also have SVG titles are rare; the current regex prioritizes the first `<title>` which is almost always the document title.

## Templating

### #14 — Screenshot URL was unencoded
**Before:** `fmt.Sprintf("https://image.thum.io/get/width/800/%s", targetURL)` — if `targetURL` has `?` or `&`, thum.io misparses.

**Fix:** Now uses `url.QueryEscape` on the target URL.

## What's Now Tested

```
=== Discovery Layer ===
TestInScope                            (10 cases: case-sensitivity, suffix injection, exact match, empties)
TestCleanHost                          (13 cases: protocols, paths, ports, wildcards, invalid chars)
TestParseShodanOutput_NoColor          (apex, www, api CNAME, admin with ports, MX with priority, NS, TXT, _acme-challenge)
TestParseShodanOutput_WithAnsiColors   (real ANSI escape sequences from click.style)
TestParseShodanOutput_NoDetails        (output without -D flag — no ports expected)
TestParseShodanOutput_EmptyAndErrors   (empty input, Error: lines)
TestParseShodanOutput_CRLF             (Windows line endings)
TestParseShodanOutput_ShortLineFallback (future format / no padding)
TestParseShodanOutput_TXTWithSpaces    (SPF records with spaces shouldn't get truncated)
TestBuildShodanHost                    (empty sub = apex, FQDN dedup)
TestGenerateURLs_WithExtraPorts        (extra ports probed both schemes, 80/443 not duplicated)

=== Year / Filter ===
TestYearRegex_Variants                 (©, &copy;, &#169;, &#xa9;, COPYRIGHT, Copr., ranges, out-of-range)
TestLT, TestGT, TestEQ, TestRange      (each operator)
TestSmartMode                          (staleness + cluster + risk priority heuristics)
TestRangeAutoSwap                      (swap when -year > -year-end)

Total: 19 tests, all passing.
```

## Files Updated

- `scanner.go` — discovery refactor, Shodan parser rewrite, dedup overhaul
- `discovery_test.go` — NEW: 12 tests for the fixed pieces
- `scanner_test.go` — existing year-op tests (unchanged, still pass)
- `template.go` — screenshot URL encoding fix

Build: `go build .` clean. Vet: clean. Tests: 19/19 pass.
