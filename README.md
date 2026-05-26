# GoStale — Subdomain Copyright Staleness Scanner v1

A fast Go-based recon tool that discovers subdomains from multiple sources, probes them for stale copyright-year patterns, and produces a rich HTML/JSON/CSV report with a beautiful terminal UI.

## Quick Start

```bash
go build -o gostale .

# Find stale sites
./gostale -domain example.com -year-op lt -year 2023

# Smart mode (no year needed)
./gostale -domain example.com -year-op smart

# With API keys directly in command (no env vars needed)
./gostale -domain example.com -year-op smart \\
  -chaos-key YOUR\_CHAOS\_KEY \\
  -shodan-key YOUR\_SHODAN\_KEY

# Feed your own subdomain list (replaces discovery)
./gostale -domain example.com -year-op smart -subdomains mysubs.txt

# Merge your list with auto-discovery
./gostale -domain example.com -year-op smart \\
  -subdomains mysubs.txt -merge-discovery

# No color / CI mode
./gostale -domain example.com -year-op smart -no-color -silent
```

## CLI Flags

|Flag|Default|Description|
|-|-|-|
|`-domain`|(req)|Target root domain|
|`-year-op`|`lt`|Filter: `lt` `gt` `eq` `range` `smart`|
|`-year`|—|Year (required unless smart). Lower bound for range.|
|`-year-end`|—|Upper bound (range mode only)|
|`-output`|`report`|Output filename prefix (.html/.json/.csv)|
|`-threads`|30|Concurrent probe workers|
|`-timeout`|10|Per-request timeout (seconds)|
|`-chaos-key`|—|Chaos API key (overrides `CHAOS\_API\_KEY` env)|
|`-shodan-key`|—|Shodan API key (interactive prompt if CLI is init'd-needed)|
|`-subdomains`|—|Path to file with one subdomain per line (replaces discovery)|
|`-merge-discovery`|false|Merge `-subdomains` file with auto-discovered (instead of replace)|
|`-silent`|false|Suppress all verbose output|
|`-no-color`|false|Disable ANSI colors (CI/pipe friendly)|

## Shodan Key Flow

When the Shodan CLI is installed but not initialized, GoStale will:

1. First check if `-shodan-key` flag or `SHODAN\_API\_KEY` env is set → run `shodan init <key>` automatically
2. Otherwise, prompt interactively:

```
   \[shodan] Not initialized. Options:
     \[1] Enter your Shodan API key now
     \[2] Skip Shodan enumeration
   Choice \[1/2]:
   ```

## crt.sh Fallback

If crt.sh fails (timeout, rate-limit, parse error), GoStale logs loudly and continues with the other sources:

```
  ⚠ crt.sh FAILED — <reason> — continuing without it
    Tip: crt.sh is often rate-limited or slow. Try again later.
```

## Subdomain List Modes

* **Replace** (default): `-subdomains subs.txt` — only subs from file are probed
* **Merge**: `-subdomains subs.txt -merge-discovery` — file subs + auto-discovered are deduplicated and merged

File format: one hostname per line, bare labels (`api`) or FQDNs (`api.example.com`) both accepted. Lines starting with `#` are ignored.

## Discovery Sources

1. **crt.sh** — Certificate Transparency (3× retry, loud fallback on failure)
2. **chaos** — ProjectDiscovery (`-chaos-key` or `CHAOS\_API\_KEY`)
3. **Wayback Machine** — Historical CDX crawl
4. **Shodan CLI** — DNS+port enrichment (`-shodan-key` or interactive prompt)

## Terminal Output

GoStale features a rich live terminal UI with:

* **Live progress bar** — `━━━━━━━━────────── 45.2%  182/403  ✓12  ✗3  8.7 req/s ETA:38s`
* **Per-host verbose lines** — severity badge, HTTP status (color-coded), TLS status, URL, page title, copyright years, size, response time, tech stack, CDN
* **Scan summary box** at completion
* `-silent` for piping/CI, `-no-color` for non-TTY environments

