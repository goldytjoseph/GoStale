package main

import (
	"bufio"
	"context"
	"crypto/md5"
	"crypto/tls"
	"encoding/base64"
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// -------------------- ANSI Color Palette --------------------

const (
	reset   = "\033[0m"
	bold    = "\033[1m"
	dim     = "\033[2m"
	red     = "\033[31m"
	green   = "\033[32m"
	yellow  = "\033[33m"
	blue    = "\033[34m"
	magenta = "\033[35m"
	cyan    = "\033[36m"
	white   = "\033[37m"
	bgRed   = "\033[41m"

	brightRed     = "\033[91m"
	brightGreen   = "\033[92m"
	brightYellow  = "\033[93m"
	brightBlue    = "\033[94m"
	brightMagenta = "\033[95m"
	brightCyan    = "\033[96m"
	brightWhite   = "\033[97m"
)

// -------------------- Data Structures --------------------

type Result struct {
	URL            string   `json:"url"`
	Hostname       string   `json:"hostname"`
	IP             string   `json:"ip"`
	Port           string   `json:"port"`
	StatusCode     int      `json:"status_code"`
	Title          string   `json:"title"`
	Server         string   `json:"server"`
	TechStack      []string `json:"tech_stack"`
	FaviconHash    string   `json:"favicon_hash"`
	ScreenshotURL  string   `json:"screenshot_url"`
	DNSRecords     DNSInfo  `json:"dns"`
	CDN            string   `json:"cdn"`
	WAF            string   `json:"waf"`
	CopyrightYears []int    `json:"copyright_years"`
	OldestYear     int      `json:"oldest_year"`
	LatestYear     int      `json:"latest_year"`
	Severity       string   `json:"severity"`
	Tags           []string `json:"tags"`
	TLSValid       bool     `json:"tls_valid"`
	TLSExpiry      string   `json:"tls_expiry,omitempty"`
	ContentLength  int      `json:"content_length"`
	Source         []string `json:"discovery_source"`
	SmartScore     int      `json:"smart_score,omitempty"`
	SmartReasons   []string `json:"smart_reasons,omitempty"`
	ResponseTime   int64    `json:"response_time_ms,omitempty"`
}

type DNSInfo struct {
	A     []string `json:"a"`
	CNAME string   `json:"cname"`
	MX    []string `json:"mx"`
}

type Config struct {
	Domain         string
	YearOp         string
	Year           int
	YearEnd        int
	OutputFile     string
	Threads        int
	Timeout        int
	ChaosKey       string
	ShodanKey      string
	SubdomainFile  string
	MergeDiscovery bool
	Silent         bool
	NoColor        bool
}

type CrtShResult struct {
	NameValue string `json:"name_value"`
}

type ChaosResult struct {
	Subdomains []string `json:"subdomains"`
}

// -------------------- Progress / Verbose Engine --------------------

// progressState tracks the live probe progress bar
type progressState struct {
	total     int64
	done      int64
	found     int64 // hosts with copyright content
	errors    int64
	startTime time.Time
}

var progress progressState
var progressMu sync.Mutex
var lastBarLen int

// printProgress renders the live progress bar to stderr
// Style inspired by httpx but more informative
func printProgress(force bool) {
	done := atomic.LoadInt64(&progress.done)
	total := atomic.LoadInt64(&progress.total)
	found := atomic.LoadInt64(&progress.found)
	errs := atomic.LoadInt64(&progress.errors)

	if total == 0 {
		return
	}

	pct := float64(done) / float64(total)
	elapsed := time.Since(progress.startTime)
	rps := 0.0
	if elapsed.Seconds() > 0 {
		rps = float64(done) / elapsed.Seconds()
	}
	eta := ""
	if rps > 0 && done < total {
		remaining := float64(total-done) / rps
		eta = fmt.Sprintf(" ETA:%s", formatDuration(time.Duration(remaining)*time.Second))
	}

	// Bar width
	barWidth := 30
	filled := int(math.Round(pct * float64(barWidth)))
	if filled > barWidth {
		filled = barWidth
	}

	bar := ""
	if cfg.NoColor {
		bar = "[" + strings.Repeat("=", filled) + strings.Repeat("-", barWidth-filled) + "]"
	} else {
		filledStr := brightCyan + strings.Repeat("━", filled) + reset
		emptyStr := dim + strings.Repeat("─", barWidth-filled) + reset
		bar = brightBlue + "[" + reset + filledStr + emptyStr + brightBlue + "]" + reset
	}

	line := fmt.Sprintf("\r %s %s %s%d%s/%s%d%s  %s✓%s%d  %s✗%s%d  %s%.1f req/s%s%s  %s",
		bar,
		colorPct(pct),
		bold, done, reset,
		dim, total, reset,
		brightGreen, reset, found,
		brightRed, reset, errs,
		cyan, rps, reset,
		eta,
		dim+"[probing]"+reset,
	)

	// Pad to erase previous line
	if len(line) < lastBarLen {
		line += strings.Repeat(" ", lastBarLen-len(line))
	}
	lastBarLen = len(line)

	fmt.Fprint(os.Stderr, line)
}

func colorPct(pct float64) string {
	s := fmt.Sprintf("%5.1f%%", pct*100)
	if cfg.NoColor {
		return s
	}
	if pct < 0.33 {
		return yellow + s + reset
	} else if pct < 0.66 {
		return cyan + s + reset
	}
	return brightGreen + s + reset
}

func clearProgress() {
	if lastBarLen > 0 {
		fmt.Fprintf(os.Stderr, "\r%s\r", strings.Repeat(" ", lastBarLen+5))
		lastBarLen = 0
	}
}

func formatDuration(d time.Duration) string {
	d = d.Round(time.Second)
	h := d / time.Hour
	d -= h * time.Hour
	m := d / time.Minute
	d -= m * time.Minute
	s := d / time.Second
	if h > 0 {
		return fmt.Sprintf("%dh%02dm%02ds", h, m, s)
	}
	if m > 0 {
		return fmt.Sprintf("%dm%02ds", m, s)
	}
	return fmt.Sprintf("%ds", s)
}

// -------------------- Verbose Logging --------------------

// logVerb prints a verbose probe result line, httpx-style but richer
func logVerb(r Result) {
	if cfg.Silent {
		return
	}
	clearProgress()

	sev := severityBadge(r.Severity)
	sc := statusBadge(r.StatusCode)
	tls := tlsBadge(r.TLSValid, r.URL)
	host := fmt.Sprintf("%s%-45s%s", bold, r.URL, reset)

	title := r.Title
	if len(title) > 50 {
		title = title[:47] + "..."
	}
	if title == "" {
		title = dim + "(no title)" + reset
	} else {
		title = brightWhite + title + reset
	}

	size := formatSize(r.ContentLength)
	years := formatYears(r.CopyrightYears)
	rt := ""
	if r.ResponseTime > 0 {
		rt = dim + fmt.Sprintf(" [%dms]", r.ResponseTime) + reset
	}

	tech := ""
	if len(r.TechStack) > 0 {
		tech = dim + " [" + strings.Join(r.TechStack[:min(3, len(r.TechStack))], ",") + "]" + reset
	}

	cdn := ""
	if r.CDN != "" {
		cdn = cyan + " CDN:" + r.CDN + reset
	}

	fmt.Fprintf(os.Stderr, " %s %s %s %s %s  %s  %s%s%s%s\n",
		sev, sc, tls, host, title,
		years, size, rt, tech, cdn,
	)
}

func logVerbError(targetURL string, reason string) {
	if cfg.Silent {
		return
	}
	// Only show errors in very verbose mode — skip for clean output
	_ = targetURL
	_ = reason
}

func severityBadge(sev string) string {
	if cfg.NoColor {
		return fmt.Sprintf("[%-8s]", sev)
	}
	switch sev {
	case "Critical":
		return bgRed + bold + "[CRIT]   " + reset
	case "High":
		return brightRed + bold + "[HIGH]   " + reset
	case "Medium":
		return brightYellow + "[MED]    " + reset
	case "Low":
		return green + "[LOW]    " + reset
	}
	return dim + "[?]      " + reset
}

func statusBadge(code int) string {
	s := fmt.Sprintf("%3d", code)
	if cfg.NoColor {
		return s
	}
	switch {
	case code >= 200 && code < 300:
		return brightGreen + s + reset
	case code >= 300 && code < 400:
		return cyan + s + reset
	case code >= 400 && code < 500:
		return yellow + s + reset
	case code >= 500:
		return brightRed + s + reset
	}
	return dim + s + reset
}

func tlsBadge(valid bool, u string) string {
	if !strings.HasPrefix(u, "https://") {
		return dim + "   " + reset
	}
	if valid {
		return brightGreen + "TLS" + reset
	}
	return brightRed + "TLS" + reset
}

func formatSize(n int) string {
	switch {
	case n >= 1024*1024:
		return fmt.Sprintf("%s%.1fMB%s", dim, float64(n)/(1024*1024), reset)
	case n >= 1024:
		return fmt.Sprintf("%s%.1fKB%s", dim, float64(n)/1024, reset)
	default:
		return fmt.Sprintf("%s%dB%s", dim, n, reset)
	}
}

func formatYears(years []int) string {
	if len(years) == 0 {
		return dim + "no-year" + reset
	}
	if len(years) == 1 {
		return yellow + strconv.Itoa(years[0]) + reset
	}
	return yellow + fmt.Sprintf("%d→%d", years[0], years[len(years)-1]) + reset
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// -------------------- Source badge --------------------

func sourceBadge(src string) string {
	if cfg.NoColor {
		return "[" + src + "]"
	}
	colors := map[string]string{
		"crt.sh":  brightBlue,
		"chaos":   brightMagenta,
		"wayback": brightYellow,
		"shodan":  brightCyan,
		"file":    brightGreen,
	}
	c, ok := colors[src]
	if !ok {
		c = white
	}
	return c + "[" + src + "]" + reset
}

// -------------------- Globals --------------------

var (
	cfg     Config
	results []Result
	resMu   sync.Mutex
)

// ilog = informational log (always shown unless -silent)
func ilog(format string, a ...interface{}) {
	if cfg.Silent {
		return
	}
	clearProgress()
	fmt.Fprintf(os.Stderr, format, a...)
}

// -------------------- Main --------------------

func main() {
	parseFlags()
	banner()

	// ---- Subdomain Discovery ----
	var subdomains []string

	if cfg.SubdomainFile != "" && !cfg.MergeDiscovery {
		// Replace mode: use only the file
		ilog("%s[INPUT]%s Loading subdomains from %s%s%s\n",
			brightCyan, reset, bold, cfg.SubdomainFile, reset)
		subdomains = loadSubdomainFile(cfg.SubdomainFile, cfg.Domain)
		ilog("%s[+]%s %s%d%s subdomains loaded from file\n",
			brightGreen, reset, bold, len(subdomains), reset)
		// still need to init the source maps
		sourceMap := make(map[string][]string)
		portMap := make(map[string][]int)
		for _, s := range subdomains {
			sourceMap[s] = []string{"file"}
		}
		subSources = sourceMap
		subExtraPorts = portMap
	} else {
		// Normal discovery (or merge mode)
		ilog("%s[*]%s Discovering subdomains for %s%s%s\n",
			brightBlue, reset, bold, cfg.Domain, reset)
		discovered := discoverSubdomains(cfg.Domain)

		if cfg.SubdomainFile != "" && cfg.MergeDiscovery {
			// Merge mode: discovered + file
			ilog("%s[INPUT]%s Merging file %s%s%s with discovery results\n",
				brightCyan, reset, bold, cfg.SubdomainFile, reset)
			fileSubs := loadSubdomainFile(cfg.SubdomainFile, cfg.Domain)
			ilog("%s[+]%s %s%d%s subdomains from file\n",
				brightGreen, reset, bold, len(fileSubs), reset)
			merged := mergeSubdomains(discovered, fileSubs)
			subdomains = merged
		} else {
			subdomains = discovered
		}
	}

	if len(subdomains) == 0 {
		ilog("%s[-]%s No subdomains discovered. Exiting.\n", brightRed, reset)
		os.Exit(1)
	}
	ilog("%s[+]%s Total unique subdomains: %s%d%s\n",
		brightGreen, reset, bold, len(subdomains), reset)

	urls := generateURLs(subdomains)
	ilog("%s[*]%s Probing %s%d%s endpoints  threads:%s%d%s  timeout:%s%ds%s\n\n",
		brightBlue, reset,
		bold, len(urls), reset,
		cyan, cfg.Threads, reset,
		cyan, cfg.Timeout, reset)

	// Print header row
	printVerbHeader()

	// Start progress ticker
	atomic.StoreInt64(&progress.total, int64(len(urls)))
	progress.startTime = time.Now()
	ticker := time.NewTicker(100 * time.Millisecond)
	tickerDone := make(chan struct{})
	go func() {
		for {
			select {
			case <-ticker.C:
				printProgress(false)
			case <-tickerDone:
				return
			}
		}
	}()

	probeAll(urls)

	ticker.Stop()
	close(tickerDone)
	clearProgress()

	elapsed := time.Since(progress.startTime)
	ilog("\n%s[+]%s Probe complete in %s%s%s — %s%d%s hosts with copyright content\n",
		brightGreen, reset,
		bold, formatDuration(elapsed), reset,
		bold, len(results), reset)

	results = applyYearFilter(results)
	ilog("%s[+]%s After filter: %s%d%s matching hosts\n",
		brightGreen, reset, bold, len(results), reset)

	if len(results) == 0 {
		ilog("%s[-]%s No results matched the filter. Skipping report.\n", yellow, reset)
		return
	}

	sort.Slice(results, func(i, j int) bool {
		if cfg.YearOp == "smart" && results[i].SmartScore != results[j].SmartScore {
			return results[i].SmartScore > results[j].SmartScore
		}
		if results[i].Severity != results[j].Severity {
			return severityRank(results[i].Severity) > severityRank(results[j].Severity)
		}
		return results[i].OldestYear < results[j].OldestYear
	})

	writeHTML()
	writeJSON()
	writeCSV()
	printSummary()
}

func printVerbHeader() {
	if cfg.Silent {
		return
	}
	header := fmt.Sprintf(" %s%-9s%s %s%-3s%s %s%-3s%s %s%-45s%s %s%-50s%s %s%-9s%s  %s\n",
		dim, "SEVERITY", reset,
		dim, "SC", reset,
		dim, "TLS", reset,
		dim, "TARGET", reset,
		dim, "TITLE", reset,
		dim, "YEARS", reset,
		dim+"SIZE"+reset,
	)
	fmt.Fprint(os.Stderr, header)
	sep := dim + " " + strings.Repeat("─", 160) + reset + "\n"
	fmt.Fprint(os.Stderr, sep)
}

func printSummary() {
	s := computeStats()
	ilog("\n%s╔══════════════════════════════════════╗%s\n", brightBlue, reset)
	ilog("%s║%s   %sGoStale Scan Summary%s                %s║%s\n", brightBlue, reset, bold+brightWhite, reset, brightBlue, reset)
	ilog("%s╠══════════════════════════════════════╣%s\n", brightBlue, reset)
	ilog("%s║%s   Total Hosts Found  : %s%-5d%s          %s║%s\n", brightBlue, reset, bold, s.total, reset, brightBlue, reset)
	ilog("%s║%s   Critical           : %s%-5d%s          %s║%s\n", brightBlue, reset, bgRed+bold, s.critical, reset, brightBlue, reset)
	ilog("%s║%s   High               : %s%-5d%s          %s║%s\n", brightBlue, reset, brightRed+bold, s.high, reset, brightBlue, reset)
	ilog("%s║%s   Medium             : %s%-5d%s          %s║%s\n", brightBlue, reset, brightYellow, s.medium, reset, brightBlue, reset)
	ilog("%s║%s   Low                : %s%-5d%s          %s║%s\n", brightBlue, reset, green, s.low, reset, brightBlue, reset)
	ilog("%s╠══════════════════════════════════════╣%s\n", brightBlue, reset)
	ilog("%s║%s   report.html / .json / .csv        %s║%s\n", brightBlue, reset, brightBlue, reset)
	ilog("%s╚══════════════════════════════════════╝%s\n\n", brightBlue, reset)
}

func banner() {
	if cfg.Silent {
		return
	}
	fmt.Fprintf(os.Stderr, `
%s  ██████╗  ██████╗ ███████╗████████╗ █████╗ ██╗     ███████╗%s
%s ██╔════╝ ██╔═══██╗██╔════╝╚══██╔══╝██╔══██╗██║     ██╔════╝%s
%s ██║  ███╗██║   ██║███████╗   ██║   ███████║██║     █████╗  %s
%s ██║   ██║██║   ██║╚════██║   ██║   ██╔══██║██║     ██╔══╝  %s
%s ╚██████╔╝╚██████╔╝███████║   ██║   ██║  ██║███████╗███████╗%s
%s  ╚═════╝  ╚═════╝ ╚══════╝   ╚═╝   ╚═╝  ╚═╝╚══════╝╚══════╝%s

`,
		brightCyan, reset,
		brightCyan, reset,
		cyan, reset,
		cyan, reset,
		blue, reset,
		blue, reset,
	)
	fmt.Fprintf(os.Stderr, "  %sCopyright Staleness Scanner%s  %sv2.3%s  %sby GoStale%s\n",
		bold+brightWhite, reset, brightYellow, reset, dim, reset)
	fmt.Fprintf(os.Stderr, "  %s────────────────────────────────────────────────%s\n", dim, reset)
	fmt.Fprintf(os.Stderr, "  %sTarget:%s  %s%s%s\n", dim, reset, bold+brightGreen, cfg.Domain, reset)
	fmt.Fprintf(os.Stderr, "  %sFilter:%s  %s%s%s\n", dim, reset, brightYellow, filterDescription(), reset)
	fmt.Fprintf(os.Stderr, "  %s────────────────────────────────────────────────%s\n\n", dim, reset)
}

func filterDescription() string {
	switch cfg.YearOp {
	case "lt":
		return fmt.Sprintf("copyright year < %d", cfg.Year)
	case "gt":
		return fmt.Sprintf("copyright year > %d", cfg.Year)
	case "eq":
		return fmt.Sprintf("copyright year = %d", cfg.Year)
	case "range":
		return fmt.Sprintf("copyright year in [%d, %d]", cfg.Year, cfg.YearEnd)
	case "smart":
		return "SMART MODE (staleness + cluster outliers + risk priority)"
	}
	return "unknown"
}

// -------------------- CLI --------------------

func parseFlags() {
	flag.StringVar(&cfg.Domain, "domain", "", "Target domain (required)")
	flag.StringVar(&cfg.YearOp, "year-op", "lt", "Filter operator: lt|gt|eq|range|smart")
	flag.IntVar(&cfg.Year, "year", 0, "Year value (required unless -year-op=smart). For range, the lower bound.")
	flag.IntVar(&cfg.YearEnd, "year-end", 0, "Upper-bound year (only for -year-op=range)")
	flag.StringVar(&cfg.OutputFile, "output", "report", "Output filename prefix")
	flag.IntVar(&cfg.Threads, "threads", 30, "Concurrent probe workers")
	flag.IntVar(&cfg.Timeout, "timeout", 10, "Per-request timeout in seconds")
	// API key flags (override env)
	flag.StringVar(&cfg.ChaosKey, "chaos-key", "", "Chaos API key (overrides CHAOS_API_KEY env)")
	flag.StringVar(&cfg.ShodanKey, "shodan-key", "", "Shodan API key (will run 'shodan init <key>' if needed)")
	// Subdomain list
	flag.StringVar(&cfg.SubdomainFile, "subdomains", "", "Path to a file with one subdomain per line (replaces discovery by default)")
	flag.BoolVar(&cfg.MergeDiscovery, "merge-discovery", false, "When -subdomains is set, merge file list with discovered subdomains instead of replacing")
	// Output control
	flag.BoolVar(&cfg.Silent, "silent", false, "Suppress all output except errors")
	flag.BoolVar(&cfg.NoColor, "no-color", false, "Disable color output")
	flag.Parse()

	if cfg.Domain == "" {
		usage("-domain is required")
	}

	cfg.YearOp = strings.ToLower(cfg.YearOp)
	switch cfg.YearOp {
	case "lt", "gt", "eq":
		if cfg.Year == 0 {
			usage(fmt.Sprintf("-year is required when -year-op=%s", cfg.YearOp))
		}
	case "range":
		if cfg.Year == 0 || cfg.YearEnd == 0 {
			usage("-year and -year-end are both required when -year-op=range")
		}
		if cfg.Year > cfg.YearEnd {
			cfg.Year, cfg.YearEnd = cfg.YearEnd, cfg.Year
		}
	case "smart":
		// no year required
	default:
		usage(fmt.Sprintf("invalid -year-op %q (use lt|gt|eq|range|smart)", cfg.YearOp))
	}

	// Resolve Chaos key: flag > env
	if cfg.ChaosKey == "" {
		cfg.ChaosKey = os.Getenv("CHAOS_API_KEY")
	}

	// Resolve Shodan key: flag > env > interactive prompt (handled in discoverSubdomains)
	if cfg.ShodanKey == "" {
		cfg.ShodanKey = os.Getenv("SHODAN_API_KEY")
	}
}

func usage(msg string) {
	fmt.Fprintf(os.Stderr, "%s%sError:%s %s\n\n", bold, red, reset, msg)
	fmt.Fprintln(os.Stderr, bold+"Usage:"+reset)
	fmt.Fprintln(os.Stderr, "  scanner -domain <domain> -year-op <op> [-year N] [flags]")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, bold+"Key Flags:"+reset)
	fmt.Fprintln(os.Stderr, "  -chaos-key <key>       Chaos API key (or set CHAOS_API_KEY env)")
	fmt.Fprintln(os.Stderr, "  -shodan-key <key>      Shodan API key (interactive prompt if missing)")
	fmt.Fprintln(os.Stderr, "  -subdomains <file>     Feed a subdomain list directly (one per line)")
	fmt.Fprintln(os.Stderr, "  -merge-discovery       Merge -subdomains file with auto-discovered ones")
	fmt.Fprintln(os.Stderr, "  -silent                Suppress verbose output")
	fmt.Fprintln(os.Stderr, "  -no-color              Disable ANSI colors")
	fmt.Fprintln(os.Stderr, "")
	flag.PrintDefaults()
	os.Exit(1)
}

// -------------------- Subdomain File Loader --------------------

func loadSubdomainFile(path, domain string) []string {
	f, err := os.Open(path)
	if err != nil {
		ilog("%s[!] Cannot open subdomain file: %v%s\n", brightRed, err, reset)
		return nil
	}
	defer f.Close()

	seen := make(map[string]bool)
	var out []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// If it's a bare label (no dot), expand to FQDN before cleanHost validation
		if !strings.Contains(line, ".") && line != "" {
			line = line + "." + domain
		}
		host, ok := cleanHost(line)
		if !ok {
			continue
		}
		if !inScope(host, domain) {
			continue
		}
		if !seen[host] {
			seen[host] = true
			out = append(out, host)
		}
	}
	return out
}

func mergeSubdomains(discovered, fromFile []string) []string {
	seen := make(map[string]bool)
	for _, s := range discovered {
		seen[s] = true
	}
	out := append([]string{}, discovered...)
	added := 0
	for _, s := range fromFile {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
			added++
			// Mark file source
			if subSources != nil {
				subSources[s] = append(subSources[s], "file")
			}
		}
	}
	if added > 0 {
		ilog("%s[+]%s %s%d%s new subdomains added from file\n",
			brightGreen, reset, bold, added, reset)
	}
	return out
}

// -------------------- Discovery --------------------

type SubdomainInfo struct {
	Host    string
	Sources map[string]bool
	Ports   map[int]bool
}

func newSubdomainInfo(host string) *SubdomainInfo {
	return &SubdomainInfo{
		Host:    host,
		Sources: make(map[string]bool),
		Ports:   make(map[int]bool),
	}
}

func inScope(host, domain string) bool {
	host = strings.ToLower(strings.TrimSpace(host))
	domain = strings.ToLower(strings.TrimSpace(domain))
	if host == "" || domain == "" {
		return false
	}
	if host == domain {
		return true
	}
	return strings.HasSuffix(host, "."+domain)
}

func cleanHost(s string) (string, bool) {
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "" {
		return "", false
	}
	if i := strings.Index(s, "://"); i != -1 {
		s = s[i+3:]
	}
	if i := strings.IndexAny(s, "/?#"); i != -1 {
		s = s[:i]
	}
	if i := strings.Index(s, ":"); i != -1 {
		s = s[:i]
	}
	s = strings.TrimPrefix(s, "*.")
	s = strings.Trim(s, ".")
	if s == "" {
		return "", false
	}
	// Reject anything with spaces or HTML/shell characters first
	for _, c := range s {
		if c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '"' || c == '\'' || c == '<' || c == '>' {
			return "", false
		}
	}
	// Reject bare single-label names (localhost, etc.) — no dot = not a useful hostname
	if !strings.Contains(s, ".") {
		return "", false
	}
	return s, true
}

func discoverSubdomains(domain string) []string {
	unique := make(map[string]*SubdomainInfo)
	var mu sync.Mutex
	var wg sync.WaitGroup

	add := func(host, source string) {
		clean, ok := cleanHost(host)
		if !ok || !inScope(clean, domain) {
			return
		}
		mu.Lock()
		defer mu.Unlock()
		info, exists := unique[clean]
		if !exists {
			info = newSubdomainInfo(clean)
			unique[clean] = info
		}
		info.Sources[source] = true
	}

	addWithPorts := func(host, source string, ports []int) {
		clean, ok := cleanHost(host)
		if !ok || !inScope(clean, domain) {
			return
		}
		mu.Lock()
		defer mu.Unlock()
		info, exists := unique[clean]
		if !exists {
			info = newSubdomainInfo(clean)
			unique[clean] = info
		}
		info.Sources[source] = true
		for _, p := range ports {
			if p > 0 && p <= 65535 {
				info.Ports[p] = true
			}
		}
	}

	// 1. crt.sh
	wg.Add(1)
	go func() {
		defer wg.Done()
		ilog("  %s crt.sh%s querying certificate transparency logs...\n", brightBlue, reset)
		subs, crtErr := fetchCrtSh(domain)
		if crtErr != nil {
			// LOUD fallback notice
			ilog("  %s⚠ crt.sh%s %sFAILED%s — %v — continuing without it\n",
				brightYellow, reset, brightRed+bold, reset, crtErr)
			ilog("  %s  Tip: crt.sh is often rate-limited or slow. Try again later.%s\n", dim, reset)
		} else {
			for _, s := range subs {
				add(s, "crt.sh")
			}
			ilog("  %s✓ crt.sh%s %s%d%s subdomains\n",
				brightGreen, reset, bold, len(subs), reset)
		}
	}()

	// 2. Chaos
	wg.Add(1)
	go func() {
		defer wg.Done()
		if cfg.ChaosKey == "" {
			ilog("  %s- chaos%s skipped %s(use -chaos-key <key> or set CHAOS_API_KEY)%s\n",
				dim, reset, dim, reset)
			return
		}
		ilog("  %s chaos%s querying ProjectDiscovery Chaos...\n", brightMagenta, reset)
		subs := fetchChaos(domain, cfg.ChaosKey)
		for _, s := range subs {
			var fqdn string
			if strings.Contains(s, ".") {
				fqdn = s
			} else if s != "" {
				fqdn = s + "." + domain
			}
			if fqdn != "" {
				add(fqdn, "chaos")
			}
		}
		ilog("  %s✓ chaos%s %s%d%s subdomains\n",
			brightGreen, reset, bold, len(subs), reset)
	}()

	// 3. Wayback Machine
	wg.Add(1)
	go func() {
		defer wg.Done()
		ilog("  %s wayback%s querying Wayback Machine CDX API...\n", brightYellow, reset)
		subs := fetchWayback(domain)
		for _, s := range subs {
			add(s, "wayback")
		}
		ilog("  %s✓ wayback%s %s%d%s subdomains\n",
			brightGreen, reset, bold, len(subs), reset)
	}()

	// 4. Shodan
	wg.Add(1)
	go func() {
		defer wg.Done()
		if !commandExists("shodan") {
			ilog("  %s- shodan%s skipped %s(shodan CLI not found in PATH)%s\n",
				dim, reset, dim, reset)
			return
		}

		// Check init status
		key, skipShodan := resolveShodanKey()
		if skipShodan {
			ilog("  %s- shodan%s skipped by user\n", dim, reset)
			return
		}
		if key != "" {
			ilog("  %s shodan%s initialising with provided key...\n", brightCyan, reset)
			initOut, err := exec.Command("shodan", "init", key).CombinedOutput()
			if err != nil {
				ilog("  %s⚠ shodan init failed:%s %v\n  %s%s%s\n",
					brightRed, reset, err, dim, strings.TrimSpace(string(initOut)), reset)
			} else {
				ilog("  %s✓ shodan%s initialised successfully\n", brightGreen, reset)
			}
		}

		ilog("  %s shodan%s querying domain records...\n", brightCyan, reset)
		records, err := fetchShodan(domain)
		if err != nil {
			ilog("  %s⚠ shodan%s error: %v\n", brightRed, reset, err)
			return
		}
		count := 0
		for _, rec := range records {
			addWithPorts(rec.Host, "shodan", rec.Ports)
			count++
		}
		ilog("  %s✓ shodan%s %s%d%s records\n",
			brightGreen, reset, bold, count, reset)
	}()

	wg.Wait()

	out := make([]string, 0, len(unique))
	sourceMap := make(map[string][]string)
	portMap := make(map[string][]int)
	for host, info := range unique {
		out = append(out, host)
		for src := range info.Sources {
			sourceMap[host] = append(sourceMap[host], src)
		}
		for p := range info.Ports {
			portMap[host] = append(portMap[host], p)
		}
		sort.Strings(sourceMap[host])
		sort.Ints(portMap[host])
	}
	subSources = sourceMap
	subExtraPorts = portMap
	return out
}

var (
	subSources    map[string][]string
	subExtraPorts map[string][]int
)

// resolveShodanKey figures out what Shodan key to use (if any).
// Priority: -shodan-key flag → SHODAN_API_KEY env → check if already init'd → interactive prompt → skip.
// Returns (key, shouldSkip).
// If key == "" and shouldSkip == false, the caller should proceed with shodan already init'd.
func resolveShodanKey() (string, bool) {
	// 1. Key already provided via flag or env
	if cfg.ShodanKey != "" {
		return cfg.ShodanKey, false
	}

	// 2. Check if shodan is already initialised by running `shodan info`
	infoOut, err := exec.Command("shodan", "info").CombinedOutput()
	if err == nil {
		infoStr := strings.ToLower(strings.TrimSpace(string(infoOut)))
		// If it shows an API plan it's init'd; "not initialised" or "error" means it's not
		if !strings.Contains(infoStr, "not initialized") &&
			!strings.Contains(infoStr, "please run") &&
			!strings.Contains(infoStr, "error") {
			return "", false // already init'd, no key needed
		}
	}

	// 3. Interactive prompt (only if stdin is a TTY)
	fmt.Fprintf(os.Stderr, "\n%s[shodan]%s Not initialized. Options:\n", brightYellow, reset)
	fmt.Fprintf(os.Stderr, "  %s[1]%s Enter your Shodan API key now\n", cyan, reset)
	fmt.Fprintf(os.Stderr, "  %s[2]%s Skip Shodan enumeration\n", cyan, reset)
	fmt.Fprintf(os.Stderr, "%sChoice [1/2]:%s ", brightWhite, reset)

	reader := bufio.NewReader(os.Stdin)
	choice, _ := reader.ReadString('\n')
	choice = strings.TrimSpace(choice)

	if choice == "2" || strings.ToLower(choice) == "s" || strings.ToLower(choice) == "skip" {
		return "", true
	}

	if choice == "1" || choice == "" {
		fmt.Fprintf(os.Stderr, "%sShodan API key:%s ", brightWhite, reset)
		key, _ := reader.ReadString('\n')
		key = strings.TrimSpace(key)
		if key == "" {
			fmt.Fprintf(os.Stderr, "%s[shodan] No key entered — skipping%s\n", yellow, reset)
			return "", true
		}
		return key, false
	}

	// Treat any other input as the key itself (they may have pasted the key)
	if len(choice) > 10 {
		return choice, false
	}

	return "", true
}

// -------------------- crt.sh --------------------

func fetchCrtSh(domain string) ([]string, error) {
	apiURL := "https://crt.sh/?q=%25." + domain + "&output=json"
	client := &http.Client{Timeout: 60 * time.Second}

	var resp *http.Response
	var lastErr error
	for i := 0; i < 3; i++ {
		req, _ := http.NewRequest("GET", apiURL, nil)
		req.Header.Set("User-Agent", "GoStale/2.3 (+recon)")
		r, err := client.Do(req)
		lastErr = err
		if err == nil && r.StatusCode == 200 {
			resp = r
			break
		}
		if r != nil {
			r.Body.Close()
		}
		if i < 2 {
			ilog("  %s  crt.sh retry %d/3...%s\n", dim, i+2, reset)
			time.Sleep(time.Duration(i+1) * 2 * time.Second)
		}
	}
	if resp == nil {
		if lastErr != nil {
			return nil, lastErr
		}
		return nil, fmt.Errorf("crt.sh returned non-200 after 3 retries")
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 50*1024*1024))
	if err != nil {
		return nil, err
	}

	var data []CrtShResult
	if err := json.Unmarshal(body, &data); err != nil {
		for _, line := range strings.Split(string(body), "\n") {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			var one CrtShResult
			if json.Unmarshal([]byte(line), &one) == nil {
				data = append(data, one)
			}
		}
		if len(data) == 0 {
			return nil, fmt.Errorf("crt.sh response parse error: %v", err)
		}
	}

	out := make([]string, 0, len(data)*2)
	out = append(out, domain)
	for _, r := range data {
		for _, n := range strings.Split(r.NameValue, "\n") {
			n = strings.TrimSpace(n)
			n = strings.TrimPrefix(n, "*.")
			if n != "" {
				out = append(out, n)
			}
		}
	}
	return out, nil
}

// -------------------- Other Discovery Sources --------------------

func fetchChaos(domain, key string) []string {
	apiURL := fmt.Sprintf("https://dns.projectdiscovery.io/dns/%s/subdomains", domain)
	req, _ := http.NewRequest("GET", apiURL, nil)
	req.Header.Set("Authorization", key)
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil || resp.StatusCode != 200 {
		if resp != nil {
			resp.Body.Close()
		}
		return nil
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	var data ChaosResult
	if err := json.Unmarshal(body, &data); err != nil {
		return nil
	}
	return data.Subdomains
}

func fetchWayback(domain string) []string {
	apiURL := fmt.Sprintf("https://web.archive.org/cdx/search/cdx?url=*.%s/*&output=json&fl=original&collapse=urlkey", url.QueryEscape(domain))
	client := &http.Client{Timeout: 90 * time.Second}
	req, _ := http.NewRequest("GET", apiURL, nil)
	req.Header.Set("User-Agent", "GoStale/2.3 (+recon)")
	resp, err := client.Do(req)
	if err != nil {
		ilog("  %s⚠ wayback error: %v%s\n", yellow, err, reset)
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		ilog("  %s⚠ wayback HTTP %d%s\n", yellow, resp.StatusCode, reset)
		return nil
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 100*1024*1024))
	if err != nil {
		return nil
	}
	var data [][]string
	if err := json.Unmarshal(body, &data); err != nil {
		return nil
	}
	seen := make(map[string]bool)
	for i, row := range data {
		if len(row) == 0 {
			continue
		}
		if i == 0 && row[0] == "original" {
			continue
		}
		u, err := url.Parse(row[0])
		if err != nil {
			continue
		}
		h := strings.ToLower(u.Hostname())
		if h != "" {
			seen[h] = true
		}
	}
	out := make([]string, 0, len(seen))
	for h := range seen {
		out = append(out, h)
	}
	return out
}

// -------------------- Shodan --------------------

type ShodanRecord struct {
	Host  string
	Type  string
	Value string
	Ports []int
}

var ansiRegex = regexp.MustCompile(`\x1b\[[0-9;]*[a-zA-Z]`)
var shodanPortsRegex = regexp.MustCompile(`(?i)\bPorts:\s*([\d,\s]+?)\s*$`)

func fetchShodan(domain string) ([]ShodanRecord, error) {
	const shodanTimeout = 120 * time.Second

	ctx, cancel := context.WithTimeout(context.Background(), shodanTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, "shodan", "domain", "-D", domain)
	output, err := cmd.CombinedOutput()

	if ctx.Err() == context.DeadlineExceeded {
		return nil, fmt.Errorf("shodan CLI timed out after %s", shodanTimeout)
	}

	outStr := string(output)
	if isShodanFatalError(outStr) {
		return nil, fmt.Errorf("shodan CLI: %s", strings.TrimSpace(strings.SplitN(outStr, "\n", 2)[0]))
	}

	if err != nil {
		ctx2, cancel2 := context.WithTimeout(context.Background(), shodanTimeout)
		defer cancel2()

		cmd2 := exec.CommandContext(ctx2, "shodan", "domain", domain)
		output2, err2 := cmd2.CombinedOutput()

		if ctx2.Err() == context.DeadlineExceeded {
			return nil, fmt.Errorf("shodan CLI timed out after %s", shodanTimeout)
		}
		if err2 != nil {
			return nil, fmt.Errorf("shodan CLI failed: %v (output: %s)", err, strings.TrimSpace(string(output)))
		}
		if isShodanFatalError(string(output2)) {
			return nil, fmt.Errorf("shodan CLI: %s", strings.TrimSpace(strings.SplitN(string(output2), "\n", 2)[0]))
		}
		output = output2
	}

	return parseShodanOutput(string(output), domain), nil
}

func isShodanFatalError(s string) bool {
	s = strings.TrimSpace(s)
	if s == "" {
		return false
	}
	first := s
	if i := strings.Index(s, "\n"); i != -1 {
		first = s[:i]
	}
	first = strings.TrimSpace(first)
	lower := strings.ToLower(first)
	return strings.HasPrefix(lower, "error:") ||
		strings.HasPrefix(lower, "usage:") ||
		strings.Contains(lower, "please run \"shodan init") ||
		strings.Contains(lower, "no information available")
}

func parseShodanOutput(raw, domain string) []ShodanRecord {
	domain = strings.ToLower(strings.TrimSpace(domain))
	upperHeader := strings.ToUpper(domain)
	known := map[string]bool{"A": true, "AAAA": true, "CNAME": true, "MX": true, "NS": true, "TXT": true, "SOA": true, "PTR": true}

	var out []ShodanRecord
	for _, rawLine := range strings.Split(raw, "\n") {
		line := ansiRegex.ReplaceAllString(rawLine, "")
		line = strings.TrimRight(line, " \t\r")
		if line == "" {
			continue
		}
		if strings.TrimSpace(line) == upperHeader {
			continue
		}
		trimLine := strings.TrimSpace(line)
		if strings.HasPrefix(trimLine, "Error:") ||
			strings.HasPrefix(trimLine, "Usage:") ||
			strings.HasPrefix(trimLine, "Please ") ||
			strings.HasPrefix(trimLine, "No information") {
			continue
		}

		var ports []int
		if m := shodanPortsRegex.FindStringSubmatchIndex(line); m != nil {
			portStr := line[m[2]:m[3]]
			for _, p := range strings.Split(portStr, ",") {
				p = strings.TrimSpace(p)
				if n, err := strconv.Atoi(p); err == nil && n > 0 && n <= 65535 {
					ports = append(ports, n)
				}
			}
			line = strings.TrimRight(line[:m[0]], " \t")
		}

		if len(line) < 48 {
			if rec, ok := parseShodanShortLine(line, domain); ok {
				rec.Ports = ports
				out = append(out, rec)
			}
			continue
		}
		subPart := strings.TrimSpace(line[:32])
		typePart := strings.TrimSpace(line[32:46])
		valuePart := strings.TrimSpace(line[46:])

		if !known[strings.ToUpper(typePart)] {
			if rec, ok := parseShodanShortLine(line, domain); ok {
				rec.Ports = ports
				out = append(out, rec)
			}
			continue
		}

		recType := strings.ToUpper(typePart)
		host := buildShodanHost(subPart, domain)
		rec := ShodanRecord{Host: host, Type: recType, Value: valuePart, Ports: ports}

		if recType == "MX" {
			parts := strings.Fields(valuePart)
			if len(parts) >= 2 {
				if _, err := strconv.Atoi(parts[0]); err == nil {
					rec.Value = parts[len(parts)-1]
				}
			}
		}
		out = append(out, rec)
	}
	return out
}

func parseShodanShortLine(line, domain string) (ShodanRecord, bool) {
	fields := strings.Fields(line)
	known := map[string]bool{"A": true, "AAAA": true, "CNAME": true, "MX": true, "NS": true, "TXT": true, "SOA": true, "PTR": true}

	if len(fields) >= 3 && known[strings.ToUpper(fields[1])] {
		recType := strings.ToUpper(fields[1])
		value := strings.Join(fields[2:], " ")
		host := buildShodanHost(fields[0], domain)
		return ShodanRecord{Host: host, Type: recType, Value: value}, true
	}
	if len(fields) >= 2 && known[strings.ToUpper(fields[0])] {
		recType := strings.ToUpper(fields[0])
		value := strings.Join(fields[1:], " ")
		return ShodanRecord{Host: domain, Type: recType, Value: value}, true
	}
	return ShodanRecord{}, false
}

func buildShodanHost(sub, domain string) string {
	sub = strings.ToLower(strings.TrimSpace(sub))
	sub = strings.Trim(sub, ".")
	domain = strings.ToLower(domain)
	if sub == "" {
		return domain
	}
	if sub == domain {
		return domain
	}
	if strings.HasSuffix(sub, "."+domain) {
		return sub
	}
	return sub + "." + domain
}

func commandExists(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

// -------------------- URL Generation --------------------

func generateURLs(subdomains []string) []string {
	var urls []string
	for _, sub := range subdomains {
		urls = append(urls, "http://"+sub, "https://"+sub)
		for _, p := range subExtraPorts[sub] {
			if p == 80 || p == 443 {
				continue
			}
			if p == 8443 || p == 9443 || p == 4443 {
				urls = append(urls, fmt.Sprintf("https://%s:%d", sub, p), fmt.Sprintf("http://%s:%d", sub, p))
				continue
			}
			urls = append(urls,
				fmt.Sprintf("http://%s:%d", sub, p),
				fmt.Sprintf("https://%s:%d", sub, p),
			)
		}
	}
	return urls
}

// -------------------- Probing --------------------

func probeAll(urls []string) {
	var wg sync.WaitGroup
	sem := make(chan struct{}, cfg.Threads)
	probed := make(map[string]Result)
	var pmu sync.Mutex

	for _, u := range urls {
		wg.Add(1)
		sem <- struct{}{}
		go func(target string) {
			defer wg.Done()
			defer func() { <-sem }()
			r, ok := probe(target)
			atomic.AddInt64(&progress.done, 1)
			if !ok {
				atomic.AddInt64(&progress.errors, 1)
				return
			}
			atomic.AddInt64(&progress.found, 1)

			key := r.Hostname + ":" + r.Port
			pmu.Lock()
			existing, exists := probed[key]
			if !exists {
				probed[key] = r
				pmu.Unlock()
				logVerb(r)
				return
			}
			existingHTTPS := strings.HasPrefix(existing.URL, "https://")
			newHTTPS := strings.HasPrefix(r.URL, "https://")
			if newHTTPS && !existingHTTPS {
				probed[key] = r
				pmu.Unlock()
				logVerb(r)
				return
			}
			pmu.Unlock()
		}(u)
	}
	wg.Wait()

	resMu.Lock()
	defer resMu.Unlock()
	for _, r := range probed {
		results = append(results, r)
	}
}

func probe(targetURL string) (Result, bool) {
	start := time.Now()
	parsed, err := url.Parse(targetURL)
	if err != nil {
		return Result{}, false
	}

	tlsValid := true
	tlsExpiry := ""

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		DialContext: (&net.Dialer{
			Timeout: time.Duration(cfg.Timeout) * time.Second,
		}).DialContext,
		MaxIdleConns:        10,
		IdleConnTimeout:     30 * time.Second,
		TLSHandshakeTimeout: 5 * time.Second,
		DisableKeepAlives:   true,
	}
	client := &http.Client{
		Transport: tr,
		Timeout:   time.Duration(cfg.Timeout) * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}

	req, err := http.NewRequest("GET", targetURL, nil)
	if err != nil {
		return Result{}, false
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36")
	req.Header.Set("Accept", "text/html,application/xhtml+xml")

	resp, err := client.Do(req)
	if err != nil {
		return Result{}, false
	}
	defer resp.Body.Close()

	if parsed.Scheme == "https" && resp.TLS != nil && len(resp.TLS.PeerCertificates) > 0 {
		cert := resp.TLS.PeerCertificates[0]
		tlsExpiry = cert.NotAfter.Format("2006-01-02")
		if err := cert.VerifyHostname(parsed.Hostname()); err != nil {
			tlsValid = false
		}
		if time.Now().After(cert.NotAfter) {
			tlsValid = false
		}
	}

	bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, 2*1024*1024))
	if err != nil {
		return Result{}, false
	}
	body := string(bodyBytes)

	years := extractYears(body)
	if len(years) == 0 {
		return Result{}, false
	}
	oldest := years[0]
	latest := years[0]
	for _, y := range years {
		if y < oldest {
			oldest = y
		}
		if y > latest {
			latest = y
		}
	}

	rt := time.Since(start).Milliseconds()

	r := Result{
		URL:            targetURL,
		Hostname:       parsed.Hostname(),
		Port:           inferPort(parsed),
		StatusCode:     resp.StatusCode,
		Title:          extractTitle(body),
		Server:         resp.Header.Get("Server"),
		TechStack:      detectTech(body, resp.Header),
		FaviconHash:    favHash(parsed),
		ScreenshotURL:  "https://image.thum.io/get/width/800/" + url.QueryEscape(targetURL),
		CopyrightYears: years,
		OldestYear:     oldest,
		LatestYear:     latest,
		TLSValid:       tlsValid,
		TLSExpiry:      tlsExpiry,
		ContentLength:  len(bodyBytes),
		Source:         subSources[parsed.Hostname()],
		ResponseTime:   rt,
	}
	r.IP = resolveIP(r.Hostname)
	r.DNSRecords = lookupDNS(r.Hostname)
	r.CDN, r.WAF = detectCDNWAF(resp.Header, r.DNSRecords)
	r.Severity, r.Tags = computeSeverity(r)

	return r, true
}

// -------------------- Extractors --------------------

var yearRegex = regexp.MustCompile(`(?i)(?:©|&copy;|&#0*169;|&#x0*a9;|\bcopyright\b|\bcopr\.)[^0-9]{0,40}(\d{4})(?:\s*[-–—/,]\s*(\d{4}))?`)

func extractYears(body string) []int {
	matches := yearRegex.FindAllStringSubmatch(body, -1)
	seen := make(map[int]bool)
	var years []int
	for _, m := range matches {
		for _, g := range m[1:] {
			if g == "" {
				continue
			}
			y, err := strconv.Atoi(g)
			if err != nil {
				continue
			}
			if y >= 1990 && y <= time.Now().Year()+1 && !seen[y] {
				seen[y] = true
				years = append(years, y)
			}
		}
	}
	sort.Ints(years)
	return years
}

var titleRegex = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)

func extractTitle(body string) string {
	m := titleRegex.FindStringSubmatch(body)
	if len(m) < 2 {
		return ""
	}
	t := strings.TrimSpace(m[1])
	t = regexp.MustCompile(`\s+`).ReplaceAllString(t, " ")
	if len(t) > 120 {
		t = t[:120] + "..."
	}
	return t
}

func inferPort(u *url.URL) string {
	if p := u.Port(); p != "" {
		return p
	}
	if u.Scheme == "https" {
		return "443"
	}
	return "80"
}

func resolveIP(host string) string {
	ips, err := net.LookupIP(host)
	if err != nil || len(ips) == 0 {
		return ""
	}
	for _, ip := range ips {
		if v4 := ip.To4(); v4 != nil {
			return v4.String()
		}
	}
	return ips[0].String()
}

func lookupDNS(host string) DNSInfo {
	var d DNSInfo
	if ips, err := net.LookupIP(host); err == nil {
		for _, ip := range ips {
			if v4 := ip.To4(); v4 != nil {
				d.A = append(d.A, v4.String())
			}
		}
	}
	if cname, err := net.LookupCNAME(host); err == nil {
		d.CNAME = strings.TrimSuffix(cname, ".")
	}
	if mxs, err := net.LookupMX(host); err == nil {
		for _, mx := range mxs {
			d.MX = append(d.MX, strings.TrimSuffix(mx.Host, "."))
		}
	}
	return d
}

// -------------------- Tech / CDN / WAF Detection --------------------

func detectTech(body string, headers http.Header) []string {
	var techs []string
	add := func(t string) {
		for _, x := range techs {
			if x == t {
				return
			}
		}
		techs = append(techs, t)
	}

	lower := strings.ToLower(body)

	if v := headers.Get("X-Powered-By"); v != "" {
		add(v)
	}
	if v := headers.Get("X-Generator"); v != "" {
		add(v)
	}
	if v := headers.Get("X-AspNet-Version"); v != "" {
		add("ASP.NET " + v)
	}

	fingerprints := map[string]string{
		"wp-content":           "WordPress",
		"wp-includes":          "WordPress",
		"/sites/default/files": "Drupal",
		"joomla":               "Joomla",
		"shopify":              "Shopify",
		"cdn.shopify.com":      "Shopify",
		"react":                "React",
		"ng-version":           "Angular",
		"vue.js":               "Vue.js",
		"__next_data__":        "Next.js",
		"_nuxt":                "Nuxt.js",
		"laravel_session":      "Laravel",
		"csrfmiddlewaretoken":  "Django",
		"phpsessid":            "PHP",
		"jsessionid":           "Java",
		"bootstrap":            "Bootstrap",
		"jquery":               "jQuery",
		"google-analytics.com": "Google Analytics",
		"googletagmanager":     "Google Tag Manager",
		"cloudflare":           "Cloudflare",
	}
	for sig, name := range fingerprints {
		if strings.Contains(lower, sig) {
			add(name)
		}
	}
	return techs
}

func detectCDNWAF(headers http.Header, dns DNSInfo) (cdn, waf string) {
	h := strings.ToLower(strings.Join(allHeaders(headers), " "))
	cname := strings.ToLower(dns.CNAME)

	switch {
	case strings.Contains(h, "cloudflare"), strings.Contains(cname, "cloudflare"):
		cdn = "Cloudflare"
	case strings.Contains(h, "akamai"), strings.Contains(cname, "akamai"):
		cdn = "Akamai"
	case strings.Contains(h, "cloudfront"), strings.Contains(cname, "cloudfront.net"):
		cdn = "AWS CloudFront"
	case strings.Contains(h, "fastly"), strings.Contains(cname, "fastly"):
		cdn = "Fastly"
	case strings.Contains(cname, "azureedge"):
		cdn = "Azure CDN"
	}

	switch {
	case strings.Contains(h, "cf-ray"):
		waf = "Cloudflare WAF"
	case strings.Contains(h, "x-sucuri"):
		waf = "Sucuri"
	case strings.Contains(h, "x-akamai"):
		waf = "Akamai"
	case strings.Contains(h, "incapsula"), strings.Contains(h, "imperva"):
		waf = "Imperva/Incapsula"
	case strings.Contains(h, "awselb"), strings.Contains(h, "x-amz-cf"):
		waf = "AWS WAF"
	}
	return
}

func allHeaders(h http.Header) []string {
	var out []string
	for k, v := range h {
		out = append(out, k+": "+strings.Join(v, ","))
	}
	return out
}

// -------------------- Severity --------------------

func computeSeverity(r Result) (string, []string) {
	var tags []string
	age := time.Now().Year() - r.LatestYear

	if age >= 5 {
		tags = append(tags, "Very Stale")
	} else if age >= 3 {
		tags = append(tags, "Stale")
	} else if age >= 1 {
		tags = append(tags, "Outdated")
	}

	if !r.TLSValid && strings.HasPrefix(r.URL, "https://") {
		tags = append(tags, "Invalid/Expired TLS")
	}
	if r.StatusCode >= 500 {
		tags = append(tags, "Server Error")
	}
	if r.StatusCode == 401 || r.StatusCode == 403 {
		tags = append(tags, "Auth-Gated")
	}

	lowerTitle := strings.ToLower(r.Title)
	lowerHost := strings.ToLower(r.Hostname)
	exposed := []string{"admin", "phpmyadmin", "jenkins", "kibana", "grafana", "wp-admin", "login", "dashboard", "portal"}
	for _, e := range exposed {
		if strings.Contains(lowerHost, e) || strings.Contains(lowerTitle, e) {
			tags = append(tags, "Possible Admin/Exposed Panel")
			break
		}
	}

	dev := []string{"dev", "staging", "test", "uat", "qa", "preprod"}
	for _, d := range dev {
		if strings.HasPrefix(lowerHost, d+".") || strings.Contains(lowerHost, "."+d+".") {
			tags = append(tags, "Non-Production")
			break
		}
	}

	sev := "Low"
	if age >= 3 || !r.TLSValid {
		sev = "Medium"
	}
	if age >= 5 || hasTag(tags, "Possible Admin/Exposed Panel") {
		sev = "High"
	}
	if age >= 5 && hasTag(tags, "Possible Admin/Exposed Panel") {
		sev = "Critical"
	}
	return sev, tags
}

func hasTag(tags []string, t string) bool {
	for _, x := range tags {
		if x == t {
			return true
		}
	}
	return false
}

func severityRank(s string) int {
	switch s {
	case "Critical":
		return 4
	case "High":
		return 3
	case "Medium":
		return 2
	case "Low":
		return 1
	}
	return 0
}

// -------------------- Favicon --------------------

func favHash(u *url.URL) string {
	favURL := fmt.Sprintf("%s://%s/favicon.ico", u.Scheme, u.Host)
	client := &http.Client{
		Timeout:   5 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
	}
	resp, err := client.Get(favURL)
	if err != nil || resp.StatusCode != 200 {
		if resp != nil {
			resp.Body.Close()
		}
		return ""
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
	if len(b) == 0 {
		return ""
	}
	h := md5.Sum(b)
	return base64.StdEncoding.EncodeToString(h[:])
}

// -------------------- Output Writers --------------------

func writeJSON() {
	path := cfg.OutputFile + ".json"
	f, err := os.Create(path)
	if err != nil {
		ilog("%s[-] Failed to write JSON: %v%s\n", brightRed, err, reset)
		return
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	if err := enc.Encode(results); err != nil {
		ilog("%s[-] JSON encode error: %v%s\n", brightRed, err, reset)
		return
	}
	ilog("%s[+]%s JSON  → %s%s%s\n", brightGreen, reset, bold, path, reset)
}

func writeCSV() {
	path := cfg.OutputFile + ".csv"
	f, err := os.Create(path)
	if err != nil {
		ilog("%s[-] Failed to write CSV: %v%s\n", brightRed, err, reset)
		return
	}
	defer f.Close()
	w := csv.NewWriter(f)
	defer w.Flush()

	w.Write([]string{
		"Severity", "URL", "Hostname", "IP", "Port", "Status", "Title",
		"Server", "Tech", "CDN", "WAF", "TLS Valid", "TLS Expiry",
		"Oldest Year", "Latest Year", "Tags", "Sources", "Smart Score", "Smart Reasons", "Response Time (ms)",
	})
	for _, r := range results {
		w.Write([]string{
			r.Severity, r.URL, r.Hostname, r.IP, r.Port,
			strconv.Itoa(r.StatusCode), r.Title, r.Server,
			strings.Join(r.TechStack, ", "), r.CDN, r.WAF,
			strconv.FormatBool(r.TLSValid), r.TLSExpiry,
			strconv.Itoa(r.OldestYear), strconv.Itoa(r.LatestYear),
			strings.Join(r.Tags, ", "), strings.Join(r.Source, ", "),
			strconv.Itoa(r.SmartScore), strings.Join(r.SmartReasons, "; "),
			strconv.FormatInt(r.ResponseTime, 10),
		})
	}
	ilog("%s[+]%s CSV   → %s%s%s\n", brightGreen, reset, bold, path, reset)
}

func writeHTML() {
	path := cfg.OutputFile + ".html"
	f, err := os.Create(path)
	if err != nil {
		ilog("%s[-] Failed to write HTML: %v%s\n", brightRed, err, reset)
		return
	}
	defer f.Close()

	jsonBytes, _ := json.Marshal(results)
	stats := computeStats()

	fmt.Fprintf(f, htmlTemplate,
		cfg.Domain,
		cfg.Domain,
		filterDescription(),
		time.Now().Format("2006-01-02 15:04:05 MST"),
		stats.total, stats.critical, stats.high, stats.medium, stats.low,
		string(jsonBytes),
	)
	ilog("%s[+]%s HTML  → %s%s%s\n", brightGreen, reset, bold, path, reset)
}

type stats struct {
	total, critical, high, medium, low int
}

func computeStats() stats {
	var s stats
	s.total = len(results)
	for _, r := range results {
		switch r.Severity {
		case "Critical":
			s.critical++
		case "High":
			s.high++
		case "Medium":
			s.medium++
		case "Low":
			s.low++
		}
	}
	return s
}

// -------------------- Year Filter Pipeline --------------------

func applyYearFilter(all []Result) []Result {
	switch cfg.YearOp {
	case "lt":
		return filterFunc(all, func(r Result) bool { return r.OldestYear < cfg.Year })
	case "gt":
		return filterFunc(all, func(r Result) bool { return r.LatestYear > cfg.Year })
	case "eq":
		return filterFunc(all, func(r Result) bool {
			for _, y := range r.CopyrightYears {
				if y == cfg.Year {
					return true
				}
			}
			return false
		})
	case "range":
		return filterFunc(all, func(r Result) bool {
			for _, y := range r.CopyrightYears {
				if y >= cfg.Year && y <= cfg.YearEnd {
					return true
				}
			}
			return false
		})
	case "smart":
		return smartMode(all)
	}
	return all
}

func filterFunc(all []Result, keep func(Result) bool) []Result {
	out := make([]Result, 0, len(all))
	for _, r := range all {
		if keep(r) {
			out = append(out, r)
		}
	}
	return out
}

func smartMode(all []Result) []Result {
	if len(all) == 0 {
		return all
	}
	now := time.Now().Year()
	scored := make([]Result, 0, len(all))

	var allLatest []int
	for _, r := range all {
		allLatest = append(allLatest, r.LatestYear)
	}
	sort.Ints(allLatest)
	median := allLatest[len(allLatest)/2]
	ilog("%s[smart]%s Population median latest-year: %s%d%s\n", brightMagenta, reset, bold, median, reset)

	for _, r := range all {
		score := 0
		reasons := []string{}

		gap := now - r.LatestYear
		if gap >= 5 {
			score += 50
			reasons = append(reasons, fmt.Sprintf("Very stale: %d years behind current year", gap))
		} else if gap >= 3 {
			score += 25
			reasons = append(reasons, fmt.Sprintf("Stale: %d years behind current year", gap))
		}

		clusterGap := median - r.LatestYear
		if clusterGap >= 5 {
			score += 40
			reasons = append(reasons, fmt.Sprintf("Cluster outlier: %d years behind peer median (%d)", clusterGap, median))
		} else if clusterGap >= 3 {
			score += 20
			reasons = append(reasons, fmt.Sprintf("Below peer median by %d years", clusterGap))
		}

		if hasTag(r.Tags, "Possible Admin/Exposed Panel") {
			score += 35
			reasons = append(reasons, "Exposed admin/login panel detected")
		}
		if hasTag(r.Tags, "Invalid/Expired TLS") {
			score += 20
			reasons = append(reasons, "Invalid or expired TLS certificate")
		}
		if hasTag(r.Tags, "Non-Production") {
			score += 15
			reasons = append(reasons, "Non-production environment (dev/staging/uat)")
		}
		if hasTag(r.Tags, "Server Error") {
			score += 10
			reasons = append(reasons, "Returning HTTP 5xx errors")
		}
		if hasTag(r.Tags, "Auth-Gated") {
			score += 5
			reasons = append(reasons, "Authentication-gated endpoint")
		}

		if score > 0 {
			r.SmartScore = score
			r.SmartReasons = reasons
			switch {
			case score >= 80:
				r.Severity = "Critical"
			case score >= 50:
				r.Severity = "High"
			case score >= 25:
				r.Severity = "Medium"
			default:
				r.Severity = "Low"
			}
			scored = append(scored, r)
		}
	}

	ilog("%s[smart]%s %s%d%s/%d hosts flagged by smart heuristics\n",
		brightMagenta, reset, bold, len(scored), reset, len(all))
	return scored
}
