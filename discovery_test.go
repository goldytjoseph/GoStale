package main

import (
	"reflect"
	"sort"
	"strings"
	"testing"
)

// ===================== Scope / Hostname Cleaning =====================

func TestInScope(t *testing.T) {
	cases := []struct {
		host, domain string
		want         bool
	}{
		{"example.com", "example.com", true},
		{"www.example.com", "example.com", true},
		{"a.b.example.com", "example.com", true},
		{"notexample.com", "example.com", false},      // sneaky suffix
		{"evilexample.com", "example.com", false},     // no dot before
		{"example.com.attacker.io", "example.com", false}, // suffix injection
		{"", "example.com", false},
		{"example.com", "", false},
		{"EXAMPLE.com", "example.com", true},          // case-insensitive
		{"example.COM", "example.com", true},
	}
	for _, c := range cases {
		got := inScope(c.host, c.domain)
		if got != c.want {
			t.Errorf("inScope(%q, %q) = %v, want %v", c.host, c.domain, got, c.want)
		}
	}
}

func TestCleanHost(t *testing.T) {
	cases := []struct {
		in        string
		wantHost  string
		wantOK    bool
	}{
		{"www.example.com", "www.example.com", true},
		{"http://www.example.com/path", "www.example.com", true},
		{"https://api.example.com:8080/x?y=z", "api.example.com", true},
		{"*.example.com", "example.com", true},
		{"  WWW.example.com  ", "www.example.com", true},
		{"www.example.com.", "www.example.com", true}, // trailing dot
		{".www.example.com", "www.example.com", true}, // leading dot
		{"", "", false},
		{"   ", "", false},
		{"localhost", "", false},                       // no dot -> reject
		{"javascript:alert(1)", "", false},             // no protocol cleanup -> "alert(1)" -> rejected
		{"www example com", "", false},                 // whitespace
		{"<script>", "", false},                        // invalid chars
		{"http://", "", false},
	}
	for _, c := range cases {
		gotHost, gotOK := cleanHost(c.in)
		if gotOK != c.wantOK || gotHost != c.wantHost {
			t.Errorf("cleanHost(%q) = (%q, %v), want (%q, %v)", c.in, gotHost, gotOK, c.wantHost, c.wantOK)
		}
	}
}

// ===================== Shodan Output Parser =====================

func TestParseShodanOutput_NoColor(t *testing.T) {
	// Realistic shodan domain -D output (color codes already stripped here).
	// Real CLI output uses click.style for colors; we test the no-color path.
	// Fixed-width: subdomain padded to 32 chars, type padded to 14 chars.
	input := "" +
		"EXAMPLE.COM\n" +
		"\n" +
		"                                 A              192.0.2.1 Ports: 80, 443\n" +
		"www                              A              192.0.2.2 Ports: 80, 443, 8080\n" +
		"api                              CNAME          api-lb.example.com\n" +
		"admin                            A              192.0.2.3 Ports: 22, 80, 443, 9000\n" +
		"                                 MX             10 mx1.example.com\n" +
		"                                 NS             ns1.example.com\n" +
		"                                 TXT            v=spf1 -all\n" +
		"_acme-challenge                  TXT            xyz123\n"

	recs := parseShodanOutput(input, "example.com")

	// Build a lookup
	byHost := make(map[string][]ShodanRecord)
	for _, r := range recs {
		byHost[r.Host] = append(byHost[r.Host], r)
	}

	// Apex domain A record
	apex := byHost["example.com"]
	hasApexA := false
	hasApexMX := false
	hasApexNS := false
	hasApexTXT := false
	for _, r := range apex {
		switch r.Type {
		case "A":
			hasApexA = true
			if r.Value != "192.0.2.1" {
				t.Errorf("apex A value = %q, want 192.0.2.1", r.Value)
			}
			if !reflect.DeepEqual(sortInts(r.Ports), []int{80, 443}) {
				t.Errorf("apex A ports = %v, want [80 443]", r.Ports)
			}
		case "MX":
			hasApexMX = true
			if r.Value != "mx1.example.com" {
				t.Errorf("MX value = %q, want mx1.example.com (priority stripped)", r.Value)
			}
		case "NS":
			hasApexNS = true
		case "TXT":
			hasApexTXT = true
		}
	}
	if !hasApexA {
		t.Error("missing apex A record")
	}
	if !hasApexMX {
		t.Error("missing apex MX record")
	}
	if !hasApexNS {
		t.Error("missing apex NS record")
	}
	if !hasApexTXT {
		t.Error("missing apex TXT record")
	}

	// www subdomain — A record with ports
	if len(byHost["www.example.com"]) != 1 {
		t.Errorf("www.example.com should have 1 record, got %d", len(byHost["www.example.com"]))
	} else {
		r := byHost["www.example.com"][0]
		if r.Type != "A" || r.Value != "192.0.2.2" {
			t.Errorf("www record wrong: %+v", r)
		}
		if !reflect.DeepEqual(sortInts(r.Ports), []int{80, 443, 8080}) {
			t.Errorf("www ports = %v, want [80 443 8080]", r.Ports)
		}
	}

	// api subdomain — CNAME, no ports
	if len(byHost["api.example.com"]) != 1 {
		t.Errorf("api.example.com should have 1 record")
	} else {
		r := byHost["api.example.com"][0]
		if r.Type != "CNAME" || r.Value != "api-lb.example.com" {
			t.Errorf("api record wrong: %+v", r)
		}
		if len(r.Ports) != 0 {
			t.Errorf("CNAME should have no ports, got %v", r.Ports)
		}
	}

	// admin subdomain — 4 ports including non-standard
	admin := byHost["admin.example.com"]
	if len(admin) != 1 {
		t.Errorf("admin.example.com should have 1 record")
	} else {
		want := []int{22, 80, 443, 9000}
		if !reflect.DeepEqual(sortInts(admin[0].Ports), want) {
			t.Errorf("admin ports = %v, want %v", admin[0].Ports, want)
		}
	}

	// _acme-challenge — TXT with underscore (valid for DNS)
	if len(byHost["_acme-challenge.example.com"]) != 1 {
		t.Error("missing _acme-challenge record")
	}
}

func TestParseShodanOutput_WithAnsiColors(t *testing.T) {
	// Real shodan CLI output with ANSI escapes from click.style
	esc := "\x1b"
	input := "" +
		esc + "[32mEXAMPLE.COM" + esc + "[0m\n" +
		"\n" +
		esc + "[36m                                " + esc + "[0m " + esc + "[33mA             " + esc + "[0m 192.0.2.1\n" +
		esc + "[36mwww                             " + esc + "[0m " + esc + "[33mA             " + esc + "[0m 192.0.2.2" + esc + "[34m Ports: 80, 443" + esc + "[0m\n"

	recs := parseShodanOutput(input, "example.com")
	if len(recs) < 2 {
		t.Fatalf("expected at least 2 records after ANSI strip, got %d: %+v", len(recs), recs)
	}
	// Locate the www record
	var www *ShodanRecord
	for i := range recs {
		if recs[i].Host == "www.example.com" {
			www = &recs[i]
			break
		}
	}
	if www == nil {
		t.Fatal("www.example.com not parsed after ANSI strip")
	}
	if www.Type != "A" {
		t.Errorf("www type = %q, want A", www.Type)
	}
	if www.Value != "192.0.2.2" {
		t.Errorf("www value = %q, want 192.0.2.2", www.Value)
	}
	if !reflect.DeepEqual(sortInts(www.Ports), []int{80, 443}) {
		t.Errorf("www ports = %v, want [80 443]", www.Ports)
	}
}

func TestParseShodanOutput_NoDetails(t *testing.T) {
	// Output WITHOUT the -D flag — no "Ports:" suffix anywhere
	input := "" +
		"EXAMPLE.COM\n" +
		"www                              A              192.0.2.2\n" +
		"api                              CNAME          api-lb.example.com\n"
	recs := parseShodanOutput(input, "example.com")
	if len(recs) != 2 {
		t.Fatalf("want 2 records, got %d", len(recs))
	}
	for _, r := range recs {
		if len(r.Ports) != 0 {
			t.Errorf("expected no ports in non-detail output, got %v for %s", r.Ports, r.Host)
		}
	}
}

func TestParseShodanOutput_EmptyAndErrors(t *testing.T) {
	if recs := parseShodanOutput("", "example.com"); len(recs) != 0 {
		t.Errorf("empty input should produce 0 records, got %d", len(recs))
	}
	errOutput := "Error: Invalid API key\n"
	if recs := parseShodanOutput(errOutput, "example.com"); len(recs) != 0 {
		t.Errorf("error output should produce 0 records, got %d: %+v", len(recs), recs)
	}
}

func TestBuildShodanHost(t *testing.T) {
	cases := []struct {
		sub, domain, want string
	}{
		{"", "example.com", "example.com"},
		{"www", "example.com", "www.example.com"},
		{"example.com", "example.com", "example.com"},
		{"www.example.com", "example.com", "www.example.com"},
		{".www.", "example.com", "www.example.com"},
	}
	for _, c := range cases {
		got := buildShodanHost(c.sub, c.domain)
		if got != c.want {
			t.Errorf("buildShodanHost(%q,%q) = %q, want %q", c.sub, c.domain, got, c.want)
		}
	}
}

// ===================== URL Generation with Ports =====================

func TestGenerateURLs_WithExtraPorts(t *testing.T) {
	subExtraPorts = map[string][]int{
		"admin.example.com": {22, 80, 443, 9000},
		"www.example.com":   {},
	}
	defer func() { subExtraPorts = nil }()

	urls := generateURLs([]string{"admin.example.com", "www.example.com"})
	got := make(map[string]bool)
	for _, u := range urls {
		got[u] = true
	}

	must := []string{
		"http://admin.example.com",
		"https://admin.example.com",
		"http://admin.example.com:22",
		"https://admin.example.com:22",
		"http://admin.example.com:9000",
		"https://admin.example.com:9000",
		"http://www.example.com",
		"https://www.example.com",
	}
	for _, u := range must {
		if !got[u] {
			t.Errorf("missing URL %q from generated set", u)
		}
	}
	// Should NOT regenerate :80 or :443 explicitly (already in defaults)
	if got["http://admin.example.com:80"] {
		t.Error("port 80 should be folded into default http://, not duplicated")
	}
	if got["https://admin.example.com:443"] {
		t.Error("port 443 should be folded into default https://, not duplicated")
	}
}

// ===================== Year Regex =====================

func TestYearRegex_Variants(t *testing.T) {
	cases := []struct {
		body string
		want []int
	}{
		{"<footer>© 2014 Acme Corp</footer>", []int{2014}},
		{"<p>Copyright 2018-2020 Acme</p>", []int{2018, 2020}},
		{"&copy; 2019", []int{2019}},
		{"&#169; 2017", []int{2017}},          // HTML entity for ©
		{"&#xa9; 2016", []int{2016}},          // HTML hex entity
		{"COPYRIGHT 2015", []int{2015}},       // upper-case
		{"Copr. 2013 Foo", []int{2013}},
		{"Just text 2020 with no copyright marker", nil}, // intentional miss
		{"© 2099 future date", nil},                       // out of range -> filtered
		{"© 1850 too old", nil},                           // out of range
		{"© 2020 / 2024 Acme", []int{2020, 2024}},        // slash separator
		{"© 2018 — 2024 Acme", []int{2018, 2024}},        // em-dash
	}
	for _, c := range cases {
		got := extractYears(c.body)
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("extractYears(%q) = %v, want %v", c.body, got, c.want)
		}
	}
}

// ===================== Helpers =====================

func sortInts(s []int) []int {
	out := append([]int(nil), s...)
	sort.Ints(out)
	return out
}

// Sanity: ensure parser is resilient to lines with trailing whitespace and \r\n
func TestParseShodanOutput_CRLF(t *testing.T) {
	input := "EXAMPLE.COM\r\nwww                              A              192.0.2.2\r\n"
	recs := parseShodanOutput(input, "example.com")
	if len(recs) != 1 {
		t.Fatalf("want 1 record with CRLF, got %d", len(recs))
	}
	if recs[0].Host != "www.example.com" {
		t.Errorf("got host %q", recs[0].Host)
	}
}

// Sanity: even if the line is shorter than 48 chars but well-formed via whitespace
func TestParseShodanOutput_ShortLineFallback(t *testing.T) {
	// imagine a future CLI format with tighter padding
	input := "www A 192.0.2.2\n"
	recs := parseShodanOutput(input, "example.com")
	if len(recs) != 1 {
		t.Fatalf("want 1 fallback record, got %d: %+v", len(recs), recs)
	}
	if recs[0].Host != "www.example.com" || recs[0].Type != "A" || recs[0].Value != "192.0.2.2" {
		t.Errorf("fallback parse wrong: %+v", recs[0])
	}
}

// Sanity: TXT record with spaces in value should not be split
func TestParseShodanOutput_TXTWithSpaces(t *testing.T) {
	input := "                                 TXT            v=spf1 include:_spf.example.com -all\n"
	recs := parseShodanOutput(input, "example.com")
	if len(recs) != 1 {
		t.Fatalf("want 1 TXT record, got %d", len(recs))
	}
	if !strings.Contains(recs[0].Value, "include:_spf.example.com") {
		t.Errorf("TXT value got truncated: %q", recs[0].Value)
	}
}
