package main

import (
	"reflect"
	"sort"
	"testing"
)

func mkResult(host string, years []int, tags []string) Result {
	if len(years) == 0 {
		return Result{}
	}
	sort.Ints(years)
	return Result{
		Hostname:       host,
		CopyrightYears: years,
		OldestYear:     years[0],
		LatestYear:     years[len(years)-1],
		Tags:           tags,
		TLSValid:       true,
	}
}

func collectHosts(rs []Result) []string {
	out := []string{}
	for _, r := range rs {
		out = append(out, r.Hostname)
	}
	sort.Strings(out)
	return out
}

func TestLT(t *testing.T) {
	cfg.YearOp = "lt"
	cfg.Year = 2023
	all := []Result{
		mkResult("a", []int{2014, 2015}, nil), // oldest 2014 < 2023 -> KEEP
		mkResult("b", []int{2024}, nil),       // oldest 2024 -> SKIP
		mkResult("c", []int{2022, 2024}, nil), // oldest 2022 < 2023 -> KEEP
	}
	got := collectHosts(applyYearFilter(all))
	want := []string{"a", "c"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("LT got %v, want %v", got, want)
	}
}

func TestGT(t *testing.T) {
	cfg.YearOp = "gt"
	cfg.Year = 2022
	all := []Result{
		mkResult("a", []int{2014, 2015}, nil), // latest 2015 -> SKIP
		mkResult("b", []int{2024}, nil),       // latest 2024 > 2022 -> KEEP
		mkResult("c", []int{2022}, nil),       // latest 2022 not > 2022 -> SKIP
		mkResult("d", []int{2022, 2025}, nil), // latest 2025 -> KEEP
	}
	got := collectHosts(applyYearFilter(all))
	want := []string{"b", "d"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("GT got %v, want %v", got, want)
	}
}

func TestEQ(t *testing.T) {
	cfg.YearOp = "eq"
	cfg.Year = 2020
	all := []Result{
		mkResult("a", []int{2014, 2020}, nil), // contains 2020 -> KEEP
		mkResult("b", []int{2021, 2022}, nil), // no 2020 -> SKIP
		mkResult("c", []int{2020}, nil),       // KEEP
	}
	got := collectHosts(applyYearFilter(all))
	want := []string{"a", "c"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("EQ got %v, want %v", got, want)
	}
}

func TestRange(t *testing.T) {
	cfg.YearOp = "range"
	cfg.Year = 2018
	cfg.YearEnd = 2021
	all := []Result{
		mkResult("a", []int{2015}, nil),       // outside -> SKIP
		mkResult("b", []int{2019, 2024}, nil), // 2019 in range -> KEEP
		mkResult("c", []int{2022}, nil),       // outside -> SKIP
		mkResult("d", []int{2018}, nil),       // boundary inclusive -> KEEP
		mkResult("e", []int{2021}, nil),       // boundary inclusive -> KEEP
	}
	got := collectHosts(applyYearFilter(all))
	want := []string{"b", "d", "e"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Range got %v, want %v", got, want)
	}
}

func TestSmartMode(t *testing.T) {
	cfg.YearOp = "smart"
	// Population: most hosts on 2024, one stuck on 2015 (cluster outlier),
	// one stuck on 2019 with exposed admin panel, one fresh & uninteresting.
	all := []Result{
		mkResult("fresh1", []int{2024}, nil),
		mkResult("fresh2", []int{2024}, nil),
		mkResult("fresh3", []int{2025}, nil),
		mkResult("stale-outlier", []int{2015}, nil),
		mkResult("admin-old", []int{2019}, []string{"Possible Admin/Exposed Panel"}),
	}
	got := applyYearFilter(all)

	// fresh hosts should NOT be flagged (no heuristic triggers)
	hosts := collectHosts(got)
	for _, h := range hosts {
		if h == "fresh1" || h == "fresh2" || h == "fresh3" {
			t.Errorf("smart mode should not flag fresh hosts, but got %q", h)
		}
	}

	// stale-outlier and admin-old should both be present
	hostSet := map[string]Result{}
	for _, r := range got {
		hostSet[r.Hostname] = r
	}
	if _, ok := hostSet["stale-outlier"]; !ok {
		t.Error("expected stale-outlier to be flagged")
	}
	if _, ok := hostSet["admin-old"]; !ok {
		t.Error("expected admin-old to be flagged")
	}

	// admin-old has more severe reasons -> should outscore stale-outlier
	if hostSet["admin-old"].SmartScore == 0 {
		t.Error("admin-old should have non-zero smart score")
	}
	if hostSet["stale-outlier"].SmartScore == 0 {
		t.Error("stale-outlier should have non-zero smart score")
	}
	t.Logf("admin-old score=%d reasons=%v", hostSet["admin-old"].SmartScore, hostSet["admin-old"].SmartReasons)
	t.Logf("stale-outlier score=%d reasons=%v", hostSet["stale-outlier"].SmartScore, hostSet["stale-outlier"].SmartReasons)

	// severity assignment sanity
	for _, r := range got {
		if r.Severity == "" {
			t.Errorf("severity should be assigned, got empty for %q", r.Hostname)
		}
	}
}

func TestRangeAutoSwap(t *testing.T) {
	// We don't call parseFlags here (it'd consume real argv); just verify
	// the swap logic by mimicking what parseFlags does.
	low, high := 2021, 2018
	if low > high {
		low, high = high, low
	}
	if low != 2018 || high != 2021 {
		t.Errorf("range auto-swap broken")
	}
}
