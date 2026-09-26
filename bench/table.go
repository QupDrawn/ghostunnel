package main

import (
	"fmt"
	"math"
	"sort"
	"strings"
)

// commas formats an integer with thousands separators.
func commas(n int64) string {
	s := fmt.Sprintf("%d", n)
	neg := strings.HasPrefix(s, "-")
	if neg {
		s = s[1:]
	}
	var out []byte
	for i, c := range []byte(s) {
		if i > 0 && (len(s)-i)%3 == 0 {
			out = append(out, ',')
		}
		out = append(out, c)
	}
	if neg {
		return "-" + string(out)
	}
	return string(out)
}

// num formats a benchmark figure: integers with separators, small values
// with decimals.
func num(v float64) string {
	if v == 0 {
		return "0"
	}
	if v == math.Trunc(v) && math.Abs(v) >= 1000 {
		return commas(int64(v))
	}
	if v == math.Trunc(v) {
		return fmt.Sprintf("%.0f", v)
	}
	if math.Abs(v) < 10 {
		return fmt.Sprintf("%.3f", v)
	}
	if math.Abs(v) < 1000 {
		return fmt.Sprintf("%.1f", v)
	}
	return commas(int64(math.Round(v)))
}

// delta is the signed change of fork against base in percent, two
// decimals; "-" when either side is missing or base is zero.
func delta(base, fork float64) string {
	if base == 0 {
		return "-"
	}
	return fmt.Sprintf("%+.2f%%", (fork-base)/base*100)
}

// renderTable lays out rows under a header; column 0 is left-aligned and
// the rest right-aligned.
func renderTable(header []string, rows [][]string) string {
	width := make([]int, len(header))
	for i, h := range header {
		width[i] = len(h)
	}
	for _, r := range rows {
		for i, c := range r {
			if len(c) > width[i] {
				width[i] = len(c)
			}
		}
	}
	var b strings.Builder
	line := func(cells []string) {
		for i, c := range cells {
			if i > 0 {
				b.WriteString(" | ")
			}
			if i == 0 {
				fmt.Fprintf(&b, "%-*s", width[i], c)
			} else {
				fmt.Fprintf(&b, "%*s", width[i], c)
			}
		}
		b.WriteString("\n")
	}
	line(header)
	for i := range header {
		if i > 0 {
			b.WriteString("-+-")
		}
		b.WriteString(strings.Repeat("-", width[i]))
	}
	b.WriteString("\n")
	for _, r := range rows {
		line(r)
	}
	return b.String()
}

func renderGoBenchTable(base, fork map[string]benchStat) string {
	names := map[string]bool{}
	for n := range base {
		names[n] = true
	}
	for n := range fork {
		names[n] = true
	}
	if len(names) == 0 {
		return "no benchmark results\n"
	}
	var sorted []string
	for n := range names {
		sorted = append(sorted, n)
	}
	sort.Strings(sorted)
	header := []string{"benchmark", "base ns/op", "fork ns/op", "delta %", "base B/op", "fork B/op", "allocs base/fork"}
	var rows [][]string
	for _, n := range sorted {
		b, inBase := base[n]
		f, inFork := fork[n]
		label := n
		switch {
		case inBase && !inFork:
			label += " (base only)"
		case inFork && !inBase:
			label += " (fork only)"
		}
		cell := func(ok bool, v float64) string {
			if !ok {
				return "-"
			}
			return num(v)
		}
		d := "-"
		if inBase && inFork {
			d = delta(b.nsOp, f.nsOp)
		}
		rows = append(rows, []string{
			label, cell(inBase, b.nsOp), cell(inFork, f.nsOp), d,
			cell(inBase, b.bOp), cell(inFork, f.bOp),
			cell(inBase, b.allocsOp) + "/" + cell(inFork, f.allocsOp),
		})
	}
	return renderTable(header, rows)
}

// e2eRow describes one end-to-end measurement line.
type e2eRow struct {
	label   string
	get     func(*e2eResult) float64
	fmt     func(float64) string
	noDelta bool
}

var e2eRows = []e2eRow{
	{"churn: connections/s", func(r *e2eResult) float64 { return r.churn.connsPerSec }, rate, false},
	{"churn: p50 ms", func(r *e2eResult) float64 { return r.churn.p50 }, ms, false},
	{"churn: p95 ms", func(r *e2eResult) float64 { return r.churn.p95 }, ms, false},
	{"churn: p99 ms", func(r *e2eResult) float64 { return r.churn.p99 }, ms, false},
	{"churn: max ms", func(r *e2eResult) float64 { return r.churn.max }, ms, false},
	{"bulk: MiB/s", func(r *e2eResult) float64 { return r.bulkMiBps }, rate, false},
	{"concurrent x16: connections/s", func(r *e2eResult) float64 { return r.conc.connsPerSec }, rate, false},
	{"concurrent x16: p99 ms", func(r *e2eResult) float64 { return r.conc.p99 }, ms, false},
	{"concurrent x16: max ms", func(r *e2eResult) float64 { return r.conc.max }, ms, false},
	{"connections retried (all runs)", func(r *e2eResult) float64 { return float64(r.retries) }, count, true},
}

func rate(v float64) string  { return fmt.Sprintf("%.1f", v) }
func ms(v float64) string    { return fmt.Sprintf("%.3f", v) }
func count(v float64) string { return fmt.Sprintf("%.0f", v) }

func renderE2ETable(base, fork *e2eResult) string {
	if base == nil && fork == nil {
		return "no end-to-end results\n"
	}
	header := []string{"measurement", "base", "fork", "delta %"}
	var rows [][]string
	for _, r := range e2eRows {
		bc, fc, d := "-", "-", "-"
		if base != nil {
			bc = r.fmt(r.get(base))
		}
		if fork != nil {
			fc = r.fmt(r.get(fork))
		}
		if base != nil && fork != nil && !r.noDelta {
			d = delta(r.get(base), r.get(fork))
		}
		rows = append(rows, []string{r.label, bc, fc, d})
	}
	return renderTable(header, rows)
}
