package main

import (
	"bufio"
	"bytes"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// benchStat is one benchmark's medians across the runs.
type benchStat struct {
	nsOp, bOp, allocsOp float64
	runs                int
}

var benchFuncRe = regexp.MustCompile(`(?m)^func Benchmark[A-Za-z0-9_]*\(`)

// benchmarkPackages lists every package (as ./dir) under tree, outside
// vendor/ and .git/, that has a Benchmark function in a _test.go file.
func benchmarkPackages(tree string) ([]string, error) {
	set := map[string]bool{}
	err := filepath.WalkDir(tree, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case "vendor", ".git", "testdata", "node_modules":
				if p != tree {
					return filepath.SkipDir
				}
			}
			return nil
		}
		if !strings.HasSuffix(d.Name(), "_test.go") {
			return nil
		}
		data, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		if benchFuncRe.Match(data) {
			rel, err := filepath.Rel(tree, filepath.Dir(p))
			if err != nil {
				return err
			}
			set["./"+filepath.ToSlash(rel)] = true
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	var pkgs []string
	for p := range set {
		pkgs = append(pkgs, strings.TrimSuffix(p, "/."))
	}
	sort.Strings(pkgs)
	return pkgs, nil
}

// runGoBench runs the benchmarks count times and returns the raw output.
// A non-zero exit is returned as an error together with whatever was
// printed, so partial results still parse.
func runGoBench(tree string, pkgs []string, count int) (string, error) {
	args := append([]string{"test", "-run", "^$", "-bench", ".", "-benchmem", "-count", strconv.Itoa(count), "-timeout", "120m"}, pkgs...)
	cmd := exec.Command("go", args...)
	cmd.Dir = tree
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	ownGroup(cmd)
	g := &goTest{cmd: cmd}
	err := startChild(cmd, g)
	if err == nil {
		err = cmd.Wait()
		releaseChild(g)
	}
	if err != nil {
		err = fmt.Errorf("go %s: %v", strings.Join(args[:7], " "), err)
	}
	return out.String(), err
}

// benchLineRe matches a benchmark result line as go test prints it.
var (
	benchLineRe = regexp.MustCompile(`^(Benchmark[^\s]+)\s+(\d+)\s+([0-9.]+) ns/op(.*)$`)
	pkgLineRe   = regexp.MustCompile(`^pkg:\s+(\S+)`)
	cpuSuffixRe = regexp.MustCompile(`-\d+$`)
	bOpRe       = regexp.MustCompile(`([0-9.]+) B/op`)
	allocsRe    = regexp.MustCompile(`([0-9.]+) allocs/op`)
)

// parseBenchOutput parses every Benchmark line and takes the median of
// each metric per benchmark. Names are keyed "pkg.Benchmark" with the
// package's module prefix and the -GOMAXPROCS suffix removed.
func parseBenchOutput(raw string) map[string]benchStat {
	type samples struct{ ns, b, allocs []float64 }
	acc := map[string]*samples{}
	pkg := ""
	sc := bufio.NewScanner(strings.NewReader(raw))
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		line := strings.TrimRight(sc.Text(), "\r")
		if m := pkgLineRe.FindStringSubmatch(line); m != nil {
			pkg = m[1]
			if i := strings.LastIndex(pkg, "/"); i >= 0 {
				pkg = pkg[i+1:]
			}
			continue
		}
		m := benchLineRe.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		name := cpuSuffixRe.ReplaceAllString(m[1], "")
		if pkg != "" {
			name = pkg + "." + name
		}
		s := acc[name]
		if s == nil {
			s = &samples{}
			acc[name] = s
		}
		ns, _ := strconv.ParseFloat(m[3], 64)
		s.ns = append(s.ns, ns)
		if bm := bOpRe.FindStringSubmatch(m[4]); bm != nil {
			v, _ := strconv.ParseFloat(bm[1], 64)
			s.b = append(s.b, v)
		}
		if am := allocsRe.FindStringSubmatch(m[4]); am != nil {
			v, _ := strconv.ParseFloat(am[1], 64)
			s.allocs = append(s.allocs, v)
		}
	}
	out := map[string]benchStat{}
	for name, s := range acc {
		out[name] = benchStat{nsOp: median(s.ns), bOp: median(s.b), allocsOp: median(s.allocs), runs: len(s.ns)}
	}
	return out
}

// median of a sample set; NaN-free: an empty set yields 0.
func median(v []float64) float64 {
	if len(v) == 0 {
		return 0
	}
	s := append([]float64(nil), v...)
	sort.Float64s(s)
	n := len(s)
	if n%2 == 1 {
		return s[n/2]
	}
	return (s[n/2-1] + s[n/2]) / 2
}
