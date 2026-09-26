package main

// render.go builds one frame as lines. Built rather than printed, so the
// watch loop can repaint each line where it already is instead of clearing
// the screen and drawing it again: a full clear once a second flickers,
// overwriting does not.

import (
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// ---- painting -------------------------------------------------------------

var colours = map[string]string{
	"green": "0;32", "red": "1;31", "amber": "0;33",
	"grey": "0;90", "bold": "1", "cyan": "0;36",
}

func paint(text, colour string, noColor bool) string {
	if noColor {
		return text
	}
	code, ok := colours[colour]
	if !ok {
		code = "0"
	}
	return "\033[" + code + "m" + text + "\033[0m"
}

var reEscape = regexp.MustCompile("\033\\[[0-9;]*m")

// visibleWidth is the length without the escapes, in bytes: the width the
// columns are padded against, so a middle dot counts two and a cell holding
// one is padded a column short of the others.
func visibleWidth(s string) int {
	return len(reEscape.ReplaceAllString(s, ""))
}

// pad pads to a width. It has to ignore the escapes, or every column after a
// coloured cell drifts by the width of the escape sequence. It never
// truncates.
func pad(text string, width int) string {
	n := width - visibleWidth(text)
	if n <= 0 {
		return text
	}
	return text + strings.Repeat(" ", n)
}

func duration(seconds int64) string {
	switch {
	case seconds < 60:
		return fmt.Sprintf("%ds", seconds)
	case seconds < 3600:
		return fmt.Sprintf("%dm %ds", seconds/60, seconds%60)
	case seconds < 86400:
		return fmt.Sprintf("%dh %dm", seconds/3600, seconds%3600/60)
	}
	return fmt.Sprintf("%dd %dh", seconds/86400, seconds%86400/3600)
}

// ageColour: two cadences of grace before an age is worth colouring, six
// before it is red. The gates' own windows are what actually decide this;
// these are for reading.
func ageColour(age, cadence int64) string {
	switch {
	case cadence > 0 && age > cadence*6:
		return "red"
	case cadence > 0 && age > cadence*2:
		return "amber"
	}
	return "green"
}

// cycleCell is the measured cycle against the ceiling it must stay under, in
// one cell, because neither number means much without the other. A cycle
// should sit well under the cadence; approaching it is the warning, reaching
// it is what the members' own cycle check faults on.
func cycleCell(rate *float64, cadence int64, noColor bool) string {
	c := func(text, colour string) string { return paint(text, colour, noColor) }
	var cycle string
	switch {
	case rate == nil:
		cycle = c("--", "grey")
	case cadence <= 0:
		cycle = c(fmt.Sprintf("%.1fs", *rate), "grey")
	case *rate >= float64(cadence):
		cycle = c(fmt.Sprintf("%.1fs", *rate), "red")
	case *rate > float64(cadence)*0.7:
		cycle = c(fmt.Sprintf("%.1fs", *rate), "amber")
	default:
		cycle = c(fmt.Sprintf("%.1fs", *rate), "green")
	}
	return cycle + c(fmt.Sprintf("/%ds", cadence), "grey")
}

// ---- one frame ------------------------------------------------------------

type memberState struct {
	hb     *heartbeat
	fault  faultFile
	halt   haltFile
	slots  []string
	folder folder
	rate   *float64
	since  *time.Time
}

func (s *memberState) stopped() bool { return s.halt.present || len(s.slots) > 0 }

func renderLines(stores string, rates map[string]*float64, now time.Time, noColor bool) []string {
	c := func(text, colour string) string { return paint(text, colour, noColor) }
	var L []string

	state := map[string]*memberState{}
	for _, m := range members {
		root := filepath.Join(stores, m)
		state[m] = &memberState{
			hb:     latestHeartbeat(filepath.Join(root, "heartbeat")),
			fault:  readFault(filepath.Join(root, "fault")),
			halt:   readHalt(filepath.Join(root, "halt")),
			slots:  slotsIn(filepath.Join(root, "halts")),
			folder: scanFolder(filepath.Join(root, "heartbeat")),
			rate:   rates[m],
			since:  observingSince(root),
		}
	}

	// --- the verdict ---
	//
	// Taken from the files rather than computed: a halt in force is a halt
	// in force, whatever anything here thinks of the members' freshness.
	//
	// A member is stopped when its gate refuses, and the gate reads its own
	// halts/ as well as its own halt file. Only the member that raised the
	// halt writes a halt file of its own; everybody else is stopped by the
	// slot delivered into their halts/. Counting halt files alone would say
	// one of four when all four are refusing.
	var stopped []string
	var reason *haltInfo
	who := "a member"
	for _, m := range members {
		s := state[m]
		if s.stopped() {
			stopped = append(stopped, m)
		}
		if s.halt.info != nil && reason == nil {
			reason = s.halt.info
			who = m
		}
	}
	// A delivered slot carries the same bytes as the raiser's own file, so it
	// answers just as well when that file is gone.
	if reason == nil {
		for _, m := range members {
			for _, slot := range state[m].slots {
				if h := readHalt(filepath.Join(stores, m, "halts", slot)); h.info != nil {
					reason = h.info
					who = slot
					break
				}
			}
			if reason != nil {
				break
			}
		}
	}
	var missing []string
	for _, m := range members {
		if state[m].hb == nil {
			missing = append(missing, m)
		}
	}

	// The banner. The gap is sized so the time starts in a fixed column.
	L = append(L, "")
	L = append(L, "  "+c("GHOSTUNNEL", "bold")+c("  ·  observer ring", "grey")+
		strings.Repeat(" ", 29)+c(now.UTC().Format(timestampLayout), "grey"))
	L = append(L, "")

	switch {
	case len(stopped) > 0:
		line := "  " + c(" RING HALTED ", "red") + "  "
		if reason != nil {
			line += c(reason.Reason, "bold")
			if reason.Subject != nil && *reason.Subject != "" {
				line += c(" on "+*reason.Subject, "bold")
			}
			foundBy := reason.Observer
			if foundBy == "" {
				foundBy = who
			}
			line += c(", found by "+foundBy, "grey")
			if when, ok := parseTimestamp(reason.When); ok {
				line += c(", "+duration(int64(now.Sub(when).Seconds()))+" ago", "grey")
			}
		} else {
			// Nothing that is in force could be parsed. The file still stops
			// the member, and the suffix says why the reason is unknown.
			line += c("unknown", "bold") + c(", found by "+who, "grey") + c(" (halt file unreadable)", "grey")
		}
		L = append(L, line)
		L = append(L, "  "+c(fmt.Sprintf("%d of %d members stopped.", len(stopped), len(members))+
			" Clearing is unanimous, so the work stays stopped until every member reads clean.", "grey"))
	case len(missing) > 0:
		L = append(L, "  "+c(" RING INCOMPLETE ", "amber")+"  "+
			c("no readable heartbeat from: "+strings.Join(missing, ", "), "bold"))
	default:
		L = append(L, "  "+c(" RING CLEAR ", "green")+"  "+
			c(fmt.Sprintf("%d members · %d directed edges · nothing halted", len(members), len(members)*(len(members)-1)), "grey"))
	}
	L = append(L, "")

	// --- the members ---

	L = append(L, "  "+c(pad("MEMBER", 10)+pad("STATE", 16)+pad("SEQUENCE", 12)+
		pad("LAST BEAT", 12)+pad("CYCLE", 12)+pad("OBSERVING", 14)+"CHECKS", "grey"))

	for _, m := range members {
		s := state[m]
		hb := s.hb
		if hb == nil {
			L = append(L, "  "+pad(c(m, "bold"), 10)+c("no heartbeat", "red"))
			continue
		}

		cadence := hb.CadenceSeconds
		var ageCell string
		if ts, ok := parseTimestamp(hb.Timestamp); ok {
			age := int64(now.Sub(ts).Seconds())
			ageCell = c(fmt.Sprintf("%ds ago", age), ageColour(age, cadence))
		} else {
			ageCell = c("bad time", "red")
		}

		// Fault before halt, because the member that found the problem has
		// both files and would otherwise look like every member merely
		// carrying the halt it raised.
		//
		//   fault    this one found something wrong; the line below says what
		//   halt     this one is stopped, on a finding somebody else made
		//   stopped  its heartbeat says stop: it is winding down on its own
		//   clear    nothing wrong here
		//
		// halt counts a delivered slot as well as a halt file of its own,
		// because that is what its gate reads.
		var label string
		switch {
		case s.fault.present:
			label = c("fault", "red")
		case s.stopped():
			label = c("halt", "red")
		case hb.Stop:
			label = c("stopped", "amber")
		default:
			label = c("clear", "green")
		}
		if hb.booted() {
			label += c(" · booted", "amber")
		}

		// Wall-clock since the member first ran, which survives restarts
		// because the file does. Not this process's uptime, and not a count
		// of anything.
		observing := c("--", "red")
		if s.since != nil {
			observing = c(duration(max(0, int64(now.Sub(*s.since).Seconds()))), "grey")
		}

		// STATE is 16 wide and `stopped · booted` fills it, so that one label
		// runs into SEQUENCE.
		L = append(L, "  "+pad(c(m, "bold"), 10)+
			pad(label, 16)+
			pad(fmt.Sprint(hb.Sequence), 12)+
			pad(ageCell, 12)+
			pad(cycleCell(s.rate, cadence, noColor), 12)+
			pad(observing, 14)+
			c(fmt.Sprint(hb.checkCount()), "grey"))

		// A readable fault file with nothing listed gets no line. One that
		// will not parse gets a line saying so.
		if s.fault.present {
			switch {
			case !s.fault.readable:
				L = append(L, "  "+strings.Repeat(" ", 10)+c("failing: (fault file unreadable)", "red"))
			case len(s.fault.failing) > 0:
				L = append(L, "  "+strings.Repeat(" ", 10)+c("failing: "+strings.Join(s.fault.failing, ", "), "red"))
			}
		}
	}
	L = append(L, "")

	// --- the edges ---
	//
	// Each member records, in its own heartbeat, the hash of the heartbeat it
	// read from every other member. That is the edge: not a claim that it
	// looked, but bytes it could not produce without having looked. The
	// recorded hash is searched for in the subject's folder as it stands now.
	//
	// `ok` means the reader's evidence is the subject's current publication.
	// `-n` means it is n publications behind, which is ordinary when the two
	// run on different cadences. `past` means the hash is not among the files
	// that could be read: pruned beyond it, or a disagreement, or an entry
	// that would not open, which this tool cannot tell apart. The member's
	// own chain check can, and its fault file above is the answer.

	L = append(L, "  "+c("EDGES", "grey")+
		c("   who has read whose heartbeat, and how recently. The row is the one doing the reading.", "grey"))
	L = append(L, "")

	head := "  " + pad("", 10)
	for _, m := range members {
		head += pad(c(m, "grey"), 10)
	}
	L = append(L, head)

	for _, reader := range members {
		row := "  " + pad(c(reader, "bold"), 10)
		for _, subject := range members {
			if reader == subject {
				row += pad(c("·", "grey"), 10)
				continue
			}
			var recorded *string
			if hb := state[reader].hb; hb != nil {
				recorded = hb.Observed[subject]
			}
			if recorded == nil {
				row += pad(c("none", "red"), 10)
				continue
			}
			switch behind := state[subject].folder.behind(*recorded); {
			case behind < 0:
				row += pad(c("past", "amber"), 10)
			case behind == 0:
				row += pad(c("ok", "green"), 10)
			default:
				row += pad(c(fmt.Sprintf("-%d", behind), "green"), 10)
			}
		}
		L = append(L, row)
	}

	// Plain words. Whoever reads this at three in the morning should not
	// have to work out what a cell means.
	L = append(L, "")
	legend := func(cell, colour, text string) {
		L = append(L, "  "+strings.Repeat(" ", 8)+pad(c(cell, colour), 8)+c(text, "grey"))
	}
	legend("ok", "green", "read the newest one")
	legend("-1", "green", "read the one before that. Normal: they do not run in step")
	legend("-2", "green", "two behind, and so on")
	legend("past", "amber", "read something so old it has been deleted since")
	legend("none", "red", "has not read it at all. Not normal")
	L = append(L, "")

	// --- the copies ---
	//
	// Every member writes its heartbeat a second time, into a peer's copy/
	// and into super/copy-<self>/. The reader compares the deposit against
	// the author's own store, so a member publishing one thing to its own
	// store and another to its peer is caught by the peer. The author never
	// makes this comparison, which is the point of it.

	type copySpot struct{ dir, author, label string }
	var copies []copySpot
	for _, m := range members {
		if m == coordinator {
			for _, a := range structural {
				copies = append(copies, copySpot{filepath.Join(stores, m, "copy-"+a, "heartbeat"), a, m + "/copy-" + a})
			}
			continue
		}
		copies = append(copies, copySpot{filepath.Join(stores, m, "copy", "heartbeat"), copyAuthor[m], m + "/copy"})
		copies = append(copies, copySpot{filepath.Join(stores, m, "copy-"+coordinator, "heartbeat"), coordinator, m + "/copy-" + coordinator})
	}

	type copyRow struct{ label, author, status string }
	var rows []copyRow
	matching := 0
	for _, cp := range copies {
		files := heartbeatFiles(cp.dir)
		if len(files) == 0 {
			rows = append(rows, copyRow{cp.label, cp.author, c("empty", "red")})
			continue
		}
		b, err := readFileBytes(filepath.Join(cp.dir, files[len(files)-1]))
		switch {
		case err != nil:
			rows = append(rows, copyRow{cp.label, cp.author, c("unreadable", "red")})
		case state[cp.author].folder.behind(sha256Hex(b)) >= 0:
			matching++
			rows = append(rows, copyRow{cp.label, cp.author, c("ok", "green")})
		default:
			rows = append(rows, copyRow{cp.label, cp.author, c("past", "amber")})
		}
	}

	summary := c(fmt.Sprintf("%d of %d match", matching, len(copies)), "amber")
	if matching == len(copies) {
		summary = c(fmt.Sprintf("all %d match", len(copies)), "green")
	}
	L = append(L, "  "+pad(c("COPIES", "grey"), 10)+pad(summary, 18)+
		c("each member writes its heartbeat a second time into another member's", "grey"))
	L = append(L, "  "+strings.Repeat(" ", 10)+
		c("folder, and that member checks the copy against the original", "grey"))
	L = append(L, "")
	for _, r := range rows {
		L = append(L, "  "+strings.Repeat(" ", 8)+pad(c(r.label, "bold"), 22)+
			pad(c("from "+r.author, "grey"), 16)+r.status)
	}
	L = append(L, "")

	// --- halt slots ---
	//
	// Only shown when something is in force. A slot is a halt delivered into
	// a member's store by another member, at a path the holder cannot write,
	// so a compromised member cannot delete the news about itself.

	anySlot := false
	for _, m := range members {
		if len(state[m].slots) > 0 {
			anySlot = true
		}
	}
	if anySlot {
		L = append(L, "  "+c("HALT SLOTS", "grey")+
			c("   delivered into a store by members that cannot be overwritten by its holder", "grey"))
		L = append(L, "")
		for _, m := range members {
			slots := state[m].slots
			cell := c("none", "grey")
			if len(slots) > 0 {
				cell = c("from "+strings.Join(slots, ", "), "red")
			}
			L = append(L, "  "+pad(c(m, "bold"), 10)+cell)
		}
		L = append(L, "")
	}

	return L
}
