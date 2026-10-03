package sentinelcore

import (
	"math/rand"
	"testing"
)

// refState is an independent brute-force reference: it keeps every
// event and decides satisfiability by exhaustive backtracking over
// slot assignments within the active window.
type refState struct {
	rule    Rule
	window  int64
	clock   int64
	events  []Event
	matched map[string]bool
	alerts  int
}

func newRef(rule Rule, w int64) *refState {
	return &refState{rule: rule, window: w, matched: make(map[string]bool)}
}

func (r *refState) activeEvents(entity string) []Event {
	var out []Event
	for _, ev := range r.events {
		if ev.EntityID != entity {
			continue
		}
		if ev.Timestamp > r.clock-r.window && ev.Timestamp <= r.clock {
			out = append(out, ev)
		}
	}
	return out
}

func slotOk(s Slot, ev Event) bool {
	if ev.Severity < s.MinSeverity {
		return false
	}
	if len(s.Domains) > 0 {
		found := false
		for _, d := range s.Domains {
			if d == ev.Domain {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	for _, tag := range s.Tags {
		if !hasTag(ev.Tags, tag) {
			return false
		}
	}
	return true
}

// satisfiable exhaustively tries every assignment of distinct events
// to slots.
func (r *refState) satisfiable(entity string) bool {
	evs := r.activeEvents(entity)
	if len(evs) < len(r.rule.Slots) {
		return false
	}
	used := make([]bool, len(evs))
	var dfs func(slot int) bool
	dfs = func(slot int) bool {
		if slot == len(r.rule.Slots) {
			return true
		}
		for i, ev := range evs {
			if used[i] || !slotOk(r.rule.Slots[slot], ev) {
				continue
			}
			used[i] = true
			if dfs(slot + 1) {
				return true
			}
			used[i] = false
		}
		return false
	}
	return dfs(0)
}

func (r *refState) ingest(ev Event) bool {
	if ev.Timestamp > r.clock {
		r.clock = ev.Timestamp
	}
	r.events = append(r.events, ev)
	now := r.satisfiable(ev.EntityID)
	was := r.matched[ev.EntityID]
	r.matched[ev.EntityID] = now
	if now && !was {
		r.alerts++
		return true
	}
	return false
}

func (r *refState) advance(t int64) {
	if t > r.clock {
		r.clock = t
	}
	for _, ev := range r.events {
		r.matched[ev.EntityID] = r.satisfiable(ev.EntityID)
	}
}

// checkEvidence verifies that evidence is a genuine assignment:
// distinct in-window events of the entity, each satisfying its slot.
func checkEvidence(t *testing.T, r *refState, entity string, evd []string) {
	t.Helper()
	if len(evd) != len(r.rule.Slots) {
		t.Fatalf("evidence length %d, want %d", len(evd), len(r.rule.Slots))
	}
	active := make(map[string]Event)
	for _, ev := range r.activeEvents(entity) {
		active[ev.ID] = ev
	}
	seen := make(map[string]bool)
	for i, id := range evd {
		ev, ok := active[id]
		if !ok {
			t.Fatalf("evidence[%d]=%q not an active event of %s", i, id, entity)
		}
		if seen[id] {
			t.Fatalf("evidence event %q used twice", id)
		}
		seen[id] = true
		if !slotOk(r.rule.Slots[i], ev) {
			t.Fatalf("evidence[%d]=%q does not satisfy slot %d", i, id, i)
		}
	}
}

func TestDifferentialAgainstBruteForce(t *testing.T) {
	rng := rand.New(rand.NewSource(20261003))
	rule := Rule{Slots: []Slot{
		{Domains: []string{"proc", "net"}, MinSeverity: 2, Tags: []string{"a"}},
		{Domains: []string{"net"}, Tags: []string{"b"}},
		{Domains: []string{"proc", "mail", "net"}, MinSeverity: 1},
		{Domains: []string{"mail"}, Tags: []string{"a", "b"}},
	}}
	const W = 40
	eng := mustEngine(t, rule, W)
	ref := newRef(rule, W)
	entities := []string{"e1", "e2", "e3", "e4", "e5"}
	domains := []string{"proc", "net", "mail", "cloud"}
	tagPool := []string{"a", "b"}

	var clock int64
	var idSeq int
	var engAlerts int

	checkAll := func(step int) {
		for _, ent := range entities {
			gotEvd, gotOK := eng.Match(ent)
			wantOK := ref.satisfiable(ent)
			if gotOK != wantOK {
				t.Fatalf("step %d: entity %s satisfiability mismatch: engine=%v ref=%v",
					step, ent, gotOK, wantOK)
			}
			if gotOK {
				checkEvidence(t, ref, ent, gotEvd)
			}
		}
		if engAlerts != ref.alerts {
			t.Fatalf("step %d: alert count mismatch: engine=%d ref=%d", step, engAlerts, ref.alerts)
		}
	}

	for step := 0; step < 4000; step++ {
		switch op := rng.Intn(100); {
		case op < 65:
			idSeq++
			clock += int64(rng.Intn(6))
			var tags []string
			for _, tag := range tagPool {
				if rng.Intn(2) == 0 {
					tags = append(tags, tag)
				}
			}
			event := Event{
				ID:        "ev" + itoa(idSeq),
				EntityID:  entities[rng.Intn(len(entities))],
				Timestamp: clock,
				Domain:    domains[rng.Intn(len(domains))],
				Severity:  rng.Intn(4),
				Tags:      tags,
			}
			alert := eng.Ingest(event)
			wantAlert := ref.ingest(event)
			if (alert != nil) != wantAlert {
				t.Fatalf("step %d: alert mismatch: engine=%v ref=%v", step, alert != nil, wantAlert)
			}
			if alert != nil {
				engAlerts++
				if alert.EntityID != event.EntityID {
					t.Fatalf("step %d: alert entity %q, want %q", step, alert.EntityID, event.EntityID)
				}
				checkEvidence(t, ref, event.EntityID, alert.Evidence)
			}
		case op < 85:
			clock += int64(rng.Intn(30))
			eng.Advance(clock)
			ref.advance(clock)
		default:
			ent := entities[rng.Intn(len(entities))]
			gotEvd, gotOK := eng.Match(ent)
			wantOK := ref.satisfiable(ent)
			if gotOK != wantOK {
				t.Fatalf("step %d: Match(%s)=%v, ref=%v", step, ent, gotOK, wantOK)
			}
			if gotOK {
				checkEvidence(t, ref, ent, gotEvd)
			}
		}
		checkAll(step)
	}
	if engAlerts == 0 {
		t.Fatal("differential run produced no alerts; adjust generator")
	}
	t.Logf("differential OK: %d alerts over 4000 ops", engAlerts)
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}
