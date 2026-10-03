package sentinelcore

import "testing"

func mustEngine(t *testing.T, rule Rule, w int64) *Engine {
	t.Helper()
	e, err := NewEngine(rule, w)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	return e
}

func ev(id, entity string, ts int64, domain string, sev int, tags ...string) Event {
	return Event{ID: id, EntityID: entity, Timestamp: ts, Domain: domain, Severity: sev, Tags: tags}
}

// Two slots overlap on one event; a greedy assignment that gives e1 to
// slot B would starve slot A. The matcher must find the valid
// assignment A->e1, B->e2.
func TestOverlappingSlotsGreedyFailure(t *testing.T) {
	rule := Rule{Slots: []Slot{
		{Domains: []string{"proc"}},        // A: only e1 qualifies
		{Domains: []string{"proc", "net"}}, // B: e1 and e2 qualify
	}}
	e := mustEngine(t, rule, 100)

	if a := e.Ingest(ev("e1", "ent", 0, "proc", 1)); a != nil {
		t.Fatalf("unexpected alert after e1: %+v", a)
	}
	a := e.Ingest(ev("e2", "ent", 1, "net", 1))
	if a == nil {
		t.Fatal("expected alert after e2")
	}
	want := []string{"e1", "e2"}
	for i := range want {
		if a.Evidence[i] != want[i] {
			t.Fatalf("evidence = %v, want %v", a.Evidence, want)
		}
	}
}

// Every slot has candidates and there are more events than slots, yet
// no complete assignment exists (Hall violation): slots A,B,C share
// only two usable events.
func TestHallViolationNoMatch(t *testing.T) {
	rule := Rule{Slots: []Slot{
		{Domains: []string{"d"}}, // A
		{Domains: []string{"d"}}, // B
		{Domains: []string{"d"}}, // C
		{Domains: []string{"x"}}, // D
	}}
	e := mustEngine(t, rule, 1000)
	e.Ingest(ev("e1", "ent", 0, "d", 1))
	e.Ingest(ev("e2", "ent", 1, "d", 1))
	e.Ingest(ev("e3", "ent", 2, "x", 1))
	e.Ingest(ev("e4", "ent", 3, "x", 1))
	if a := e.Ingest(ev("e5", "ent", 4, "x", 1)); a != nil {
		t.Fatalf("unexpected alert: %+v", a)
	}
	if _, ok := e.Match("ent"); ok {
		t.Fatal("Match reported success despite Hall violation")
	}
}

// A matched evidence event expires, but an interchangeable replacement
// keeps the rule satisfied; no new alert may fire and Match must
// return the refreshed evidence.
func TestExpiryReplacementMaintainsMatch(t *testing.T) {
	rule := Rule{Slots: []Slot{
		{Domains: []string{"d"}, Tags: []string{"x"}}, // A
		{Domains: []string{"d"}},                      // B
	}}
	e := mustEngine(t, rule, 100)
	e.Ingest(ev("e1", "ent", 0, "d", 1, "x"))
	if a := e.Ingest(ev("e2", "ent", 5, "d", 1)); a == nil {
		t.Fatal("expected initial alert")
	}
	e.Ingest(ev("e3", "ent", 6, "d", 1, "x")) // future replacement for slot A
	e.Advance(101)                            // cutoff=1: only e1 (ts=0) expires
	got, ok := e.Match("ent")
	if !ok {
		t.Fatal("expected entity to stay matched after replacement")
	}
	if got[0] != "e3" || got[1] != "e2" {
		t.Fatalf("evidence = %v, want [e3 e2]", got)
	}
	// Still satisfied later: further ingests must not re-alert.
	if a := e.Ingest(ev("e4", "ent", 102, "d", 1)); a != nil {
		t.Fatalf("duplicate alert while continuously satisfied: %+v", a)
	}
}

// At the window boundary the old evidence expires in the same
// timestamp at which a new event arrives: expiry runs first, the
// entity drops out of the matched state, and the new event restores
// it, which must raise a fresh alert.
func TestBoundaryExpireThenRecoverSameTimestamp(t *testing.T) {
	rule := Rule{Slots: []Slot{{Domains: []string{"d"}}}}
	e := mustEngine(t, rule, 100)
	if a := e.Ingest(ev("e1", "ent", 100, "d", 1)); a == nil {
		t.Fatal("expected first alert")
	}
	// ts=100 expires when clock reaches 200 (100 <= 200-100).
	a := e.Ingest(ev("e2", "ent", 200, "d", 1))
	if a == nil {
		t.Fatal("expected re-alert after expiry+recovery at same timestamp")
	}
	if a.Evidence[0] != "e2" {
		t.Fatalf("evidence = %v, want [e2]", a.Evidence)
	}
}

// Window boundary is strict: timestamp == clock-W is expired,
// timestamp == clock-W+1 is still active.
func TestWindowBoundaryStrictness(t *testing.T) {
	rule := Rule{Slots: []Slot{{Domains: []string{"d"}}}}

	atBoundary := mustEngine(t, rule, 100)
	atBoundary.Ingest(ev("e1", "ent", 100, "d", 1))
	atBoundary.Advance(200) // cutoff=100: ts=100 is NOT > 100
	if _, ok := atBoundary.Match("ent"); ok {
		t.Fatal("event at clock-W must be expired")
	}

	inside := mustEngine(t, rule, 100)
	inside.Ingest(ev("e1", "ent", 101, "d", 1))
	inside.Advance(200) // cutoff=100: ts=101 > 100
	if _, ok := inside.Match("ent"); !ok {
		t.Fatal("event at clock-W+1 must still be active")
	}
}

// Advance must update entities that receive no new events.
func TestAdvanceExpiresEntity(t *testing.T) {
	rule := Rule{Slots: []Slot{{Domains: []string{"d"}}}}
	e := mustEngine(t, rule, 100)
	if a := e.Ingest(ev("e1", "ent", 0, "d", 1)); a == nil {
		t.Fatal("expected alert")
	}
	e.Advance(1000)
	if _, ok := e.Match("ent"); ok {
		t.Fatal("expected match to lapse after Advance beyond window")
	}
	// Re-satisfaction after the lapse must alert again.
	if a := e.Ingest(ev("e2", "ent", 1000, "d", 1)); a == nil {
		t.Fatal("expected alert on re-satisfaction")
	}
}

// Evidence from different entities must never combine.
func TestEntityIsolation(t *testing.T) {
	rule := Rule{Slots: []Slot{
		{Domains: []string{"d"}, Tags: []string{"x"}},
		{Domains: []string{"d"}, Tags: []string{"y"}},
	}}
	e := mustEngine(t, rule, 100)
	e.Ingest(ev("e1", "ent1", 0, "d", 1, "x"))
	e.Ingest(ev("e2", "ent2", 0, "d", 1, "y"))
	if _, ok := e.Match("ent1"); ok {
		t.Fatal("ent1 must not match using ent2's event")
	}
	if _, ok := e.Match("ent2"); ok {
		t.Fatal("ent2 must not match using ent1's event")
	}
}

// Severity lower bound and multi-tag requirements are enforced.
func TestSlotConstraints(t *testing.T) {
	rule := Rule{Slots: []Slot{
		{Domains: []string{"cloud"}, MinSeverity: 3, Tags: []string{"a", "b"}},
	}}
	e := mustEngine(t, rule, 100)
	e.Ingest(ev("low", "ent", 0, "cloud", 2, "a", "b")) // severity too low
	e.Ingest(ev("notag", "ent", 1, "cloud", 3, "a"))    // missing tag b
	e.Ingest(ev("dom", "ent", 2, "proc", 5, "a", "b"))  // wrong domain
	if _, ok := e.Match("ent"); ok {
		t.Fatal("no event should satisfy the slot yet")
	}
	if a := e.Ingest(ev("good", "ent", 3, "cloud", 3, "a", "b")); a == nil {
		t.Fatal("expected alert for fully qualifying event")
	}
}

func TestMatchUnknownEntity(t *testing.T) {
	e := mustEngine(t, Rule{Slots: []Slot{{}}}, 100)
	if _, ok := e.Match("nope"); ok {
		t.Fatal("unknown entity must not match")
	}
}

func TestNewEngineValidation(t *testing.T) {
	if _, err := NewEngine(Rule{}, 100); err == nil {
		t.Fatal("expected error for empty rule")
	}
	slots := make([]Slot, 13)
	if _, err := NewEngine(Rule{Slots: slots}, 100); err == nil {
		t.Fatal("expected error for 13 slots")
	}
	if _, err := NewEngine(Rule{Slots: []Slot{{}}}, 0); err == nil {
		t.Fatal("expected error for non-positive window")
	}
}
