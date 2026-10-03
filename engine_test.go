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
	return Event{EventID: id, EntityID: entity, Timestamp: ts, Domain: domain, Severity: sev, Tags: tags}
}

// 重叠槽位：e1 同时满足槽位0和槽位1，e2 只满足槽位1。
// 若贪心地把 e1 分给槽位1 会失败；正确匹配应为 e1->槽0, e2->槽1。
func TestOverlappingSlotsGreedyFailure(t *testing.T) {
	rule := Rule{Slots: []Slot{
		{Domains: []string{"proc"}, Tags: []string{"a"}},
		{Domains: []string{"proc"}},
	}}
	e := mustEngine(t, rule, 1000)
	if alerts := e.Ingest(ev("e1", "u1", 100, "proc", 1, "a")); len(alerts) != 0 {
		t.Fatalf("unexpected alert: %v", alerts)
	}
	alerts := e.Ingest(ev("e2", "u1", 200, "proc", 1))
	if len(alerts) != 1 {
		t.Fatalf("expected 1 alert, got %v", alerts)
	}
	want := []string{"e1", "e2"}
	for i, id := range alerts[0].Evidence {
		if id != want[i] {
			t.Fatalf("evidence[%d]=%s want %s", i, id, want[i])
		}
	}
	if _, ok := e.Match("u1"); !ok {
		t.Fatal("Match should report satisfied")
	}
}

// 每个槽位都有候选、事件总数(3)>=槽位数(3)，但三个槽位共享两个可互换事件，
// 霍尔条件不满足，不存在完整分配。
func TestHallViolationNoMatch(t *testing.T) {
	rule := Rule{Slots: []Slot{
		{Tags: []string{"rare"}},
		{Tags: []string{"rare"}},
		{Tags: []string{"rare"}},
	}}
	e := mustEngine(t, rule, 1000)
	e.Ingest(ev("e1", "u1", 100, "proc", 1, "rare"))
	e.Ingest(ev("e2", "u1", 200, "proc", 1, "rare"))
	// e3 在窗口内但不满足任何槽位，使事件总数足够。
	alerts := e.Ingest(ev("e3", "u1", 300, "proc", 1, "other"))
	if len(alerts) != 0 {
		t.Fatalf("must not alert on Hall violation: %v", alerts)
	}
	if _, ok := e.Match("u1"); ok {
		t.Fatal("Match must report no match")
	}
	// 补入第三个 rare 事件后应命中。
	alerts = e.Ingest(ev("e4", "u1", 400, "proc", 1, "rare"))
	if len(alerts) != 1 || len(alerts[0].Evidence) != 3 {
		t.Fatalf("expected alert with 3 evidence, got %v", alerts)
	}
}

// 已选证据到期，但替代证据仍在窗口内维持命中：不告警、不失配。
func TestExpiryWithReplacementKeepsMatch(t *testing.T) {
	rule := Rule{Slots: []Slot{{Tags: []string{"x"}}}}
	e := mustEngine(t, rule, 1000)
	if alerts := e.Ingest(ev("e1", "u1", 100, "proc", 1, "x")); len(alerts) != 1 {
		t.Fatalf("expected alert, got %v", alerts)
	}
	e.Ingest(ev("e2", "u1", 500, "proc", 1, "x")) // 替代候选
	// t=1101 时 e1(ts=100) 到期（100 <= 1101-1000），e2 仍在窗口内。
	e.Advance(1101)
	got, ok := e.Match("u1")
	if !ok || len(got) != 1 || got[0] != "e2" {
		t.Fatalf("expected evidence [e2], got %v ok=%v", got, ok)
	}
}

// 窗口边界：timestamp == t-W 的事件到期。到期先失配，随后同时间新事件
// 恢复满足，必须产生新告警。
func TestBoundaryExpiryThenSameTimeRearm(t *testing.T) {
	rule := Rule{Slots: []Slot{{Tags: []string{"x"}}}}
	e := mustEngine(t, rule, 1000)
	e.Ingest(ev("e1", "u1", 100, "proc", 1, "x")) // 告警1
	e.Advance(500)
	if _, ok := e.Match("u1"); !ok {
		t.Fatal("should still be satisfied at t=500")
	}
	// t=1100：e1 的 ts=100 <= 1100-1000，恰好在边界上到期，先失配；
	// 同时间新事件 e2 使其恢复满足，必须再次告警。
	alerts := e.Ingest(ev("e2", "u1", 1100, "proc", 1, "x"))
	if len(alerts) != 1 || alerts[0].Evidence[0] != "e2" {
		t.Fatalf("expected re-arm alert with e2, got %v", alerts)
	}
	// 边界另一侧：t=1099 时 ts=100 仍活跃（1099-1000=99 < 100）。
	e2 := mustEngine(t, rule, 1000)
	e2.Ingest(ev("e1", "u1", 100, "proc", 1, "x"))
	e2.Advance(1099)
	if _, ok := e2.Match("u1"); !ok {
		t.Fatal("event at ts==t-W+1 must remain active")
	}
}

// Advance 只推进时钟：失配的实体即使没有新事件也必须更新状态；
// 之后重新满足时再次告警。
func TestAdvanceExpiresWithoutNewEvents(t *testing.T) {
	rule := Rule{Slots: []Slot{{Tags: []string{"x"}}}}
	e := mustEngine(t, rule, 1000)
	e.Ingest(ev("e1", "u1", 100, "proc", 1, "x")) // 告警
	e.Advance(2000)                               // e1 到期，实体失配且状态被回收
	if _, ok := e.Match("u1"); ok {
		t.Fatal("Advance must expire the entity's evidence")
	}
	alerts := e.Ingest(ev("e2", "u1", 2100, "proc", 1, "x"))
	if len(alerts) != 1 {
		t.Fatalf("expected re-arm alert after expiry, got %v", alerts)
	}
}

// 持续满足期间证据更换不得重复告警。
func TestNoDuplicateAlertWhileSatisfied(t *testing.T) {
	rule := Rule{Slots: []Slot{{Tags: []string{"x"}}}}
	e := mustEngine(t, rule, 1000)
	e.Ingest(ev("e1", "u1", 100, "proc", 1, "x"))
	for i, ts := range []int64{200, 300, 400} {
		if alerts := e.Ingest(ev("ex"+string(rune('a'+i)), "u1", ts, "proc", 1, "x")); len(alerts) != 0 {
			t.Fatalf("duplicate alert at ts=%d: %v", ts, alerts)
		}
	}
}

// 不同实体的事件不能拼成证据。
func TestEntitiesDoNotShareEvidence(t *testing.T) {
	rule := Rule{Slots: []Slot{{Tags: []string{"a"}}, {Tags: []string{"b"}}}}
	e := mustEngine(t, rule, 1000)
	e.Ingest(ev("e1", "u1", 100, "proc", 1, "a"))
	e.Ingest(ev("e2", "u2", 100, "proc", 1, "b"))
	if _, ok := e.Match("u1"); ok {
		t.Fatal("u1 must not match with u2's event")
	}
	if _, ok := e.Match("u2"); ok {
		t.Fatal("u2 must not match with u1's event")
	}
}

// severity 下限与 domain 集合约束。
func TestSlotConditions(t *testing.T) {
	rule := Rule{Slots: []Slot{{Domains: []string{"net", "cloud"}, MinSeverity: 3}}}
	e := mustEngine(t, rule, 1000)
	e.Ingest(ev("e1", "u1", 100, "proc", 5)) // domain 不允许
	e.Ingest(ev("e2", "u1", 200, "net", 2))  // severity 不足
	if _, ok := e.Match("u1"); ok {
		t.Fatal("neither event should satisfy the slot")
	}
	alerts := e.Ingest(ev("e3", "u1", 300, "cloud", 3))
	if len(alerts) != 1 || alerts[0].Evidence[0] != "e3" {
		t.Fatalf("expected alert with e3, got %v", alerts)
	}
}

func TestNewEngineValidation(t *testing.T) {
	if _, err := NewEngine(Rule{}, 100); err == nil {
		t.Fatal("expected error for 0 slots")
	}
	if _, err := NewEngine(Rule{Slots: make([]Slot, 13)}, 100); err == nil {
		t.Fatal("expected error for 13 slots")
	}
	if _, err := NewEngine(Rule{Slots: []Slot{{}}}, 0); err == nil {
		t.Fatal("expected error for non-positive window")
	}
}
