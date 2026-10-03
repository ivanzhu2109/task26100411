package sentinelcore

import (
	"math/rand"
	"testing"
)

// refEntity 为穷举参考实现中单个实体的状态。
type refEntity struct {
	events    []Event // 窗口内活跃事件
	satisfied bool
}

// reference 为独立的穷举参考实现：每次操作后重扫窗口、回溯枚举全部槽位分配。
type reference struct {
	rule     Rule
	w        int64
	now      int64
	entities map[string]*refEntity
	alerts   int
}

func newReference(rule Rule, w int64) *reference {
	return &reference{rule: rule, w: w, entities: make(map[string]*refEntity)}
}

func slotSat(slot Slot, ev Event) bool {
	return slotSatisfied(slot, ev)
}

// satisfiable 回溯枚举全部槽位分配（仅用于小规模对拍）。
func (r *reference) satisfiable(evts []Event) bool {
	used := make([]bool, len(evts))
	var assign func(s int) bool
	assign = func(s int) bool {
		if s == len(r.rule.Slots) {
			return true
		}
		for i, ev := range evts {
			if used[i] || !slotSat(r.rule.Slots[s], ev) {
				continue
			}
			used[i] = true
			if assign(s + 1) {
				return true
			}
			used[i] = false
		}
		return false
	}
	return assign(0)
}

func (r *reference) expire() {
	cutoff := r.now - r.w
	for id, st := range r.entities {
		kept := st.events[:0]
		for _, ev := range st.events {
			if ev.Timestamp > cutoff && ev.Timestamp <= r.now {
				kept = append(kept, ev)
			}
		}
		st.events = kept
		sat := len(st.events) > 0 && r.satisfiable(st.events)
		if !sat {
			st.satisfied = false
		}
		if len(st.events) == 0 {
			delete(r.entities, id)
		}
	}
}

func (r *reference) ingest(ev Event) int {
	if ev.Timestamp > r.now {
		r.now = ev.Timestamp
	}
	r.expire()
	st := r.entities[ev.EntityID]
	if st == nil {
		st = &refEntity{}
		r.entities[ev.EntityID] = st
	}
	st.events = append(st.events, ev)
	sat := r.satisfiable(st.events)
	if sat && !st.satisfied {
		st.satisfied = true
		return 1
	}
	return 0
}

func (r *reference) advance(t int64) {
	if t > r.now {
		r.now = t
	}
	r.expire()
}

func (r *reference) matchable(entityID string) bool {
	st := r.entities[entityID]
	return st != nil && st.satisfied
}

// checkEvidence 校验引擎给出的证据真实有效：按槽位满足条件、互不相同、
// 属于同一实体且全部落在当前窗口内。
func checkEvidence(t *testing.T, rule Rule, now, w int64, entity string, evidence []string, known map[string]Event) {
	t.Helper()
	if len(evidence) != len(rule.Slots) {
		t.Fatalf("evidence len=%d want %d", len(evidence), len(rule.Slots))
	}
	seen := make(map[string]bool)
	for s, id := range evidence {
		ev, ok := known[id]
		if !ok {
			t.Fatalf("evidence %q unknown", id)
		}
		if seen[id] {
			t.Fatalf("event %s used for multiple slots", id)
		}
		seen[id] = true
		if ev.EntityID != entity {
			t.Fatalf("evidence %s belongs to %s, not %s", id, ev.EntityID, entity)
		}
		if ev.Timestamp <= now-w || ev.Timestamp > now {
			t.Fatalf("evidence %s ts=%d outside window (%d,%d]", id, ev.Timestamp, now-w, now)
		}
		if !slotSat(rule.Slots[s], ev) {
			t.Fatalf("evidence %s does not satisfy slot %d", id, s)
		}
	}
}

// TestRandomizedCrossCheck 用固定种子生成小规模操作序列，
// 与穷举参考实现逐次核对可满足性、告警次数与证据有效性。
func TestRandomizedCrossCheck(t *testing.T) {
	rng := rand.New(rand.NewSource(20261003))
	domains := []string{"proc", "net", "mail", "cloud"}
	tags := []string{"a", "b", "c"}
	entities := []string{"u0", "u1", "u2"}

	for trial := 0; trial < 30; trial++ {
		nslots := 1 + rng.Intn(4)
		rule := Rule{Slots: make([]Slot, nslots)}
		for s := range rule.Slots {
			slot := Slot{MinSeverity: rng.Intn(4)}
			if rng.Intn(2) == 0 {
				slot.Domains = []string{domains[rng.Intn(len(domains))]}
			}
			if rng.Intn(2) == 0 {
				slot.Tags = []string{tags[rng.Intn(len(tags))]}
			}
			rule.Slots[s] = slot
		}
		w := int64(20 + rng.Intn(40))
		eng, err := NewEngine(rule, w)
		if err != nil {
			t.Fatal(err)
		}
		ref := newReference(rule, w)
		known := make(map[string]Event)
		now := int64(0)
		engineAlerts := 0

		for op := 0; op < 2000; op++ {
			if rng.Intn(100) < 80 {
				now += int64(rng.Intn(6))
				ev := Event{
					EventID:   "ev" + itoa(trial*2000+op),
					EntityID:  entities[rng.Intn(len(entities))],
					Timestamp: now,
					Domain:    domains[rng.Intn(len(domains))],
					Severity:  rng.Intn(5),
				}
				if rng.Intn(2) == 0 {
					ev.Tags = append(ev.Tags, tags[rng.Intn(len(tags))])
				}
				if rng.Intn(4) == 0 {
					ev.Tags = append(ev.Tags, tags[rng.Intn(len(tags))])
				}
				known[ev.EventID] = ev
				got := eng.Ingest(ev)
				engineAlerts += len(got)
				ref.alerts += ref.ingest(ev)
				for _, a := range got {
					checkEvidence(t, rule, now, w, a.EntityID, a.Evidence, known)
				}
			} else {
				now += int64(rng.Intn(15))
				eng.Advance(now)
				ref.advance(now)
			}
			for _, ent := range entities {
				evidence, ok := eng.Match(ent)
				if ok != ref.matchable(ent) {
					t.Fatalf("trial=%d op=%d entity=%s: engine match=%v, ref=%v",
						trial, op, ent, ok, ref.matchable(ent))
				}
				if ok {
					checkEvidence(t, rule, now, w, ent, evidence, known)
				}
			}
		}
		if engineAlerts != ref.alerts {
			t.Fatalf("trial=%d: engine alerts=%d, ref alerts=%d", trial, engineAlerts, ref.alerts)
		}
	}
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
