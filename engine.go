package sentinelcore

import "errors"

// Engine evaluates a single fixed rule over a sliding time window.
// All calls must be made from a single goroutine with globally
// non-decreasing timestamps.
type Engine struct {
	slots  []preparedSlot
	nSlots int
	window int64
	clock  int64

	entities map[string]*entityState
	expiry   []expiryItem
	head     int
}

type preparedSlot struct {
	domains map[string]struct{} // nil means any domain
	minSev  int
	tags    []string
}

type expiryItem struct {
	ts       int64
	entityID string
	eventID  string
}

// NewEngine validates the rule and returns a ready-to-use engine.
func NewEngine(rule Rule, windowMs int64) (*Engine, error) {
	if len(rule.Slots) < 1 || len(rule.Slots) > 12 {
		return nil, errors.New("rule must have between 1 and 12 slots")
	}
	if windowMs <= 0 {
		return nil, errors.New("window must be positive")
	}
	e := &Engine{
		nSlots:   len(rule.Slots),
		window:   windowMs,
		entities: make(map[string]*entityState),
	}
	e.slots = make([]preparedSlot, len(rule.Slots))
	for i, s := range rule.Slots {
		ps := preparedSlot{minSev: s.MinSeverity, tags: s.Tags}
		if len(s.Domains) > 0 {
			ps.domains = make(map[string]struct{}, len(s.Domains))
			for _, d := range s.Domains {
				ps.domains[d] = struct{}{}
			}
		}
		e.slots[i] = ps
	}
	return e, nil
}

// Ingest advances the clock to the event timestamp, expires stale
// events, then inserts the event. It returns the newly raised alert,
// or nil if the entity did not transition into the matched state.
func (e *Engine) Ingest(ev Event) *Alert {
	e.advanceClock(ev.Timestamp)
	mask := e.slotMask(ev)
	if mask == 0 || ev.ID == "" {
		return nil
	}
	st := e.entities[ev.EntityID]
	if st == nil {
		st = newEntityState(e.nSlots)
		e.entities[ev.EntityID] = st
	}
	st.addEvent(&evRec{id: ev.ID, mask: mask})
	e.expiry = append(e.expiry, expiryItem{ts: ev.Timestamp, entityID: ev.EntityID, eventID: ev.ID})

	was := st.ok
	st.tryMatch()
	if st.ok && !was {
		return &Alert{EntityID: ev.EntityID, Evidence: st.evidence()}
	}
	return nil
}

// Advance only moves the clock forward and processes expirations.
func (e *Engine) Advance(t int64) {
	e.advanceClock(t)
}

// Match returns one valid evidence assignment for the entity, or
// false when the entity is not currently matched.
func (e *Engine) Match(entityID string) ([]string, bool) {
	st := e.entities[entityID]
	if st == nil || !st.ok {
		return nil, false
	}
	return st.evidence(), true
}

// advanceClock moves the clock to t (never backwards) and expires all
// events with timestamp <= clock-window. Expirations are processed in
// timestamp order from the front of the FIFO queue.
func (e *Engine) advanceClock(t int64) {
	if t <= e.clock {
		return
	}
	e.clock = t
	cutoff := e.clock - e.window
	for e.head < len(e.expiry) && e.expiry[e.head].ts <= cutoff {
		item := e.expiry[e.head]
		e.head++
		st := e.entities[item.entityID]
		if st == nil {
			continue
		}
		rec := st.events[item.eventID]
		if rec == nil {
			continue
		}
		st.removeEvent(rec)
		if st.active == 0 {
			delete(e.entities, item.entityID)
		}
	}
	// Compact the queue once the consumed prefix dominates it.
	if e.head > 1024 && e.head*2 > len(e.expiry) {
		e.expiry = append([]expiryItem(nil), e.expiry[e.head:]...)
		e.head = 0
	}
	if e.head == len(e.expiry) {
		e.expiry = e.expiry[:0]
		e.head = 0
	}
}

// slotMask computes which slots the event satisfies.
func (e *Engine) slotMask(ev Event) uint16 {
	var mask uint16
	for i := range e.slots {
		if slotAccepts(&e.slots[i], ev) {
			mask |= 1 << uint(i)
		}
	}
	return mask
}

func slotAccepts(s *preparedSlot, ev Event) bool {
	if ev.Severity < s.minSev {
		return false
	}
	if s.domains != nil {
		if _, ok := s.domains[ev.Domain]; !ok {
			return false
		}
	}
	for _, tag := range s.tags {
		if !hasTag(ev.Tags, tag) {
			return false
		}
	}
	return true
}

func hasTag(tags []string, want string) bool {
	for _, t := range tags {
		if t == want {
			return true
		}
	}
	return false
}
