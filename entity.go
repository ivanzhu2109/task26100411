package sentinelcore

// evRec is a stored window event together with its precomputed slot mask.
type evRec struct {
	id   string
	mask uint16 // bit i set => event satisfies slot i
}

// slotState tracks candidates of one slot.
type slotState struct {
	// queue holds unmatched-candidate event IDs in ingestion order.
	// Entries of matched events are skipped lazily; expired events are
	// removed eagerly at the front because ingestion and expiry are both
	// time ordered.
	queue []string
	// matched lists currently matched event IDs that satisfy this slot.
	// Total matched events per entity never exceed the slot count (<=12),
	// so this stays tiny.
	matched []string
}

// entityState holds the sliding-window state of a single entity and
// maintains a maximum bipartite matching between slots and events.
type entityState struct {
	events  map[string]*evRec
	slots   []slotState
	matchAt []string       // slot -> event ID ("" when free)
	matchEv map[string]int // event ID -> slot
	matched int            // number of matched slots
	active  int            // number of stored window events
	ok      bool           // satisfied == matched == slot count

	// scratch buffers reused by augmenting-path searches
	bfsQueue   []int
	bfsVisited []bool
	parentSlot []int
	parentEv   []string
}

func newEntityState(n int) *entityState {
	return &entityState{
		events:     make(map[string]*evRec),
		slots:      make([]slotState, n),
		matchAt:    make([]string, n),
		matchEv:    make(map[string]int, n),
		bfsVisited: make([]bool, n),
		parentSlot: make([]int, n),
		parentEv:   make([]string, n),
	}
}

// addEvent inserts a window event and pushes it to the candidate
// queues of every slot it satisfies.
func (st *entityState) addEvent(rec *evRec) {
	st.events[rec.id] = rec
	st.active++
	mask := rec.mask
	for mask != 0 {
		i := bitIndex(mask)
		st.slots[i].queue = append(st.slots[i].queue, rec.id)
		mask &= mask - 1
	}
}

// removeEvent deletes an expired event. If the event was matched, the
// freed slot immediately triggers a re-augmentation attempt.
func (st *entityState) removeEvent(rec *evRec) {
	delete(st.events, rec.id)
	st.active--
	mask := rec.mask
	for m := mask; m != 0; m &= m - 1 {
		i := bitIndex(m)
		q := st.slots[i].queue
		// The event's entry is either at the front (all older entries
		// were already consumed or expired) or was consumed earlier by
		// an augmenting search.
		if len(q) > 0 && q[0] == rec.id {
			st.slots[i].queue = q[1:]
		}
	}
	slot, wasMatched := st.matchEv[rec.id]
	if wasMatched {
		delete(st.matchEv, rec.id)
		st.matchAt[slot] = ""
		st.matched--
		for m := mask; m != 0; m &= m - 1 {
			i := bitIndex(m)
			st.slots[i].matched = removeString(st.slots[i].matched, rec.id)
		}
		st.tryAugment(slot)
	}
	st.ok = st.matched == len(st.slots)
}

// tryMatch attempts to grow the matching by one after an event was
// added. Adding a single vertex can raise the maximum matching by at
// most one, so the first successful augmentation is enough.
func (st *entityState) tryMatch() {
	n := len(st.slots)
	if st.matched == n {
		return
	}
	for s := 0; s < n; s++ {
		if st.matchAt[s] == "" && st.tryAugment(s) {
			break
		}
	}
	st.ok = st.matched == n
}

// tryAugment searches for an augmenting path starting at the free slot
// `start` using BFS over the alternating graph. From a reached slot we
// can move to any unmatched candidate (path endpoint) or traverse a
// matched edge to the slot that currently owns a matched candidate.
func (st *entityState) tryAugment(start int) bool {
	for i := range st.bfsVisited {
		st.bfsVisited[i] = false
	}
	st.bfsQueue = st.bfsQueue[:0]
	st.bfsVisited[start] = true
	st.bfsQueue = append(st.bfsQueue, start)
	for head := 0; head < len(st.bfsQueue); head++ {
		x := st.bfsQueue[head]
		if u, found := st.popUnmatched(x); found {
			st.augment(x, u, start)
			return true
		}
		for _, mid := range st.slots[x].matched {
			y := st.matchEv[mid]
			if !st.bfsVisited[y] {
				st.bfsVisited[y] = true
				st.parentSlot[y] = x
				st.parentEv[y] = mid
				st.bfsQueue = append(st.bfsQueue, y)
			}
		}
	}
	return false
}

// popUnmatched pops and returns the oldest live unmatched candidate of
// slot x, discarding stale entries (events already matched elsewhere).
func (st *entityState) popUnmatched(x int) (string, bool) {
	q := st.slots[x].queue
	for len(q) > 0 {
		id := q[0]
		q = q[1:]
		if _, taken := st.matchEv[id]; taken {
			continue
		}
		if _, alive := st.events[id]; !alive {
			continue
		}
		st.slots[x].queue = q
		return id, true
	}
	st.slots[x].queue = q
	return "", false
}

// augment flips the matching along the discovered path: slot x takes
// the previously unmatched event u, and displaced matched events shift
// back along the parent chain to the originally free slot `start`.
func (st *entityState) augment(x int, u string, start int) {
	st.assign(x, u)
	for x != start {
		ps := st.parentSlot[x]
		pe := st.parentEv[x]
		st.matchAt[ps] = pe
		st.matchEv[pe] = ps
		x = ps
	}
	st.matched++
}

// assign matches event id to slot s, registering it as a matched
// candidate of every slot it satisfies.
func (st *entityState) assign(s int, id string) {
	st.matchAt[s] = id
	st.matchEv[id] = s
	rec := st.events[id]
	for mask := rec.mask; mask != 0; mask &= mask - 1 {
		i := bitIndex(mask)
		st.slots[i].matched = append(st.slots[i].matched, id)
	}
}

// evidence returns the matched event IDs in slot order.
// Callers must ensure st.ok is true.
func (st *entityState) evidence() []string {
	out := make([]string, len(st.matchAt))
	copy(out, st.matchAt)
	return out
}

func bitIndex(mask uint16) int {
	i := 0
	for m := mask; m&1 == 0; m >>= 1 {
		i++
	}
	return i
}

func removeString(s []string, v string) []string {
	for i, x := range s {
		if x == v {
			return append(s[:i], s[i+1:]...)
		}
	}
	return s
}
