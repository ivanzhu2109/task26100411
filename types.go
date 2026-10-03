package sentinelcore

// Event is a normalized security-relevant activity record.
type Event struct {
	ID        string
	EntityID  string
	Timestamp int64 // milliseconds
	Domain    string
	Severity  int
	Tags      []string
}

// Slot is one ordered evidence position of a rule.
type Slot struct {
	Domains     []string // allowed domains (empty means any)
	MinSeverity int      // inclusive lower bound
	Tags        []string // all must be present on the event
}

// Rule is a fixed ordered list of 1..12 slots.
type Rule struct {
	Slots []Slot
}

// Alert is emitted when an entity transitions from unmatched to matched.
// Evidence[i] is the event ID assigned to slot i.
type Alert struct {
	EntityID string
	Evidence []string
}
