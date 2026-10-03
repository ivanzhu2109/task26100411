package sentinelcore

import (
	"fmt"
	"runtime"
	"testing"
	"time"
)

// TestStressMillionEvents drives 1M events through a 12-slot rule with
// 10k entities, 80% of traffic on one hot entity, a peak of ~300k
// active window events, a long mismatch phase where two slots share
// too few rare events, and continuous expiry/refill churn.
//
// Run with: go test -run TestStress -v (skipped in -short mode).
func TestStressMillionEvents(t *testing.T) {
	if testing.Short() {
		t.Skip("stress test skipped in short mode")
	}
	const (
		total     = 1_000_000
		windowMs  = 300_000
		otherEnts = 9_999
	)
	rule := Rule{Slots: make([]Slot, 12)}
	for i := 0; i < 10; i++ {
		rule.Slots[i] = Slot{Domains: []string{"proc"}}
	}
	// Slots 10 and 11 both require the rare tag: they compete for the
	// same scarce evidence.
	rule.Slots[10] = Slot{Domains: []string{"proc"}, Tags: []string{"rare"}}
	rule.Slots[11] = Slot{Domains: []string{"proc"}, Tags: []string{"rare"}}

	eng := mustEngine(t, rule, windowMs)

	isRare := func(i int) bool {
		switch {
		case i == 400_001: // phase 2: a single rare event shared by 2 slots
			return true
		case i == 450_001 || i == 450_002: // phase 3: enough rares -> match
			return true
		case i >= 800_000: // phase 5: steady rare refill after expiry gap
			return i%2000 == 1
		default:
			return false // phases 1 and 4: no rare evidence at all
		}
	}

	var mem runtime.MemStats
	var peakHeap uint64
	peakActive := 0
	peakEntities := 0
	hotAlerts := 0
	totalAlerts := 0

	start := time.Now()
	batchStart := start
	for i := 0; i < total; i++ {
		entity := fmt.Sprintf("ent-%d", i%otherEnts)
		if i%5 != 0 { // 80% of traffic to the hot entity
			entity = "hot"
		}
		var tags []string
		if isRare(i) {
			tags = []string{"rare"}
		}
		alert := eng.Ingest(Event{
			ID:        fmt.Sprintf("ev-%d", i),
			EntityID:  entity,
			Timestamp: int64(i),
			Domain:    "proc",
			Severity:  i % 5,
			Tags:      tags,
		})
		if alert != nil {
			totalAlerts++
			if alert.EntityID == "hot" {
				hotAlerts++
			}
		}
		if i%100_000 == 99_999 {
			eng.Advance(int64(i))
			runtime.ReadMemStats(&mem)
			if mem.HeapAlloc > peakHeap {
				peakHeap = mem.HeapAlloc
			}
			active := 0
			for _, st := range eng.entities {
				active += st.active
			}
			if active > peakActive {
				peakActive = active
			}
			if len(eng.entities) > peakEntities {
				peakEntities = len(eng.entities)
			}
			t.Logf("batch %7d: %8s active=%d entities=%d heap=%dMiB",
				i+1, time.Since(batchStart).Round(time.Millisecond), active,
				len(eng.entities), mem.HeapAlloc>>20)
			batchStart = time.Now()
		}
	}
	elapsed := time.Since(start)

	// Drain the whole window: all state must be reclaimed.
	eng.Advance(2_000_000)
	if len(eng.entities) != 0 {
		t.Fatalf("expected all entity state reclaimed, %d remain", len(eng.entities))
	}
	runtime.GC()
	runtime.ReadMemStats(&mem)
	finalHeap := mem.HeapAlloc

	t.Logf("total: %s for %d events (%.0f events/s)", elapsed.Round(time.Millisecond),
		total, float64(total)/elapsed.Seconds())
	t.Logf("peak: active=%d entities=%d heap=%dMiB; final heap after drain=%dMiB",
		peakActive, peakEntities, peakHeap>>20, finalHeap>>20)
	t.Logf("alerts: hot=%d total=%d", hotAlerts, totalAlerts)

	if hotAlerts != 2 {
		t.Fatalf("hot entity alerts = %d, want 2 (match, lapse, re-match)", hotAlerts)
	}
	if totalAlerts != 2 {
		t.Fatalf("total alerts = %d, want 2", totalAlerts)
	}
	if peakEntities > otherEnts+1 {
		t.Fatalf("peak entities %d exceeds %d", peakEntities, otherEnts+1)
	}
	if peakActive < 250_000 {
		t.Fatalf("peak active events %d below expected ~300k", peakActive)
	}
	if peakHeap > 1<<30 {
		t.Fatalf("peak heap %dMiB exceeds 1GiB bound", peakHeap>>20)
	}
	if finalHeap > 256<<20 {
		t.Fatalf("heap after drain %dMiB exceeds 256MiB bound", finalHeap>>20)
	}
}
