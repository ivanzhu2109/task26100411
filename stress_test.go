package sentinelcore

import (
	"fmt"
	"runtime"
	"testing"
	"time"
)

// TestStress 可复现压力测试：
//   - 12 个槽位：槽位 0..9 需要常见证据（大量重复候选），槽位 10..11 共享稀有证据；
//   - 1 万个实体，80% 事件集中于热点实体，峰值约 30 万活跃事件；
//   - 阶段一：稀有证据每次至多 1 个存活，热点实体长期失配；
//   - 阶段二：3 个周期反复“补入稀有证据对 -> 命中告警 -> 到期失配”；
//   - 逐操作核对热点实体可满足性，校验证据，记录耗时与峰值内存；
//   - 结尾 Advance 清空全部状态，确认内存不随历史输入增长。
func TestStress(t *testing.T) {
	const (
		windowMs   = int64(60_000)
		numSlots   = 12
		numEntity  = 10_000
		hotEntity  = "hot"
		perTick    = 5 // 每毫秒 5 条事件 -> 峰值 30 万活跃
		phase1Tick = 120_000
		cycles     = 3
		cycleTick  = 70_000
	)
	rule := Rule{Slots: make([]Slot, numSlots)}
	for s := 0; s < numSlots-2; s++ {
		rule.Slots[s] = Slot{Domains: []string{"proc"}, MinSeverity: 1, Tags: []string{"common"}}
	}
	rule.Slots[numSlots-2] = Slot{Domains: []string{"proc"}, Tags: []string{"rare"}}
	rule.Slots[numSlots-1] = Slot{Domains: []string{"proc"}, Tags: []string{"rare"}}

	eng, err := NewEngine(rule, windowMs)
	if err != nil {
		t.Fatal(err)
	}

	runtime.GC()
	var base, peak runtime.MemStats
	runtime.ReadMemStats(&base)

	rareTS := make(map[string]int64) // 稀有事件 id -> 时间戳（数量很少）
	var rareAlive []int64            // 热点实体当前窗口内的稀有事件时间戳
	var now int64
	var seq, total, alerts int
	start := time.Now()

	expectedSatisfied := func() bool {
		kept := rareAlive[:0]
		for _, ts := range rareAlive {
			if ts > now-windowMs {
				kept = append(kept, ts)
			}
		}
		rareAlive = kept
		return len(rareAlive) >= 2
	}
	checkHot := func() {
		t.Helper()
		evidence, ok := eng.Match(hotEntity)
		if ok != expectedSatisfied() {
			t.Fatalf("total=%d now=%d: engine satisfied=%v, want %v", total, now, ok, !ok)
		}
		if ok {
			seen := make(map[string]bool)
			for i, id := range evidence {
				if seen[id] {
					t.Fatalf("duplicate evidence %s", id)
				}
				seen[id] = true
				if i >= numSlots-2 {
					ts, isRare := rareTS[id]
					if !isRare || ts <= now-windowMs {
						t.Fatalf("slot %d evidence %s is not live rare evidence", i, id)
					}
				}
			}
		}
	}
	emit := func(entity, domain string, tags ...string) {
		seq++
		total++
		id := fmt.Sprintf("e%d", seq)
		for _, tg := range tags {
			if tg == "rare" && entity == hotEntity {
				rareTS[id] = now
				rareAlive = append(rareAlive, now)
			}
		}
		got := eng.Ingest(Event{
			EventID: id, EntityID: entity, Timestamp: now,
			Domain: domain, Severity: 5, Tags: tags,
		})
		alerts += len(got)
		for _, a := range got {
			if a.EntityID != hotEntity {
				t.Fatalf("unexpected alert for %s", a.EntityID)
			}
			if len(a.Evidence) != numSlots {
				t.Fatalf("alert evidence len=%d", len(a.Evidence))
			}
		}
		checkHot()
		if total%100_000 == 0 {
			var m runtime.MemStats
			runtime.ReadMemStats(&m)
			if m.HeapAlloc > peak.HeapAlloc {
				peak = m
			}
		}
	}
	tick := func() {
		now++
		for i := 0; i < perTick; i++ {
			if i < 4 { // 80% 集中于热点实体
				emit(hotEntity, "proc", "common")
			} else {
				emit(fmt.Sprintf("u%d", seq%numEntity), "proc", "common")
			}
		}
	}

	// 阶段一：长期失配。稀有证据每 90s 一个，任意时刻至多 1 个存活。
	for tk := 0; tk < phase1Tick; tk++ {
		tick()
		if tk == 0 || tk == 90_000 {
			emit(hotEntity, "proc", "rare", "common")
		}
	}
	if alerts != 0 {
		t.Fatalf("phase1: expected no alerts, got %d", alerts)
	}

	// 阶段二：反复到期补入。每周期补入一对稀有证据（命中告警），
	// 间隔 70s 保证上一对完全到期（失配）后再补。
	for c := 0; c < cycles; c++ {
		for tk := 0; tk < 1_000; tk++ {
			tick()
		}
		emit(hotEntity, "proc", "rare", "common")
		for tk := 0; tk < 500; tk++ {
			tick()
		}
		emit(hotEntity, "proc", "rare", "common")
		for tk := 0; tk < cycleTick-1_500; tk++ {
			tick()
		}
	}
	if alerts != cycles {
		t.Fatalf("expected %d alerts, got %d", cycles, alerts)
	}

	// 全部到期：状态必须完全回收。
	eng.Advance(now + windowMs + 1)
	if len(eng.entities) != 0 {
		t.Fatalf("expected all entity state reclaimed, %d left", len(eng.entities))
	}
	if eng.head != len(eng.queue) {
		t.Fatalf("expiry queue not drained: head=%d len=%d", eng.head, len(eng.queue))
	}
	eng.queue = nil
	runtime.GC()
	var fin runtime.MemStats
	runtime.ReadMemStats(&fin)

	elapsed := time.Since(start)
	t.Logf("events=%d alerts=%d elapsed=%v (%.0f events/s)", total, alerts, elapsed, float64(total)/elapsed.Seconds())
	t.Logf("heap: baseline=%dMB peak=%dMB final=%dMB", base.HeapAlloc>>20, peak.HeapAlloc>>20, fin.HeapAlloc>>20)

	if total < 1_000_000 {
		t.Fatalf("too few events: %d", total)
	}
	if peak.HeapAlloc > 2<<30 {
		t.Fatalf("peak heap too large: %dMB", peak.HeapAlloc>>20)
	}
	// 状态回收后堆内存应回落到基线附近，不随历史输入增长。
	if fin.HeapAlloc > base.HeapAlloc+64<<20 {
		t.Fatalf("heap not reclaimed: baseline=%dMB final=%dMB", base.HeapAlloc>>20, fin.HeapAlloc>>20)
	}
}
