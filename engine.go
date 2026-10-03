package sentinelcore

import "fmt"

// expiryItem 为全局到期队列中的一项。输入时间全局非递减，
// 因此单一 FIFO 队列即可按序弹出全部到期事件，无需遍历实体。
type expiryItem struct {
	ts       int64
	entityID string
	eventID  string
}

// Engine 为单条规则、固定窗口的匹配引擎。非并发安全，调用方需单线程使用。
type Engine struct {
	rule     Rule
	w        int64
	now      int64
	nslots   int
	entities map[string]*entityState
	queue    []expiryItem // 活跃事件的到期队列（按时间升序）
	head     int          // 队列头下标，弹出不回溯
}

// NewEngine 创建引擎。规则槽位数须在 1..12，窗口 W 为正整数毫秒。
func NewEngine(rule Rule, windowMs int64) (*Engine, error) {
	if len(rule.Slots) < 1 || len(rule.Slots) > 12 {
		return nil, fmt.Errorf("sentinelcore: rule must have 1..12 slots, got %d", len(rule.Slots))
	}
	if windowMs <= 0 {
		return nil, fmt.Errorf("sentinelcore: window must be positive, got %d", windowMs)
	}
	return &Engine{
		rule:     rule,
		w:        windowMs,
		nslots:   len(rule.Slots),
		entities: make(map[string]*entityState),
	}, nil
}

// Ingest 将时钟推进到 ev.Timestamp 并处理到期，然后加入事件。
// 返回本次新增告警（至多一条，证据按槽位排列）。
func (e *Engine) Ingest(ev Event) []Alert {
	if ev.Timestamp > e.now {
		e.now = ev.Timestamp
	}
	e.expire()

	st := e.entities[ev.EntityID]
	if st == nil {
		st = newEntityState(e.nslots)
		e.entities[ev.EntityID] = st
	}
	node := &evNode{id: ev.EventID, ts: ev.Timestamp, matchedSlot: -1, slotMask: e.slotMaskOf(ev)}
	st.add(node)
	e.queue = append(e.queue, expiryItem{ts: ev.Timestamp, entityID: ev.EntityID, eventID: ev.EventID})

	if st.matchCount == st.nslots && !st.satisfied {
		st.satisfied = true
		return []Alert{{EntityID: ev.EntityID, Evidence: st.evidence()}}
	}
	return nil
}

// Advance 只推进时钟并处理到期。到期只会使实体失配，不会产生新告警。
func (e *Engine) Advance(t int64) {
	if t > e.now {
		e.now = t
	}
	e.expire()
}

// Match 返回该实体当前的一组完整证据（按槽位排列），不存在时 ok=false。
func (e *Engine) Match(entityID string) (evidence []string, ok bool) {
	st := e.entities[entityID]
	if st == nil || st.matchCount < st.nslots {
		return nil, false
	}
	return st.evidence(), true
}

// expire 弹出全部到期事件（timestamp <= now-W），逐项从所属实体中移除。
// 实体窗口清空后回收其全部内部状态。
func (e *Engine) expire() {
	cutoff := e.now - e.w
	for e.head < len(e.queue) && e.queue[e.head].ts <= cutoff {
		item := e.queue[e.head]
		e.head++
		st := e.entities[item.entityID]
		if st == nil {
			continue
		}
		node := st.events[item.eventID]
		if node == nil {
			continue
		}
		st.remove(node)
		if st.matchCount < st.nslots {
			st.satisfied = false
		}
		if len(st.events) == 0 {
			delete(e.entities, item.entityID)
		}
	}
	// 队列头部弹出过多时压缩底层数组，避免内存随历史增长。
	if e.head > 1024 && e.head*2 > len(e.queue) {
		e.queue = append([]expiryItem(nil), e.queue[e.head:]...)
		e.head = 0
	}
}

// slotMaskOf 计算事件满足的槽位集合。
func (e *Engine) slotMaskOf(ev Event) uint16 {
	var mask uint16
	for s, slot := range e.rule.Slots {
		if slotSatisfied(slot, ev) {
			mask |= 1 << uint(s)
		}
	}
	return mask
}

func slotSatisfied(slot Slot, ev Event) bool {
	if len(slot.Domains) > 0 {
		found := false
		for _, d := range slot.Domains {
			if d == ev.Domain {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	if ev.Severity < slot.MinSeverity {
		return false
	}
	for _, t := range slot.Tags {
		found := false
		for _, et := range ev.Tags {
			if et == t {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}
