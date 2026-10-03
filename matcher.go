package sentinelcore

// evNode 为窗口内一个活跃事件的内部节点。
type evNode struct {
	id          string
	ts          int64
	slotMask    uint16 // 该事件满足哪些槽位（位 i 表示槽位 i）
	matchedSlot int    // 当前占据的槽位，-1 表示未参与匹配
}

// entityState 为单个实体的全部窗口内状态。
// 匹配采用增量维护的二部图最大匹配（槽位 <= 12，事件侧按槽位候选集遍历）：
// 只在事件增删时沿增广路局部调整，绝不重扫全部窗口事件重建匹配。
type entityState struct {
	nslots     int
	events     map[string]*evNode   // 窗口内全部活跃事件
	slotCands  []map[string]*evNode // 每个槽位的活跃候选事件集
	matched    []*evNode            // 每个槽位当前占据的事件（nil 表示空）
	matchCount int                  // 当前匹配边数
	satisfied  bool                 // 上一时刻是否满足（用于告警沿检测）
}

func newEntityState(nslots int) *entityState {
	st := &entityState{
		nslots:    nslots,
		events:    make(map[string]*evNode),
		slotCands: make([]map[string]*evNode, nslots),
		matched:   make([]*evNode, nslots),
	}
	for i := range st.slotCands {
		st.slotCands[i] = make(map[string]*evNode)
	}
	return st
}

// add 插入事件并在匹配未饱和时尝试以该事件为起点增广。
func (st *entityState) add(ev *evNode) {
	st.events[ev.id] = ev
	for s := 0; s < st.nslots; s++ {
		if ev.slotMask&(1<<uint(s)) != 0 {
			st.slotCands[s][ev.id] = ev
		}
	}
	if st.matchCount < st.nslots {
		if st.tryPlace(ev, make([]bool, st.nslots)) {
			st.matchCount++
		}
	}
}

// remove 删除事件；若其占据槽位，释放后从该槽位出发寻找增广路补位。
func (st *entityState) remove(ev *evNode) {
	delete(st.events, ev.id)
	for s := 0; s < st.nslots; s++ {
		if ev.slotMask&(1<<uint(s)) != 0 {
			delete(st.slotCands[s], ev.id)
		}
	}
	if ev.matchedSlot >= 0 {
		s := ev.matchedSlot
		st.matched[s] = nil
		ev.matchedSlot = -1
		st.matchCount--
		if st.augmentSlot(s, make([]bool, st.nslots)) {
			st.matchCount++
		}
	}
}

// tryPlace 为事件 ev 寻找槽位（标准 Kuhn 增广，事件侧出发）。
// 递归深度与 visited 数组均受槽位数（<=12）约束。
func (st *entityState) tryPlace(ev *evNode, seen []bool) bool {
	for s := 0; s < st.nslots; s++ {
		if ev.slotMask&(1<<uint(s)) == 0 || seen[s] {
			continue
		}
		seen[s] = true
		if st.matched[s] == nil || st.tryPlace(st.matched[s], seen) {
			st.matched[s] = ev
			ev.matchedSlot = s
			return true
		}
	}
	return false
}

// augmentSlot 尝试为空闲槽位 s 寻找证据：先找未占据的候选（热点路径 O(1)），
// 找不到再尝试让已占据候选迁入并递归填补其原槽位。
// 成功时匹配数恰好 +1（链末端必有一个新事件进入匹配），由调用方计数。
func (st *entityState) augmentSlot(s int, seen []bool) bool {
	if seen[s] {
		return false
	}
	seen[s] = true
	for _, c := range st.slotCands[s] {
		if c.matchedSlot < 0 {
			st.matched[s] = c
			c.matchedSlot = s
			return true
		}
	}
	for _, c := range st.slotCands[s] {
		old := c.matchedSlot
		if old < 0 || old == s {
			continue
		}
		if st.augmentSlot(old, seen) {
			st.matched[s] = c
			c.matchedSlot = s
			return true
		}
	}
	return false
}

// evidence 在匹配饱和时返回按槽位排列的证据 id。
func (st *entityState) evidence() []string {
	out := make([]string, st.nslots)
	for s, ev := range st.matched {
		out[s] = ev.id
	}
	return out
}
