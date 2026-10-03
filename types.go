// Package sentinelcore 实现跨域检测规则的滑动时间窗证据关联匹配。
package sentinelcore

// Slot 描述规则中的一个有序槽位：事件必须满足全部条件才能占据该槽位。
type Slot struct {
	Domains     []string // 允许的 domain 集合（空表示任意）
	MinSeverity int      // severity 下限
	Tags        []string // 必须全部包含的 tags
}

// Rule 为一条固定规则，包含 1 到 12 个有序槽位。
type Rule struct {
	Slots []Slot
}

// Event 为规范化后的输入事件。调用方保证 event_id 全局唯一、
// 输入时间全局非递减、调用单线程执行。
type Event struct {
	EventID   string
	EntityID  string
	Timestamp int64 // 毫秒
	Domain    string
	Severity  int
	Tags      []string
}

// Alert 表示某实体由不满足变为满足时产生的一次告警，
// Evidence 按槽位顺序给出证据 event_id。
type Alert struct {
	EntityID string
	Evidence []string
}
