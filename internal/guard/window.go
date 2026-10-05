package guard

import "time"

// maxHitsPerWindow 是单个 IP 在窗口内的记录上限。
//
// 一旦计数远超任何合理阈值，继续记录就没有意义了（反正已经要封），
// 这个上限是为了防止极端洪水场景下内存被撑爆。
const maxHitsPerWindow = 100000

// hitWindow 记录某个 IP 在滑动窗口内的命中时间点。
//
// 用时间戳切片而不是分桶计数：窗口内事件数正常情况下是几十的量级，
// 切片开销远小于精确滑动窗口带来的复杂度，且能精确处理窗口边界。
type hitWindow struct {
	// hits 是毫秒时间戳，单调递增。
	hits []int64
	// last 是该 IP 最近一次活动时间，用于淘汰冷 key。
	last time.Time
}

// add 记录一次命中并返回窗口内的命中总数。
func (w *hitWindow) add(now time.Time, window time.Duration) int {
	cut := now.Add(-window).UnixMilli()
	w.last = now

	// 丢弃滑出窗口的记录。切片头部是有序的，直接找分割点。
	i := 0
	for i < len(w.hits) && w.hits[i] < cut {
		i++
	}
	if i > 0 {
		w.hits = append(w.hits[:0], w.hits[i:]...)
	}

	if len(w.hits) >= maxHitsPerWindow {
		return len(w.hits)
	}
	w.hits = append(w.hits, now.UnixMilli())
	return len(w.hits)
}

// count 返回窗口内当前命中数，不记录新命中。
func (w *hitWindow) count(now time.Time, window time.Duration) int {
	cut := now.Add(-window).UnixMilli()
	i := 0
	for i < len(w.hits) && w.hits[i] < cut {
		i++
	}
	return len(w.hits) - i
}

// reset 清空窗口，用于解封后重新计数。
func (w *hitWindow) reset() {
	w.hits = w.hits[:0]
}
