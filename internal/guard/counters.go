package guard

import (
	"sort"
	"time"

	"github.com/dreamstation625/FrpFireWall/internal/firewall"
	"github.com/dreamstation625/FrpFireWall/internal/model"
)

// ---------- 丢包计数的采样与展示 ----------

const (
	// counterSampleInterval 是采样间隔。
	//
	// 一小时：更密的话表增长快、信息量却不增加（丢包是慢变量）；更疏的话
	// "最近一小时新增"就没有可比的前一批。
	counterSampleInterval = time.Hour
	// counterRetention 是采样点的保留期。7 天 = 168 个点，画趋势足够，
	// 表也不会无限长。
	counterRetention = 7 * 24 * time.Hour
)

// CounterView 是一条计数的展示结构。
type CounterView struct {
	firewall.RuleCounter
	// DeltaPackets 是相对上一批采样的新增包数。
	//
	// 没有可比的前一批时（首次采样、或中途换过后端）为 0，同时快照里的
	// BaselineAt 为空 —— 界面据此显示"—"而不是 0，否则会被读成
	// "这段时间一个包都没拦到"，而真相是"无从比较"。
	DeltaPackets uint64 `json:"delta_packets"`
}

// CounterSnapshot 是丢包统计接口的一次响应。
type CounterSnapshot struct {
	Backend string `json:"backend"`
	// Granularity 是计数粒度：addr = 按地址（iptables），group = 按分组
	// （nftables，地址装在集合里数不出来）。空串表示当前后端读不到计数。
	Granularity string `json:"granularity"`
	// At 是这批实时读数的时刻。
	At time.Time `json:"at"`
	// BaselineAt 是算增幅时用的那一批采样时刻，空表示没有基线。
	BaselineAt *time.Time `json:"baseline_at"`
	// Unsupported 说明当前为什么拿不到计数，界面直接展示。
	Unsupported string        `json:"unsupported"`
	Items       []CounterView `json:"items"`
	// TotalPackets 是当前所有条目的丢包累计（内核口径，重建会归零）。
	TotalPackets uint64 `json:"total_packets"`
	// Series 是趋势：每个采样点一个"这一小时新增了多少包"。
	//
	// 存的是增量而不是累计值：累计值会随规则重建掉回 0，画成折线会看到
	// 莫名其妙的断崖，而断崖的真实含义只是"重建过规则"。
	Series []SeriesPoint `json:"series"`
}

// SeriesPoint 是趋势图上的一个点。
type SeriesPoint struct {
	Ts      time.Time `json:"ts"`
	Packets uint64    `json:"packets"`
	Bytes   uint64    `json:"bytes"`
}

// CountersSnapshot 组装一次丢包统计视图。
//
// 实时读数直接问内核要（不读库）：库里的是采样历史，只用来算增幅与趋势。
// 两者分开是有意的 —— 界面上"当前拦了多少"必须是此刻的真值，不能是上个小时
// 采样的旧值。
func (m *Manager) CountersSnapshot(hours int) (*CounterSnapshot, error) {
	m.mu.RLock()
	drv := m.drv
	m.mu.RUnlock()

	snap := &CounterSnapshot{Items: []CounterView{}, Series: []SeriesPoint{}}
	if drv == nil {
		snap.Unsupported = "当前没有可用的防火墙后端"
		return snap, nil
	}
	snap.Backend = drv.Name()
	cap := drv.Capability()
	snap.Granularity = cap.CounterGranularity

	now := time.Now()
	snap.At = now

	list, err := drv.Counters()
	if err != nil {
		// 读不到计数不是致命错误，界面要能显示"当前后端不支持"而不是报错。
		snap.Unsupported = err.Error()
		return snap, nil
	}
	if len(list) == 0 && cap.CounterGranularity == "" {
		snap.Unsupported = "当前后端读不到丢包计数"
	}

	// 上一批采样：算增幅用。同一条目按 kind+key+family 对号。
	prev := make(map[string]model.CounterSample, len(list))
	if batch, err := m.store.LatestCounterBatch(now); err != nil {
		m.log.Warn("读取上一批丢包计数采样失败", "err", err)
	} else if len(batch) > 0 {
		t := batch[0].Ts
		snap.BaselineAt = &t
		for _, s := range batch {
			prev[counterKey(s.Kind, s.Key, s.Family)] = s
		}
	}

	for _, c := range list {
		v := CounterView{RuleCounter: c}
		if p, ok := prev[counterKey(c.Kind, c.Key, c.Family)]; ok {
			// 读数比上一批还小 = 这中间规则被重建过，计数已经归零重新数。
			// 这时候"新增量"就是当前值本身，而不是一个负数。
			if c.Packets >= p.Packets {
				v.DeltaPackets = c.Packets - p.Packets
			} else {
				v.DeltaPackets = c.Packets
			}
		}
		snap.Items = append(snap.Items, v)
		snap.TotalPackets += c.Packets
	}
	// 条目很多时按丢包数排，界面上最该看的排在前面。
	sort.SliceStable(snap.Items, func(i, j int) bool {
		if snap.Items[i].Packets != snap.Items[j].Packets {
			return snap.Items[i].Packets > snap.Items[j].Packets
		}
		return snap.Items[i].Key < snap.Items[j].Key
	})

	if hours > 0 {
		if rows, err := m.store.CounterSeries(now.Add(-time.Duration(hours) * time.Hour)); err != nil {
			m.log.Warn("读取丢包计数趋势失败", "err", err)
		} else {
			snap.Series = counterSeries(rows)
		}
	}
	return snap, nil
}

// counterKey 是采样点的对号凭据：种类 + 标识 + 协议栈。
//
// 三者缺一不可：同一个地址在 v4 / v6 各有一条规则（协议栈区分），同一个地址
// 在全端口与端口限定两条链里也各有一条（种类区分）。
func counterKey(kind, key, family string) string {
	return kind + "\x00" + key + "\x00" + family
}

// counterSeries 把采样点折算成"每小时新增多少"的序列。
//
// 按条目分别算增量再求和，而不是先把每批求和再做差：后者在一个条目被解封
// （它消失）或新封（它出现）时，总量会凭空跳变，看起来像丢包量突变。
func counterSeries(rows []model.CounterSample) []SeriesPoint {
	if len(rows) == 0 {
		return []SeriesPoint{}
	}
	// 1. 按批次时间归组
	type bucket struct {
		ts      time.Time
		packets uint64
		bytes   uint64
	}
	byTS := make(map[time.Time]*bucket)
	for _, r := range rows {
		b, ok := byTS[r.Ts]
		if !ok {
			b = &bucket{ts: r.Ts}
			byTS[r.Ts] = b
		}
		b.packets += r.Packets
		b.bytes += r.Bytes
	}
	times := make([]time.Time, 0, len(byTS))
	for t := range byTS {
		times = append(times, t)
	}
	sort.Slice(times, func(i, j int) bool { return times[i].Before(times[j]) })

	// 2. 逐批做差，第一批没有前值、按"这批就是新增"处理
	out := make([]SeriesPoint, 0, len(times))
	var last *bucket
	for _, t := range times {
		b := byTS[t]
		p := SeriesPoint{Ts: t, Packets: b.packets, Bytes: b.bytes}
		if last != nil {
			p.Packets = deltaOrReset(b.packets, last.packets)
			p.Bytes = deltaOrReset(b.bytes, last.bytes)
		}
		out = append(out, p)
		cp := *b
		last = &cp
	}
	return out
}

// deltaOrReset 算两次读数的增量；读数变小说明计数被重置过，增量就是当前值。
func deltaOrReset(cur, prev uint64) uint64 {
	if cur >= prev {
		return cur - prev
	}
	return cur
}

// sampleCounters 采一批当前计数入库。
//
// 失败只记日志：计数是增强信息，采不到不该影响任何主流程。
func (m *Manager) sampleCounters() {
	m.mu.RLock()
	drv := m.drv
	m.mu.RUnlock()
	if drv == nil {
		return
	}
	list, err := drv.Counters()
	if err != nil {
		m.log.Warn("读取防火墙丢包计数失败", "err", err)
		return
	}
	if len(list) == 0 {
		// 读不到计数（后端不支持或还没建规则）时写空批次没意义，
		// 反而会把"上一批"的时间戳往前推，让增幅失去基线。
		return
	}

	// 一批一个时间戳：查上一批靠的是 ts 的最大值，同一批里 ts 不一致会
	// 把自己也算成历史批次。
	now := time.Now()
	rows := make([]model.CounterSample, 0, len(list))
	for _, c := range list {
		rows = append(rows, model.CounterSample{
			Ts: now, Backend: drv.Name(), Kind: c.Kind, Key: c.Key,
			Family: c.Family, Label: c.Label, Packets: c.Packets, Bytes: c.Bytes,
		})
	}
	if err := m.store.SaveCounterSamples(rows); err != nil {
		m.log.Warn("写入丢包计数采样失败", "err", err)
	}
}

// purgeCounterSamples 清理超过保留期的采样点。
func (m *Manager) purgeCounterSamples() {
	before := time.Now().Add(-counterRetention)
	if n, err := m.store.PurgeCounterSamples(before); err == nil && n > 0 {
		m.log.Debug("已清理过期丢包计数采样", "rows", n)
	} else if err != nil {
		m.log.Warn("清理丢包计数采样失败", "err", err)
	}
}
