package guard

import (
	"testing"
	"time"

	"github.com/dreamstation625/FrpFireWall/internal/firewall"
	"github.com/dreamstation625/FrpFireWall/internal/model"
)

// fakeDriver 是防火墙驱动的测试替身。
//
// guard 这一层不能真的去动内核（本机也没有 iptables / nft），而计数的读数、
// 采样、增幅、趋势这套逻辑全在 guard 里，不给驱动一个替身就一处都测不到。
type fakeDriver struct {
	counts []firewall.RuleCounter
	err    error
}

func (f *fakeDriver) Name() string { return "fake" }

func (f *fakeDriver) Capability() firewall.Capability {
	return firewall.Capability{Backend: "fake", Supported: true, CounterGranularity: firewall.CounterKindAddr}
}

func (f *fakeDriver) EnsureBase() error           { return nil }
func (f *fakeDriver) Sync(firewall.Desired) error { return nil }
func (f *fakeDriver) AddBlock(string) error       { return nil }
func (f *fakeDriver) DelBlock(string) error       { return nil }
func (f *fakeDriver) DumpManaged() (*firewall.ManagedRules, error) {
	return &firewall.ManagedRules{}, nil
}
func (f *fakeDriver) DumpSystem() (string, error)               { return "", nil }
func (f *fakeDriver) Preview(firewall.Desired) (string, error)  { return "", nil }
func (f *fakeDriver) Snapshot() (string, error)                 { return "", nil }
func (f *fakeDriver) Restore(string) error                      { return nil }
func (f *fakeDriver) Counters() ([]firewall.RuleCounter, error) { return f.counts, f.err }

func newTestManagerWithDriver(t *testing.T, drv firewall.Driver) (*Manager, *fakeDriver) {
	t.Helper()
	m := newTestManager(t)
	m.SetDriver(drv)
	return m, drv.(*fakeDriver)
}

// 增幅的语义是"自最近一次采样以来新增多少"，不是"最近一个完整采样周期"。
//
// 基线取**最近那批**而不是倒数第二批：取倒数第二批的话，界面上显示的永远是
// 上一个采样周期的增量，刚被扫的那一下要等下一个周期才看得见，而"现在正在挨打吗"
// 才是这张表要回答的问题。
func TestCounterSnapshotDelta(t *testing.T) {
	m := newTestManager(t)
	f := &fakeDriver{counts: []firewall.RuleCounter{
		{Kind: firewall.CounterKindAddr, Key: "203.0.113.7", Family: "ipv4", Packets: 7, Bytes: 420},
	}}
	m.SetDriver(f)

	// 采样之前没有基线：界面上要显示"—"而不是 0。
	snap, err := m.CountersSnapshot(24)
	if err != nil {
		t.Fatal(err)
	}
	if snap.BaselineAt != nil {
		t.Fatal("还没采过样时不该有基线")
	}
	if len(snap.Items) != 1 || snap.Items[0].Packets != 7 {
		t.Fatalf("实时读数 = %+v，期望 1 条 7 包", snap.Items)
	}

	// 采一批（7 包），此后内核继续数到 12。
	m.sampleCounters()
	f.counts[0].Packets = 12
	f.counts[0].Bytes = 720

	snap, err = m.CountersSnapshot(24)
	if err != nil {
		t.Fatal(err)
	}
	if snap.BaselineAt == nil {
		t.Fatal("采过样之后应当有基线")
	}
	if snap.Items[0].DeltaPackets != 5 {
		t.Fatalf("增幅应当是 12-7=5，实际 %d", snap.Items[0].DeltaPackets)
	}
	if snap.TotalPackets != 12 {
		t.Fatalf("总量应当是 12，实际 %d", snap.TotalPackets)
	}
}

// 规则被重建后计数归零：读数比上一批小时，"新增"就是当前值本身，
// 而不是一个负数（负数在界面上没法解释）。
func TestCounterSnapshotDeltaAfterReset(t *testing.T) {
	m := newTestManager(t)
	f := &fakeDriver{counts: []firewall.RuleCounter{
		{Kind: firewall.CounterKindAddr, Key: "203.0.113.7", Family: "ipv4", Packets: 100},
	}}
	m.SetDriver(f)
	m.sampleCounters()

	f.counts[0].Packets = 3 // 重建后从 0 重新数到 3

	snap, err := m.CountersSnapshot(24)
	if err != nil {
		t.Fatal(err)
	}
	if snap.Items[0].DeltaPackets != 3 {
		t.Fatalf("重建后的新增量应当是 3，实际 %d", snap.Items[0].DeltaPackets)
	}
}

// v4 与 v6 是两条规则，不能互相干扰。
func TestCounterSnapshotSeparatesFamilies(t *testing.T) {
	m := newTestManager(t)
	f := &fakeDriver{counts: []firewall.RuleCounter{
		{Kind: firewall.CounterKindAddr, Key: "203.0.113.7", Family: "ipv4", Packets: 5},
		{Kind: firewall.CounterKindAddr, Key: "203.0.113.7", Family: "ipv6", Packets: 9},
	}}
	m.SetDriver(f)
	m.sampleCounters()

	f.counts[0].Packets = 8
	f.counts[1].Packets = 9 // v6 没变

	snap, err := m.CountersSnapshot(24)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]uint64{}
	for _, it := range snap.Items {
		got[it.Family] = it.DeltaPackets
	}
	if got["ipv4"] != 3 || got["ipv6"] != 0 {
		t.Fatalf("增幅 = %v，期望 ipv4=3 / ipv6=0", got)
	}
}

// 没有驱动时不能报错：界面要能显示"当前没有可用的防火墙后端"。
func TestCounterSnapshotWithoutDriver(t *testing.T) {
	m := newTestManager(t) // 驱动为 nil
	snap, err := m.CountersSnapshot(24)
	if err != nil {
		t.Fatalf("没有驱动时不该返回错误，实际 %v", err)
	}
	if snap.Unsupported == "" {
		t.Fatal("应当给出不支持的原因")
	}
	if snap.Items == nil {
		t.Fatal("items 应当是空切片而不是 nil，否则前端渲染会炸")
	}
}

// 驱动读不到计数时不写空批次。
//
// 写了会把"上一批"的时间戳往前推，下一批算出来的增幅就对不上了 ——
// 相当于用一批全是 0（或压根没有）的数据当基线。
func TestSampleCountersSkipsEmptyRead(t *testing.T) {
	m := newTestManager(t)
	m.SetDriver(&fakeDriver{}) // Counters 返回空

	m.sampleCounters()

	rows, err := m.store.CounterSeries(time.Now().Add(-time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 0 {
		t.Fatalf("读不到计数时不该写采样，实际写了 %d 行", len(rows))
	}
}

func TestCounterSeriesDeltas(t *testing.T) {
	base := time.Date(2026, 10, 4, 10, 0, 0, 0, time.UTC)
	rows := []model.CounterSample{
		{Ts: base, Kind: "addr", Key: "a", Packets: 10, Bytes: 100},
		{Ts: base, Kind: "addr", Key: "b", Packets: 5, Bytes: 50},
		{Ts: base.Add(time.Hour), Kind: "addr", Key: "a", Packets: 14, Bytes: 140},
		{Ts: base.Add(time.Hour), Kind: "addr", Key: "b", Packets: 5, Bytes: 50},
	}
	got := counterSeries(rows)
	if len(got) != 2 {
		t.Fatalf("应当有 2 个点，实际 %d 个：%+v", len(got), got)
	}
	// 第一批没有前值，按"这批就是新增"处理：10 + 5 = 15
	if got[0].Packets != 15 || got[0].Bytes != 150 {
		t.Fatalf("第一个点 = %+v，期望 15 / 150", got[0])
	}
	// 第二点：a 涨 4、b 没动 → 4
	if got[1].Packets != 4 || got[1].Bytes != 40 {
		t.Fatalf("第二个点 = %+v，期望 4 / 40", got[1])
	}
}

// 归零：读数变小说明中间重建过规则，增量取当前值而不是负数。
func TestCounterSeriesReset(t *testing.T) {
	base := time.Date(2026, 10, 4, 10, 0, 0, 0, time.UTC)
	rows := []model.CounterSample{
		{Ts: base, Kind: "addr", Key: "a", Packets: 100},
		{Ts: base.Add(time.Hour), Kind: "addr", Key: "a", Packets: 2},
	}
	got := counterSeries(rows)
	if got[1].Packets != 2 {
		t.Fatalf("重建后的增量应当是 2，实际 %d", got[1].Packets)
	}
}

func TestCounterSeriesEmpty(t *testing.T) {
	if got := counterSeries(nil); got == nil {
		t.Fatal("空输入应当返回空切片而不是 nil —— 前端要直接遍历它")
	}
}
