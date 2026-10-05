package guard

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dreamstation625/FrpFireWall/internal/firewall"
)

type checkedDriver struct {
	fakeDriver
	name        string
	active      atomic.Int32
	peak        atomic.Int32
	calls       atomic.Int32
	cleaned     atomic.Int32
	failSync    bool
	failCleanup bool
}

func (d *checkedDriver) Name() string { return d.name }
func (d *checkedDriver) Sync(firewall.Desired) error {
	n := d.active.Add(1)
	defer d.active.Add(-1)
	for old := d.peak.Load(); n > old; old = d.peak.Load() {
		if d.peak.CompareAndSwap(old, n) {
			break
		}
	}
	d.calls.Add(1)
	time.Sleep(time.Millisecond)
	if d.failSync {
		return errors.New("sync failed")
	}
	return nil
}
func (d *checkedDriver) Cleanup() error {
	d.cleaned.Add(1)
	if d.failCleanup {
		return errors.New("cleanup failed")
	}
	return nil
}

func TestReconcileAndDriverReplacementAreSerialized(t *testing.T) {
	m := newTestManager(t)
	a, b := &checkedDriver{name: "a"}, &checkedDriver{name: "b"}
	m.SetDriver(a)
	var wg sync.WaitGroup
	for i := range 48 {
		wg.Go(func() {
			if i%3 == 0 {
				m.SetDriver(b)
			} else if i%3 == 1 {
				m.SetDriver(a)
			}
			if err := m.Reconcile(); err != nil {
				t.Error(err)
			}
		})
	}
	wg.Wait()
	if a.peak.Load() > 1 || b.peak.Load() > 1 || a.calls.Load()+b.calls.Load() != 48 {
		t.Fatalf("驱动同步发生交错: a=%d b=%d", a.peak.Load(), b.peak.Load())
	}
}

func TestDriverSwitchFailuresKeepOriginalReference(t *testing.T) {
	for _, stage := range []string{"sync", "cleanup"} {
		t.Run(stage, func(t *testing.T) {
			m := newTestManager(t)
			old := &checkedDriver{name: "old", failCleanup: stage == "cleanup"}
			next := &checkedDriver{name: "next", failSync: stage == "sync"}
			m.SetDriver(old)
			if err := m.SwitchDriver(next); err == nil {
				t.Fatal("失败切换应返回错误")
			}
			if m.drv != old || next.cleaned.Load() != 1 {
				t.Fatal("引用改变或新后端残留")
			}
			if stage == "cleanup" && old.calls.Load() != 1 {
				t.Fatal("未恢复旧保护")
			}
		})
	}
}
