package firewall

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"sync"
)

const nftRateChain = "frpfirewall_rate_guard"

var nftIdentifier = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_.-]*$`)

// serialDriver 保护驱动状态；HTTP 查询、后台同步和后端切换共用此入口。
type serialDriver struct {
	Driver
	mu sync.Mutex
}

func (d *serialDriver) Capability() Capability {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.Driver.Capability()
}
func (d *serialDriver) EnsureBase() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.Driver.EnsureBase()
}
func (d *serialDriver) Sync(v Desired) error { return d.SyncContext(context.Background(), v) }
func (d *serialDriver) SyncContext(ctx context.Context, v Desired) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	return SyncContext(ctx, d.Driver, v)
}
func (d *serialDriver) AddBlock(v string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.Driver.AddBlock(v)
}
func (d *serialDriver) DelBlock(v string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.Driver.DelBlock(v)
}
func (d *serialDriver) DumpManaged() (*ManagedRules, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.Driver.DumpManaged()
}
func (d *serialDriver) Counters() ([]RuleCounter, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.Driver.Counters()
}
func (d *serialDriver) DumpSystem() (string, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.Driver.DumpSystem()
}
func (d *serialDriver) Preview(v Desired) (string, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.Driver.Preview(v)
}
func (d *serialDriver) Snapshot() (string, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.Driver.Snapshot()
}
func (d *serialDriver) Restore(v string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.Driver.Restore(v)
}
func (d *serialDriver) Cleanup() error { d.mu.Lock(); defer d.mu.Unlock(); return Cleanup(d.Driver) }

func SyncContext(ctx context.Context, d Driver, v Desired) error {
	if x, ok := d.(interface {
		SyncContext(context.Context, Desired) error
	}); ok {
		return x.SyncContext(ctx, v)
	}
	return d.Sync(v)
}
func Cleanup(d Driver) error {
	if x, ok := d.(interface{ Cleanup() error }); ok {
		return x.Cleanup()
	}
	return fmt.Errorf("后端 %s 不支持安全清理", d.Name())
}

func ownIPTChain(c string) bool {
	return c == ManagedChain || c == managedBlackChain || c == managedPortBlackChain
}
func restoreHeader() string {
	var b strings.Builder
	b.WriteString("*filter\n")
	for _, c := range []string{ManagedChain, managedBlackChain, managedPortBlackChain} {
		fmt.Fprintf(&b, ":%s - [0:0]\n-F %s\n", c, c)
	}
	return b.String()
}
func restoreScript(r iptRules) string {
	var b strings.Builder
	b.WriteString(restoreHeader())
	// 参数单独引用，规则名称或中文空格不能拆成不同参数。
	write := func(args []string) {
		var q []string
		for _, a := range args {
			if strings.ContainsAny(a, " \t\"\\") {
				a = strconv.Quote(a)
			}
			q = append(q, a)
		}
		b.WriteString(strings.Join(q, " ") + "\n")
	}
	for _, rule := range r.Guard {
		write(rule.Args)
	}
	for _, a := range r.Black {
		write([]string{"-A", managedBlackChain, "-s", a, "-j", "DROP"})
	}
	for _, args := range portBlockRules(r.PortGroups) {
		write(args)
	}
	b.WriteString("COMMIT\n")
	return b.String()
}

func (d *iptablesDriver) Cleanup() error {
	ctx := context.Background()
	for _, f := range d.fams {
		for {
			if _, err := run(ctx, f.bin, "-w", "-C", "INPUT", "-j", ManagedChain); err != nil {
				break
			}
			if _, err := run(ctx, f.bin, "-w", "-D", "INPUT", "-j", ManagedChain); err != nil {
				return err
			}
		}
		for _, c := range []string{ManagedChain, managedBlackChain, managedPortBlackChain} {
			if _, err := run(ctx, f.bin, "-w", "-S", c); err != nil {
				return err
			}
			if _, err := run(ctx, f.bin, "-w", "-F", c); err != nil {
				return err
			}
		}
		for _, c := range []string{ManagedChain, managedBlackChain, managedPortBlackChain} {
			if _, err := run(ctx, f.bin, "-w", "-X", c); err != nil {
				return err
			}
		}
	}
	return nil
}

func (d *nftablesDriver) Cleanup() error {
	ctx := context.Background()
	out, err := run(ctx, "nft", "-j", "list", "ruleset")
	if err != nil {
		return err
	}
	var doc struct {
		Nftables []map[string]json.RawMessage `json:"nftables"`
	}
	if err = json.Unmarshal([]byte(out), &doc); err != nil || doc.Nftables == nil {
		return fmt.Errorf("无法可靠读取 nft 规则集")
	}
	var rules, chains, sets strings.Builder
	for _, item := range doc.Nftables {
		var obj struct {
			Family  string `json:"family"`
			Table   string `json:"table"`
			Chain   string `json:"chain"`
			Name    string `json:"name"`
			Comment string `json:"comment"`
			Handle  int    `json:"handle"`
		}
		for kind, raw := range item {
			if err = json.Unmarshal(raw, &obj); err != nil {
				return err
			}
			// 只允许安全标识符，避免从系统规则名称构造脚本时发生注入。
			f, t, c := obj.Family, obj.Table, obj.Chain
			owned := (kind == "rule" && strings.HasPrefix(obj.Comment, "frpfirewall:")) || (kind == "chain" && obj.Name == nftRateChain) || (kind == "set" && (obj.Name == setBlack || obj.Name == setBlack6 || isRateSetName(obj.Name) || isPortSetName(obj.Name)))
			if owned && (!nftIdentifier.MatchString(t) || (kind == "rule" && !nftIdentifier.MatchString(c)) || (f != "ip" && f != "ip6" && f != "inet")) {
				return fmt.Errorf("受管 nft 对象的名称无法安全编译")
			}
			switch kind {
			case "rule":
				if strings.HasPrefix(obj.Comment, "frpfirewall:") {
					fmt.Fprintf(&rules, "delete rule %s %s %s handle %d\n", f, t, c, obj.Handle)
				}
			case "chain":
				if obj.Name == nftRateChain {
					fmt.Fprintf(&chains, "delete chain %s %s %s\n", f, t, obj.Name)
				}
			case "set":
				if obj.Name == setBlack || obj.Name == setBlack6 || isRateSetName(obj.Name) || isPortSetName(obj.Name) {
					fmt.Fprintf(&sets, "delete set %s %s %s\n", f, t, obj.Name)
				}
			}
		}
	}
	script := rules.String() + chains.String() + sets.String()
	if script == "" {
		return nil
	}
	_, err = runStdin(ctx, script, "nft", "-f", "-")
	if err == nil {
		d.ready = false
	}
	return err
}
