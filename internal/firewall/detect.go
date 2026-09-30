package firewall

import (
	"context"
	"os"
	"regexp"
	"runtime"
	"strings"
)

// Report 是主机环境探测结果，直接喂给前端展示。
type Report struct {
	OS               string   `json:"os"`
	OSVersion        string   `json:"os_version"`
	OSPretty         string   `json:"os_pretty"`
	Kernel           string   `json:"kernel"`
	Arch             string   `json:"arch"`
	HasIPTables      bool     `json:"has_iptables"`
	IPTablesVersion  string   `json:"iptables_version"`
	IPTablesProvider string   `json:"iptables_provider"` // nf_tables | legacy
	IPTablesPath     string   `json:"iptables_path"`
	HasNFTables      bool     `json:"has_nftables"`
	NFTablesVersion  string   `json:"nftables_version"`
	NFTablesPath     string   `json:"nftables_path"`
	FirewalldActive  bool     `json:"firewalld_active"`
	UFWActive        bool     `json:"ufw_active"`
	BaoTaPresent     bool     `json:"baota_present"`
	Recommended      string   `json:"recommended"`
	Warnings         []string `json:"warnings"`
}

var (
	reIPTHost = regexp.MustCompile(`v([0-9.]+)`)
	reNFTHost = regexp.MustCompile(`v([0-9.]+)`)
)

// Detect 探测主机环境与可用防火墙后端。
// 任何一步失败都只记录到 Warnings，不返回错误——探测本身要能在陌生环境里跑完。
func Detect(ctx context.Context) *Report {
	r := &Report{
		Arch:     runtime.GOARCH,
		Warnings: make([]string, 0, 4),
	}

	// ---- 发行版 ----
	parseOSRelease(r)

	if out, err := run(ctx, "uname", "-r"); err == nil {
		r.Kernel = strings.TrimSpace(out)
	}

	// ---- iptables ----
	if path, ok := lookPath("iptables"); ok {
		r.HasIPTables = true
		r.IPTablesPath = path
		if out, err := run(ctx, "iptables", "-V"); err == nil {
			out = strings.TrimSpace(out)
			r.IPTablesVersion = out
			if m := reIPTHost.FindStringSubmatch(out); len(m) > 1 {
				r.IPTablesVersion = m[1]
			}
			if strings.Contains(out, "nf_tables") {
				r.IPTablesProvider = "nf_tables"
			} else if strings.Contains(out, "legacy") {
				r.IPTablesProvider = "legacy"
			} else {
				r.IPTablesProvider = "unknown"
			}
		}
	}

	// ---- nftables ----
	if path, ok := lookPath("nft"); ok {
		r.HasNFTables = true
		r.NFTablesPath = path
		if out, err := run(ctx, "nft", "--version"); err == nil {
			out = strings.TrimSpace(out)
			r.NFTablesVersion = out
			if m := reNFTHost.FindStringSubmatch(out); len(m) > 1 {
				r.NFTablesVersion = m[1]
			}
		}
	}

	// ---- 冲突组件 ----
	r.FirewalldActive = serviceActive(ctx, "firewalld")
	r.UFWActive = serviceActive(ctx, "ufw")
	if _, err := os.Stat("/www/server/panel"); err == nil {
		r.BaoTaPresent = true
	}

	// ---- 建议后端与告警 ----
	switch {
	case r.HasNFTables:
		r.Recommended = string(BackendNFTables)
	case r.HasIPTables:
		r.Recommended = string(BackendIPTables)
	default:
		r.Recommended = ""
		r.Warnings = append(r.Warnings,
			"未检测到 iptables 或 nftables，无法下发防火墙规则。Debian/Ubuntu 请安装：apt install nftables 或 apt install iptables")
	}

	if !r.HasNFTables && r.HasIPTables && r.IPTablesProvider == "legacy" {
		r.Warnings = append(r.Warnings,
			"当前 iptables 走的是 legacy 后端，与 nftables 规则不共享同一套钩子；建议改用 nftables 后端")
	}

	if r.FirewalldActive {
		r.Warnings = append(r.Warnings,
			"检测到 firewalld 正在运行。firewalld 执行 reload 时会重建规则链，可能移除本程序的自定义链。建议改用 nftables 后端，或把 frpfirewall 的链加入 firewalld 的 direct 规则")
	}

	if r.UFWActive {
		r.Warnings = append(r.Warnings,
			"检测到 ufw 正在运行。ufw 底层同为 iptables/nftables，本程序的独立链可以共存，但 ufw reload 后请确认规则仍在（可在概览页看配置漂移提示）")
	}

	if r.BaoTaPresent {
		r.Warnings = append(r.Warnings,
			"检测到宝塔面板。若启用了宝塔的「系统防火墙」，其操作可能重建 iptables 规则链，建议改用 nftables 后端以规避冲突")
	}

	return r
}

func parseOSRelease(r *Report) {
	data, err := os.ReadFile("/etc/os-release")
	if err != nil {
		r.OSPretty = runtime.GOOS
		return
	}
	kv := make(map[string]string, 8)
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		kv[strings.TrimSpace(k)] = strings.Trim(strings.TrimSpace(v), `"'`)
	}
	r.OS = kv["ID"]
	r.OSVersion = kv["VERSION_ID"]
	r.OSPretty = kv["PRETTY_NAME"]
	if r.OSPretty == "" {
		r.OSPretty = r.OS
	}
}

func serviceActive(ctx context.Context, name string) bool {
	if _, ok := lookPath("systemctl"); !ok {
		return false
	}
	out, err := run(ctx, "systemctl", "is-active", name)
	if err != nil {
		return false
	}
	return strings.TrimSpace(out) == "active"
}

// New 按指定后端创建驱动。backend 为 auto 时按探测结果择优。
func New(ctx context.Context, backend string, report *Report) (Driver, error) {
	if report == nil {
		report = Detect(ctx)
	}

	pick := func(b Backend) (Driver, error) {
		switch b {
		case BackendIPTables:
			return newIPTablesDriver(report), nil
		case BackendNFTables:
			return newNFTablesDriver(report), nil
		default:
			return nil, ErrNotSupported
		}
	}

	switch Backend(backend) {
	case BackendIPTables:
		return pick(BackendIPTables)
	case BackendNFTables:
		return pick(BackendNFTables)
	}

	// auto：优先 nftables（能力更强、原子提交、原生集合），其次 iptables。
	if report.HasNFTables {
		return pick(BackendNFTables)
	}
	if report.HasIPTables {
		return pick(BackendIPTables)
	}
	return nil, ErrNotSupported
}
