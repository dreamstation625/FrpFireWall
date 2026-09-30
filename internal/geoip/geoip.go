// Package geoip 提供 IP 属地查询。
//
// 双库互补：
//   - MaxMind GeoLite2（Country/City mmdb）：全球国家、大洲、城市
//   - ip2region xdb：国内省市的精度和中文可读性明显更好
//
// 属地判定全部在应用层实时完成，不往内核写任何 CIDR 集合。
// 代价是只能拦住 frp 协议流量（纯 TCP 扫描不会触发 frps 插件），
// 这部分由连接速率限制兜底。
package geoip

import (
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/lionsoul2014/ip2region/binding/golang/xdb"
	"github.com/oschwald/maxminddb-golang"
)

// 标准库文件名，放在 data_dir 下。
const (
	FileCountry = "GeoLite2-Country.mmdb"
	FileCity    = "GeoLite2-City.mmdb"
	FileRegion  = "ip2region.xdb"
)

// staleAfter 超过这个时长未更新即视为过期。
const staleAfter = 30 * 24 * time.Hour

// Info 是一次属地查询结果。
type Info struct {
	IP          string `json:"ip"`
	Found       bool   `json:"found"`
	Country     string `json:"country"`      // ISO 3166-1 alpha-2
	CountryName string `json:"country_name"` // 中文名
	Continent   string `json:"continent"`
	Province    string `json:"province"`
	City        string `json:"city"`
	ISP         string `json:"isp"`
	Source      string `json:"source"` // maxmind / ip2region / maxmind+ip2region
}

// Status 是数据库状态，供前端展示。
type Status struct {
	DataDir string `json:"data_dir"`

	CountryLoaded bool      `json:"country_loaded"`
	CountryPath   string    `json:"country_path"`
	CountryTime   time.Time `json:"country_time"`
	CountrySize   int64     `json:"country_size"`

	CityLoaded bool      `json:"city_loaded"`
	CityPath   string    `json:"city_path"`
	CityTime   time.Time `json:"city_time"`
	CitySize   int64     `json:"city_size"`

	RegionLoaded bool      `json:"region_loaded"`
	RegionPath   string    `json:"region_path"`
	RegionTime   time.Time `json:"region_time"`
	RegionSize   int64     `json:"region_size"`
	RegionIsV4   bool      `json:"region_is_v4"`

	Stale  bool   `json:"stale"`
	Reason string `json:"reason"`
}

// Resolver 持有各数据库句柄。
type Resolver struct {
	// mu 保护下面几个指针：查询持读锁（允许多路并发），
	// 重载持写锁（此时会关闭旧句柄，必须独占）。
	mu sync.RWMutex

	dataDir string

	country *maxminddb.Reader
	city    *maxminddb.Reader

	// regionQueryMu 串行化 ip2region 查询。
	// xdb.Searcher 内部有文件 Seek 和 ioCount 写入，官方明确说明不是线程安全的。
	regionQueryMu sync.Mutex
	region        *xdb.Searcher
	regionIsV4    bool

	status Status
}

// New 创建 Resolver 并尝试加载 dataDir 下的库文件。
func New(dataDir string) *Resolver {
	r := &Resolver{dataDir: dataDir}
	r.status.DataDir = dataDir
	_ = r.Reload()
	return r
}

// Reload 重新加载数据目录下的所有库文件。
// 任何一个库缺失或损坏都只记录状态，不影响其它库可用。
func (r *Resolver) Reload() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.reloadLocked()
}

func (r *Resolver) reloadLocked() error {
	var reasons []string

	// ---- GeoLite2 Country ----
	cPath := filepath.Join(r.dataDir, FileCountry)
	if rd, err := maxminddb.Open(cPath); err == nil {
		if r.country != nil {
			_ = r.country.Close()
		}
		r.country = rd
		r.status.CountryLoaded = true
		r.status.CountryPath = cPath
		r.status.CountryTime, r.status.CountrySize = fileMeta(cPath)
	} else {
		r.status.CountryLoaded = false
		if !os.IsNotExist(err) {
			reasons = append(reasons, "GeoLite2-Country 加载失败: "+err.Error())
		}
	}

	// ---- GeoLite2 City（可选，用于国外城市的细分展示）----
	cityPath := filepath.Join(r.dataDir, FileCity)
	if rd, err := maxminddb.Open(cityPath); err == nil {
		if r.city != nil {
			_ = r.city.Close()
		}
		r.city = rd
		r.status.CityLoaded = true
		r.status.CityPath = cityPath
		r.status.CityTime, r.status.CitySize = fileMeta(cityPath)
	} else {
		r.status.CityLoaded = false
	}

	// ---- ip2region ----
	rPath := filepath.Join(r.dataDir, FileRegion)
	if _, err := os.Stat(rPath); err == nil {
		searcher, isV4, err := openRegion(rPath)
		if err == nil {
			if r.region != nil {
				r.region.Close()
			}
			r.region = searcher
			r.regionIsV4 = isV4
			r.status.RegionLoaded = true
			r.status.RegionPath = rPath
			r.status.RegionIsV4 = isV4
			r.status.RegionTime, r.status.RegionSize = fileMeta(rPath)
		} else {
			r.status.RegionLoaded = false
			reasons = append(reasons, "ip2region 加载失败: "+err.Error())
		}
	} else {
		r.status.RegionLoaded = false
	}

	// ---- 过期判定 ----
	r.status.Stale = false
	if r.status.CountryLoaded && time.Since(r.status.CountryTime) > staleAfter {
		r.status.Stale = true
		reasons = append(reasons, "GeoLite2 数据库已超过 30 天未更新")
	}
	if r.status.RegionLoaded && time.Since(r.status.RegionTime) > staleAfter {
		r.status.Stale = true
		reasons = append(reasons, "ip2region 数据库已超过 30 天未更新")
	}
	if !r.status.CountryLoaded && !r.status.RegionLoaded {
		reasons = append(reasons, "未加载任何属地数据库，属地相关功能不可用")
	}
	r.status.Reason = strings.Join(reasons, "；")

	return nil
}

// openRegion 打开 xdb 文件。版本从文件头读取，避免用错 IP 版本。
func openRegion(path string) (*xdb.Searcher, bool, error) {
	header, err := xdb.LoadHeaderFromFile(path)
	if err != nil {
		return nil, false, fmt.Errorf("读取 xdb 文件头失败: %w", err)
	}
	ver, err := xdb.VersionFromHeader(header)
	if err != nil {
		return nil, false, fmt.Errorf("识别 xdb 版本失败: %w", err)
	}
	idx, err := xdb.LoadVectorIndexFromFile(path)
	if err != nil {
		return nil, false, fmt.Errorf("加载向量索引失败: %w", err)
	}
	searcher, err := xdb.NewWithVectorIndex(ver, path, idx)
	if err != nil {
		return nil, false, err
	}
	return searcher, ver.Id == xdb.IPv4VersionNo, nil
}

func fileMeta(path string) (time.Time, int64) {
	fi, err := os.Stat(path)
	if err != nil {
		return time.Time{}, 0
	}
	return fi.ModTime(), fi.Size()
}

// Status 返回数据库状态快照。
func (r *Resolver) Status() Status {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.status
}

// Available 表示至少有一个库可用。
func (r *Resolver) Available() bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.status.CountryLoaded || r.status.RegionLoaded
}

// CountryBlockAvailable 表示是否具备按国家判定的能力。
func (r *Resolver) CountryBlockAvailable() bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.status.CountryLoaded || r.status.CityLoaded
}

// Lookup 查询单个 IP 的属地。
func (r *Resolver) Lookup(addr netip.Addr) *Info {
	info := &Info{IP: addr.String()}
	if !addr.IsValid() {
		return info
	}
	addr = addr.Unmap()

	// 回环 / 内网 / 链路本地地址没有属地意义，直接返回，避免无谓查询与误导展示。
	if addr.IsLoopback() || addr.IsPrivate() || addr.IsUnspecified() || addr.IsLinkLocalUnicast() {
		info.CountryName = "内网"
		return info
	}

	r.mu.RLock()
	defer r.mu.RUnlock()

	var sources []string

	// ---- MaxMind：国家 / 大洲 / 城市 ----
	if r.country != nil {
		var rec maxmindCountry
		if err := r.country.Lookup(net.IP(addr.AsSlice()), &rec); err == nil {
			if rec.Country.ISOCode != "" {
				info.Country = strings.ToUpper(rec.Country.ISOCode)
				info.CountryName = CountryName(info.Country)
				info.Continent = rec.Continent.Code
				info.Found = true
				sources = append(sources, "maxmind")
			}
		}
	}

	if r.city != nil {
		var rec maxmindCity
		if err := r.city.Lookup(net.IP(addr.AsSlice()), &rec); err == nil {
			if info.Country == "" && rec.Country.ISOCode != "" {
				info.Country = strings.ToUpper(rec.Country.ISOCode)
				info.CountryName = CountryName(info.Country)
				info.Continent = rec.Continent.Code
				info.Found = true
			}
			if len(rec.Subdivisions) > 0 && info.Province == "" {
				info.Province = pickName(rec.Subdivisions[0].Names)
			}
			if info.City == "" {
				info.City = pickName(rec.City.Names)
			}
			if !containsStr(sources, "maxmind") {
				sources = append(sources, "maxmind")
			}
		}
	}

	// ---- ip2region：国内省市更准，覆盖上面的结果 ----
	if r.region != nil && (addr.Is4() || !r.regionIsV4) {
		r.regionQueryMu.Lock()
		regionStr, err := r.region.Search(addr.String())
		r.regionQueryMu.Unlock()

		if err == nil && regionStr != "" {
			prov, cityName, isp := parseRegion(regionStr)
			// "0" 是 ip2region 表示"无该级数据"的占位符
			if prov != "" && prov != "0" {
				info.Province = prov
			}
			if cityName != "" && cityName != "0" {
				info.City = cityName
			}
			if isp != "" && isp != "0" {
				info.ISP = isp
			}
			if info.Country == "" {
				info.Country = "CN"
				info.CountryName = CountryName("CN")
				info.Found = true
			}
			sources = append(sources, "ip2region")
		}
	}

	info.Source = strings.Join(sources, "+")
	if info.CountryName == "" && info.Country != "" {
		info.CountryName = info.Country
	}
	return info
}

// LookupString 是 Lookup 的字符串入口，兼容 "1.2.3.4:5678" 形式。
func (r *Resolver) LookupString(s string) *Info {
	s = strings.TrimSpace(s)
	if ap, err := netip.ParseAddrPort(s); err == nil {
		return r.Lookup(ap.Addr())
	}
	addr, err := netip.ParseAddr(s)
	if err != nil {
		return &Info{IP: s}
	}
	return r.Lookup(addr)
}

// SaveUpload 把上传的库文件写入数据目录并重新加载。
// name 必须是白名单里的文件名之一，避免任意路径写入。
func (r *Resolver) SaveUpload(name string, src io.Reader) error {
	switch name {
	case FileCountry, FileCity, FileRegion:
	default:
		return fmt.Errorf("不支持的文件名 %q，只接受 %s / %s / %s",
			name, FileCountry, FileCity, FileRegion)
	}

	dst := filepath.Join(r.dataDir, name)
	tmp := dst + ".tmp"

	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return fmt.Errorf("创建临时文件失败: %w", err)
	}
	if _, err := io.Copy(f, src); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return fmt.Errorf("写入失败: %w", err)
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("关闭文件失败: %w", err)
	}

	// 先校验新文件可用，再替换，避免把好库换成坏的。
	if name == FileRegion {
		if _, _, err := openRegion(tmp); err != nil {
			_ = os.Remove(tmp)
			return fmt.Errorf("ip2region 文件校验失败: %w", err)
		}
	} else {
		rd, err := maxminddb.Open(tmp)
		if err != nil {
			_ = os.Remove(tmp)
			return fmt.Errorf("mmdb 文件校验失败: %w", err)
		}
		_ = rd.Close()
	}

	if err := os.Rename(tmp, dst); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("替换文件失败: %w", err)
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	return r.reloadLocked()
}

// ---- MaxMind 记录结构 ----

type maxmindCountry struct {
	Country struct {
		ISOCode string `maxminddb:"iso_code"`
	} `maxminddb:"country"`
	Continent struct {
		Code string `maxminddb:"code"`
	} `maxminddb:"continent"`
}

type maxmindCity struct {
	Country struct {
		ISOCode string `maxminddb:"iso_code"`
	} `maxminddb:"country"`
	Continent struct {
		Code string `maxminddb:"code"`
	} `maxminddb:"continent"`
	City struct {
		Names map[string]string `maxminddb:"names"`
	} `maxminddb:"city"`
	Subdivisions []struct {
		Names map[string]string `maxminddb:"names"`
	} `maxminddb:"subdivisions"`
}

func pickName(names map[string]string) string {
	if names == nil {
		return ""
	}
	if v, ok := names["zh-CN"]; ok && v != "" {
		return v
	}
	if v, ok := names["en"]; ok && v != "" {
		return v
	}
	for _, v := range names {
		return v
	}
	return ""
}

// parseRegion 解析 ip2region 的返回格式："国家|区域|省份|城市|ISP"。
func parseRegion(s string) (province, city, isp string) {
	parts := strings.Split(s, "|")
	get := func(i int) string {
		if i < len(parts) {
			return strings.TrimSpace(parts[i])
		}
		return ""
	}
	return get(2), get(3), get(4)
}

func containsStr(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}
