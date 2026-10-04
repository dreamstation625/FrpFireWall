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

	// downloadMu 保证同一时刻只有一个下载任务。
	// 除了省带宽，主要是两个下载会撞在同一个 <file>.tmp 上。
	// 用 TryLock 而不是 Lock：第二个请求直接告诉用户「正在下」，不用干等。
	downloadMu sync.Mutex

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

	// ---- MaxMind：国家 / 大洲 / 省市 ----
	//
	// 省市先存成候选（mmProvince / mmCity），不直接写进 info：
	// 到底用谁，要看最终判定的国家是哪一个（见下面「按国家分流」那一段）。
	mmProvince, mmCity := "", ""
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
			if len(rec.Subdivisions) > 0 {
				mmProvince = pickName(rec.Subdivisions[0].Names)
			}
			mmCity = pickName(rec.City.Names)
			if !containsStr(sources, "maxmind") {
				sources = append(sources, "maxmind")
			}
		}
	}

	// ---- ip2region：先整条解析出来，同样做个候选 ----
	var reg regionRecord
	haveReg := false
	if r.region != nil && (addr.Is4() || !r.regionIsV4) {
		r.regionQueryMu.Lock()
		regionStr, err := r.region.Search(addr.String())
		r.regionQueryMu.Unlock()

		if err == nil && regionStr != "" {
			reg = parseRegion(regionStr)
			haveReg = true
			sources = append(sources, "ip2region")
		}
	}

	// ---- 国家码：MaxMind 优先，xdb 的 ISO 码兜底 ----
	//
	// 取的是 ISO 码这个专门字段（不是国名、也不是省市位），原因见
	// regionRecord.fallbackCountry 的注释 —— 按「有没有省市」判定国家是
	// 踩过的坑，会把国外 IP 标成 CN。
	if info.Country == "" && haveReg {
		if cc := reg.fallbackCountry(); cc != "" {
			info.Country = cc
			info.CountryName = CountryName(cc)
			info.Found = true
		}
	}

	// ---- 省市：按国家分流，两边各取所长 ----
	//
	// 两个库的强项正好互补：
	//   - xdb 是面向中文地区做的：中国大陆与港澳台返回中文省市名，精度也高于
	//     MaxMind（后者在国内经常只到省、甚至给错城市）；
	//   - 这些地区之外的记录，xdb 只给英文名、粒度也更粗
	//     （1.1.1.1 → Queensland / Brisbane），而 MaxMind 有更完整的分区数据，
	//     带 zh-CN 翻译时还会优先取中文。
	//
	// 所以这里不是"哪个库为主"，而是**按国家决定谁先**：中文地区信 xdb、
	// 其余信 MaxMind，两边都拿对方兜底。一刀切"xdb 无条件覆盖"的写法，代价是
	// 国外 IP 的省市被更粗的英文数据盖掉；一刀切"MaxMind 为主"则会把国内城市
	// 降到只到省的程度，而国内恰恰是这套东西的主要使用场景。
	//
	// 具体怎么取见 mergeRegion —— 抽成独立函数是为了能直接单测这段分流，
	// 否则只能靠真库文件跑集成，而仓库里不放库文件。
	info.Province, info.City = mergeRegion(info.Country, mmProvince, mmCity, reg)

	// ISP 只有 xdb 有（MaxMind 的运营商数据在单独的付费库里），始终取它。
	if haveReg && !isPlaceholder(reg.isp) {
		info.ISP = reg.isp
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

// maxFileSize 单个库文件的大小上限。最大的是 GeoLite2-City（约 64MB），
// 留足余量；上传与下载共用同一个上限。
const maxFileSize = 200 << 20

// isKnownFile 判断文件名是否在白名单里。库文件名只允许这几个，
// 否则一个 ../ 就能把文件写到数据目录外面。
func isKnownFile(name string) bool {
	switch name {
	case FileCountry, FileCity, FileRegion:
		return true
	}
	return false
}

// SaveUpload 把上传的库文件写入数据目录并重新加载。
// name 必须是白名单里的文件名之一，避免任意路径写入。
func (r *Resolver) SaveUpload(name string, src io.Reader) error {
	_, err := r.install(name, src, maxFileSize)
	return err
}

// install 把 src 的内容装成 name 对应的库文件：
// 写临时文件 → 校验文件头 → 原子替换 → 热加载。
//
// 校验不通过就删掉临时文件、旧库原样在用 —— 把下载到一半的坏文件换上去，
// 属地功能会整个失效，比安装失败严重得多。返回写入的字节数，供调用方判断超限。
func (r *Resolver) install(name string, src io.Reader, maxSize int64) (int64, error) {
	if !isKnownFile(name) {
		return 0, fmt.Errorf("不支持的文件名 %q，只接受 %s / %s / %s",
			name, FileCountry, FileCity, FileRegion)
	}

	dst := filepath.Join(r.dataDir, name)
	tmp := dst + ".tmp"

	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return 0, fmt.Errorf("创建临时文件失败: %w", err)
	}

	// 多读一个字节，好把「正好等于上限」和「超过上限」分开。
	lr := &io.LimitedReader{R: src, N: maxSize + 1}
	n, copyErr := io.Copy(f, lr)
	closeErr := f.Close()

	if copyErr != nil {
		_ = os.Remove(tmp)
		return n, fmt.Errorf("写入失败: %w", copyErr)
	}
	if closeErr != nil {
		_ = os.Remove(tmp)
		return n, fmt.Errorf("关闭文件失败: %w", closeErr)
	}
	if n > maxSize {
		_ = os.Remove(tmp)
		return n, fmt.Errorf("文件大小 %d 字节，超过上限 %d 字节", n, maxSize)
	}

	if err := verifyArtifact(name, tmp); err != nil {
		_ = os.Remove(tmp)
		return n, err
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	// 替换前必须先放开旧句柄：Windows 上 Go 打开文件只共享 READ|WRITE，
	// 没有 FILE_SHARE_DELETE，被 mmap 着的目标文件会拒绝被替换
	// （ERROR_SHARING_VIOLATION）。Linux 上无所谓，但一套代码要两边都能跑。
	// 这里有写锁，并发的 Lookup 取不到读锁，不会看到「reader 全为 nil」的中间态。
	r.closeReadersLocked()

	if err := os.Rename(tmp, dst); err != nil {
		_ = os.Remove(tmp)
		// 旧文件还在（rename 没成功），重新打开它，别让属地功能一直缺着。
		_ = r.reloadLocked()
		return n, fmt.Errorf("替换文件失败: %w", err)
	}
	if err := r.reloadLocked(); err != nil {
		return n, err
	}
	return n, nil
}

// verifyArtifact 在替换旧库之前先确认新文件真的能用。
func verifyArtifact(name, path string) error {
	if name == FileRegion {
		searcher, _, err := openRegion(path)
		if err != nil {
			return fmt.Errorf("ip2region 文件校验失败: %w", err)
		}
		// 必须关掉：openRegion 会打开文件并一直持有句柄。不关的话下一步的
		// os.Rename 会撞上自己 —— Windows 上直接报「being used by another
		// process」，连删临时文件都一起失败，留下一个 11MB 的 .tmp；
		// Linux 上 rename 能过，但每次安装泄漏一个 fd。
		searcher.Close()
		return nil
	}
	rd, err := maxminddb.Open(path)
	if err != nil {
		return fmt.Errorf("mmdb 文件校验失败: %w", err)
	}
	_ = rd.Close()
	return nil
}

// closeReadersLocked 关闭并清空所有库句柄。调用方必须持有写锁。
func (r *Resolver) closeReadersLocked() {
	if r.country != nil {
		_ = r.country.Close()
		r.country = nil
	}
	if r.city != nil {
		_ = r.city.Close()
		r.city = nil
	}
	if r.region != nil {
		r.region.Close()
		r.region = nil
	}
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

// regionRecord 是 ip2region 返回的一条记录。
type regionRecord struct {
	country  string // 国名，中英混用："中国" / "United States"
	code     string // ISO 国家码："CN" / "US" / "AU"
	province string
	city     string
	isp      string
}

// parseRegion 解析 ip2region xdb 的返回值。
//
// 格式固定 5 段：国家|省份|城市|ISP|国家码。实测（ip2region_v4.xdb，版本号 4，
// 与 ip2region.xdb 同格式 —— xdb 只有 IPv4VersionNo=4 / IPv6VersionNo=6 两种版本，
// 不存在另一套字段布局）：
//
//	中国|江苏省|南京市|0|CN
//	中国|北京市|北京市|电信|CN
//	United States|California|0|Google LLC|US
//	Reserved|Reserved|Reserved|0|0        ← 保留地址段
//
// **不要按"国家|区域|省份|城市|ISP"从索引 2 起取**。老代码就是这么写的，
// 结果在真库上省份拿到的是城市名（南京市）、城市拿到 "0"、ISP 拿到国家码（CN）——
// 而且看起来毫无异常。省份规则因此只能命中北京/上海/天津/重庆四个直辖市
// （它们省市同名），拿直辖市测根本发现不了。
func parseRegion(s string) regionRecord {
	parts := strings.Split(s, "|")
	get := func(i int) string {
		if i < len(parts) {
			return strings.TrimSpace(parts[i])
		}
		return ""
	}
	return regionRecord{
		country:  get(0),
		province: get(1),
		city:     get(2),
		isp:      get(3),
		code:     get(4),
	}
}

// isPlaceholder 判断某一级是不是「没有数据」。
// "0" 是最常见的占位符，保留地址段给的是 "Reserved"。
func isPlaceholder(s string) bool {
	s = strings.TrimSpace(s)
	return s == "" || s == "0" || strings.EqualFold(s, "Reserved")
}

// mergeRegion 按国家决定省市的取值来源，两边互相兜底。
//
// 分流规则见 preferRegionDB：中文地区先取 xdb（中文名、粒度细），其余先取
// MaxMind（分区数据更全、带 zh-CN 翻译时优先取中文）。先取的那一边若是占位值
// （"0" / "Reserved" / 空），就落到另一边；不像 preferRegionDB 那样一刀切，
// 是为了"某个库在这条记录上没数据"不至于把另一边的数据也丢掉。
//
// 国家码为空（两个库都没认出国家）时按"非中文地区"处理：这时候谁都说不准，
// 而 MaxMind 的覆盖更广，选它出错概率更低。
func mergeRegion(country, mmProvince, mmCity string, reg regionRecord) (province, city string) {
	if preferRegionDB(country) {
		province, city = mmProvince, mmCity
		if !isPlaceholder(reg.province) {
			province = reg.province
		}
		if !isPlaceholder(reg.city) {
			city = reg.city
		}
		return province, city
	}
	province, city = mmProvince, mmCity
	// 只补空，不覆盖：这一步是兜底，MaxMind 已经给了值就以它为准。
	if province == "" && !isPlaceholder(reg.province) {
		province = reg.province
	}
	if city == "" && !isPlaceholder(reg.city) {
		city = reg.city
	}
	return province, city
}

// preferRegionDB 判断这个国家/地区的省市是否应当以 ip2region 为准。
//
// 判据是"xdb 在这个地区返回的是不是中文、粒度够不够细"，目前包括中国大陆与
// 港澳台：xdb 对它们给中文省市名，精度高于 MaxMind（后者在国内经常只到省、
// 甚至给错城市）。其余地区反过来 —— xdb 只给英文名、粒度更粗，MaxMind 更准。
//
// 香港、澳门、台湾一并算进来，是因为它们同属中文地区，xdb 的中文名称处理
// 也更贴合界面上的写法（「中国香港」等），而不是按政治实体去分。
func preferRegionDB(country string) bool {
	switch strings.ToUpper(strings.TrimSpace(country)) {
	case "CN", "HK", "MO", "TW":
		return true
	}
	return false
}

// fallbackCountry 取出可用于兜底的国家码，取不到返回空串。
//
// 用最后一段的 ISO 国家码，不是国名也不是省市位：
//   - 国名中英混用（"中国" / "China" / "United States"），比对要维护映射表；
//   - 省市位不能当判据 —— 国外记录同样带省市，1.1.1.1 返回的是
//     "Australia|Queensland|Brisbane|0|AU"。早期按「有省市就算中国」写，
//     结果 Cloudflare 的澳洲节点被标成 CN，「只放行中国」的白名单形同虚设。
func (r regionRecord) fallbackCountry() string {
	if isPlaceholder(r.code) {
		return ""
	}
	return strings.ToUpper(r.code)
}

func containsStr(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}
