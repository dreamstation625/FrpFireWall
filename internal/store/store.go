package store

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
	"gorm.io/gorm/logger"

	"github.com/dreamstation625/FrpFireWall/internal/model"
)

// Store 封装 SQLite 访问。用纯 Go 驱动（glebarez/sqlite），
// 免 CGO，交叉编译单二进制无负担。
type Store struct {
	db *gorm.DB
}

// Page 是统一分页返回结构。
type Page[T any] struct {
	Items []T   `json:"items"`
	Total int64 `json:"total"`
	Page  int   `json:"page"`
	Size  int   `json:"size"`
}

func Open(dataDir string) (*Store, error) {
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return nil, fmt.Errorf("创建数据目录失败: %w", err)
	}

	dbPath := filepath.ToSlash(filepath.Join(dataDir, "frpfirewall.db"))
	dsn := "file:" + dbPath +
		"?_pragma=busy_timeout(5000)" +
		"&_pragma=journal_mode(WAL)" +
		"&_pragma=synchronous(NORMAL)" +
		"&_pragma=foreign_keys(1)"

	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		return nil, fmt.Errorf("打开数据库失败: %w", err)
	}

	s := &Store{db: db}
	if err := s.migrate(); err != nil {
		return nil, err
	}
	if err := s.seed(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Store) DB() *gorm.DB { return s.db }

func (s *Store) Close() error {
	sqlDB, err := s.db.DB()
	if err != nil {
		return err
	}
	return sqlDB.Close()
}

func (s *Store) migrate() error {
	return s.db.AutoMigrate(
		&model.ACLEntry{},
		&model.BanRecord{},
		&model.Policy{},
		&model.RateRule{},
		&model.Event{},
		&model.CounterSample{},
		&model.RuleChange{},
		&model.FirewallProfile{},
		&model.Setting{},
	)
}

// ---------- 键值配置 ----------

// GetSetting 读配置，不存在时返回空串。
func (s *Store) GetSetting(key string) (string, error) {
	var v model.Setting
	err := s.db.Where("key = ?", key).First(&v).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	return v.Value, nil
}

func (s *Store) SetSetting(key, value string) error {
	return s.db.Save(&model.Setting{Key: key, Value: value, UpdatedAt: time.Now()}).Error
}

// AllSettings 一次读出全部键值。
// 启动时用它组装配置，避免逐项查询。
func (s *Store) AllSettings() (map[string]string, error) {
	var rows []model.Setting
	if err := s.db.Find(&rows).Error; err != nil {
		return nil, err
	}
	m := make(map[string]string, len(rows))
	for _, r := range rows {
		m[r.Key] = r.Value
	}
	return m, nil
}

// SetSettings 批量写入，放在一个事务里，避免只落一半导致配置自相矛盾。
func (s *Store) SetSettings(kv map[string]string) error {
	if len(kv) == 0 {
		return nil
	}
	now := time.Now()
	rows := make([]model.Setting, 0, len(kv))
	for k, v := range kv {
		rows = append(rows, model.Setting{Key: k, Value: v, UpdatedAt: now})
	}
	return s.db.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "key"}},
		DoUpdates: clause.AssignmentColumns([]string{"value", "updated_at"}),
	}).Create(&rows).Error
}

func (s *Store) seed() error {
	var pc int64
	if err := s.db.Model(&model.Policy{}).Count(&pc).Error; err != nil {
		return err
	}
	if pc == 0 {
		if err := s.db.Create(&model.Policy{
			ID:                  1,
			WindowSeconds:       60,
			Threshold:           10,
			BanDurations:        "600,3600,86400,0",
			EscalateWindowHours: 24,
			BanGranularity:      "ip",
			FailMode:            "open",
			AutoBanEnabled:      true,
			GeoIPMode:           "blacklist",
			RateLimitPerSec:     20,
			RateLimitBurst:      40,
			UpdatedAt:           time.Now(),
		}).Error; err != nil {
			return err
		}
	}

	var fc int64
	if err := s.db.Model(&model.FirewallProfile{}).Count(&fc).Error; err != nil {
		return err
	}
	if fc == 0 {
		if err := s.db.Create(&model.FirewallProfile{ID: 1, Preferred: "auto"}).Error; err != nil {
			return err
		}
	}
	return nil
}

// ---------- 策略 ----------

func (s *Store) GetPolicy() (*model.Policy, error) {
	var p model.Policy
	if err := s.db.First(&p, 1).Error; err != nil {
		return nil, err
	}
	return &p, nil
}

func (s *Store) SavePolicy(p *model.Policy) error {
	return savePolicyTx(s.db, p)
}

func savePolicyTx(tx *gorm.DB, p *model.Policy) error {
	p.ID = 1
	p.UpdatedAt = time.Now()
	return tx.Save(p).Error
}

// ---------- 频控细分规则 ----------

// RateRules 返回全部细分频控规则，按匹配顺序（priority 升序，同值按 id）。
func (s *Store) RateRules() ([]model.RateRule, error) {
	var out []model.RateRule
	err := s.db.Order("priority asc, id asc").Find(&out).Error
	return out, err
}

// ReplaceRateRules 用给定列表整体替换细分规则，一次事务完成。
//
// 为什么是整体替换而不是逐条增删改：**规则的顺序本身就是配置的一部分**
// （按顺序匹配，第一条命中的生效）。拆成 N 次请求之后，"顺序"就没人保证了 ——
// 两次请求之间别的会话插进来一条，顺序就变了，而且看不出来。
//
// 顺序直接取数组下标，回写到 priority。前端拖出来的顺序就是最终顺序。
//
// 每次替换都重建行（ID 会变）。这是刻意的：没有任何东西跨保存持有规则 ID ——
// 封禁记录里记的是规则名，界面保存后本来就要重新拉一次列表。
// 保留 ID 需要逐条 upsert 并处理"ID 不存在"，多出来的分支换不到实际收益。
func (s *Store) ReplaceRateRules(rules []model.RateRule) error {
	return s.db.Transaction(func(tx *gorm.DB) error {
		return replaceRateRulesTx(tx, rules)
	})
}

// SavePolicyWithRules 在一个事务里同时保存全局策略与细分规则。
//
// 界面上这两样是同一个"保存"按钮，所以库这边也必须是同一次落盘：
// 分开写的话，规则校验失败会留下"策略已经改了、规则还是旧的"这种半截状态，
// 而且用户看到的报错是"保存失败"，他并不知道策略其实已经生效了。
func (s *Store) SavePolicyWithRules(p *model.Policy, rules []model.RateRule) error {
	return s.db.Transaction(func(tx *gorm.DB) error {
		if err := savePolicyTx(tx, p); err != nil {
			return err
		}
		return replaceRateRulesTx(tx, rules)
	})
}

func replaceRateRulesTx(tx *gorm.DB, rules []model.RateRule) error {
	if err := tx.Where("1 = 1").Delete(&model.RateRule{}).Error; err != nil {
		return err
	}
	now := time.Now()
	for i := range rules {
		r := rules[i]
		r.ID = 0
		r.Priority = i
		r.CreatedAt = now
		r.UpdatedAt = now
		if err := tx.Create(&r).Error; err != nil {
			return err
		}
	}
	return nil
}

// ---------- 防火墙后端偏好 ----------

func (s *Store) GetFirewallProfile() (*model.FirewallProfile, error) {
	var p model.FirewallProfile
	if err := s.db.First(&p, 1).Error; err != nil {
		return nil, err
	}
	return &p, nil
}

func (s *Store) SaveFirewallProfile(p *model.FirewallProfile) error {
	p.ID = 1
	return s.db.Save(p).Error
}

// ---------- 黑白名单 ----------

// ListACL 分页查询名单。keywords 之间是"或"的关系，任一命中即返回该条。
//
// 之所以收一组词而不是一个词：界面里地区条目显示的是中文名，而库里存的是国家码，
// 照界面上的字搜索必须也能搜到（展开在 api 层做，见 aclSearchTerms）。
//
// 多个词必须**各自带括号**再或起来。直接 `q.Where(A).Or(B)` 会拼成
// `kind = ? AND A OR B` —— AND 优先级高于 OR，于是 B 一旦命中就会把 kind 条件
// 一起绕过去，白名单页搜出黑名单条目。
func (s *Store) ListACL(kind string, keywords []string, page, size int) (*Page[model.ACLEntry], error) {
	q := s.db.Model(&model.ACLEntry{}).Where("kind = ?", kind)
	if len(keywords) > 0 {
		like := "%" + keywords[0] + "%"
		cond := s.db.Where("target LIKE ? OR remark LIKE ? OR country LIKE ?", like, like, like)
		for _, kw := range keywords[1:] {
			l := "%" + kw + "%"
			cond = cond.Or("target LIKE ? OR remark LIKE ? OR country LIKE ?", l, l, l)
		}
		q = q.Where(cond)
	}

	var total int64
	if err := q.Count(&total).Error; err != nil {
		return nil, err
	}

	items := make([]model.ACLEntry, 0, size)
	if err := q.Order("id DESC").Offset((page - 1) * size).Limit(size).Find(&items).Error; err != nil {
		return nil, err
	}
	return &Page[model.ACLEntry]{Items: items, Total: total, Page: page, Size: size}, nil
}

// AllACL 返回某名单的全量条目，用于灌进内存做判定与规则下发。
func (s *Store) AllACL(kind string) ([]model.ACLEntry, error) {
	items := make([]model.ACLEntry, 0, 64)
	err := s.db.Where("kind = ?", kind).Order("id ASC").Find(&items).Error
	return items, err
}

func (s *Store) CreateACL(e *model.ACLEntry) error {
	return s.db.Create(e).Error
}

// UpsertACL 已存在同 (kind,target) 时更新范围、端口、备注与到期时间，不报错。
func (s *Store) UpsertACL(e *model.ACLEntry) error {
	return s.db.Clauses(clause.OnConflict{
		Columns: []clause.Column{{Name: "kind"}, {Name: "target"}},
		// ports 必须在内：命中冲突时它是"这次改动的本体"，漏掉它的表现是
		// 重新添加同一个地址后端口没变，而接口返回的却是新值 —— 界面刷新一下
		// 就变回旧的，中间完全看不出是哪一步丢了。
		DoUpdates: clause.AssignmentColumns(
			[]string{"scope", "ports", "remark", "enabled", "expires_at", "updated_at", "country", "province"}),
	}).Create(e).Error
}

func (s *Store) GetACL(id uint) (*model.ACLEntry, error) {
	var e model.ACLEntry
	if err := s.db.First(&e, id).Error; err != nil {
		return nil, err
	}
	return &e, nil
}

func (s *Store) UpdateACL(e *model.ACLEntry) error {
	return s.db.Model(&model.ACLEntry{}).Where("id = ?", e.ID).
		Updates(map[string]any{
			"scope":      e.Scope,
			"ports":      e.Ports,
			"remark":     e.Remark,
			"enabled":    e.Enabled,
			"expires_at": e.ExpiresAt,
			"updated_at": time.Now(),
		}).Error
}

func (s *Store) DeleteACL(id uint) error {
	return s.db.Delete(&model.ACLEntry{}, id).Error
}

func (s *Store) DeleteACLBatch(ids []uint) error {
	if len(ids) == 0 {
		return nil
	}
	return s.db.Where("id IN ?", ids).Delete(&model.ACLEntry{}).Error
}

// PurgeExpiredACL 清掉已过期的临时名单条目。
func (s *Store) PurgeExpiredACL(now time.Time) (int64, error) {
	tx := s.db.Where("expires_at IS NOT NULL AND expires_at <= ?", now).Delete(&model.ACLEntry{})
	return tx.RowsAffected, tx.Error
}

// ---------- 封禁记录 ----------

func (s *Store) ListBans(status, keyword string, page, size int) (*Page[model.BanRecord], error) {
	q := s.db.Model(&model.BanRecord{})
	if st := strings.TrimSpace(status); st != "" && st != "all" {
		q = q.Where("status = ?", st)
	}
	if kw := strings.TrimSpace(keyword); kw != "" {
		like := "%" + kw + "%"
		q = q.Where("target LIKE ? OR reason LIKE ? OR trigger_user LIKE ? OR country LIKE ?", like, like, like, like)
	}

	var total int64
	if err := q.Count(&total).Error; err != nil {
		return nil, err
	}

	items := make([]model.BanRecord, 0, size)
	if err := q.Order("id DESC").Offset((page - 1) * size).Limit(size).Find(&items).Error; err != nil {
		return nil, err
	}
	return &Page[model.BanRecord]{Items: items, Total: total, Page: page, Size: size}, nil
}

// ActiveBans 返回所有仍生效的封禁，用于重建内存状态。
func (s *Store) ActiveBans() ([]model.BanRecord, error) {
	items := make([]model.BanRecord, 0, 64)
	err := s.db.Where("status = ?", model.BanActive).Find(&items).Error
	return items, err
}

func (s *Store) CreateBan(b *model.BanRecord) error {
	return s.db.Create(b).Error
}

// ReleaseBansByRef 同时解除来源相同的历史重复活跃记录。
func (s *Store) ReleaseBansByRef(ref, by string) (int64, error) {
	tx := s.db.Model(&model.BanRecord{}).Where("source_ref = ? AND status = ?", ref, model.BanActive).
		Updates(map[string]any{"status": model.BanReleased, "released_at": time.Now(), "released_by": by})
	return tx.RowsAffected, tx.Error
}

// FindActiveBan 查某个 target 当前是否已在封禁中。
func (s *Store) FindActiveBan(target string) (*model.BanRecord, error) {
	var b model.BanRecord
	err := s.db.Where("target = ? AND status = ?", target, model.BanActive).
		Order("id DESC").First(&b).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &b, nil
}

// LastBanOfTarget 查某 target 最近一条封禁记录，用于阶梯升级判定。
func (s *Store) LastBanOfTarget(target string) (*model.BanRecord, error) {
	var b model.BanRecord
	err := s.db.Where("target = ?", target).Order("id DESC").First(&b).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &b, nil
}

func (s *Store) GetBan(id uint) (*model.BanRecord, error) {
	var b model.BanRecord
	if err := s.db.First(&b, id).Error; err != nil {
		return nil, err
	}
	return &b, nil
}

// ReleaseBan 把封禁标记为已解除。
func (s *Store) ReleaseBan(id uint, by string, status string) error {
	return s.db.Transaction(func(tx *gorm.DB) error {
		var rec model.BanRecord
		if err := tx.First(&rec, id).Error; err != nil {
			return err
		}
		now := time.Now()
		// 同一地址的旧版本重复活跃记录一并解除，保留历史审计行。
		return tx.Model(&model.BanRecord{}).Where("target = ? AND status = ?", rec.Target, model.BanActive).Updates(map[string]any{"status": status, "released_at": now, "released_by": by}).Error
	})
}

// ReleaseBans 批量把一组封禁标记为已解除。
//
// 用于"来源条目被删除"这类联动解禁：一次可能解除几十上百条，逐条 update
// 既慢又多开事务，而它们本来是同一件事。ids 为空直接返回，不发空 UPDATE。
func (s *Store) ReleaseBans(ids []uint, by string, status string) error {
	if len(ids) == 0 {
		return nil
	}
	now := time.Now()
	return s.db.Model(&model.BanRecord{}).Where("id IN ?", ids).
		Updates(map[string]any{
			"status":      status,
			"released_at": &now,
			"released_by": by,
		}).Error
}

// CountActiveBansOfRef 数某条来源（名单条目 / 细分规则）当前还有多少条活跃封禁。
//
// 用在"删条目 / 改规则之后回头确认解禁做干净了没有"：一次联动解禁可能漏掉几条，
// 而漏掉的表现是"界面上依据已经没了、地址却还进不来"。返回计数而不是布尔值，
// 是因为调用方还要把它报给用户（"已解禁 N 个地址"）。
func (s *Store) CountActiveBansOfRef(ref string) (int64, error) {
	var n int64
	err := s.db.Model(&model.BanRecord{}).
		Where("status = ? AND source_ref = ?", model.BanActive, ref).
		Count(&n).Error
	return n, err
}

// ReleaseExpired 把所有已到期的封禁批量标记为 expired。
func (s *Store) ReleaseExpired(now time.Time) ([]model.BanRecord, error) {
	var expired []model.BanRecord
	if err := s.db.Where("status = ? AND expires_at IS NOT NULL AND expires_at <= ?",
		model.BanActive, now).Find(&expired).Error; err != nil {
		return nil, err
	}
	if len(expired) == 0 {
		return nil, nil
	}
	ids := make([]uint, 0, len(expired))
	for _, b := range expired {
		ids = append(ids, b.ID)
	}
	if err := s.db.Model(&model.BanRecord{}).Where("id IN ?", ids).
		Updates(map[string]any{
			"status":      model.BanExpired,
			"released_at": &now,
			"released_by": "system",
		}).Error; err != nil {
		return nil, err
	}
	return expired, nil
}

func (s *Store) CountActiveBans() (int64, error) {
	var n int64
	err := s.db.Model(&model.BanRecord{}).Where("status = ?", model.BanActive).Count(&n).Error
	return n, err
}

// ---------- 事件 ----------

func (s *Store) AddEvent(e *model.Event) error {
	if e.Ts.IsZero() {
		e.Ts = time.Now()
	}
	return s.db.Create(e).Error
}

// ListEventsPage 按 id 倒序取一页事件，页码从 1 开始。
//
// 这里用 offset 而不是「id < 游标」，因为界面上的分页器要能选页码、显示总页数，
// 就必须能随机跳到第 N 页，而游标只能顺着往后走。代价有两个，都是这一个选择
// 自带的，不是实现问题：
//   - 每次翻页都要重算 total（分页器要显示总页数，而 count 要扫全表）；
//   - 深翻页时数据库要先扫过并丢弃前面所有行，页越靠后越慢。
//
// 事件量级（自建场景，每天几百到几千条）下两条都可忽略，换来的是「跳到第几页
// 都行、还能选每页条数」。筛选条件与其它分页接口保持同一种写法（Count 后复用
// 同一个 q 再 Find），免得同一个列表在不同调用点给出不一样的条数。
func (s *Store) ListEventsPage(category, keyword string, since *time.Time, page, size int) (*Page[model.Event], error) {
	if page < 1 {
		page = 1
	}
	if size <= 0 {
		size = 20
	}
	if size > 500 {
		size = 500
	}

	q := s.db.Model(&model.Event{})
	if c := strings.TrimSpace(category); c != "" && c != "all" {
		q = q.Where("category = ?", c)
	}
	if since != nil {
		q = q.Where("ts >= ?", *since)
	}
	if kw := strings.TrimSpace(keyword); kw != "" {
		like := "%" + kw + "%"
		// proxy_name 也在搜索范围内：代理名是"哪个隧道在被撞"的唯一线索，
		// 搜不到就等于这列只在肉眼扫的时候有用。
		q = q.Where("ip LIKE ? OR user LIKE ? OR detail LIKE ? OR country LIKE ? OR proxy_name LIKE ?",
			like, like, like, like, like)
	}

	var total int64
	if err := q.Count(&total).Error; err != nil {
		return nil, err
	}

	items := make([]model.Event, 0, size)
	if err := q.Order("id DESC").Offset((page - 1) * size).Limit(size).Find(&items).Error; err != nil {
		return nil, err
	}
	return &Page[model.Event]{Items: items, Total: total, Page: page, Size: size}, nil
}

// ListProxyNames 返回最近出现过的代理（隧道）名，最近出现的在前。
//
// 来源是事件表 —— 代理名只出现在 frps 的回调里，程序没有别的地方记它。
// 这带来两个必须说清的后果：
//
//  1. **受事件保留期影响**：保留期是 30 天（可配）时，一个隧道三个月没被访问
//     过，它的名字就会从这个列表里消失。所以界面上必须能手填，不能只给选。
//  2. **没被访问过的隧道不在列表里**：新建了一个代理、还没有任何连接，这里
//     查不到它 —— 同样靠手填兜住。
func (s *Store) ListProxyNames(limit int) ([]string, error) {
	if limit <= 0 {
		limit = 100
	}
	if limit > 1000 {
		limit = 1000
	}
	var names []string
	// 按"最后一次出现"排序而不是按字母：用户要找的是最近在动的那个隧道，
	// 而字母序会把一堆 test-xxx 顶在前面。
	err := s.db.Model(&model.Event{}).
		Where("proxy_name <> ''").
		Select("proxy_name").
		Group("proxy_name").
		Order("MAX(ts) DESC").
		Limit(limit).
		Pluck("proxy_name", &names).Error
	if err != nil {
		return nil, err
	}
	if names == nil {
		names = []string{}
	}
	return names, nil
}

// EventStats 给概览页用的聚合统计。
type EventStats struct {
	TotalLoginFail int64            `json:"total_login_fail"`
	TotalLoginOK   int64            `json:"total_login_ok"`
	TotalBans      int64            `json:"total_bans"`
	ActiveBans     int64            `json:"active_bans"`
	Trend          []EventTrendItem `json:"trend"`
	TopIPs         []TopItem        `json:"top_ips"`
	TopCountries   []TopItem        `json:"top_countries"`
}

type EventTrendItem struct {
	Hour  string `json:"hour"`
	Fail  int64  `json:"fail"`
	Block int64  `json:"block"`
}

type TopItem struct {
	Name  string `json:"name"`
	Count int64  `json:"count"`
}

func (s *Store) EventStats(since time.Time) (*EventStats, error) {
	// 三个列表一律初始化为空切片：nil slice 会被序列化成 null，
	// 前端拿到 null 就得处处兜底，接口契约应该是「永远是数组」。
	st := &EventStats{
		Trend:        []EventTrendItem{},
		TopIPs:       []TopItem{},
		TopCountries: []TopItem{},
	}

	if err := s.db.Model(&model.Event{}).Where("category = ? AND ts >= ?", model.EvtLoginBlocked, since).
		Count(&st.TotalLoginFail).Error; err != nil {
		return nil, err
	}
	if err := s.db.Model(&model.Event{}).Where("category = ? AND ts >= ?", model.EvtLoginAttempt, since).
		Count(&st.TotalLoginOK).Error; err != nil {
		return nil, err
	}
	if err := s.db.Model(&model.BanRecord{}).Where("banned_at >= ?", since).
		Count(&st.TotalBans).Error; err != nil {
		return nil, err
	}
	if err := s.db.Model(&model.BanRecord{}).Where("status = ?", model.BanActive).
		Count(&st.ActiveBans).Error; err != nil {
		return nil, err
	}

	// 按小时的失败趋势
	type trendRow struct {
		Bucket string
		N      int64
	}
	var rows []trendRow
	if err := s.db.Model(&model.Event{}).
		Select("strftime('%Y-%m-%dT%H:00', ts, 'localtime') AS bucket, COUNT(*) AS n").
		Where("category = ? AND ts >= ?", model.EvtLoginBlocked, since).
		Group("bucket").Order("bucket ASC").Scan(&rows).Error; err != nil {
		return nil, err
	}
	for _, r := range rows {
		st.Trend = append(st.Trend, EventTrendItem{Hour: r.Bucket, Fail: r.N})
	}

	// Top 攻击 IP
	topIPs := []TopItem{}
	if err := s.db.Model(&model.Event{}).
		Select("ip AS name, COUNT(*) AS count").
		Where("category = ? AND ts >= ? AND ip <> ''", model.EvtLoginBlocked, since).
		Group("ip").Order("count DESC").Limit(10).Scan(&topIPs).Error; err != nil {
		return nil, err
	}
	st.TopIPs = topIPs

	// Top 来源国家
	topCountries := []TopItem{}
	if err := s.db.Model(&model.Event{}).
		Select("country AS name, COUNT(*) AS count").
		Where("category = ? AND ts >= ? AND country <> ''", model.EvtLoginBlocked, since).
		Group("country").Order("count DESC").Limit(10).Scan(&topCountries).Error; err != nil {
		return nil, err
	}
	st.TopCountries = topCountries

	return st, nil
}

// PurgeEvents 清理超过保留期的事件，防止表无限增长。
func (s *Store) PurgeEvents(before time.Time) (int64, error) {
	tx := s.db.Where("ts < ?", before).Delete(&model.Event{})
	return tx.RowsAffected, tx.Error
}

// ---------- 丢包计数采样 ----------

// SaveCounterSamples 写入一批采样点。
//
// 调用方必须给这批行传**同一个** Ts：查"上一批"靠的是
// `ts < 当前` 里的最大值，同一批里 Ts 不一致会把它自己也算成历史批次。
func (s *Store) SaveCounterSamples(rows []model.CounterSample) error {
	if len(rows) == 0 {
		return nil
	}
	return s.db.CreateInBatches(rows, 200).Error
}

// LatestCounterBatch 返回不晚于 before 的**最近一批**采样点。
//
// 没有更早的批次时返回空切片（不是错误）：还没采过样就是这种情况，界面上按
// "没有可比的历史"处理，增幅显示为 — 而不是把当前值整个当成增量。
//
// 边界用 `<=` 而不是 `<`：采样与查询可能落在系统时钟的同一个刻度上
// （Windows 的时钟粒度约 15ms，两次 time.Now() 完全可以相等），
// 用 `<` 会把刚采的那批排除掉，表现成"明明采过样却说没有基线"。
func (s *Store) LatestCounterBatch(before time.Time) ([]model.CounterSample, error) {
	// 先定位批次时间，再整批取回。分两步而不是一个 IN 子查询，是因为
	// sqlite 对带 ORDER BY 的子查询优化得很差，两步反而更稳。
	//
	// 用 Pluck 而不是 Scan 到单个 time.Time：Scan 的单列基本类型目标在
	// 不同驱动下行为不一致，Pluck 是"取一列"的正经写法。
	var stamps []time.Time
	if err := s.db.Model(&model.CounterSample{}).
		Where("ts <= ?", before).Order("ts DESC").Limit(1).
		Pluck("ts", &stamps).Error; err != nil {
		return nil, err
	}
	if len(stamps) == 0 {
		return nil, nil
	}
	ts := stamps[0]
	if ts.IsZero() {
		return nil, nil
	}
	out := make([]model.CounterSample, 0, 32)
	if err := s.db.Where("ts = ?", ts).Find(&out).Error; err != nil {
		return nil, err
	}
	return out, nil
}

// CounterSeries 返回时间窗内的全部采样点，由调用方聚合画图。
//
// 不在这里做 GROUP BY 求和：不同的界面要的聚合方式不一样（总量趋势 vs 单条目
// 趋势），在 store 里定死一种就只能再加一个方法。数据量也可控 —— 每 5 分钟一批、
// 每批条目数与封禁规模同量级。
func (s *Store) CounterSeries(since time.Time) ([]model.CounterSample, error) {
	out := make([]model.CounterSample, 0, 256)
	if err := s.db.Where("ts >= ?", since).Order("ts ASC").Find(&out).Error; err != nil {
		return nil, err
	}
	return out, nil
}

// PurgeCounterSamples 清理超过保留期的采样点。
func (s *Store) PurgeCounterSamples(before time.Time) (int64, error) {
	tx := s.db.Where("ts < ?", before).Delete(&model.CounterSample{})
	return tx.RowsAffected, tx.Error
}

// ---------- 规则变更审计 ----------

func (s *Store) AddRuleChange(r *model.RuleChange) error {
	if r.Ts.IsZero() {
		r.Ts = time.Now()
	}
	return s.db.Create(r).Error
}

func (s *Store) ListRuleChanges(page, size int) (*Page[model.RuleChange], error) {
	var total int64
	if err := s.db.Model(&model.RuleChange{}).Count(&total).Error; err != nil {
		return nil, err
	}
	items := make([]model.RuleChange, 0, size)
	if err := s.db.Order("id DESC").Offset((page - 1) * size).Limit(size).Find(&items).Error; err != nil {
		return nil, err
	}
	return &Page[model.RuleChange]{Items: items, Total: total, Page: page, Size: size}, nil
}
