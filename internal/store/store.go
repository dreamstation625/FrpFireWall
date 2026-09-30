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
		&model.Event{},
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
	p.ID = 1
	p.UpdatedAt = time.Now()
	return s.db.Save(p).Error
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

func (s *Store) ListACL(kind, keyword string, page, size int) (*Page[model.ACLEntry], error) {
	q := s.db.Model(&model.ACLEntry{}).Where("kind = ?", kind)
	if kw := strings.TrimSpace(keyword); kw != "" {
		like := "%" + kw + "%"
		q = q.Where("target LIKE ? OR remark LIKE ? OR country LIKE ?", like, like, like)
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

// UpsertACL 已存在同 (kind,target) 时更新备注与到期时间，不报错。
func (s *Store) UpsertACL(e *model.ACLEntry) error {
	return s.db.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "kind"}, {Name: "target"}},
		DoUpdates: clause.AssignmentColumns([]string{"remark", "expires_at", "updated_at", "country", "province"}),
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
			"remark":     e.Remark,
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
	now := time.Now()
	return s.db.Model(&model.BanRecord{}).Where("id = ?", id).
		Updates(map[string]any{
			"status":      status,
			"released_at": &now,
			"released_by": by,
		}).Error
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

// EventCursor 是事件列表的游标分页结果。
type EventCursor struct {
	Items []model.Event `json:"items"`
	// NextCursor 是下一页要传的游标（即本页最后一条的 id）；为 0 表示已到底。
	NextCursor uint `json:"next_cursor"`
	HasMore    bool `json:"has_more"`
	Total      int64 `json:"total"`
}

// ListEventsCursor 按 id 倒序取一页事件，用自增主键做游标。
//
// 事件表只增不减，offset 分页在深翻页时要先扫过并丢弃前面所有行，
// 越翻越慢且耗时随总量线性增长；游标分页每页代价恒定。
// beforeID 为 0 表示取最新一页。
func (s *Store) ListEventsCursor(category, keyword string, since *time.Time, beforeID uint, limit int) (*EventCursor, error) {
	if limit <= 0 {
		limit = 50
	}
	if limit > 500 {
		limit = 500
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
		q = q.Where("ip LIKE ? OR user LIKE ? OR detail LIKE ? OR country LIKE ?", like, like, like, like)
	}

	// 总数只在首屏统计一次：count 要扫全表，翻页时没必要重复付这个代价。
	var total int64
	if beforeID == 0 {
		if err := q.Count(&total).Error; err != nil {
			return nil, err
		}
	}

	if beforeID > 0 {
		q = q.Where("id < ?", beforeID)
	}

	// 多取一条，用来判断后面还有没有数据，省掉一次 count。
	items := make([]model.Event, 0, limit+1)
	if err := q.Order("id DESC").Limit(limit + 1).Find(&items).Error; err != nil {
		return nil, err
	}

	hasMore := len(items) > limit
	if hasMore {
		items = items[:limit]
	}
	next := uint(0)
	if hasMore && len(items) > 0 {
		next = items[len(items)-1].ID
	}

	return &EventCursor{Items: items, NextCursor: next, HasMore: hasMore, Total: total}, nil
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
