package guard

import (
	"context"
	"fmt"
	"time"

	"github.com/dreamstation625/FrpFireWall/internal/firewall"
)

// SwitchDriver 在新后端成功同步后清理旧后端；失败保留原引用并尝试恢复保护。
func (m *Manager) SwitchDriver(next firewall.Driver) error {
	m.applyMu.Lock()
	defer m.applyMu.Unlock()
	m.mu.RLock()
	old := m.drv
	m.mu.RUnlock()
	des := m.desired()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if m.dryRun() {
		if _, err := next.Preview(des); err != nil {
			return err
		}
	} else {
		if err := firewall.SyncContext(ctx, next, des); err != nil {
			if old != nil && old.Name() != next.Name() {
				if cleanErr := firewall.Cleanup(next); cleanErr != nil {
					return fmt.Errorf("新后端同步失败: %w；清理失败: %v", err, cleanErr)
				}
			}
			return err
		}
		if old != nil && old.Name() != next.Name() {
			if err := firewall.Cleanup(old); err != nil {
				restoreErr := old.Sync(des)
				if restoreErr != nil {
					return fmt.Errorf("清理旧后端失败: %w；恢复失败: %v", err, restoreErr)
				}
				if cleanErr := firewall.Cleanup(next); cleanErr != nil {
					return fmt.Errorf("清理旧后端失败: %w；清理新后端失败: %v", err, cleanErr)
				}
				return err
			}
		}
	}
	m.mu.Lock()
	m.drv = next
	m.mu.Unlock()
	return nil
}
