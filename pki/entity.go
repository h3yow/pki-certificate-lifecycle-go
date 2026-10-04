package pki

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
)

// RegisterEntity 登记受管实体，限定其可申请的用途范围，并生成第一代实体密钥。
// 登记与密钥生成在同一临界区内完成并先持久化再对外确认：
// 进程重启后已确认的登记不丢失。
// 重复登记同一实体返回 ErrEntityExists；标识或用途非法返回可区分原因。
func (c *CA) RegisterEntity(identity string, allowed KeyUsage) error {
	if err := validateIdentity(identity); err != nil {
		return err
	}
	if !allowed.Valid() {
		return fmt.Errorf("%w: 授权用途为空或含未知位 (%s)", ErrUsageConflict, allowed)
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	if _, ok := c.st.Entities[identity]; ok {
		return fmt.Errorf("%w: %q", ErrEntityExists, identity)
	}
	next := c.st.clone()
	rec := entityRecord{AllowedUsages: allowed, CurrentEpoch: 1}
	if err := rec.addKey(1); err != nil {
		return fmt.Errorf("%w: 生成实体密钥失败: %v", ErrStoreCorrupt, err)
	}
	if next.Entities == nil {
		next.Entities = make(map[string]entityRecord)
	}
	next.Entities[identity] = rec
	if err := c.store.Save(next); err != nil {
		return err
	}
	c.st = next
	return nil
}

// SetEntityUsages 调整已登记实体的授权用途范围，先持久化再对外确认。
// 未登记的实体返回 ErrEntityNotRegistered；用途非法返回 ErrUsageConflict。
// 重复设置为相同范围是稳定的成功结果（幂等）。
// 调整只影响之后的签发判定，不影响已签发证书的有效性。
func (c *CA) SetEntityUsages(identity string, allowed KeyUsage) error {
	if err := validateIdentity(identity); err != nil {
		return err
	}
	if !allowed.Valid() {
		return fmt.Errorf("%w: 授权用途为空或含未知位 (%s)", ErrUsageConflict, allowed)
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	rec, ok := c.st.Entities[identity]
	if !ok {
		return fmt.Errorf("%w: %q", ErrEntityNotRegistered, identity)
	}
	if rec.AllowedUsages == allowed {
		return nil // 幂等：范围未变化，结果稳定
	}
	next := c.st.clone()
	rec = next.Entities[identity]
	rec.AllowedUsages = allowed
	next.Entities[identity] = rec
	if err := c.store.Save(next); err != nil {
		return err
	}
	c.st = next
	return nil
}

// EntityUsages 返回实体当前授权的用途范围；未登记时返回 ErrEntityNotRegistered。
func (c *CA) EntityUsages(identity string) (KeyUsage, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	rec, ok := c.st.Entities[identity]
	if !ok {
		return 0, fmt.Errorf("%w: %q", ErrEntityNotRegistered, identity)
	}
	return rec.AllowedUsages, nil
}

// RotateEntityKey 轮换实体密钥：生成新一代密钥并原子切换当前代，
// 旧代密钥保留用于历史证书判定。
// 切换在单次原子持久化中完成；中途失败不留下半更新状态，
// 也不会出现既不被旧代也不被新代承认的证书。
// 未登记的实体返回 ErrEntityNotRegistered。
func (c *CA) RotateEntityKey(identity string) (newEpoch uint64, err error) {
	if err := validateIdentity(identity); err != nil {
		return 0, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	rec, ok := c.st.Entities[identity]
	if !ok {
		return 0, fmt.Errorf("%w: %q", ErrEntityNotRegistered, identity)
	}
	next := c.st.clone()
	rec = next.Entities[identity]
	epoch := rec.CurrentEpoch + 1
	if err := rec.addKey(epoch); err != nil {
		return 0, fmt.Errorf("%w: 生成实体密钥失败: %v", ErrRotationFailed, err)
	}
	rec.CurrentEpoch = epoch
	next.Entities[identity] = rec
	if err := c.store.Save(next); err != nil {
		// 旧状态未被修改：既不会半更新，也不会签发无法被承认的证书。
		return 0, fmt.Errorf("%w: 持久化失败: %v", ErrRotationFailed, err)
	}
	c.st = next
	return epoch, nil
}

// addKey 生成一代新的 ed25519 实体密钥并追加到记录中。
func (r *entityRecord) addKey(epoch uint64) error {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	r.Keys = append(r.Keys, entityKeyRecord{Epoch: epoch, Public: pub, Private: priv})
	return nil
}

// entityKeyForEpoch 返回实体指定代的密钥；不存在时返回 nil。
func (r *entityRecord) entityKeyForEpoch(epoch uint64) *entityKeyRecord {
	for i := range r.Keys {
		if r.Keys[i].Epoch == epoch {
			return &r.Keys[i]
		}
	}
	return nil
}
