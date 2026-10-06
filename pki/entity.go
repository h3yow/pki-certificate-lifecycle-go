package pki

import (
	"bytes"
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
		// 已存在的记录若已损坏，按状态损坏报告，便于与正常重复登记区分。
		rec := c.st.Entities[identity]
		if err := rec.validate(); err != nil {
			return fmt.Errorf("%w: 实体 %q 记录损坏: %v", ErrStoreCorrupt, identity, err)
		}
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
	if err := rec.validate(); err != nil {
		return fmt.Errorf("%w: 实体 %q 记录损坏: %v", ErrStoreCorrupt, identity, err)
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
	if err := rec.validate(); err != nil {
		return 0, fmt.Errorf("%w: 实体 %q 记录损坏: %v", ErrStoreCorrupt, identity, err)
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
	// 记录损坏时拒绝轮换：不能在不一致的密钥历史上继续追加代次。
	if err := rec.validate(); err != nil {
		return 0, fmt.Errorf("%w: 实体 %q 记录损坏: %v", ErrStoreCorrupt, identity, err)
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

// validate 检查实体记录的内部一致性。登记从第 1 代开始、轮换只追加
// CurrentEpoch+1 且从不删除历史，因此合法记录的密钥历史恰好覆盖
// 1..CurrentEpoch。以下任一情形都视为本地状态损坏，必须明确拒绝，
// 不得当成正常实体继续使用：
//   - 授权用途为空或含未知位；
//   - 当前代为 0，或当前代在密钥历史中找不到；
//   - 密钥历史缺某一代、出现重复的代、或代次超出 [1, CurrentEpoch]；
//   - 某代密钥材料本身不合法（长度不符或公钥与私钥不匹配）。
func (r *entityRecord) validate() error {
	if !r.AllowedUsages.Valid() {
		return fmt.Errorf("授权用途为空或含未知位 (%s)", r.AllowedUsages)
	}
	if r.CurrentEpoch == 0 {
		return fmt.Errorf("当前密钥代为 0")
	}
	if uint64(len(r.Keys)) != r.CurrentEpoch {
		return fmt.Errorf("密钥历史共 %d 代，与当前代 %d 对不上（缺代或当前代越界）",
			len(r.Keys), r.CurrentEpoch)
	}
	seen := make(map[uint64]bool, len(r.Keys))
	for i := range r.Keys {
		k := &r.Keys[i]
		if k.Epoch == 0 || k.Epoch > r.CurrentEpoch {
			return fmt.Errorf("密钥代 %d 超出有效范围 [1, %d]", k.Epoch, r.CurrentEpoch)
		}
		if seen[k.Epoch] {
			return fmt.Errorf("密钥代 %d 重复", k.Epoch)
		}
		seen[k.Epoch] = true
		if err := k.validateKeyMaterial(); err != nil {
			return fmt.Errorf("第 %d 代密钥材料不合法: %v", k.Epoch, err)
		}
	}
	return nil
}

// validateKeyMaterial 检查一代实体密钥材料本身是否合法：
// 长度符合 ed25519 规范且公钥与私钥匹配。
func (k *entityKeyRecord) validateKeyMaterial() error {
	if len(k.Private) != ed25519.PrivateKeySize {
		return fmt.Errorf("私钥长度 %d，期望 %d", len(k.Private), ed25519.PrivateKeySize)
	}
	if len(k.Public) != ed25519.PublicKeySize {
		return fmt.Errorf("公钥长度 %d，期望 %d", len(k.Public), ed25519.PublicKeySize)
	}
	derived := ed25519.PrivateKey(k.Private).Public().(ed25519.PublicKey)
	if !bytes.Equal(derived, k.Public) {
		return fmt.Errorf("公钥与私钥不匹配")
	}
	return nil
}
