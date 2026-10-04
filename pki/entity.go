package pki

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

// EntityInfo 是受管实体的只读快照。
type EntityInfo struct {
	Identity      string
	AllowedUsages KeyUsage
	CurrentEpoch  uint64
}

// RegisterEntity 登记一个受管实体，限定其最多可申请的用途，
// 并为其生成第一代独立密钥（区别于签发方密钥）。
// 重复登记同一标识返回 ErrEntityAlreadyExists，结果稳定不产生副作用。
func (c *CA) RegisterEntity(identity string, allowedUsages KeyUsage) (*EntityInfo, error) {
	if err := validateIdentity(identity); err != nil {
		return nil, err
	}
	if !allowedUsages.Valid() {
		return nil, fmt.Errorf("%w: 授权用途为空或含未知位 (%s)", ErrUsageConflict, allowedUsages)
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.st.findEntity(identity) != nil {
		return nil, fmt.Errorf("%w: %s", ErrEntityAlreadyExists, identity)
	}
	next := c.st.clone()
	e := entityRecord{Identity: identity, AllowedUsages: allowedUsages, CurrentEpoch: 1}
	if err := addEntityKey(&e, 1); err != nil {
		return nil, fmt.Errorf("%w: 生成实体密钥失败: %v", ErrRotationFailed, err)
	}
	next.Entities = append(next.Entities, e)
	// 先持久化再确认：登记结论重启后不丢失，持久化失败则整体不可见。
	if err := c.store.Save(next); err != nil {
		return nil, err
	}
	c.st = next
	return entityInfo(e), nil
}

// SetEntityAuthorizedUsages 全量替换实体的授权用途范围，立即对后续签发生效；
// 已签发的历史证书不因此改变。实体不存在返回 ErrEntityNotFound。
// 该操作原子持久化：失败时旧授权范围保持有效。
func (c *CA) SetEntityAuthorizedUsages(identity string, allowedUsages KeyUsage) (*EntityInfo, error) {
	if err := validateIdentity(identity); err != nil {
		return nil, err
	}
	if !allowedUsages.Valid() {
		return nil, fmt.Errorf("%w: 授权用途为空或含未知位 (%s)", ErrUsageConflict, allowedUsages)
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.st.findEntity(identity) == nil {
		return nil, fmt.Errorf("%w: %s", ErrEntityNotFound, identity)
	}
	next := c.st.clone()
	e := next.findEntity(identity)
	e.AllowedUsages = allowedUsages
	if err := c.store.Save(next); err != nil {
		return nil, err
	}
	c.st = next
	return entityInfo(*e), nil
}

// RotateEntityKey 原子轮换实体密钥：生成新一代实体密钥并切换当前代。
// 旧代密钥全部保留，历史证书仍按其签发时记录的代次判定；
// 中途失败（密钥生成或持久化失败）整体回退，不留下半更新状态，
// 不会出现证书既不被旧代也不被新代实体密钥承认的情况。
func (c *CA) RotateEntityKey(identity string) (newEpoch uint64, err error) {
	if err := validateIdentity(identity); err != nil {
		return 0, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.st.findEntity(identity) == nil {
		return 0, fmt.Errorf("%w: %s", ErrEntityNotFound, identity)
	}
	next := c.st.clone()
	e := next.findEntity(identity)
	epoch := e.CurrentEpoch + 1
	if err := addEntityKey(e, epoch); err != nil {
		return 0, fmt.Errorf("%w: 生成实体密钥失败: %v", ErrRotationFailed, err)
	}
	e.CurrentEpoch = epoch
	if err := c.store.Save(next); err != nil {
		// 旧状态未被修改：当前代不前进，新代密钥未提交，不会有证书引用它。
		return 0, fmt.Errorf("%w: 持久化失败: %v", ErrRotationFailed, err)
	}
	c.st = next
	return epoch, nil
}

// Entity 返回实体当前登记信息的只读快照；不存在返回 ErrEntityNotFound。
func (c *CA) Entity(identity string) (*EntityInfo, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e := c.st.findEntity(identity)
	if e == nil {
		return nil, fmt.Errorf("%w: %s", ErrEntityNotFound, identity)
	}
	return entityInfo(*e), nil
}

// findEntity 返回指定标识的实体记录指针；不存在返回 nil。
func (s *state) findEntity(identity string) *entityRecord {
	for i := range s.Entities {
		if s.Entities[i].Identity == identity {
			return &s.Entities[i]
		}
	}
	return nil
}

// entityKeyForEpoch 返回实体指定代的密钥记录；不存在返回 nil。
func (e *entityRecord) entityKeyForEpoch(epoch uint64) *entityKeyRecord {
	for i := range e.Keys {
		if e.Keys[i].Epoch == epoch {
			return &e.Keys[i]
		}
	}
	return nil
}

// addEntityKey 生成一代新的 ed25519 实体密钥并追加到实体记录中。
func addEntityKey(e *entityRecord, epoch uint64) error {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	e.Keys = append(e.Keys, entityKeyRecord{
		Epoch:  epoch,
		KeyID:  entityKeyID(pub),
		Public: append([]byte(nil), pub...),
	})
	return nil
}

// entityKeyID 计算实体公钥的确定性指纹（SHA-256，十六进制）。
func entityKeyID(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:])
}

// entityInfo 由持久化记录构造对外只读快照。
func entityInfo(e entityRecord) *EntityInfo {
	return &EntityInfo{
		Identity:      e.Identity,
		AllowedUsages: e.AllowedUsages,
		CurrentEpoch:  e.CurrentEpoch,
	}
}
