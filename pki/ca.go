package pki

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"sync"
)

// CA 是本地模拟的私有签发方，持有密钥材料与签发/吊销状态。
// 所有方法可并发调用；状态切换原子可见。
type CA struct {
	mu    sync.Mutex
	store *Store
	st    *state
}

// NewCA 从 dir 加载或初始化一个签发方。
// 状态损坏或版本超出支持范围时返回错误，拒绝以不确定状态服务。
func NewCA(dir string) (*CA, error) {
	store, err := OpenStore(dir)
	if err != nil {
		return nil, err
	}
	st, err := store.Load()
	if err != nil {
		return nil, err
	}
	c := &CA{store: store, st: st}
	if len(st.Keys) == 0 {
		// 首次初始化：生成第一代签发密钥并立即持久化。
		next := c.st.clone()
		if err := next.addKey(1); err != nil {
			return nil, err
		}
		next.CurrentEpoch = 1
		if err := store.Save(next); err != nil {
			return nil, err
		}
		c.st = next
	}
	return c, nil
}

// Issue 按请求约束签发证书；非法请求被拒绝并返回可区分原因。
// 序列号分配与签发记录在同一临界区内完成并先持久化，
// 因此并发签发不会产生重复序列号，进程重启后已确认的签发不丢失。
func (c *CA) Issue(req IssueRequest) (*Certificate, error) {
	if err := req.validate(); err != nil {
		return nil, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	next := c.st.clone()
	serial := req.Serial
	if serial == 0 {
		serial = next.NextSerial
	} else {
		// 显式序列号：不得与已签发记录重复，也不得更改分配游标。
		for _, r := range next.Issued {
			if r.Serial == serial {
				return nil, fmt.Errorf("%w: 序列号 %d 已签发", ErrSerialConflict, serial)
			}
		}
	}
	key := next.currentKey()
	if key == nil {
		return nil, fmt.Errorf("%w: 当前密钥代 %d 不存在", ErrStoreCorrupt, next.CurrentEpoch)
	}
	subjectID := req.SubjectID
	if subjectID == "" {
		subjectID = "subj:" + req.Identity
	}
	cert := &Certificate{
		Serial:      serial,
		Identity:    req.Identity,
		Usages:      req.Usages,
		NotBefore:   req.NotBefore.UTC(),
		NotAfter:    req.NotAfter.UTC(),
		IssuerEpoch: key.Epoch,
		SubjectID:   subjectID,
	}
	cert.Signature = ed25519.Sign(key.Private, signingPayload(cert))
	next.Issued = append(next.Issued, certRecord{
		Serial:      cert.Serial,
		Identity:    cert.Identity,
		Usages:      cert.Usages,
		NotBefore:   cert.NotBefore,
		NotAfter:    cert.NotAfter,
		IssuerEpoch: cert.IssuerEpoch,
		SubjectID:   cert.SubjectID,
		Signature:   cert.Signature,
	})
	if serial >= next.NextSerial {
		next.NextSerial = serial + 1
	}
	// 先持久化，再对外确认：确认过的签发结论重启后不丢失。
	if err := c.store.Save(next); err != nil {
		return nil, err
	}
	c.st = next
	return cert, nil
}

// Rotate 轮换签发方密钥：新密钥生效后旧密钥仍保留用于历史证书校验。
// 切换在单次原子持久化中完成；中途失败不留下半更新状态。
func (c *CA) Rotate() (newEpoch uint64, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	next := c.st.clone()
	epoch := next.CurrentEpoch + 1
	if err := next.addKey(epoch); err != nil {
		return 0, fmt.Errorf("%w: 生成新密钥失败: %v", ErrRotationFailed, err)
	}
	next.CurrentEpoch = epoch
	if err := c.store.Save(next); err != nil {
		// 旧状态未被修改：既不会出现半更新，也不会签发无法被信任的证书。
		return 0, fmt.Errorf("%w: 持久化失败: %v", ErrRotationFailed, err)
	}
	c.st = next
	return epoch, nil
}

// clone 深拷贝状态，保证任何修改在持久化成功前对旧状态不可见。
func (s *state) clone() *state {
	out := *s
	out.Keys = append([]keyRecord(nil), s.Keys...)
	out.Issued = append([]certRecord(nil), s.Issued...)
	out.Revoked = append([]revokeRecord(nil), s.Revoked...)
	return &out
}

// addKey 生成一代新的 ed25519 密钥并追加到状态中。
func (s *state) addKey(epoch uint64) error {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	s.Keys = append(s.Keys, keyRecord{Epoch: epoch, Public: pub, Private: priv})
	return nil
}

// currentKey 返回当前代密钥；不存在时返回 nil。
func (s *state) currentKey() *keyRecord { return s.keyForEpoch(s.CurrentEpoch) }

// keyForEpoch 返回指定代密钥；不存在时返回 nil。
func (s *state) keyForEpoch(epoch uint64) *keyRecord {
	for i := range s.Keys {
		if s.Keys[i].Epoch == epoch {
			return &s.Keys[i]
		}
	}
	return nil
}

// signingPayload 构造证书签名覆盖内容的确定性编码。
func signingPayload(cert *Certificate) []byte {
	buf := make([]byte, 0, 128)
	var num [8]byte
	putU64 := func(v uint64) { binary.BigEndian.PutUint64(num[:], v); buf = append(buf, num[:]...) }
	putStr := func(s string) { putU64(uint64(len(s))); buf = append(buf, s...) }
	putU64(cert.Serial)
	putStr(cert.Identity)
	putU64(uint64(cert.Usages))
	putU64(uint64(cert.NotBefore.UnixNano()))
	putU64(uint64(cert.NotAfter.UnixNano()))
	putU64(cert.IssuerEpoch)
	putStr(cert.SubjectID)
	return buf
}
