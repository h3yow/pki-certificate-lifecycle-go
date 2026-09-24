package pki

import (
	"fmt"
	"time"
)

// Revoke 吊销指定序列号的证书。
// 吊销记录先持久化再对外确认：生效后对所有后续校验可见且不可回退，
// 进程重启后已确认的吊销结论不丢失。
// 重复吊销返回 ErrAlreadyRevoked，吊销不存在的证书返回 ErrCertNotFound。
func (c *CA) Revoke(serial uint64) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	found := false
	for _, r := range c.st.Issued {
		if r.Serial == serial {
			found = true
			break
		}
	}
	if !found {
		return fmt.Errorf("%w: 序列号 %d", ErrCertNotFound, serial)
	}
	for _, r := range c.st.Revoked {
		if r.Serial == serial {
			return fmt.Errorf("%w: 序列号 %d", ErrAlreadyRevoked, serial)
		}
	}
	next := c.st.clone()
	next.Revoked = append(next.Revoked, revokeRecord{Serial: serial, RevokedAt: time.Now().UTC()})
	if err := c.store.Save(next); err != nil {
		return err
	}
	c.st = next
	return nil
}

// IsRevoked 报告序列号是否处于已吊销状态。
func (c *CA) IsRevoked(serial uint64) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, r := range c.st.Revoked {
		if r.Serial == serial {
			return true
		}
	}
	return false
}
