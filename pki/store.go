package pki

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sync/atomic"
)

// stateFileName 是状态文件名。
const stateFileName = "state.json"

// Store 负责本地状态的持久化与加载。
// 持久化格式向后兼容；版本超出支持范围或内容损坏时明确拒绝。
type Store struct {
	dir string
	// failSaves 仅供测试注入持久化失败：大于 0 时 Save 失败一次并递减。
	failSaves atomic.Int32
}

// OpenStore 打开（必要时创建）位于 dir 的状态存储。
func OpenStore(dir string) (*Store, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("%w: 创建状态目录失败: %v", ErrStoreCorrupt, err)
	}
	return &Store{dir: dir}, nil
}

func (s *Store) path() string { return filepath.Join(s.dir, stateFileName) }

// Load 读取持久化状态；文件不存在时返回初始状态。
// 内容损坏返回 ErrStoreCorrupt；版本超出支持范围返回 ErrStoreVersion。
func (s *Store) Load() (*state, error) {
	data, err := os.ReadFile(s.path())
	if errors.Is(err, fs.ErrNotExist) {
		return &state{Version: stateFormatVersion, NextSerial: 1}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("%w: 读取状态失败: %v", ErrStoreCorrupt, err)
	}
	// 严格解码：未知字段视为损坏，避免静默错列或丢弃。
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var st state
	if err := dec.Decode(&st); err != nil {
		return nil, fmt.Errorf("%w: 状态解析失败: %v", ErrStoreCorrupt, err)
	}
	if st.Version > stateFormatVersion {
		return nil, fmt.Errorf("%w: 状态版本 %d > 支持版本 %d",
			ErrStoreVersion, st.Version, stateFormatVersion)
	}
	// 缺失字段的确定语义：version 缺省视为 1；nextSerial 缺省视为 1；
	// currentEpoch 缺省视为 keys 中最大代数。
	if st.Version == 0 {
		st.Version = 1
	}
	if st.NextSerial == 0 {
		st.NextSerial = 1
	}
	if st.CurrentEpoch == 0 {
		for _, k := range st.Keys {
			if k.Epoch > st.CurrentEpoch {
				st.CurrentEpoch = k.Epoch
			}
		}
	}
	if err := st.validateEntities(); err != nil {
		return nil, err
	}
	return &st, nil
}

// validateEntities 校验实体层记录的内部完整性。
// 实体记录自相矛盾（重复标识、非法授权、代次缺失/重复、公钥与指纹不符、
// 当前代不在密钥史中）属于“状态被改坏”，加载即拒绝，返回 ErrStoreCorrupt。
// 证书与实体之间的代次/指纹对不上不在此拦截：这类“代次对不上”由 Verify
// 明确给出 SUBJECT_EPOCH_UNKNOWN / SUBJECT_KEY_MISMATCH / UNKNOWN_ENTITY，
// 不按猜测放行，也不与损坏状态混淆。
// 旧状态（无 entities 段）天然通过：实体层是追加能力，不影响旧数据。
func (s *state) validateEntities() error {
	corrupt := func(format string, args ...any) error {
		return fmt.Errorf("%w: %s", ErrStoreCorrupt, fmt.Sprintf(format, args...))
	}
	seen := make(map[string]bool, len(s.Entities))
	for i := range s.Entities {
		e := &s.Entities[i]
		if err := validateIdentity(e.Identity); err != nil {
			return corrupt("实体记录标识非法: %v", err)
		}
		if seen[e.Identity] {
			return corrupt("实体标识重复登记: %s", e.Identity)
		}
		seen[e.Identity] = true
		if !e.AllowedUsages.Valid() {
			return corrupt("实体 %s 授权用途非法: %s", e.Identity, e.AllowedUsages)
		}
		if len(e.Keys) == 0 {
			return corrupt("实体 %s 没有任何密钥代", e.Identity)
		}
		epochs := make(map[uint64]bool, len(e.Keys))
		for _, k := range e.Keys {
			if k.Epoch == 0 {
				return corrupt("实体 %s 存在零代次密钥", e.Identity)
			}
			if epochs[k.Epoch] {
				return corrupt("实体 %s 密钥代次重复: %d", e.Identity, k.Epoch)
			}
			epochs[k.Epoch] = true
			if len(k.Public) != ed25519.PublicKeySize || entityKeyID(ed25519.PublicKey(k.Public)) != k.KeyID {
				return corrupt("实体 %s 第 %d 代公钥损坏或与指纹不一致", e.Identity, k.Epoch)
			}
		}
		if !epochs[e.CurrentEpoch] {
			return corrupt("实体 %s 当前密钥代 %d 不在密钥史中", e.Identity, e.CurrentEpoch)
		}
	}
	return nil
}

// Save 原子写入持久化状态（写临时文件 + fsync + rename），
// 中途失败不会留下半更新状态。
func (s *Store) Save(st *state) error {
	if s.failSaves.Load() > 0 {
		s.failSaves.Add(-1)
		return fmt.Errorf("%w: 注入的持久化失败", ErrStoreCorrupt)
	}
	buf, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return fmt.Errorf("%w: 状态编码失败: %v", ErrStoreCorrupt, err)
	}
	tmp, err := os.CreateTemp(s.dir, "state-*.tmp")
	if err != nil {
		return fmt.Errorf("%w: 创建临时状态文件失败: %v", ErrStoreCorrupt, err)
	}
	tmpName := tmp.Name()
	if _, err := io.Copy(tmp, bytes.NewReader(buf)); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return fmt.Errorf("%w: 写入临时状态失败: %v", ErrStoreCorrupt, err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return fmt.Errorf("%w: 落盘失败: %v", ErrStoreCorrupt, err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("%w: 关闭临时状态失败: %v", ErrStoreCorrupt, err)
	}
	if err := os.Rename(tmpName, s.path()); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("%w: 原子替换状态失败: %v", ErrStoreCorrupt, err)
	}
	return nil
}
