package pki

import (
	"bytes"
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
	// currentEpoch 缺省视为 keys 中最大代数；entities 缺省视为空
	// （版本 1 的状态文件没有实体表，视为无任何已登记实体）。
	if st.Version == 0 {
		st.Version = 1
	}
	// 旧版本状态在内存中升级到当前格式；下次保存即按当前版本落盘。
	st.Version = stateFormatVersion
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
	// 实体记录必须内部一致：当前代在密钥历史中、历史完整覆盖
	// 1..CurrentEpoch 且无重复、每代密钥材料合法。任何不满足都视为
	// 状态损坏，拒绝加载，不把损坏记录当成正常实体继续服务。
	for id, rec := range st.Entities {
		if err := rec.validate(); err != nil {
			return nil, fmt.Errorf("%w: 实体 %q 记录损坏: %v", ErrStoreCorrupt, id, err)
		}
	}
	return &st, nil
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
