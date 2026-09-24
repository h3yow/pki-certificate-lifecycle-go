# pki-certificate-lifecycle-go

本地可运行的证书签发与生命周期管理组件。使用本地密钥材料（ed25519）与本地
JSON 状态文件模拟私有签发方（CA）与受管实体，覆盖签发、校验、轮换与吊销，
在库入口（`pki` 包）与命令行入口（`cmd/pki`）下行为一致。

## 结构

- `pki/`：核心库
  - `types.go`：用途位掩码、签发请求与约束校验、校验结论类型
  - `ca.go`：签发方初始化、签发、密钥轮换
  - `verify.go`：信任链校验
  - `revoke.go`：吊销
  - `store.go` / `state.go`：本地状态的原子持久化与加载
- `cmd/pki/`：命令行入口（issue / verify / rotate / revoke）

## 签发规则

签发请求 `IssueRequest` 的约束全部强制生效，任何越界都被拒绝并返回可区分
原因，不用默认值兜底：

| 约束 | 拒绝原因 |
| --- | --- |
| 标识非空、≤64 字符、仅 `[a-zA-Z0-9._-]` | `ErrInvalidIdentity` |
| 用途非空且不含未知位 | `ErrUsageConflict` |
| 生效/失效时刻显式给出且 NotBefore < NotAfter | `ErrInvalidValidity` |
| 有效期在 [1 分钟, 3650 天] 内 | `ErrInvalidValidity` |
| 显式序列号不得与已签发记录重复 | `ErrSerialConflict` |

序列号默认由签发方单调分配；分配与签发记录在同一临界区内完成并**先持久化
再对外确认**，因此并发签发不会产生重复序列号，进程重启后已确认的签发不丢失。

## 校验规则

`Verify(cert, at, requireUsage)` 按固定顺序判定，结论彼此可区分，任何失败
都不会被静默当作通过：

1. `UNTRUSTED_ISSUER`：证书记录的签发密钥代不在信任库中
2. `BAD_SIGNATURE`：签名与证书内容不匹配
3. `NOT_YET_VALID`：at < NotBefore
4. `EXPIRED`：at ≥ NotAfter
5. `USAGE_MISMATCH`：证书用途不含所要求用途（或要求的用途本身非法）
6. `REVOKED`：序列号在吊销列表中
7. `OK`：全部通过

## 轮换语义

- `Rotate()` 生成新一代签发密钥并原子切换当前代（单次原子持久化：写临时
  文件 + fsync + rename）。
- 旧代密钥**保留**在信任库中；每张证书记录其签发时刻的密钥代
  （`IssuerEpoch`），历史证书始终按签发时刻的信任关系判定。
- 中途失败（如持久化失败）整体回退：当前代不变，不会留下既不被旧信任也
  不被新信任接受的证书，也不会出现半更新状态。
- 实体密钥轮换通过重新签发实现：新证书携带新的 `SubjectID`。

## 吊销语义

- `Revoke(serial)` 将吊销记录**先持久化再确认**：生效后对所有后续校验可见
  且不可回退（无反吊销接口），重启后结论不丢失。
- 重复吊销返回 `ErrAlreadyRevoked`；吊销不存在的证书返回 `ErrCertNotFound`，
  两者可区分。

## 本地状态与兼容范围

状态保存为 `<dir>/state.json`，当前格式版本为 **1**。

- 版本 > 1：拒绝加载，返回 `ErrStoreVersion`。
- 内容损坏或含未知字段：拒绝加载，返回 `ErrStoreCorrupt`（严格解码，不静默
  错列或丢弃）。
- 缺失字段的确定语义：`version` 缺省视为 1；`nextSerial` 缺省视为 1；
  `keys`/`issued`/`revoked` 缺省视为空；`currentEpoch` 缺省视为 `keys` 中
  最大代数。
- 版本 1 的读取能力将长期保持（向后兼容承诺范围）。

## 验证方法

```sh
go build ./...
go test ./pki/ -race -v   # 日志含输入、判定依据与最终结论
```

测试覆盖：过期与未生效、用途不匹配、吊销后校验、重复与并发签发、轮换中途
失败、重启恢复、状态损坏与版本越界、缺省字段语义。

命令行冒烟：

```sh
go build -o /tmp/pki ./cmd/pki
/tmp/pki issue  -dir st -identity alice -usages sign,auth \
  -not-before 2026-01-01T00:00:00Z -not-after 2027-01-01T00:00:00Z > cert.json
/tmp/pki verify -dir st -cert cert.json -at 2026-06-01T00:00:00Z -usage sign
/tmp/pki rotate -dir st
/tmp/pki revoke -dir st -serial 1
```
