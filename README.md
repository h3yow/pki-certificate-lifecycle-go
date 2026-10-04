# pki-certificate-lifecycle-go

本地可运行的证书签发与生命周期管理组件。使用本地密钥材料（ed25519）与本地
JSON 状态文件模拟私有签发方（CA）与受管实体，覆盖签发、校验、轮换与吊销，
在库入口（`pki` 包）与命令行入口（`cmd/pki`）下行为一致。

## 结构

- `pki/`：核心库
  - `types.go`：用途位掩码、签发请求与约束校验、校验结论类型
  - `entity.go`：受管实体登记、用途授权调整、实体密钥轮换、查询
  - `ca.go`：签发方初始化、签发（接入实体登记/授权/实体密钥代次）、签发方轮换
  - `verify.go`：信任链与实体绑定校验
  - `revoke.go`：吊销
  - `store.go` / `state.go`：本地状态的原子持久化与加载
- `cmd/pki/`：命令行入口（register / authorize / entity / issue / verify /
  rotate / rotate-key / revoke）

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

## 受管实体：登记与用途授权

实体必须**先登记再签发**。登记接口 `RegisterEntity(identity, allowedUsages)`
完成两件事：记录该实体最多可申请的用途集合；为实体生成**第一代独立密钥**
（与签发方那套密钥完全不同）。

授权与登记规则：

- 未登记实体不允许签发，返回 `ErrEntityNotFound`；错误信息明确说明是
  “未登记实体不允许签发”，不会和别的签发失败原因糊在一起。
- 申请用途必须是实体授权集合的**子集**（组合用途中含任意一个未授权位也拒）。
  超范围签发返回独立原因 `ErrUsageNotAuthorized`，与请求约束类失败
  （`ErrUsageConflict` / `ErrInvalidValidity` 等）以及未登记失败彼此可区分。
- 重复登记同一标识返回 `ErrEntityAlreadyExists`，稳定失败且**无副作用**：
  已有授权范围与密钥代次不被重置。
- `SetEntityAuthorizedUsages(identity, usages)` 全量替换授权范围并立即对后续
  签发生效；实体不存在返回 `ErrEntityNotFound`。授权调整是原子持久化操作，
  中途失败旧授权保持有效。授权变化**不追溯**已签发的历史证书。

相关 API：`RegisterEntity`、`SetEntityAuthorizedUsages`、`Entity`（只读查询
当前授权范围与密钥代次）、`RotateEntityKey`。

## 实体密钥与轮换语义

- 每个实体有独立的 ed25519 密钥谱系（与签发方密钥分开）。登记时生成第 1 代，
  实体公钥以 SHA-256 指纹（`SubjectKeyID`）标识。
- 新签发的证书记录签发时刻实体密钥的**代次**（`SubjectEpoch`）与**公钥指纹**
  （`SubjectKeyID`），两项均被签发方签名覆盖，不可被事后改写。
- `RotateEntityKey(identity)` 原子轮换实体密钥：生成新一代、切换当前代，
  在单次原子持久化（写临时文件 + fsync + rename）中提交。
  - 旧代密钥**全部保留**在实体密钥史中。轮换前用旧代签发的历史证书仍按旧代
    判定（OK 就继续 OK，过期/吊销也继续按原结论），不会因轮换集体失效，也
    不会被误判成通过。
  - 中途失败（密钥生成或持久化失败）整体回退：当前代不前进、新一代不提交，
    因此不会出现某张证书既不被旧实体密钥承认、也不被新实体密钥承认的情况，
    也没有半更新状态落盘。
- 校验时的实体绑定判定（仅针对新样式证书）给出三种彼此可区分的失败结论：
  - `UNKNOWN_ENTITY`：证书主体未在实体登记库中；
  - `SUBJECT_EPOCH_UNKNOWN`：证书声称的实体密钥代次不在该实体密钥史中；
  - `SUBJECT_KEY_MISMATCH`：代次存在，但公钥指纹与登记记录不一致（公钥被改坏）。
  任何一种都明确拒绝，不按猜测放行。

## 校验规则

`Verify(cert, at, requireUsage)` 按固定顺序判定，结论彼此可区分，任何失败
都不会被静默当作通过：

1. `UNTRUSTED_ISSUER`：证书记录的签发密钥代不在信任库中
2. `BAD_SIGNATURE`：签名与证书内容不匹配
3. `UNKNOWN_ENTITY` / `SUBJECT_EPOCH_UNKNOWN` / `SUBJECT_KEY_MISMATCH`：
   实体绑定检查（仅新样式证书，见上一节）
4. `NOT_YET_VALID`：at < NotBefore
5. `EXPIRED`：at ≥ NotAfter
6. `USAGE_MISMATCH`：证书用途不含所要求用途（或要求的用途本身非法）
7. `REVOKED`：序列号在吊销列表中
8. `OK`：全部通过

## 签发方轮换语义

- `Rotate()` 生成新一代签发密钥并原子切换当前代（单次原子持久化：写临时
  文件 + fsync + rename）。
- 旧代密钥**保留**在信任库中；每张证书记录其签发时刻的密钥代
  （`IssuerEpoch`），历史证书始终按签发时刻的信任关系判定。
- 中途失败（如持久化失败）整体回退：当前代不变，不会留下既不被旧信任也
  不被新信任接受的证书，也不会出现半更新状态。
- 实体密钥的独立轮换见“实体密钥与轮换语义”一节；不再用重新签发来模拟。

## 吊销语义

- `Revoke(serial)` 将吊销记录**先持久化再确认**：生效后对所有后续校验可见
  且不可回退（无反吊销接口），重启后结论不丢失。
- 重复吊销返回 `ErrAlreadyRevoked`；吊销不存在的证书返回 `ErrCertNotFound`，
  两者可区分。

## 本地状态与兼容范围

状态保存为 `<dir>/state.json`，当前格式版本为 **1**（实体层作为新字段追加，
不提升版本号）。

- 版本 > 1：拒绝加载，返回 `ErrStoreVersion`。
- 内容损坏或含未知字段：拒绝加载，返回 `ErrStoreCorrupt`（严格解码，不静默
  错列或丢弃）。
- 缺失字段的确定语义：`version` 缺省视为 1；`nextSerial` 缺省视为 1；
  `keys`/`issued`/`revoked`/`entities` 缺省视为空；`currentEpoch` 缺省视为
  `keys` 中最大代数。
- 加载时还会校验实体记录的**内部完整性**：标识合法且不重复、授权用途合法、
  密钥代次非零且不重复、公钥长度/指纹与记录一致、当前代存在于密钥史中；
  自相矛盾一律 `ErrStoreCorrupt`，拒绝以猜测结果继续服务。证书与实体之间的
  代次/指纹对不上不属于加载期损坏，而在 `Verify` 时按
  `SUBJECT_EPOCH_UNKNOWN` / `SUBJECT_KEY_MISMATCH` / `UNKNOWN_ENTITY` 拒绝。
- 版本 1 的读取能力将长期保持（向后兼容承诺范围）。

### 旧状态与旧证书怎么处理

实体层是**纯追加**能力，升级后旧数据被确定地处理，不会被当成损坏、当成通过
或当成不受信：

- **旧状态**（没有 `entities` 段）：照常加载，签发记录、吊销记录、签发方密钥
  全部有效；此时发起新签发会因实体未登记而被 `ErrEntityNotFound` 拒绝，登记
  实体后即可继续签发，新旧数据在同一状态中共存。
- **旧证书**（没有实体密钥代次/指纹字段，两者均为零值）：校验时跳过实体绑定
  检查，仍按登记实体层出现之前的规则判定签发方可信、签名、有效期、用途与吊销；
  过期、用途不符、吊销、坏签名、未知签发代等旧结论保持不变。
- 签名载荷对旧证书保持逐字节一致：实体代次/指纹仅在新证书（字段非零）上追加，
  因此旧签名不会因升级而失效。

## 验证方法

```sh
go build ./...
go test ./pki/ -race -v   # 日志含输入、判定依据与最终结论
```

测试覆盖：

- 旧能力（无回归）：过期与未生效、用途不匹配、吊销后校验、重复与并发签发、
  签发方轮换中途失败、重启恢复、状态损坏与版本越界、缺省字段语义。
- 本轮新增：未登记实体签发被拒、超出授权用途签发被独立原因拒绝、重复登记与
  授权范围调整（扩权/收权/对不存在实体调整）、实体密钥轮换前后对历史证书的
  判定、轮换中途失败（含重启后无半更新）、伪造实体密钥代次与指纹、旧状态与
  旧证书的兼容处理（旧签名、吊销、过期、坏签名、升级后新旧并存）、加载期
  实体记录完整性拒绝，以及登记/签发/实体轮换/签发方轮换/校验的并发交织与
  重启后结果一致。

命令行冒烟：

```sh
go build -o /tmp/pki ./cmd/pki
/tmp/pki register   -dir st -identity alice -usages sign,auth
/tmp/pki issue      -dir st -identity alice -usages sign,auth \
  -not-before 2026-01-01T00:00:00Z -not-after 2027-01-01T00:00:00Z > cert.json
/tmp/pki rotate-key -dir st -identity alice
/tmp/pki verify     -dir st -cert cert.json -at 2026-06-01T00:00:00Z -usage sign
/tmp/pki authorize  -dir st -identity alice -usages sign
/tmp/pki rotate     -dir st
/tmp/pki revoke     -dir st -serial 1
```
