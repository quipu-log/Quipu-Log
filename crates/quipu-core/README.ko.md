# quipu-core

[English](README.md) | 한국어

[Quipu-Log](../../README.ko.md)의 임베디드 저장·질의 코어입니다. append-only 세그먼트(무결성은 RFC 6962 Merkle history tree가 담당), 버전 관리되는 엔티티 레지스트리, 필드 단위 보호, 보존 정책, 시점 질의를 담당합니다. 이 크레이트는 동기 엔진입니다. 비동기 파이프라인과 HTTP 프록시는 `quipu-middleware`와 `quipu-server`에 있습니다.

## 무결성: Merkle history tree

레코드마다 leaf 해시(`SHA-256(0x00 || payload)`)를 **Merkle spine** 에 덧붙입니다. spine는 테이블별 파일(`merkle.spine`)로, 그 루트가 지금껏 append된 모든 레코드를 커밋합니다(RFC 6962 history tree, `node = SHA-256(0x01 || left || right)`). 이 루트는 해시 체인의 변조 증거를 포섭하면서 — in-place 수정은 spine leaf와 안 맞고, 세그먼트 제거·재배열은 루트를 바꿉니다 — 체인이 못 주던 것을 더합니다: **제3자 독립 검증**을 O(log n)에.

- **Inclusion proof** — "레코드 E가 루트 R에 커밋돼 있다"를 audit path로. 나머지 로그 없이, 운영자 신뢰 없이 검증.
- **Consistency proof** — "크기 *m* 트리가 크기 *n* 트리의 prefix다", 즉 그 사이 이력이 append-only(무수정·무삭제)임을 증명.

spine는 해시만 담고 payload는 없어, 보존 정책으로도 절대 purge되지 않습니다 — 그래서 레코드가 만료된 뒤에도 루트와 모든 증명이 살아남습니다. 세그먼트 프레임은 `[len][crc][ts][payload]`만 가지며, CRC는 우발적 손상을, spine는 변조를 잡습니다.

```rust
let proof = store.prove_inclusion(log_id)?;           // O(log n) audit path
let root  = store.merkle_root();                       // 앵커가 고정하는 값
assert!(quipu_core::merkle::verify_inclusion(
    &proof.leaf, proof.leaf_index as usize,
    proof.tree_size as usize, &proof.path, &root));

let c = store.prove_consistency(earlier_size)?;        // 두 크기 사이 append-only
```

## 서명된 무결성 체크포인트

spine는 *부분* 변조와 append-only 이력은 증명하지만 **전체 재작성**은 못 잡습니다. 디스크 권한을 가진 내부자가 spine와 세그먼트를 전부 지우고 처음부터 자기모순 없는 트리를 다시 만들 수 있으니까요. 체크포인트가 트리를 서명으로 고정해 이 빈틈을 메웁니다.

| 필드 | 의미 |
|---|---|
| `created_at` | 서명 시각 (UTC 마이크로초) |
| `segment_seq` | 체크포인트 시점에 쓰이던 로그 세그먼트 번호 |
| `record_count` | 디스크 위 로그 레코드 수 (보존 정책 적용 후엔 줄어듦) |
| `tree_size` | 지금껏 append된 총 레코드 수 = Merkle 트리 크기 (단조 증가) |
| `merkle_root` | 앞쪽 `tree_size`개 leaf에 대한 Merkle 루트 |
| `signature` | 위 필드들에 대한 RSA PKCS#1 v1.5 / SHA-256 서명 |

이것을 스토어 루트의 `checkpoints.log`에 덧붙입니다. 세그먼트 파일은 손대지 않으므로, 체크포인트를 쓰지 않는 스토어는 디스크 포맷이 그대로입니다.

### 체크포인트가 기록되는 시점

- **세그먼트 봉인(seal) 시.** 봉인은 한 구간이 불변이 되는 순간입니다. 빈도가 `max_segment_bytes`로 제한됩니다. flush/sync 시점을 택하면 N회 append마다 도는 핫패스에 RSA 서명 연산이 올라갑니다.
- **보존 정책으로 세그먼트를 지운 직후.** 다시 체크포인트를 찍어, 검증이 정당하게 삭제된 레코드에 의존하지 않게 합니다.
- **수동으로** `AuditStore::checkpoint()` 호출 — 스케줄러에서, 또는 백업 직전에.

### 검증

`verify_integrity()`는 살아있는 레코드별 leaf를 spine와 대조한 뒤, 체크포인트가 있으면:

1. 모든 체크포인트의 서명을 RSA 공개키로 검증하고,
2. **가장 최근** 체크포인트의 `merkle_root`가 현재 트리와 일관되는지 확인합니다 — `tree_size`가 같으면 루트 일치로, 다르면 consistency proof로.

spine는 절대 purge되지 않으므로 현재 트리는 정직한 체크포인트의 확장입니다. 재작성된 트리는 체크포인트 루트를 재현할 수 없고, 꼬리를 자르면 현재 `tree_size`가 체크포인트보다 작아집니다. 둘 다 검증에서 걸립니다.

### 쓰기 전용 구성

서명에는 RSA **개인키**가 필요합니다. 공개키만 들고 도는 로그 생산 서비스(권장 구성 — 필드를 암호화할 수는 있지만 되읽지는 못함)는 서명할 수 없습니다. 그래서 거기서는 체크포인트 기능이 **조용히 비활성화**됩니다. `checkpoint()`는 `Ok(None)`을 돌려주고, 세그먼트 봉인 시에도 건너뛰며, `checkpoints.log`는 생기지 않고, `verify_integrity()`는 검사할 체크포인트가 없을 뿐입니다.

에러가 아니라 의도된 선택입니다. 쓰기 경로의 가용성이 먼저니까요. 체크포인트는 개인키가 있는 쪽에서 돌리거나, 쓰기 전용 노드에서는 spine 수준의 변조 증거만으로 운영합니다. (Merkle 루트와 증명은 키 없이도 동작합니다 — *서명된* 앵커에만 키가 필요합니다.)

### 외부 앵커링

스토어 안의 체크포인트는 결국 스토어와 운명을 같이합니다. 이 방식은 내부자가 서명 키를 쥐고 있지 않다는 전제 위에 서 있습니다. 키를 가진 내부자라면 재작성한 트리에 새로 서명하면 그만이죠. 앵커 훅은 각 체크포인트를 내부자가 손댈 수 없는 곳으로 내보냅니다.

```rust
let cfg = StoreConfig::new("/var/audit")
    .keys(keys)
    .anchor(|cp| {
        // (created_at, cp.tree_size, cp.merkle_root_hex())를 호스트 밖 어디로든:
        // 다른 머신, 티켓, 투명성 로그, 인쇄된 보고서
    });
```

훅은 체크포인트가 디스크에 기록된 직후 동기로 호출됩니다. 훅 안의 에러와 패닉은 삼켜집니다. 쓰기 경로의 가용성이 앵커링보다 우선이라, 전달 보장(큐잉, 재시도)은 훅 쪽의 몫입니다. 나중에 앵커된 루트들을 `checkpoints.log`와 대조하면 체크포인트 파일 자체가 재작성되지 않았음을 증명할 수 있고, 앵커된 `(tree_size, root)`를 든 사람은 누구나 현재 스토어에 consistency proof를 요구할 수 있습니다.

### 위협 모델 요약

| 공격 | 탐지 수단 |
|---|---|
| 레코드 in-place 수정 (CRC를 고쳐도) | Merkle spine (leaf 불일치) |
| 세그먼트 제거 / 재배열 / 교체 | Merkle 루트 변경 |
| 트리 전체 삭제 후 재작성 | 최신 체크포인트 루트 |
| 최신 레코드 꼬리 절단 | 최신 체크포인트 `tree_size` / consistency proof |
| 체크포인트 파일 위조·수정 | RSA 서명 |
| 키 보유자의 체크포인트 파일 재작성 | 외부 앵커 대조 |
| 운영자가 제3자에게 레코드를 숨기거나 위조 | **앵커된 루트에 대한 inclusion proof** |
| 운영자가 과거 이력을 몰래 수정 | **앵커된 루트에 대한 consistency proof** |
