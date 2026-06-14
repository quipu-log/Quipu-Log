# quipu-middleware

[English](README.md) | 한국어

[`quipu-core`](../quipu-core/README.ko.md) 위에 얹는 비동기 레이어. `quipu-core`는 동기·단일 writer 스토어이고, 이 크레이트는 실제 서비스에서 직접 호출하게 되는 쪽이다. writer 스레드를 소유해 요청 경로를 논블로킹으로 유지하고, 실배포에 필요한 부품을 더한다 — 재시도, 디스크 기반 데드레터 큐(DLQ), 권한, HTTP 프록시 레이어, 그리고 한 노드로 부족할 때의 샤드 라우터.

Rust 서비스에 Quipu-Log를 임베드한다면 여기가 진입점이다. `quipu-server`는 이 크레이트를 HTTP API로 감싼 것일 뿐이다.

## 맨 스토어 대비 더해주는 것

| 관심사 | 이 크레이트가 더하는 것 |
|---|---|
| **논블로킹 쓰기** | `AuditPipeline`이 전용 writer 스레드에서 스토어를 소유한다. `handle.emit()`은 바운디드 채널에 넣는 것 — 요청 경로에서 나노초, 디스크 쓰기가 아님. |
| **장애 내구성** | 실패한 쓰기는 재시도하고, 재시도를 소진한 이벤트는 재시작에도 살아남는 디스크 기반 DLQ에 적재(`redrive_dlq`). 마지막 손실은 `FallbackFn` 훅이 잡아 페이징할 수 있다. |
| **권한** | `PermissionPolicy`가 모든 `emit`/`query`/administer 호출을 `Role` 기준으로 통제(기본 거부 또는 기본 허용). |
| **HTTP 감사** | `AuditLayer`는 선택한 엔드포인트를 자동 기록하는 `tower` Layer — 핸들러에 수동 `emit` 불필요. |
| **관측성** | `handle.metrics()`/`handle.health()`가 락 없는 atomic을 읽는다(큐 깊이, DLQ 크기, 쓰기 지연, writer 생존, disk-full 래치) — writer 스레드를 건드리지 않음. |
| **수평 확장** | `ShardRouter`가 독립 단일-writer 트리 N개를 앞에서 받아 테넌트별로 쓰기를 라우팅하고 읽기를 fan-out — [샤딩](#샤딩) 참조. |

## Quick start

스토어 열기 → 파이프라인 시작 → emit 의 최소 임베디드 셋업은 [루트 README의 빠른 시작](../../README.ko.md#빠른-시작)에 있다. 골격만 보면:

```rust,no_run
use quipu_core::*;
use quipu_middleware::*;

let pipeline = AuditPipeline::start(
    store, root, PermissionPolicy::allow_all(),
    PipelineConfig::default(), None /* fallback hook */)?;
let handle = pipeline.handle();           // 싸고 clone 가능

handle.emit(&Role::new("svc"), event)?;   // 논블로킹
```

`handle`은 emit이 일어나는 모든 곳에 clone해 넣는 물건이다. 스토어는 파이프라인이 소유하고, 그 외 누구도 건드리지 않는다.

## 구성 요소

### 파이프라인 (`pipeline`)

`AuditPipeline::start`는 `AuditStore`의 소유권을 가져가 writer 스레드를 띄운다. `PipelineConfig`로 큐 용량과 재시도 스케줄을 잡고, 선택적 `FallbackFn`은 스토어 *와* DLQ가 둘 다 이벤트를 못 받을 때만 발동한다 — 그렇지 않았으면 레코드가 유실됐을 유일한 경로다. `handle.flush()`는 큐에 든 것이 전부 durable해질 때까지 블록하고, `handle.redrive_dlq(&admin)`은 적재된 이벤트를 재생한다(크래시 안전, at-least-once, 각 이벤트의 원래 발생 시각 유지).

### 필터 (`filter`)

`FilterSet`은 감사 대상 요청의 앞뒤에서 사용자 코드를 돌린다:

- **pre** — 핸들러 이전. 어떤 작업도 하기 전에 요청을 감사에서 면제하는 결정을 반환(헬스체크, 정적 자산 등).
- **post** — 응답이 정해진 뒤. 상태 코드로 스킵하거나(예: 304 제외), 응답에서 파생한 필드로 이벤트를 보강.

### 권한 (`permissions`)

`PermissionPolicy`는 `Role`을 `Action` 집합(`Emit`/`Query`/`Administer`)에 매핑한다. 정책 전체 스위치 하나로, 명시적 권한이 없는 role의 기본값을 정한다: 기본 거부(허용 목록 — 멀티테넌트나 신뢰할 수 없는 호출자에게 안전한 선택) 또는 기본 허용(거부 목록). 모든 handle 호출은 행위 `Role`을 들고 다니며 정책에 대조된다.

### HTTP 레이어 (`layer`)

`AuditLayer`는 엔드포인트별로 `tower` 서비스를 프록시하고, 한도까지 요청/응답 바디를 캡처하고, 타깃 엔티티를 파생해 자동으로 emit한다. 전체 설정 — `EndpointRule`, `target_extractor`, 바디 캡처 한도, 룰별 오버라이드 — 은 [루트 README의 "HTTP에서 기록하기"](../../README.ko.md#http에서-기록하기)에 있다. 레이어와 별개로 비-HTTP 이벤트(배치 잡, 스케줄러)에는 `handle.emit()`을 그대로 쓴다.

### 메트릭 & 헬스 (`metrics`, `health`)

`MetricsSnapshot`(큐 깊이, DLQ 크기, 쓰기/재시도/적재/손실 카운터, 지연 히스토그램)와 `HealthSnapshot`(writer 생존, disk-full 래치, 저용량 경고)은 쓰기 경로 밖 atomic에서 읽으므로 폴링이 writer와 경합하지 않는다. `quipu-server`는 바로 이것들을 Prometheus와 `/v1/healthz`로 노출한다.

## 샤딩

파이프라인 하나 = 스토어 하나 위 writer 스레드 하나 — 각 Merkle 트리를 끊김 없는 append-only 한 줄로 유지하는 불변식이다. 이 천장을 깨뜨리지 않고 넘으려고, `ShardRouter`는 **독립 파이프라인 N개**를 앞에서 받는다. 각각이 완결된 단일-writer 트리 + 레지스트리 + 체크포인트다:

```rust,no_run
use quipu_middleware::{ShardMap, ShardRouter};

// 샤드 N개, 테넌트 라우팅 안정화를 위한 해시 시드 고정.
let map = ShardMap::new(4, 0x9e3779b97f4a7c15);
let shards = /* Vec<(ShardId, AuditPipeline)>, 샤드 root마다 파이프라인 하나 */;
let router = ShardRouter::new(map, shards);

// 쓰기는 테넌트 기준으로 해당 테넌트의 owner 샤드에 라우팅.
router.emit(&role, "tenant-acme", event)?;

// 읽기: 테넌트를 주면 그 테넌트 샤드만, 안 주면 전 샤드 fan-out 후
// (timestamp, log_id)로 머지 + 커서 페이지네이션.
let page = router.query_page(&role, Some("tenant-acme"), q, None, 100)?;
```

핵심 성질(전체 모델은 [`docs/specs/horizontal-scaling`](../../docs/specs/horizontal-scaling/solution-design.md)):

- **라우팅은 테넌트 기준 일관 해싱.** 한 테넌트의 쓰기는 항상 한 샤드로 — 그 테넌트 트리가 샤드를 가로질러 쪼개지지 않는다.
- **글로벌 순서 없음.** 샤드 간 읽기는 `(timestamp_micros, log_id)`로 머지한다. 감사 로그에 단일 글로벌 시퀀스가 필요한 경우는 드물다 — 샤드별 순서 + 샤드별 서명 체크포인트면 충분. 시계는 정상으로 유지(NTP).
- **리샤딩은 추가 전용.** 트리는 재배치 불가라, 성장 시 기존 샤드를 `freeze`(읽기 전용, 영원히 단일-writer)하고 새 쓰기는 새 샤드로 보낸다. 그러면 한 테넌트 이력이 frozen + active 샤드에 걸치고, 테넌트 스코프 읽기가 둘 다 자동으로 본다.
- **샤드 간 무결성.** 샤드별 `verify`는 샤드 *내부* 변조를 잡고, `GlobalCheckpoint`/`verify_global`은 샤드별 Merkle 루트 + 트리 크기 + 샤드맵 매니페스트를 한 서명으로 묶어 샤드 *세트*에 대한 공격(샤드 통째 삭제·롤백=크기 감소·rewrite=같은 크기에 루트 변경·매니페스트 변조)을 잡는다. 트리 크기는 단조 증가라 retention 실행이 더 이상 롤백처럼 보이지 않는다.

`quipu-server`는 config에 `[shards]` 섹션이 있으면 자동으로 라우터로 전환한다. 단일 스토어 모드는 바이트·와이어 호환을 유지한다. [quipu-server README](../quipu-server/README.ko.md) 참조.

## 라이선스

Apache-2.0. [Quipu-Log](../../README.ko.md)의 일부.
