# Quipu-Log

[![CI](https://github.com/draft-dhgo/Quipu-Log/actions/workflows/ci.yml/badge.svg)](https://github.com/draft-dhgo/Quipu-Log/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![MSRV](https://img.shields.io/badge/MSRV-1.89-blue.svg)](Cargo.toml)
[![crates.io](https://img.shields.io/crates/v/quipu-core.svg)](https://crates.io/crates/quipu-core)
[![docs.rs](https://img.shields.io/docsrs/quipu-core.svg)](https://docs.rs/quipu-core)

[English](README.md) | 한국어

**Rust 서비스를 위한 변조 감지(tamper-evident) 감사 로그. 프로세스에 임베드되고, 따로 띄울 데이터베이스가 없습니다.**

누가 어떤 API로 무엇에 무슨 일을 했는지 기록합니다.

## Quipu-Log가 주는 것

Quipu-Log는 감사 로그라는 한 가지 일에 특화돼 있고, 그 집중이 다음을 줍니다.

- **운영할 게 없습니다.** 스토어는 `std::fs`로 관리되는 평범한 디렉터리 하나입니다 — 데몬도, 별도 DB 엔진도, 외부 의존성도 없습니다. 로그를 서비스 *옆에* 세우는 게 아니라 서비스 *프로세스 안에* 임베드합니다.
- **필드 단위 검색 가능 암호화.** 필드마다 보호 수준(평문 / SHA-256 / 키드 HMAC / RSA 하이브리드)을 고르고, blind index(exact / prefix / n-gram)로 **평문이 디스크에 닿지 않은 값을 그대로 검색**합니다. SSN을 평문으로 저장하지 않고도 SSN으로 로그를 찾습니다.
- **Write-only 배포.** RSA private 키 없이 서버를 띄우면, 보호 필드를 자기도 읽지 못하는 암호문으로 저장합니다. 서버가 통째로 털려도 평문은 복구되지 않습니다.
- **표준, 벤더 중립 증명.** 무결성 백본이 RFC 6962(Certificate Transparency) 머클 트리입니다. inclusion·consistency proof가 RFC를 정확히 따르므로, 제3자가 스펙만 보고 직접 짠 검증기로 당신의 로그를 검증할 수 있습니다 — 이 소프트웨어만 아는 자체 스킴이 아닙니다.
- **이력이 맥락을 유지합니다.** 액터와 타깃은 버전드 엔티티이고, 모든 로그는 작성 시점에 유효했던 버전을 고정합니다. 오늘 사용자 이름을 바꿔도 지난달 로그는 옛 이름 그대로 렌더되고, 옛 이름으로 검색까지 됩니다.
- **핸들러가 디스크를 기다리지 않습니다.** emit은 재시도·디스크 기반 DLQ·페이저로 연결할 수 있는 fallback 훅을 갖춘 비동기 파이프라인을 통해 논블로킹으로 동작합니다. `tower` 레이어가 거의 코드 변경 없이 HTTP 요청을 캡처합니다.

## 동작 원리

**이벤트** 하나 = *actor*(사용자/서비스)가 무언가(`method`, `url`, 선택적 본문)를 하나 이상의 *target*에 한 사실. actor와 target은 **엔티티** — 타입이 있는 레코드이고, 타입마다 **레지스트리**가 하나씩 생깁니다. 레지스트리는 덮어쓰지 않고, 필드가 바뀌면 불변 **버전**을 새로 붙입니다. 각 로그 행은 기록 시점의 버전을 핀으로 고정하고, 이 핀이 시점 조회(time-travel)를 가능케 합니다. 옛 값과 새 값이 둘 다 인덱스에 남습니다.

```
핸들러 ──emit──▶ 파이프라인 ──────────▶ 스토어 (append-only, Merkle 커밋)
        (논블로킹) (큐, 재시도,           ├── logs
                   DLQ, 폴백)            └── 레지스트리 (버전 관리되는 엔티티)
```

코드는 복제 가능한 **핸들**만 들고 있으면 됩니다. 스토어는 전용 writer 스레드가 소유합니다.

## 빠른 시작

```sh
cargo add quipu-core quipu-middleware
```

```rust
use quipu_core::*;
use quipu_middleware::*;

// 1. 스토어를 연다 (없으면 생성).
let root = std::path::PathBuf::from("/var/lib/myapp/audit");
let cfg = StoreConfig::new(&root)
    .retention(RetentionPolicy::days(90))
    .sync_policy(SyncPolicy::EveryN(32));
let mut store = AuditStore::open(cfg)?;

// 2. 엔티티 타입 등록 (커스텀 스키마가 필요 없으면 기본 타입으로 충분).
if !store.has_type("default_actor") {
    store.define_type(default_actor_type())?;
    store.define_type(default_target_type())?;
}

// 3. 파이프라인을 시작하고 핸들을 잡아둔다.
let pipeline = AuditPipeline::start(
    store, root, PermissionPolicy::allow_all(),
    PipelineConfig::default(), None /* 폴백 훅 */)?;
let handle = pipeline.handle();

// 4. 이벤트 발행 — 논블로킹.
handle.emit(
    &Role::new("svc"),
    AuditEvent::new(
        "default_actor",
        EntityInput::new("svc-1").text("name", "billing-service"),
        "PUT",
        "/api/docs/42",
        Content::Text("saved".into()),
    )
    .target(TargetSpec::new(
        "default_target",
        EntityInput::new("42").text("name", "doc-42"),
    )),
)?;
```

전체 예제: [`examples/axum-demo`](examples/axum-demo). HTTP 서비스는 보통 emit을 직접 부르지 않고 아래 레이어로 기록합니다.

## HTTP에서 기록하기

`tower` 레이어를 라우트 앞에 끼웁니다. 기록할 엔드포인트 선택, 본문 캡처(선택), target 엔티티 도출을 레이어가 맡습니다.

```rust
let pipeline = AuditPipeline::start(store, root, permissions, PipelineConfig::default(),
    Some(Arc::new(|event, err| page_oncall(event, err))))?; // 폴백
let layer = AuditLayer::new(pipeline.handle())
    .rules(vec![EndpointRule::prefix("/api/docs").method(Method::PUT)
        .capture_request().capture_response()        // 캡처 한도를 넘는 본문은
        .capture_limit(1024 * 1024)                  //   캡처 없이 그대로 프록시
        .target_extractor(|req, res, req_body, res_body| {
            /* 규칙 단위 target 추출 (레이어 전역 설정을 오버라이드) */
            vec![]
        })])
    .filters(FilterSet::new()
        .pre(|req| /* 핸들러 전에 실행: 헬스 체크 제외 등 */)
        .post(|req, res, event| /* 핸들러 후에 실행: 304 스킵, 이벤트 보강 */))
    .target_extractor(|req, res, req_body, res_body| /* target 엔티티 도출 */);
let app = Router::new().route(...).layer(layer);
```

HTTP가 아닌 일(배치 잡, 스크립트, cron)에는 레이어와 별개로 `handle.emit(...)`을 그대로 씁니다.

## 데이터 모델링

### 엔티티 타입

로그 행: `log_id`, `timestamp`(UTC µs), `actor`, `method`, `url`, `targets`, `content`, 그리고 등록한 커스텀 컬럼(text/number/json, 매 쓰기 검증). `targets`는 관계 테이블이라 로그 하나가 여러 엔티티를 가리킵니다. 필드는 타입마다 정의합니다.

```rust
store.define_type(TypeSchema::new("patient", vec![
    FieldDef::text("ssn").protection(FieldProtection::Hmac).indexed().required(),
    FieldDef::text("mrn").protection(FieldProtection::Sha256).indexed(),
    FieldDef::text("name").protection(FieldProtection::Rsa),
]))?;
```

커스텀 스키마가 필요 없으면 기본 제공 `default_actor`/`default_target`으로 충분합니다(빠른 시작에서 등록한 게 이 둘).

### 필드 보호

필드마다 따로, 기본은 평문. 스토어 전체 스위치는 없습니다.

| 수준 | 검색 | 키 | 비고 |
|---|---|---|---|
| `Sha256` | 정확 일치 | 불필요 | 단방향 해시. 검색어도 같은 방식으로 해시해 비교합니다. 주민번호처럼 엔트로피가 낮은 값은 디스크만 손에 넣으면 무차별 대입이 되니 `Hmac`을 쓰세요. |
| `Hmac` | 정확 일치 | `KeyRing::with_hmac_key` | 키 기반 HMAC-SHA-256. 키가 없으면 의미 없는 값입니다. |
| `Rsa` | 불가(복호화 스캔) | RSA 키쌍 | AES-256-GCM에 RSA-OAEP 키 래핑을 더한 하이브리드. 인증 암호화라, 제자리에서 고치면 복호화가 실패합니다. |

보호는 레지스트리 **필드에만** 걸립니다. `entity_id`, 로그의 `method`/`url`/`content`, 커스텀 컬럼은 항상 평문입니다(쿼리가 필터링·렌더링하는 대상). 민감한 값은 보호 필드에 담고, 엔티티 ID는 무의미한 값을 쓰고, `content`에는 PII를 넣지 마세요.

### 블라인드 인덱스

보호를 걸면 검색이 좁아집니다(해시 = 정확 일치만, RSA = 복호화 스캔). 블라인드 인덱스가 다시 넓힙니다.

```rust
FieldDef::text("ssn").protection(FieldProtection::Hmac)
    .indexed()                          // 정확 일치
    .search(FieldIndex::Ngram(3)),      // + 부분 문자열 일치
FieldDef::text("name").protection(FieldProtection::Rsa)
    .search(FieldIndex::Prefix(4)),     // + 최대 4자 접두사 일치
```

쓰기 시점에 평문을 소문자로 정규화·토큰화·다이제스트해 레코드 옆에 저장합니다. `Exact`는 값 전체, `Prefix(n)`은 앞 1..=n자, `Ngram(n)`은 n자 윈도우. 토큰은 필드의 키를 따르므로 무차별 대입 여지는 늘지 않지만, *구조*(어떤 값들이 접두사·조각을 공유하는지)는 새어 나갑니다. 필드 단위, 전역 스위치 없음.

### 스키마 진화

추가만 됩니다. 필드를 더할 수는 있지만, 지우거나 kind·보호·인덱스를 바꿀 수는 없습니다. 과거 값이 계속 검색돼야 하기 때문입니다.

## 쿼리

```rust
let hits = handle.query(&Role::new("auditor"), LogQuery {
    targets: vec![          // 여러 필터는 AND로 결합
        // 정확 일치 — 과거 값 포함 (이름이 바뀐 엔티티도
        // 옛 이름으로 찾을 수 있음)
        TargetFilter::exact("default_target", "name", Value::Text("final-report".into())),
        // LIKE 스타일 부분 문자열 일치
        TargetFilter::exact("default_target", "name", Value::Text("report".into())).contains(),
    ],
    method: Some("PUT".into()),
    ..Default::default()
})?;
```

각 히트는 기록 당시 모습 그대로의 actor/target 스냅샷과 RFC 3339 UTC 타임스탬프를 함께 돌려줍니다.

### 매칭 연산자

`exact`, `contains()`, `prefix()`, `exact_ci()`(대소문자 무시 정확 일치). 평문 필드에서는 넷 다 동작합니다. 보호 필드에서 `prefix()`/`exact_ci()`는 대응하는 `FieldIndex`를 선언해야 합니다.

`contains()`:

- **`Ngram(n)` 인덱스가 있으면:** 토큰 다이제스트로 매칭(대소문자 무시, 평문 없음). RSA 후보는 복호화해 검증(`plaintext_cache(true)` 필요). 해시 필드는 검증할 평문이 없어 거짓 양성이 가능하니 정확한 히트엔 `Rsa`.
- **인덱스가 없으면:** `plaintext_cache(true)` 필요(메모리에만, 미영속). 기본은 꺼짐 → 쿼리 거부.

### 스냅샷

쿼리는 읽기 스냅샷(`handle.snapshot(&role)?`) 위에서 돕니다. 인메모리 레지스트리 인덱스를 복제하고 호출자 스레드에서 스캔하므로 쓰기를 막지 않습니다.

```rust
handle.entity_types(&role)?;                            // 모든 타입 스키마
handle.list_entities(&role, "default_target", false)?;  // 엔티티별 최신 버전
handle.entity_history(&role, "default_target", "doc-1")?; // 모든 버전, 오래된 것부터
```

## 서버 모드: 여러 서비스, 하나의 로그

`quipu-server`는 같은 엔진을 독립 데몬으로 돌려 토큰 인증 HTTP/JSON API로 노출합니다. 언어가 무엇이든 여러 서비스가 한곳에 기록·검색합니다.

```
service A ──┐                       ┌── root/logs
service B ──┼── HTTP ── quipu-server┼── root/registry/<type>
auditor  ───┘   (bearer tokens)     └── root/dlq, ...
```

단일 프로세스 스토어. 인증은 기본 거부, 토큰마다 역할 권한. 쓰기 전용 모드(RSA 개인 키 없이 시작)는 암호화 필드를 저장하고 암호문으로 돌려주어 클라이언트가 복호화합니다. 설정·전체 API·v1 제약: [quipu-server README](crates/quipu-server/README.ko.md).

## 메타 감사: 감사 로그는 누가 들여다봤나

옵션을 켜면 스토어를 향한 모든 조회·관리 작업(쿼리, 레지스트리 둘러보기, DLQ 재처리, 보존 정책 실행, flush, 무결성 검증, 토큰 리로드)을 자체 Merkle spine·보존 기간을 가진 별도 **접근 로그**에 남깁니다. `verify_integrity` 대상에도 들어갑니다.

```rust
let cfg = StoreConfig::new("./audit-data")
    .access_log(true)                              // 옵트인
    .access_retention(RetentionPolicy::days(90));  // 본 데이터와 별도의 보존 기간
```

접근 기록은 단순 append(쿼리를 타지 않으니 자기참조 루프 없음). 파라미터 요약에는 쿼리의 *모양*(필드, 매칭 모드, 기간)만 담기고 검색어 값은 담기지 않아, 보호 필드 평문이 새지 않습니다. 조회는 `handle.query_access(&admin_role, AccessQuery::default())` 또는 `administer` 권한의 `POST /v1/access/query`.

## 변조 감지가 잡는 것

Quipu-Log는 변조를 *드러나게* 합니다. Merkle 트리 하나만으로 우발적 손상(쓰다 만 쓰기, 비트 부패, 잘린 꼬리)과 순진한 변조(제자리 수정, 바꿔치기된 세그먼트)를 잡습니다 — `verify_integrity()`가 첫 균열을 짚어냅니다. 또한 제3자가 독립 검증할 수 있습니다. inclusion proof는 레코드가 로그에 있음을, consistency proof는 이력이 append-only로 유지됐음을, 둘 다 O(log n)으로 공개된 루트에 대해 확인합니다.

서명 체크포인트와 외부 앵커링은 이 범위를 꼬리 절단과 전체 재작성까지 넓힙니다. 전체 위협 모델: [SECURITY.md](SECURITY.md).

## 수평 확장: 샤딩된 트리

각 Merkle 트리는 writer가 하나입니다. 단일 writer의 처리량을 넘어서려면 샤딩합니다 — 독립 트리 N개를 돌립니다.

- **쓰기는 샤딩으로 확장.** 테넌트로 파티셔닝합니다. 각 샤드는 독립된 단일-writer 트리 + 레지스트리 + 체크포인트라, 샤드 N개면 대략 N배 쓰기 처리량입니다. 포기하는 건 샤드 간 글로벌 전순서뿐(감사 로그엔 거의 필요 없음). `quipu-middleware`의 `ShardRouter`가 쓰기를 소유 샤드로 보내고, 쿼리는 fan-out 후 타임스탬프로 머지합니다.
- **읽기는 복제로 확장.** 봉인된 세그먼트는 불변이라 읽기 복제 노드 몇 대로든 복사됩니다. 액티브 꼬리만 약간 지연됩니다.
- **수용은 무상태로 확장.** 무상태 인제스트 프런트가 `Idempotency-Key`로 요청을 소유 샤드에 라우팅합니다.
- **리샤딩은 추가 전용.** 트리는 재배치가 불가능하므로, 증설은 기존 샤드를 동결(읽기 전용)하고 일관 해싱으로 새 쓰기를 새 샤드로 보냅니다. 레코드는 이동하지 않고, 한 테넌트의 이력은 옛 샤드와 현재 샤드에 걸치며 읽기는 둘 다 봅니다.

전체 모델 — 샤드 키·순서·리샤딩·읽기 토폴로지: [`docs/specs/horizontal-scaling`](docs/specs/horizontal-scaling/solution-design.md).

샤드는 한 프로세스라, 멈추면 그 샤드로 가는 감사 기록이 멈춥니다. 장애를 견디는 건 보내는 쪽 몫입니다 — `quipu-client`가 멱등 재전송(`Idempotency-Key`당 한 건), 각 이벤트의 `occurred_at` 보존, 장애 동안 로컬 디스크 스풀을 제공합니다. 장애 노드는 라이브 페일오버가 아니라 콜드 스탠바이로 복구합니다. [quipu-client](crates/quipu-client/README.ko.md), [콜드 스탠바이 페일오버](crates/quipu-server/README.ko.md#콜드-스탠바이-페일오버) 참고.

## 키 관리

필드를 `Hmac`이나 `Rsa`로 보호하면 키 관리를 떠안습니다. 감사 로그에서 키 분실은 식은 캐시가 아니라 더 이상 읽을 수도 검색할 수도 없는 레코드입니다.

- **로테이션은 싸고, re-key는 예외.** `KeyRing` 키에는 버전이 붙습니다. 평시 로테이션은 새 쓰기용으로 높은 버전을 얹는 게 전부, 낮은 버전은 옛 레코드용으로 남습니다. 오프라인 `rekey`는 키 *유출* 때만 돌려, 유출된 키로 스토어를 못 읽게 RSA 데이터를 다시 감쌉니다.
- **옛 키는 영구 보관.** 옛 RSA 공개 키는 옛 체크포인트를, 옛 HMAC 키는 옛 검색 토큰을 검증합니다. HMAC 필드는 re-key 불가(일방향)이라, HMAC 키가 유출되면 그 다이제스트는 노출된 것으로 봐야 합니다.
- **잃은 키는 복구 불가.** 에스크로도 백도어도 없습니다. `KeyRing`은 스토어와 분리해 백업하고 복원을 미리 연습하세요.
- **앵커링하려면 서명 키를 분리.** 체크포인트 서명은 개인 키가 데이터 노드 바깥(별도 호스트·HSM·KMS)에 있을 때만 키를 쥔 내부자를 막습니다.

단계별 로테이션·re-key 절차: [quipu-server README](crates/quipu-server/README.ko.md#키-로테이션).

## 운영 노트

- **권한** — 역할마다 `Emit` / `Query` / `Administer` 중 허용할 작업 지정. 권한 없는 역할의 기본값(기본 거부/기본 허용)은 정책 전체에 하나로 정합니다.
- **보존 정책** — `RetentionPolicy::days(90)`은 봉인된 세그먼트를 통째로 지웁니다(`unlink` 한 번, 재작성 없음). 레지스트리는 남아 옛 이력도 렌더링됩니다. `.with_max_bytes(n)`으로 용량 예산 추가(기간 OR 용량, 쓰는 중 세그먼트는 보존). 지운 뒤에도 무결성 검증 통과.
- **내구성** — `SyncPolicy::Always`, `EveryN(n)`, `OsManaged`.
- **데드레터 큐** — 재시도를 소진한 이벤트는 디스크에 보관되어 재시작에도 남고, `handle.redrive_dlq(&admin_role)`로 재생됩니다(크래시 안전, at-least-once, 원래 발생 시각 유지).
- **무결성 감사** — `store.verify_integrity()`가 모든 레코드를 Merkle 트리와 대조합니다. `prove_inclusion`/`prove_consistency`는 제3자가 검증할 증명을 발급합니다.
- **키 로테이션** — 버전 관리되는 `KeyRing` 키, 최고 버전 활성·낮은 버전 읽기용. 유출 후 오프라인 `rekey`가 RSA 데이터를 다시 감싸고 서명된 re-key 이벤트를 남겨, `verify_integrity()`가 말 없는 재작성과 구분합니다. 전체 절차: [quipu-server README](crates/quipu-server/README.ko.md#키-로테이션).
- **백업** — 봉인된 세그먼트는 불변이라 데몬이 도는 중에도 `rsync`/스냅샷으로 복사됩니다. `flush`로 액티브 꼬리를 먼저 안정시키고, 복사본은 `verify_integrity()`로 검증하세요.
- **디스크 풀** — 정의된 동작. 여유 공간이 기준(기본 1 GiB 또는 10%) 아래면 하우스키핑이 미리 경고합니다. ENOSPC 쓰기는 재시도를 건너뛰어 DLQ/폴백으로 가고, 래치를 겁니다. 래치는 다음 성공 쓰기나 회복된 공간에서 풀립니다.
- **관측성** — 쓰기는 `tracing`으로 보고·집계됩니다. `handle.metrics()`는 큐 깊이, DLQ 적체, 쓰기·재시도·보관·유실 카운터, 지연 히스토그램을 락 없이 돌려줍니다. `quipu-server`는 `GET /metrics`(Prometheus)와 `GET /v1/healthz`로 노출합니다.
- **익스포트 & SIEM** — `POST /v1/logs/export`는 쿼리 결과를 NDJSON으로 덤프합니다. 옵트인 syslog 미러(RFC 5424/UDP)는 모든 기록 이벤트를 포워딩하며, 베스트에포트라 쓰기 경로를 막지 않습니다.
- **포맷 버저닝** — 세그먼트 파일은 매직 넘버와 버전 바이트로 시작합니다. 레이아웃 변경은 마이그레이션으로 처리합니다.

## 성능

`cargo bench -p quipu-middleware --bench write_path`(criterion 0.5)로 잰 쓰기 경로 수치. 이벤트마다 actor 하나, target 하나, 짧은 텍스트 페이로드. `flush()`는 durable해질 때까지 기다리므로 end-to-end 수치입니다. Apple M4, RAM 16GB, NVMe SSD, macOS 15, rustc 1.96.0, release, emit 스레드 1개:

| 설정 | 기록 처리량 |
|---|---|
| `SyncPolicy::OsManaged` (페이지 캐시까지 flush) | 약 56,000 events/s |
| `SyncPolicy::EveryN(64)` (64건마다 fsync) | 약 4,800 events/s |

`EveryN(64)` + 큐 32,768칸, 이벤트 200,000건 호출부 `emit()` 지연:

| 백분위 | 지연 |
|---|---|
| p50 | 42 ns |
| p99 | 10.7 ms |
| p99.9 | 11.6 ms |

p50은 bounded 채널에 넣는 비용. 꼬리 지연은 백프레셔(큐가 차면 `QueueFull` 반환). `OsManaged`는 꼬리를 없애지만 전원 손실 시 내구성을 OS 페이지 캐시에 맡깁니다.

## 워크스페이스 구성

| crate | 설명 |
|---|---|
| [`quipu-core`](crates/quipu-core/README.ko.md) | 스토리지 엔진, 타입별 레지스트리, 필드 암호화, 보존 정책, 쿼리 |
| [`quipu-middleware`](crates/quipu-middleware/README.ko.md) | 이벤트 파이프라인(DLQ/폴백), pre/post 필터, 권한, `tower` 프록시 레이어, 샤드 라우터 |
| [`quipu-server`](crates/quipu-server/README.ko.md) | 독립 데몬: 같은 스토어 엔진을 토큰 인증 HTTP/JSON API로 노출 |
| [`quipu-client`](crates/quipu-client/README.ko.md) | 데몬용 레퍼런스 클라이언트: 멱등 재전송, 백오프, 옵트인 디스크 스풀 |
| [`quipu-mcp`](crates/quipu-mcp/README.ko.md) | Model Context Protocol 서버: 스토어를 LLM 에이전트에 노출(쿼리/이력/검증) |
| [`examples/axum-demo`](examples/axum-demo) | 실행 가능한 axum 연동 예제 |

## 데모와 테스트 실행

```sh
cargo test                 # core + middleware 테스트 스위트
cargo run -p axum-demo     # 이후: curl -X PUT localhost:3000/api/docs/42 -H 'x-audit-actor: alice' -d hi
```

## 라이선스

Apache-2.0
