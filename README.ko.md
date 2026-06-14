<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/logo/quipu-log-logo-dark.png">
    <img src="docs/logo/quipu-log-logo-light.png" alt="quipu-log — Tamper-evident audit log" width="440">
  </picture>
</p>

# Quipu-Log

[![CI](https://github.com/quipu-log/Quipu-Log/actions/workflows/ci.yml/badge.svg)](https://github.com/quipu-log/Quipu-Log/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![MSRV](https://img.shields.io/badge/MSRV-1.89-blue.svg)](Cargo.toml)
[![crates.io](https://img.shields.io/crates/v/quipu-core.svg)](https://crates.io/crates/quipu-core)
[![docs.rs](https://img.shields.io/docsrs/quipu-core.svg)](https://docs.rs/quipu-core)

[English](README.md) | 한국어

**Rust 서비스를 위한 감사 로그 — 한 번 기록하고 어느 각도에서나 같은 이력을 조회.** 변조 감지(tamper-evident) · 프로세스 임베드 · 별도 DB 없음.

누가 어떤 API로 무엇에 무슨 일을 했는지 기록합니다.

📖 **심화 해설:** [Quipu-Log 교과서](https://quipu-log.github.io/quipu-log-textbook/ko/) — 파일시스템 저장 엔진, 머클 무결성 모델, 검색 가능 암호화를 밑바닥부터 짚는 내부 구조 해설서.

## 빠른 시작

```sh
cargo add quipu-core quipu-middleware
```

```rust
use quipu_core::*;
use quipu_middleware::*;

let root = "/var/lib/myapp/audit";
let mut store = AuditStore::open(StoreConfig::new(root))?;   // 열기(없으면 생성)
store.define_type(default_actor_type())?;                    // 기본 엔티티 타입
store.define_type(default_target_type())?;

let pipeline = AuditPipeline::start(
    store, root.into(), PermissionPolicy::allow_all(), PipelineConfig::default(), None)?;
let handle = pipeline.handle();                              // 복제 가능; writer 스레드가 스토어 소유

// 논블로킹 — 기록: actor svc-1이 PUT /api/docs/42를 target doc-42에 수행
handle.emit(&Role::new("svc"), AuditEvent::new(
    "default_actor", EntityInput::new("svc-1").text("name", "billing"),
    "PUT", "/api/docs/42", Content::Text("saved".into()))
    .target(TargetSpec::new("default_target", EntityInput::new("42").text("name", "doc-42"))))?;
```

전체 예제: [`examples/axum-demo`](examples/axum-demo) · [`tower` 레이어로 HTTP에서 기록](#http에서-기록하기).

## Quipu-Log가 주는 것

Quipu-Log는 감사 로그라는 한 가지 일에 특화돼 있고, 그 집중이 다음을 줍니다.

- **한 번 기록, 여러 각도로 조회.** 변경에 연관된 엔티티를 모두 target으로 걸어두면, 그중 무엇을 기준으로 잡아도 같은 변경 이력이 한 번에 나옵니다 — 기록은 한 번, 조회 각도는 여럿([자세히](#기록은-한-번-조회는-여러-각도로)).
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

## 기록은 한 번, 조회는 여러 각도로

CUD를 기록할 때, 그 변경에 **연관된 엔티티를 전부 target으로 걸어두세요.** 그러면 나중에 그중 어느 엔티티를 기준으로 잡아도 관련 변경 이력이 한 번에 나옵니다.

`targets`는 관계 테이블이라 로그 한 줄이 여러 엔티티를 가리킬 수 있습니다. 예를 들어 문서 수정 하나에 *문서·작성자·프로젝트·상위 폴더*를 모두 target으로 넣어두면,

- "이 문서에 일어난 변경 전부"
- "이 사용자가 건드린 변경 전부"
- "이 프로젝트에서 일어난 변경 전부"

가 **같은 로그를 서로 다른 입구로** 찾아 들어가는 일이 됩니다 — 기록은 한 번, 조회 각도는 여럿.

엔티티가 버전드라, target으로 박힌 엔티티의 이름이 나중에 바뀌어도 **옛 이름으로 검색하면 그 변경이 그대로 나옵니다.** 6개월 전 `draft-v1`이던 문서가 지금 `final-report`여도, 둘 중 무엇으로 찾든 전체 이력이 끊기지 않습니다.

```rust
// 기록: 변경에 연관된 엔티티를 모두 target으로
handle.emit(&actor, AuditEvent::new(...)
    .target(doc_entity)
    .target(author_entity)
    .target(project_entity))?;

// 조회: 어느 입구로든 — 과거 값까지 매칭
handle.query(&auditor, LogQuery {
    targets: vec![
        TargetFilter::exact("document", "name", Value::Text("final-report".into())),
    ],
    ..Default::default()
})?;
```

조회 품질은 결국 **기록 시점에 연관을 얼마나 빠짐없이 걸었느냐**로 결정됩니다. HTTP 레이어를 쓴다면 `target_extractor`에 "이 요청에서 어떤 엔티티들을 연관으로 뽑을지"를 규칙으로 박아두면, 사람이 매번 빠뜨리지 않고 일관되게 기록됩니다.

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

로그 행: `log_id`, `timestamp`(UTC µs), `actor`, `method`, `url`, `targets`, `content`, 그리고 등록한 커스텀 컬럼(text/number/json, 매 쓰기 검증). 필드는 타입마다 정의합니다.

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

쓰기 시점에 평문을 소문자로 정규화·토큰화·다이제스트해 레코드 옆에 저장합니다. `Exact`는 값 전체, `Prefix(n)`은 앞 1..=n자, `Ngram(n)`은 n자 윈도우. 토큰은 필드의 키를 따르므로 *외부인*은 무차별 대입할 수 없습니다 — 하지만 그 키를 쥔 쪽(검색하려면 키가 필요한, 장악당한 서버 포함)은 **저엔트로피** 값의 다이제스트를 사전공격해, 필드를 복호화하지 못해도 평문을 재구성할 수 있습니다. 특히 `Ngram`은 조각 단위로 값을 복원하므로 가장 취약합니다. 또한 *구조*(어떤 값들이 접두사·조각을 공유하는지)도 새어 나갑니다. 그러니 블라인드 인덱스 — 특히 `Ngram` — 는 저엔트로피 PII에 걸지 마세요. 필드 단위, 전역 스위치 없음.

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

보호 필드에 `contains()`를 하려면 블라인드 인덱스가 필요합니다:

- **`Ngram(n)` 인덱스가 있으면:** `Sha256`·`Hmac`·`Rsa` 모두 토큰 다이제스트로 검색 가능해집니다(대소문자 무시, 평문은 디스크에 없음). 이 매칭은 *후보* 필터라 — 쿼리의 모든 n-gram이 있는지만 확인하므로 조각이 순서 없이 흩어져 있으면 과매칭이 날 수 있습니다. **저엔트로피 필드에는 이 인덱스를 걸지 마세요**(주민번호, 전화번호, 적은 후보의 이름 등): 키를 쥔 쪽 — 장악당한 서버 포함 — 이 다이제스트를 사전공격해, `Rsa`로 암호화돼 있어도 값을 재구성할 수 있습니다([블라인드 인덱스](#블라인드-인덱스) 참고).
- **인덱스가 없으면:** `plaintext_cache(true)` 필요(메모리에만, 미영속). 기본은 꺼짐 → 쿼리 거부.

이 후보 과매칭이 걸러지는지는 필드 *보호*가 정합니다:

- `Rsa`: 후보를 복호화해 실제 값과 재대조(`plaintext_cache(true)` 필요) → 거짓 양성 없음.
- `Sha256` / `Hmac`: 매칭은 되지만 재대조할 평문이 없어 과매칭이 거짓 양성으로 남습니다.

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

각 Merkle 트리는 writer가 하나라, 단일 트리의 처리량이 천장입니다. 그 너머로 확장하려면 샤딩합니다 — 독립 트리 N개를 돌리고 테넌트를 각 트리로 라우팅합니다.

- **쓰기는 샤딩으로 확장.** 테넌트로 파티셔닝합니다. 각 샤드는 독립된 단일-writer 트리 + 레지스트리 + 체크포인트라, 샤드 N개면 공유 디바이스의 fsync 대역이 포화될 때까지 대략 N배 쓰기 처리량입니다(PLP NVMe면 그 천장이 훨씬 멀어짐). 포기하는 건 샤드 간 글로벌 전순서뿐(감사 로그엔 거의 필요 없음). `quipu-middleware`의 `ShardRouter`가 쓰기를 consistent-hash로 소유 샤드에 보내고, 샤드별 group commit을 병렬 실행하며, 쿼리는 fan-out 후 타임스탬프로 머지하고, 서명된 cross-shard anchor로 무결성(tamper-evidence)이 모든 샤드에 걸쳐 유지됩니다.
- **읽기는 복제로 확장.** 봉인된 세그먼트는 불변이라 읽기 복제 노드 몇 대로든 복사됩니다. 액티브 꼬리만 약간 지연됩니다.
- **수용은 무상태로 확장.** 무상태 인제스트 프런트가 `Idempotency-Key`로 요청을 소유 샤드에 라우팅합니다.
- **리샤딩은 추가 전용.** 트리는 재배치가 불가능하므로, 증설은 기존 샤드를 동결(읽기 전용)하고 일관 해싱으로 새 쓰기를 새 샤드로 보냅니다. 레코드는 이동하지 않고, 한 테넌트의 이력은 옛 샤드와 현재 샤드에 걸치며 읽기는 둘 다 봅니다. 동결 — 쓰기는 멈추되 읽기는 계속됨 — 이 single-writer-for-life 보장을 지키는 방식입니다.

```rust
use quipu_core::{AuditStore, StoreConfig, SyncPolicy, default_actor_type, default_target_type};
use quipu_middleware::{
    AuditPipeline, PermissionPolicy, PipelineConfig, ShardId, ShardMap, ShardRouter,
};

// 샤드마다 파이프라인 하나, 각자 별도 디렉토리에 둡니다.
fn shard_pipeline(dir: &std::path::Path) -> AuditPipeline {
    std::fs::create_dir_all(dir).unwrap();
    let mut store = AuditStore::open(
        StoreConfig::new(dir).sync_policy(SyncPolicy::EveryN(256)),
    ).unwrap();
    store.define_type(default_actor_type()).unwrap();
    store.define_type(default_target_type()).unwrap();
    AuditPipeline::start(
        store, dir.to_path_buf(),
        PermissionPolicy::allow_all(), PipelineConfig::default(), None,
    ).unwrap()
}

// 고정 시드 — 라우팅 링이 여기서 파생되므로 영속화하고 절대 바꾸지 마세요.
const SEED: u64 = 0x9E37_79B9_7F4A_7C15;
let n = 8;
let shards = (0..n)
    .map(|i| (ShardId(i), shard_pipeline(&data_root.join(ShardId(i).dir_name()))))
    .collect();
let router = ShardRouter::new(ShardMap::new(n, SEED), shards);

router.emit(&role, tenant, event)?;     // 테넌트가 속한 샤드로 라우팅
router.query(&role, Some(tenant), q)?;  // 그 테넌트 조회 (active + frozen 샤드)
```

**고른 분산은 호출자 책임입니다.** 라우터는 넘긴 tenant 키를 consistent-hash 할 뿐, 부하를 보고 재배치하지 않습니다 — "가장 한가한 샤드로 보내기" 같은 동작은 없습니다. 이건 동적 로드밸런싱이 아니라 **애플리케이션 레벨 파티셔닝**입니다. 샤딩은 테넌트 *간* 확장이지 테넌트 *내* 확장이 아닙니다: 고른 분포는 *키 설계*에서 나옵니다 — 테넌트당 키 하나면 테넌트가 (볼륨이 아니라 개수 기준으로) 고르게 퍼지고, `tenant:substream`처럼 더 잘게 쪼갠 키면 핫 테넌트 한 명의 쓰기도 여러 샤드로 분산됩니다(대신 순서 보장은 substream 단위로 좁아짐). tenant를 정하는 쪽 — 보통 raw 클라이언트 입력이 아니라 요청 신원에서 도출하는 신뢰된 인증 계층 — 이 그 선택을 책임집니다.

`n`은 쓰기 동시성에 맞춰 정합니다(코어당 샤드 1개 정도가 무난한 출발점). 시드는 고정·영속화해야 합니다 — 링이 시드에 의존하므로, 재시작 후에는 `ShardMap::from_parts(active, frozen, seed)`로 복원합니다. `ShardMap::new(1, seed)`는 샤드 1개짜리 degenerate 케이스로 샤딩 안 한 스토어와 완전히 동일하게 동작하므로, `n = 1`로 시작해 나중에 키워도 됩니다.

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
- **내구성** — `SyncPolicy::Always`, `EveryN(n)`, `EveryNOrInterval(n, dur)`(group commit: append `n`건 누적 *또는* 가장 오래된 미동기 append로부터 `dur` 경과 중 먼저 충족 시 fsync), `OsManaged`.
- **데드레터 큐** — 재시도를 소진한 이벤트는 디스크에 보관되어 재시작에도 남고, `handle.redrive_dlq(&admin_role)`로 재생됩니다(크래시 안전, at-least-once, 원래 발생 시각 유지).
- **무결성 감사** — `store.verify_integrity()`가 모든 레코드를 Merkle 트리와 대조합니다. `prove_inclusion`/`prove_consistency`는 제3자가 검증할 증명을 발급합니다.
- **키 로테이션** — 버전 관리되는 `KeyRing` 키, 최고 버전 활성·낮은 버전 읽기용. 유출 후 오프라인 `rekey`가 RSA 데이터를 다시 감싸고 서명된 re-key 이벤트를 남겨, `verify_integrity()`가 말 없는 재작성과 구분합니다. 전체 절차: [quipu-server README](crates/quipu-server/README.ko.md#키-로테이션).
- **백업** — 봉인된 세그먼트는 불변이라 데몬이 도는 중에도 `rsync`/스냅샷으로 복사됩니다. `flush`로 액티브 꼬리를 먼저 안정시키고, 복사본은 `verify_integrity()`로 검증하세요.
- **디스크 풀** — 정의된 동작. 여유 공간이 기준(기본 1 GiB 또는 10%) 아래면 하우스키핑이 미리 경고합니다. ENOSPC 쓰기는 재시도를 건너뛰어 DLQ/폴백으로 가고, 래치를 겁니다. 래치는 다음 성공 쓰기나 회복된 공간에서 풀립니다.
- **관측성** — 쓰기는 `tracing`으로 보고·집계됩니다. `handle.metrics()`는 큐 깊이, DLQ 적체, 쓰기·재시도·보관·유실 카운터, 지연 히스토그램을 락 없이 돌려줍니다. `quipu-server`는 `GET /metrics`(Prometheus)와 `GET /v1/healthz`로 노출합니다.
- **익스포트 & SIEM** — `POST /v1/logs/export`는 쿼리 결과를 NDJSON으로 덤프합니다. 옵트인 syslog 미러(RFC 5424/UDP)는 모든 기록 이벤트를 포워딩하며, 베스트에포트라 쓰기 경로를 막지 않습니다.
- **포맷 버저닝** — 세그먼트 파일은 매직 넘버와 버전 바이트로 시작합니다. 레이아웃 변경은 마이그레이션으로 처리합니다.

## 성능

아래 수치는 전부 **Merkle 트리 1개, 샤딩 없음** — single writer 하나의 처리량입니다. 샤딩하면 여기서 배가됩니다([single writer 너머로 확장](#single-writer-너머로-확장-테넌트-샤딩) 참고). `cargo bench -p quipu-middleware --bench write_path`(criterion 0.5)로 잰 쓰기 경로 수치. 이벤트마다 actor 하나, target 하나, 짧은 텍스트 페이로드. `flush()`는 durable해질 때까지 기다리므로 end-to-end 수치입니다. Apple M4, RAM 16GB, NVMe SSD(APFS tempdir), macOS 26, rustc 1.96.0, release, emit 스레드 1개:

| 설정 | 기록 처리량 |
|---|---|
| `SyncPolicy::OsManaged` (페이지 캐시까지 flush) | 약 34,000 events/s |
| `SyncPolicy::EveryNOrInterval(1000, 20ms)` (group commit) | 약 29,000 events/s |
| `SyncPolicy::EveryN(64)` (64건마다 fsync) | 약 3,200 events/s |

`EveryNOrInterval`이 처리량 손잡이입니다 — fsync를 append 약 1000건(또는 20ms 윈도, 먼저 충족하는 쪽)으로 묶어 fsync 횟수를 약 16배 줄이고, fsync를 유지하면서도 페이지 캐시 천장의 약 85%까지 도달합니다(카운트만 보는 `EveryN(64)` 대비 실측 약 9배). 인터벌은 저부하 시 durable 대기 중인 append의 최대 대기시간을 상한하는데, 이는 `EveryN`만으로는 막을 수 없습니다.

`EveryN(64)` + 큐 32,768칸, 이벤트 200,000건 호출부 `emit()` 지연:

| 백분위 | 지연 |
|---|---|
| p50 | 42 ns |
| p99 | 16.3 ms |
| p99.9 | 19.3 ms |

p50은 bounded 채널에 넣는 비용. 꼬리 지연은 백프레셔(큐가 차면 `QueueFull` 반환). `OsManaged`는 꼬리를 없애지만 전원 손실 시 내구성을 OS 페이지 캐시에 맡깁니다.

### immudb 비교

[immudb](https://github.com/codenotary/immudb)의 synced append와 정면 비교 — **group commit 손잡이를 맞추고**(20ms 윈도, 1,000건 cap), immudb를 벤치한 **동일한 `rust:1` Docker 컨테이너**(Linux, 컨테이너 파일시스템 위 tempdir)에서 실행. 위와 같은 `write_path` / `EveryNOrInterval(1000, 20ms)` 벤치입니다.

| 항목 | quipu `EveryNOrInterval(1000, 20ms)` | immudb `SyncedAppend` (matched) |
|---|---|---|
| 기록 처리량 | **약 163,000 /s** | 약 38,800 /s |
| op당 시간 | 6.14 ms / 1,000 events | 257.9 ms / 10,000 txn |
| 측정 모드 | 임베디드(in-process) | 임베디드(in-process) |
| 시간 윈도 | 20 ms | 20 ms |
| 카운트 cap | 1,000 | 1,000 (`MaxActiveTransactions`) |
| 동시성 | single writer (1) | 1,000 goroutine |
| commit당 작업 | 멀티레코드 append(로그+관계+레지스트리) + 머클 해시트리 leaf | 멀티키 append + AHT leaf (MVCC; 2차 인덱스는 비동기) |
| 배수 | **4.2×** | 1.0× (기준) |

같은 내구성 쓰기 프리미티브를 공정하게 맞댄 비교입니다: 둘 다 변조탐지 해시트리(quipu는 머클 spine, immudb는 accumulate-hash-tree)에 묶인 멀티레코드 내구성 append를 group commit하고, immudb의 2차 인덱스는 비동기로 commit 경로 밖에서 만들어집니다. 손잡이(20ms / 1,000)와 환경(같은 컨테이너)을 맞춘 조건에서 quipu가 immudb 대비 **약 4.2×** 처리량을 냅니다. 둘은 설계가 다르지만(quipu는 single-writer append-only 감사 로그, immudb는 범용 MVCC 트랜잭션 KV 스토어) 공유하는 내구성 쓰기 경로에서 quipu의 Rust append가 확연히 빠릅니다.

Merkle 트리는 writer가 하나라 위 수치는 트리당 천장입니다. 한 트리 너머로 확장하려면 테넌트로 샤딩해 N개를 병렬로 돌립니다 — [수평 확장: 샤딩된 트리](#수평-확장-샤딩된-트리) 참고.

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
