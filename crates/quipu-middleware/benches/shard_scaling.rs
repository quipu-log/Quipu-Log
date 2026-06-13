//! Write-throughput scaling vs shard count.
//!
//! Each shard is an independent single-writer pipeline, so aggregate write
//! throughput should grow with the number of shards until the disk/IO ceiling.
//! This bench emits a fixed total number of events spread across tenants and
//! measures end-to-end time (including the final flush) for N = 1, 2, 4 shards.
//!
//!   cargo bench -p quipu-middleware --bench shard_scaling

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use quipu_core::{
    default_actor_type, default_target_type, AuditStore, Content, EntityInput, StoreConfig,
    SyncPolicy,
};
use quipu_middleware::{
    AuditEvent, AuditPipeline, PermissionPolicy, PipelineConfig, Role, ShardId, ShardMap,
    ShardRouter, TargetSpec,
};
use std::hint::black_box;

fn build_router(n: u32, dir: &std::path::Path) -> ShardRouter {
    let mut shards = Vec::new();
    for i in 0..n {
        let id = ShardId(i);
        let root = dir.join(id.dir_name());
        std::fs::create_dir_all(&root).unwrap();
        let cfg = StoreConfig::new(&root).sync_policy(SyncPolicy::OsManaged);
        let mut store = AuditStore::open(cfg).unwrap();
        store.define_type(default_actor_type()).unwrap();
        store.define_type(default_target_type()).unwrap();
        let pipeline = AuditPipeline::start(
            store,
            root,
            PermissionPolicy::allow_all(),
            PipelineConfig::default(),
            None,
        )
        .unwrap();
        shards.push((id, pipeline));
    }
    ShardRouter::new(ShardMap::new(n, 0x9E37_79B9_7F4A_7C15), shards)
}

fn event_for(tenant: &str) -> AuditEvent {
    AuditEvent::new(
        "default_actor",
        EntityInput::new(tenant).text("name", tenant),
        "PUT",
        "/api/docs/1",
        Content::Text("x".into()),
    )
    .target(TargetSpec::new(
        "default_target",
        EntityInput::new("doc-1").text("name", "doc-1"),
    ))
}

fn bench_shard_scaling(c: &mut Criterion) {
    const TOTAL: usize = 20_000;
    let role = Role::new("svc");
    let mut group = c.benchmark_group("shard_scaling");
    group.throughput(Throughput::Elements(TOTAL as u64));

    for n in [1u32, 2, 4] {
        group.bench_with_input(BenchmarkId::from_parameter(n), &n, |b, &n| {
            b.iter_batched(
                || {
                    let dir = tempfile::tempdir().unwrap();
                    let router = build_router(n, dir.path());
                    (dir, router)
                },
                |(_dir, router)| {
                    for i in 0..TOTAL {
                        let tenant = format!("tenant-{}", i % 64);
                        loop {
                            match router.emit(&role, &tenant, event_for(&tenant)) {
                                Ok(_) => break,
                                Err(_) => std::thread::yield_now(),
                            }
                        }
                    }
                    router.flush().unwrap();
                    black_box(())
                },
                criterion::BatchSize::PerIteration,
            );
        });
    }
    group.finish();
}

criterion_group!(benches, bench_shard_scaling);
criterion_main!(benches);
