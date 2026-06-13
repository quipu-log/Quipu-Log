use quipu_core::AuditStore;
use quipu_middleware::{
    AuditPipeline, PermissionPolicy, PipelineConfig, ShardId, ShardMap, ShardRouter,
};
use quipu_server::{router, AppState, ServerConfig, SyslogSink};
use std::sync::Arc;

/// The opened store, either a single embedded store or N sharded ones behind a
/// router. Held by `main` for the process lifetime so shutdown can flush it.
enum Backend {
    Single(AuditPipeline),
    Sharded(Arc<ShardRouter>),
}

/// Open the store(s) and start the writer thread(s) per the config: one store
/// under `store.root` (single mode), or N under `store.root/shard-NNNN` when a
/// `[shards]` section is present. The same `pipeline_cfg` (incl. the SIEM sink)
/// is shared by every shard's writer.
fn build_backend(
    cfg: &ServerConfig,
    base_root: &std::path::Path,
    pipeline_cfg: PipelineConfig,
) -> Backend {
    let Some(shards) = &cfg.shards else {
        // single-store mode: byte-compatible with an unsharded deployment
        let store_cfg = cfg.store_config().unwrap_or_else(|e| {
            eprintln!("invalid store/keys config: {e}");
            std::process::exit(1);
        });
        let store = AuditStore::open(store_cfg).unwrap_or_else(|e| {
            eprintln!("failed to open store at '{}': {e}", base_root.display());
            std::process::exit(1);
        });
        let pipeline = AuditPipeline::start(
            store,
            base_root.to_path_buf(),
            PermissionPolicy::allow_all(),
            pipeline_cfg,
            None,
        )
        .unwrap_or_else(|e| {
            eprintln!("failed to start audit pipeline: {e}");
            std::process::exit(1);
        });
        return Backend::Single(pipeline);
    };

    if shards.count == 0 {
        eprintln!("invalid [shards] config: count must be at least 1");
        std::process::exit(1);
    }
    if let Some(bad) = shards.frozen.iter().find(|f| **f >= shards.count) {
        eprintln!(
            "invalid [shards] config: frozen id {bad} is >= count {}",
            shards.count
        );
        std::process::exit(1);
    }
    let active: Vec<ShardId> = (0..shards.count)
        .filter(|i| !shards.frozen.contains(i))
        .map(ShardId)
        .collect();
    if active.is_empty() {
        eprintln!(
            "invalid [shards] config: every shard is frozen — writes would have nowhere to go"
        );
        std::process::exit(1);
    }
    let frozen: Vec<ShardId> = shards.frozen.iter().copied().map(ShardId).collect();
    let map = ShardMap::from_parts(active, frozen, shards.hash_seed);

    let mut pipelines = Vec::with_capacity(shards.count as usize);
    for id in 0..shards.count {
        let shard = ShardId(id);
        let root = base_root.join(shard.dir_name());
        if let Err(e) = std::fs::create_dir_all(&root) {
            eprintln!("failed to create shard dir '{}': {e}", root.display());
            std::process::exit(1);
        }
        let store_cfg = cfg.store_config_at(root.clone()).unwrap_or_else(|e| {
            eprintln!("invalid store/keys config for {shard}: {e}");
            std::process::exit(1);
        });
        let store = AuditStore::open(store_cfg).unwrap_or_else(|e| {
            eprintln!("failed to open {shard} store at '{}': {e}", root.display());
            std::process::exit(1);
        });
        let pipeline = AuditPipeline::start(
            store,
            root,
            PermissionPolicy::allow_all(),
            pipeline_cfg.clone(),
            None,
        )
        .unwrap_or_else(|e| {
            eprintln!("failed to start {shard} pipeline: {e}");
            std::process::exit(1);
        });
        pipelines.push((shard, pipeline));
    }
    tracing::info!(
        shards = shards.count,
        frozen = shards.frozen.len(),
        "sharded mode: {} active shard writer(s)",
        shards.count as usize - shards.frozen.len()
    );
    Backend::Sharded(Arc::new(ShardRouter::new(map, pipelines)))
}

fn usage() -> ! {
    eprintln!("usage: quipu-server <config.json>          serve");
    eprintln!("       quipu-server rekey <config.json>    offline re-key (see README)");
    std::process::exit(2);
}

fn load_config(config_path: &str) -> ServerConfig {
    match ServerConfig::load(std::path::Path::new(config_path)) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("failed to load config '{config_path}': {e}");
            std::process::exit(1);
        }
    }
}

/// Offline re-key: re-wrap RSA-protected registry values (and re-digest
/// their index tokens) under the active key versions, recording a signed
/// re-key event. The server must not be running — the store lock enforces it.
fn run_rekey(config_path: &str) -> ! {
    let cfg = load_config(config_path);
    let store_cfg = match cfg.store_config() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("invalid store/keys config: {e}");
            std::process::exit(1);
        }
    };
    let root = store_cfg.root.clone();
    let mut store = match AuditStore::open(store_cfg) {
        Ok(s) => s,
        Err(e) => {
            eprintln!(
                "failed to open store at '{}': {e} (is the server still running?)",
                root.display()
            );
            std::process::exit(1);
        }
    };
    let event = match store.rekey() {
        Ok(ev) => ev,
        Err(e) => {
            eprintln!("re-key failed: {e}");
            std::process::exit(1);
        }
    };
    if let Err(e) = store.verify_integrity() {
        eprintln!("re-key wrote an event but post-verification failed: {e}");
        std::process::exit(1);
    }
    println!(
        "re-key complete: RSA values now under key version {}, index tokens under HMAC \
         version {} ({})",
        event.rsa_version,
        event.hmac_version,
        if event.hmac_version == 0 {
            "none configured"
        } else {
            "active"
        },
    );
    for t in &event.tables {
        println!(
            "  registry '{}': {} records, chain {}.. -> {}..",
            t.type_name,
            t.records,
            &t.old_chain_head[..12.min(t.old_chain_head.len())],
            &t.new_chain_head[..12.min(t.new_chain_head.len())],
        );
    }
    println!(
        "signed re-key event recorded (signing key version {}); integrity verified",
        event.signing_key_version
    );
    std::process::exit(0);
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    let args: Vec<String> = std::env::args().skip(1).collect();
    let config_path = match args.as_slice() {
        [cmd, config] if cmd == "rekey" => run_rekey(config),
        [config] => config.clone(),
        _ => usage(),
    };
    let cfg = load_config(&config_path);

    let store_root = cfg.store.root.clone();

    // SIEM forwarding (opt-in `sink` section): each durably-written event is
    // mirrored to syslog. Hold the handle for the process lifetime so its
    // sender thread keeps draining; dropping it would close the mirror.
    let mut pipeline_cfg = cfg.pipeline_config();
    let _syslog_sink = match &cfg.sink {
        Some(s) => {
            let app = s.app_name.as_deref().unwrap_or("quipu-server");
            let cap = s.queue_capacity.unwrap_or(16_384);
            match SyslogSink::new(&s.syslog_udp, app, cap) {
                Ok(sink) => {
                    pipeline_cfg.sink = Some(sink.sink());
                    tracing::info!(collector = %s.syslog_udp, "syslog SIEM mirror enabled");
                    Some(sink)
                }
                Err(e) => {
                    eprintln!("failed to set up syslog sink '{}': {e}", s.syslog_udp);
                    std::process::exit(1);
                }
            }
        }
        None => None,
    };

    // the pipeline(s) are only reachable through the HTTP handlers here, and
    // those gate every call against the hot-reloadable AppState policy — so
    // the pipeline's own (start-time-frozen) policy must not also enforce,
    // or a SIGHUP grant change could never take effect
    let backend = build_backend(&cfg, &store_root, pipeline_cfg);

    let auth_state = match cfg.auth_state() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("invalid auth config: {e}");
            std::process::exit(1);
        }
    };
    let mut state = match &backend {
        Backend::Single(p) => AppState::new(p.handle(), auth_state, store_root),
        Backend::Sharded(r) => {
            let header = cfg
                .shards
                .as_ref()
                .and_then(|s| s.tenant_header.clone())
                .unwrap_or_else(|| quipu_server::DEFAULT_TENANT_HEADER.to_string());
            AppState::new_sharded(r.clone(), auth_state, store_root, header)
        }
    };
    if let Some(idem) = &cfg.idempotency {
        state = state.idempotency_window(idem.window);
    }

    // SIGHUP = re-read the config file and swap the auth section (token
    // issue/revoke without dropping connections); reload failures keep the
    // previous auth state
    #[cfg(unix)]
    {
        let state = state.clone();
        let path = std::path::PathBuf::from(&config_path);
        tokio::spawn(async move {
            let mut hup = match tokio::signal::unix::signal(
                tokio::signal::unix::SignalKind::hangup(),
            ) {
                Ok(s) => s,
                Err(e) => {
                    tracing::error!(error = %e, "cannot install SIGHUP handler; auth hot-reload disabled");
                    return;
                }
            };
            while hup.recv().await.is_some() {
                if let Err(e) = state.reload_auth(&path) {
                    tracing::error!(error = %e, "auth reload failed; keeping previous auth config");
                }
            }
        });
    }

    // periodic integrity verification (opt-in `verify` config section);
    // tamper findings surface as `error` log lines
    if let Some(verify) = &cfg.verify {
        quipu_server::spawn_periodic_verify(
            state.clone(),
            std::time::Duration::from_secs(verify.interval_secs),
        );
        tracing::info!(
            interval_secs = verify.interval_secs,
            "periodic integrity verification enabled"
        );
    }

    let listener = match quipu_server::bind(&cfg.listen) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("failed to bind '{}': {e}", cfg.listen);
            std::process::exit(1);
        }
    };
    tracing::info!(listen = %cfg.listen, tls = cfg.tls.is_some(), "quipu-server listening");

    let result = quipu_server::serve(listener, cfg.tls.as_ref(), router(state), async {
        let _ = tokio::signal::ctrl_c().await;
        tracing::info!("shutdown signal received");
    })
    .await;
    if let Err(e) = result {
        tracing::error!(error = %e, "server error");
    }

    // flush everything queued before the process exits — audit data must not
    // ride on the OS cache through a shutdown
    match backend {
        Backend::Single(p) => p.shutdown(),
        // serve() has returned, so no new emits; flush every shard durably.
        // A clean writer-thread join needs sole ownership of the router, which
        // the long-lived SIGHUP/verify tasks may still share — fall back to a
        // flush (which fsyncs each shard) when they do.
        Backend::Sharded(r) => match Arc::try_unwrap(r) {
            Ok(router) => router.shutdown(),
            Err(shared) => {
                let _ = shared.flush();
            }
        },
    }
}
