use axum::extract::{Path, Query, State};
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::IntoResponse;
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use futures::stream::Stream;
use std::collections::HashMap;
use std::convert::Infallible;
use std::sync::Arc;
use tokio_stream::wrappers::BroadcastStream;
use tokio_stream::StreamExt;

use crate::cost::{CostAccumulator, CostSummary, LlmUsageEvent, ModelCostDetail};
use crate::error::{ApiError, ApiResponse};
use crate::llm::LlmSessionMode;
use crate::observe::filesystem::FilesystemObserver;
use crate::observe::network::NetworkObserver;
use crate::state::AppState;
use crate::types::*;

pub fn create_router(state: Arc<AppState>) -> Router {
    Router::new()
        // Health
        .route("/health", get(health))
        // Jail lifecycle
        .route("/jails", post(create_jail))
        .route("/jails", get(list_jails))
        .route("/jails/:id", get(get_jail))
        .route("/jails/:id/start", post(start_jail))
        .route("/jails/:id/stop", post(stop_jail))
        .route("/jails/:id", delete(destroy_jail))
        // Execution
        .route("/jails/:id/exec", post(exec_in_jail))
        // Observation
        .route("/jails/:id/events", get(event_stream))
        .route("/jails/:id/report", get(get_report))
        .route("/jails/:id/fs/diff", get(get_fs_diff))
        .route("/jails/:id/network/log", get(get_network_log))
        .route("/jails/:id/processes", get(get_processes))
        // Snapshots
        .route("/jails/:id/snapshot", post(create_snapshot))
        .route("/jails/:id/snapshots", get(list_snapshots))
        .route("/snapshots/:sid/restore", post(restore_snapshot))
        .route("/snapshots/:sid/branch", post(branch_snapshot))
        .route("/snapshots/:sid/diff", get(diff_snapshot))
        // Cost tracking
        .route("/jails/:id/cost", get(get_cost))
        .route("/jails/:id/cost/breakdown", get(get_cost_breakdown))
        .route("/jails/:id/llm/usage", get(get_llm_usage))
        // LLM Interceptor
        .route("/jails/:id/llm", get(get_llm_session))
        .route("/jails/:id/llm/recordings", get(get_llm_recordings))
        .route("/jails/:id/llm/mode", post(switch_llm_mode))
        .with_state(state)
}

// ── Health ─────────────────────────────────────────────────────

async fn health(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let uptime = state.start_time.elapsed().as_secs();
    let jail_count = state.jails.len();
    let llm_available = state.llm_interceptor.health_check().await;

    Json(serde_json::json!({
        "status": "ok",
        "service": "agent-jail",
        "version": env!("CARGO_PKG_VERSION"),
        "uptime_secs": uptime,
        "jail_count": jail_count,
        "mock_llm_url": state.config.mock_llm_url,
        "mock_llm_available": llm_available,
    }))
}

// ── Jail Lifecycle ─────────────────────────────────────────────

async fn create_jail(
    State(state): State<Arc<AppState>>,
    Json(req): Json<CreateJailRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let config = req.into_config();

    if config.name.is_empty() {
        return Err(ApiError::BadRequest("Jail name cannot be empty".into()));
    }

    let mut jail = Jail::new(config);
    let id = jail.id.clone();

    // Provision rootfs
    let rootfs_paths = state.storage.ensure_rootfs_dirs(&id)?;
    state
        .rootfs_provider
        .create_minimal_rootfs(&rootfs_paths.lower)?;
    tracing::info!(jail_id = %id, "Rootfs provisioned");

    // Ensure events directory
    state.storage.ensure_events_dir(&id)?;

    // Set up LLM interception if enabled
    if jail.config.llm_intercept.enabled {
        match state
            .llm_interceptor
            .create_session(&id, &jail.config.llm_intercept.provider)
            .await
        {
            Ok(session) => {
                let env = state.llm_interceptor.env_vars(&session);
                jail.env_vars = env;
                jail.llm_session = Some(session.clone());
                state.llm_sessions.insert(id.clone(), session);
                tracing::info!(jail_id = %id, "LLM interceptor session created");
            }
            Err(e) => {
                tracing::warn!(
                    jail_id = %id,
                    error = %e,
                    "LLM interceptor unavailable — jail created without interception"
                );
            }
        }
    }

    state.save_jail(&jail)?;
    state.jails.insert(id.clone(), jail.clone());

    tracing::info!(jail_id = %id, name = %jail.config.name, "Jail created");

    Ok((axum::http::StatusCode::CREATED, Json(ApiResponse::ok(jail))))
}

async fn list_jails(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let jails: Vec<JailSummary> = state
        .jails
        .iter()
        .map(|entry| JailSummary::from(entry.value()))
        .collect();
    Json(ApiResponse::ok(jails))
}

async fn get_jail(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, ApiError> {
    let jail = state
        .get_jail(&id)
        .ok_or_else(|| ApiError::NotFound(format!("Jail not found: {}", id)))?;
    Ok(Json(ApiResponse::ok(jail)))
}

async fn start_jail(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, ApiError> {
    let mut jail = state
        .get_jail(&id)
        .ok_or_else(|| ApiError::NotFound(format!("Jail not found: {}", id)))?;

    match jail.status {
        JailStatus::Creating | JailStatus::Stopped => {}
        JailStatus::Running => {
            return Err(ApiError::Conflict("Jail already running".into()));
        }
        _ => {
            return Err(ApiError::Conflict(format!(
                "Cannot start jail in {:?} state",
                jail.status
            )));
        }
    }

    // Ensure LLM session is in record mode when starting
    if let Some(ref session) = jail.llm_session {
        if session.mode != LlmSessionMode::Record {
            let _ = state
                .llm_interceptor
                .switch_mode(&session.session_id, &LlmSessionMode::Record)
                .await;
        }
    }

    jail.status = JailStatus::Running;
    jail.started_at = Some(chrono::Utc::now());
    state.save_jail(&jail)?;
    state.jails.insert(id.clone(), jail.clone());

    tracing::info!(jail_id = %id, "Jail started");

    Ok(Json(ApiResponse::ok(jail)))
}

async fn stop_jail(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, ApiError> {
    let mut jail = state
        .get_jail(&id)
        .ok_or_else(|| ApiError::NotFound(format!("Jail not found: {}", id)))?;

    if jail.status != JailStatus::Running {
        return Err(ApiError::NotRunning(format!(
            "Jail is not running (status: {:?})",
            jail.status
        )));
    }

    // Switch LLM session to replay mode on stop
    if let Some(ref mut session) = jail.llm_session {
        match state
            .llm_interceptor
            .switch_mode(&session.session_id, &LlmSessionMode::Replay)
            .await
        {
            Ok(()) => {
                session.mode = LlmSessionMode::Replay;
                // Update recordings count
                if let Ok(info) = state.llm_interceptor.get_session(&session.session_id).await {
                    if let Some(count) = info["data"]["recordings_count"].as_u64() {
                        session.recordings_count = count;
                    }
                }
                tracing::info!(jail_id = %id, "LLM session switched to replay");
            }
            Err(e) => {
                tracing::warn!(jail_id = %id, error = %e, "Failed to switch LLM session mode");
            }
        }
    }

    // Compute final stats from stored events
    let events = state.storage.read_events(&id, None).unwrap_or_default();
    jail.stats.event_count = events.len() as u64;
    jail.stats.syscall_count = events
        .iter()
        .filter(|e| matches!(e, ObservationEvent::Syscall(_)))
        .count() as u64;
    jail.stats.file_ops_count = events
        .iter()
        .filter(|e| matches!(e, ObservationEvent::File(_)))
        .count() as u64;
    jail.stats.net_ops_count = events
        .iter()
        .filter(|e| matches!(e, ObservationEvent::Network(_)))
        .count() as u64;
    jail.stats.process_count = events
        .iter()
        .filter(|e| matches!(e, ObservationEvent::Process(_)))
        .count() as u64;

    // Accumulate LLM usage stats
    let mut acc = CostAccumulator::default();
    for event in &events {
        if let ObservationEvent::LlmUsage(u) = event {
            acc.record(&u.model, u.input_tokens, u.output_tokens, u.cost_usd);
        }
    }
    jail.stats.llm_requests = acc.total_requests;
    jail.stats.llm_input_tokens = acc.total_input_tokens;
    jail.stats.llm_output_tokens = acc.total_output_tokens;
    jail.stats.llm_cost_usd = acc.total_llm_cost_usd;
    jail.stats.cost_accumulator = acc;

    jail.status = JailStatus::Stopped;
    jail.stopped_at = Some(chrono::Utc::now());
    state.save_jail(&jail)?;
    state.jails.insert(id.clone(), jail.clone());

    tracing::info!(jail_id = %id, events = jail.stats.event_count, "Jail stopped");

    Ok(Json(ApiResponse::ok(jail)))
}

async fn destroy_jail(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, ApiError> {
    let jail = state
        .get_jail(&id)
        .ok_or_else(|| ApiError::NotFound(format!("Jail not found: {}", id)))?;

    if jail.status == JailStatus::Running {
        return Err(ApiError::Conflict(
            "Cannot destroy running jail — stop it first".into(),
        ));
    }

    // Clean up LLM session
    if let Some(ref session) = jail.llm_session {
        let _ = state
            .llm_interceptor
            .delete_session(&session.session_id)
            .await;
        state.llm_sessions.remove(&id);
    }

    state.jails.remove(&id);
    state.storage.delete_jail_dir(&id)?;

    tracing::info!(jail_id = %id, "Jail destroyed");

    Ok(Json(ApiResponse::<()>::ok(())))
}

// ── Execution ──────────────────────────────────────────────────

async fn exec_in_jail(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Json(req): Json<ExecRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let jail = state
        .get_jail(&id)
        .ok_or_else(|| ApiError::NotFound(format!("Jail not found: {}", id)))?;

    if jail.status != JailStatus::Running {
        return Err(ApiError::NotRunning(format!(
            "Jail is not running (status: {:?})",
            jail.status
        )));
    }

    if req.cmd.is_empty() {
        return Err(ApiError::BadRequest("Command cannot be empty".into()));
    }

    // Build environment string showing injected vars
    let env_info: Vec<String> = jail
        .env_vars
        .iter()
        .map(|(k, v)| {
            if k.contains("KEY") {
                format!("{}={}...", k, &v[..v.len().min(8)])
            } else {
                format!("{}={}", k, v)
            }
        })
        .collect();

    let result = ExecResult {
        exit_code: 0,
        stdout: format!(
            "[stub] Would execute: {}\nEnvironment: {}",
            req.cmd.join(" "),
            if env_info.is_empty() {
                "(none)".to_string()
            } else {
                env_info.join(", ")
            }
        ),
        stderr: String::new(),
        duration_ms: 0,
    };

    Ok(Json(ApiResponse::ok(result)))
}

// ── Observation ────────────────────────────────────────────────

#[derive(Debug, serde::Deserialize)]
struct EventQuery {
    #[serde(rename = "type")]
    event_type: Option<String>,
}

async fn event_stream(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Query(query): Query<EventQuery>,
) -> Result<Sse<impl Stream<Item = Result<Event, Infallible>>>, ApiError> {
    let _jail = state
        .get_jail(&id)
        .ok_or_else(|| ApiError::NotFound(format!("Jail not found: {}", id)))?;

    let rx = state.subscribe_events();
    let event_filter = query.event_type;
    let jail_id = id.clone();

    let stream = BroadcastStream::new(rx).filter_map(move |result| match result {
        Ok((eid, data)) if eid == jail_id => {
            if let Some(ref filter) = event_filter {
                if !data.contains(&format!("\"type\":\"{}\"", filter)) {
                    return None;
                }
            }
            Some(Ok(Event::default().data(data)))
        }
        _ => None,
    });

    Ok(Sse::new(stream).keep_alive(KeepAlive::default()))
}

async fn get_report(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, ApiError> {
    let jail = state
        .get_jail(&id)
        .ok_or_else(|| ApiError::NotFound(format!("Jail not found: {}", id)))?;

    let events = state.storage.read_events(&id, None)?;

    // Aggregate syscall counts by command
    let mut syscall_counts: HashMap<String, u64> = HashMap::new();
    for event in &events {
        if let ObservationEvent::Syscall(e) = event {
            *syscall_counts.entry(e.comm.clone()).or_default() += 1;
        }
    }
    let mut top_syscalls: Vec<(String, u64)> = syscall_counts.into_iter().collect();
    top_syscalls.sort_by(|a, b| b.1.cmp(&a.1));
    top_syscalls.truncate(10);

    // Aggregate file events
    let mut files_created = Vec::new();
    let mut files_modified = Vec::new();
    let mut files_deleted = Vec::new();
    for event in &events {
        if let ObservationEvent::File(e) = event {
            match e.op {
                FileOp::Create => files_created.push(e.path.clone()),
                FileOp::Write => files_modified.push(e.path.clone()),
                FileOp::Delete => files_deleted.push(e.path.clone()),
                _ => {}
            }
        }
    }
    // Deduplicate
    files_created.sort();
    files_created.dedup();
    files_modified.sort();
    files_modified.dedup();
    files_deleted.sort();
    files_deleted.dedup();

    // Aggregate network events
    let net_events: Vec<NetworkEvent> = events
        .iter()
        .filter_map(|e| match e {
            ObservationEvent::Network(n) => Some(n.clone()),
            _ => None,
        })
        .collect();
    let network_connections = NetworkObserver::summarize(&net_events);

    // Build process tree from events
    let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();
    let mut proc_observer = crate::observe::process::ProcessObserver::new(id.clone(), tx);
    for event in &events {
        if let ObservationEvent::Process(p) = event {
            proc_observer.record(p);
        }
    }
    let process_tree = proc_observer.build_tree();

    let duration = jail
        .stopped_at
        .unwrap_or_else(chrono::Utc::now)
        .signed_duration_since(jail.created_at)
        .num_seconds() as f64;

    let report = ObservationReport {
        jail_id: id,
        duration_secs: duration,
        stats: jail.stats.clone(),
        top_syscalls,
        files_modified,
        files_created,
        files_deleted,
        network_connections,
        process_tree,
    };

    Ok(Json(ApiResponse::ok(report)))
}

async fn get_fs_diff(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, ApiError> {
    let _jail = state
        .get_jail(&id)
        .ok_or_else(|| ApiError::NotFound(format!("Jail not found: {}", id)))?;

    // Scan actual OverlayFS upper directory for changes
    let upper_path = state.config.jail_rootfs_dir(&id).join("upper");
    let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();
    let mut fs_observer = FilesystemObserver::new(id.clone(), tx);
    fs_observer.set_upper_dir(upper_path);

    let diff = fs_observer.compute_diff().unwrap_or_else(|_| FsDiff {
        created: Vec::new(),
        modified: Vec::new(),
        deleted: Vec::new(),
    });

    Ok(Json(ApiResponse::ok(diff)))
}

async fn get_network_log(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, ApiError> {
    let _jail = state
        .get_jail(&id)
        .ok_or_else(|| ApiError::NotFound(format!("Jail not found: {}", id)))?;

    let events = state.storage.read_events(&id, Some("network"))?;
    let net_events: Vec<NetworkEvent> = events
        .into_iter()
        .filter_map(|e| match e {
            ObservationEvent::Network(n) => Some(n),
            _ => None,
        })
        .collect();

    Ok(Json(ApiResponse::ok(net_events)))
}

async fn get_processes(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, ApiError> {
    let _jail = state
        .get_jail(&id)
        .ok_or_else(|| ApiError::NotFound(format!("Jail not found: {}", id)))?;

    let events = state.storage.read_events(&id, Some("process"))?;
    let proc_events: Vec<ProcessEvent> = events
        .into_iter()
        .filter_map(|e| match e {
            ObservationEvent::Process(p) => Some(p),
            _ => None,
        })
        .collect();

    Ok(Json(ApiResponse::ok(proc_events)))
}

// ── Snapshots ──────────────────────────────────────────────────

async fn create_snapshot(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, ApiError> {
    let jail = state
        .get_jail(&id)
        .ok_or_else(|| ApiError::NotFound(format!("Jail not found: {}", id)))?;

    let snapshot_id = new_snapshot_id();

    // Copy OverlayFS upper to snapshot dir
    let upper_src = state.config.jail_rootfs_dir(&id).join("upper");
    let snap_upper = state
        .config
        .jail_snapshots_dir(&id)
        .join(&snapshot_id)
        .join("fs-upper");
    if upper_src.exists() {
        std::fs::create_dir_all(&snap_upper)?;
        copy_dir_recursive(&upper_src, &snap_upper)?;
    }

    let snapshot = Snapshot {
        id: snapshot_id.clone(),
        jail_id: id.clone(),
        parent: None,
        created_at: chrono::Utc::now(),
        status: jail.status.clone(),
        config: jail.config.clone(),
        stats_at_snapshot: jail.stats.clone(),
        fs_upper_path: snap_upper.to_string_lossy().to_string(),
        criu_dump_path: state
            .config
            .jail_snapshots_dir(&id)
            .join(&snapshot_id)
            .join("criu-dump")
            .to_string_lossy()
            .to_string(),
    };

    state.storage.save_snapshot(&id, &snapshot)?;
    state
        .snapshots
        .insert(snapshot_id.clone(), snapshot.clone());

    if let Some(mut entry) = state.jails.get_mut(&id) {
        entry.snapshot_ids.push(snapshot_id.clone());
    }

    tracing::info!(jail_id = %id, snapshot_id = %snapshot_id, "Snapshot created");

    Ok((
        axum::http::StatusCode::CREATED,
        Json(ApiResponse::ok(snapshot)),
    ))
}

async fn list_snapshots(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, ApiError> {
    let _jail = state
        .get_jail(&id)
        .ok_or_else(|| ApiError::NotFound(format!("Jail not found: {}", id)))?;

    let snapshots = state.storage.list_snapshots(&id)?;
    Ok(Json(ApiResponse::ok(snapshots)))
}

async fn restore_snapshot(
    State(state): State<Arc<AppState>>,
    Path(sid): Path<String>,
) -> Result<impl IntoResponse, ApiError> {
    let snapshot = state
        .snapshots
        .get(&sid)
        .map(|s| s.clone())
        .ok_or_else(|| ApiError::NotFound(format!("Snapshot not found: {}", sid)))?;

    let mut jail = Jail::new(snapshot.config.clone());
    jail.parent_snapshot = Some(sid.clone());
    jail.status = JailStatus::Creating;

    let id = jail.id.clone();

    // Provision rootfs and copy snapshot upper
    let rootfs_paths = state.storage.ensure_rootfs_dirs(&id)?;
    state
        .rootfs_provider
        .create_minimal_rootfs(&rootfs_paths.lower)?;

    let snap_upper = std::path::PathBuf::from(&snapshot.fs_upper_path);
    if snap_upper.exists() {
        copy_dir_recursive(&snap_upper, &rootfs_paths.upper)?;
    }

    state.save_jail(&jail)?;
    state.jails.insert(id.clone(), jail.clone());

    tracing::info!(
        snapshot_id = %sid,
        new_jail_id = %id,
        "Jail restored from snapshot"
    );

    Ok((axum::http::StatusCode::CREATED, Json(ApiResponse::ok(jail))))
}

async fn branch_snapshot(
    State(state): State<Arc<AppState>>,
    Path(sid): Path<String>,
) -> Result<impl IntoResponse, ApiError> {
    let snapshot = state
        .snapshots
        .get(&sid)
        .map(|s| s.clone())
        .ok_or_else(|| ApiError::NotFound(format!("Snapshot not found: {}", sid)))?;

    let jail = crate::snapshot::branch::branch_from_snapshot(&snapshot);
    let id = jail.id.clone();

    // Provision rootfs and copy snapshot upper
    let rootfs_paths = state.storage.ensure_rootfs_dirs(&id)?;
    state
        .rootfs_provider
        .create_minimal_rootfs(&rootfs_paths.lower)?;

    let snap_upper = std::path::PathBuf::from(&snapshot.fs_upper_path);
    if snap_upper.exists() {
        copy_dir_recursive(&snap_upper, &rootfs_paths.upper)?;
    }

    state.save_jail(&jail)?;
    state.jails.insert(id.clone(), jail.clone());

    tracing::info!(
        snapshot_id = %sid,
        branch_jail_id = %id,
        "Branched from snapshot"
    );

    Ok((axum::http::StatusCode::CREATED, Json(ApiResponse::ok(jail))))
}

async fn diff_snapshot(
    State(state): State<Arc<AppState>>,
    Path(sid): Path<String>,
) -> Result<impl IntoResponse, ApiError> {
    let snapshot = state
        .snapshots
        .get(&sid)
        .map(|s| s.clone())
        .ok_or_else(|| ApiError::NotFound(format!("Snapshot not found: {}", sid)))?;

    // Diff snapshot upper vs current jail upper
    let current_upper = state
        .config
        .jail_rootfs_dir(&snapshot.jail_id)
        .join("upper");
    let snap_upper = std::path::PathBuf::from(&snapshot.fs_upper_path);

    if current_upper.exists() && snap_upper.exists() {
        let diff = crate::snapshot::branch::diff_uppers(&snap_upper, &current_upper)?;
        Ok(Json(ApiResponse::ok(serde_json::json!({
            "snapshot_id": snapshot.id,
            "jail_id": snapshot.jail_id,
            "only_in_snapshot": diff.only_a,
            "only_in_current": diff.only_b,
            "different": diff.different,
        }))))
    } else {
        Ok(Json(ApiResponse::ok(serde_json::json!({
            "snapshot_id": snapshot.id,
            "jail_id": snapshot.jail_id,
            "only_in_snapshot": [],
            "only_in_current": [],
            "different": [],
        }))))
    }
}

// ── Cost Tracking ─────────────────────────────────────────

async fn get_cost(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, ApiError> {
    let jail = state
        .get_jail(&id)
        .ok_or_else(|| ApiError::NotFound(format!("Jail not found: {}", id)))?;

    let runtime_secs = jail
        .stopped_at
        .unwrap_or_else(chrono::Utc::now)
        .signed_duration_since(jail.created_at)
        .num_seconds() as f64;

    let acc = &jail.stats.cost_accumulator;
    let mut by_model = HashMap::new();
    for (model, &model_cost) in &acc.cost_by_model {
        let total_model_tokens = acc.tokens_by_model.get(model).copied().unwrap_or(0);
        by_model.insert(
            model.clone(),
            ModelCostDetail {
                requests: 0, // we don't track per-model request count in accumulator yet
                cost_usd: model_cost,
                input_tokens: 0,
                output_tokens: 0,
            },
        );
        // Enrich from events if available
        if let Ok(events) = state.storage.read_events(&id, Some("llm_usage")) {
            let mut req_count = 0u64;
            let mut inp = 0u64;
            let mut outp = 0u64;
            for event in &events {
                if let ObservationEvent::LlmUsage(e) = event {
                    if e.model == *model {
                        req_count += 1;
                        inp += e.input_tokens;
                        outp += e.output_tokens;
                    }
                }
            }
            if let Some(detail) = by_model.get_mut(model) {
                detail.requests = req_count;
                detail.input_tokens = inp;
                detail.output_tokens = outp;
            }
        }
        let _ = total_model_tokens; // used for quick summary when events unavailable
    }

    let summary = CostSummary {
        jail_id: id,
        total_cost_usd: acc.total_llm_cost_usd,
        total_requests: acc.total_requests,
        total_input_tokens: acc.total_input_tokens,
        total_output_tokens: acc.total_output_tokens,
        by_model,
        runtime_secs,
    };

    Ok(Json(ApiResponse::ok(summary)))
}

async fn get_cost_breakdown(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, ApiError> {
    let _jail = state
        .get_jail(&id)
        .ok_or_else(|| ApiError::NotFound(format!("Jail not found: {}", id)))?;

    let events = state.storage.read_events(&id, Some("llm_usage"))?;
    let usage_events: Vec<LlmUsageEvent> = events
        .into_iter()
        .filter_map(|e| match e {
            ObservationEvent::LlmUsage(u) => Some(u),
            _ => None,
        })
        .collect();

    Ok(Json(ApiResponse::ok(usage_events)))
}

async fn get_llm_usage(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, ApiError> {
    let _jail = state
        .get_jail(&id)
        .ok_or_else(|| ApiError::NotFound(format!("Jail not found: {}", id)))?;

    let events = state.storage.read_events(&id, Some("llm_usage"))?;
    let usage_events: Vec<LlmUsageEvent> = events
        .into_iter()
        .filter_map(|e| match e {
            ObservationEvent::LlmUsage(u) => Some(u),
            _ => None,
        })
        .collect();

    Ok(Json(ApiResponse::ok(usage_events)))
}

// ── LLM Interceptor ───────────────────────────────────────────

async fn get_llm_session(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, ApiError> {
    let jail = state
        .get_jail(&id)
        .ok_or_else(|| ApiError::NotFound(format!("Jail not found: {}", id)))?;

    match &jail.llm_session {
        Some(session) => {
            // Fetch latest info from mock-llm-service
            match state.llm_interceptor.get_session(&session.session_id).await {
                Ok(info) => Ok(Json(ApiResponse::ok(serde_json::json!({
                    "jail_id": id,
                    "session": session,
                    "proxy_url": state.config.mock_llm_url,
                    "env_vars": jail.env_vars,
                    "live_info": info.get("data"),
                })))),
                Err(_) => Ok(Json(ApiResponse::ok(serde_json::json!({
                    "jail_id": id,
                    "session": session,
                    "proxy_url": state.config.mock_llm_url,
                    "env_vars": jail.env_vars,
                    "live_info": null,
                })))),
            }
        }
        None => Err(ApiError::NotFound(format!(
            "No LLM session for jail {}",
            id
        ))),
    }
}

async fn get_llm_recordings(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, ApiError> {
    let jail = state
        .get_jail(&id)
        .ok_or_else(|| ApiError::NotFound(format!("Jail not found: {}", id)))?;

    let session = jail
        .llm_session
        .as_ref()
        .ok_or_else(|| ApiError::NotFound(format!("No LLM session for jail {}", id)))?;

    let recordings = state
        .llm_interceptor
        .list_recordings(&session.session_id)
        .await?;

    Ok(Json(recordings))
}

#[derive(Debug, serde::Deserialize)]
struct SwitchModeRequest {
    mode: String,
}

async fn switch_llm_mode(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Json(req): Json<SwitchModeRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let mut jail = state
        .get_jail(&id)
        .ok_or_else(|| ApiError::NotFound(format!("Jail not found: {}", id)))?;

    let session = jail
        .llm_session
        .as_mut()
        .ok_or_else(|| ApiError::NotFound(format!("No LLM session for jail {}", id)))?;

    let new_mode = match req.mode.as_str() {
        "record" => LlmSessionMode::Record,
        "replay" => LlmSessionMode::Replay,
        _ => {
            return Err(ApiError::BadRequest(
                "Mode must be 'record' or 'replay'".into(),
            ))
        }
    };

    state
        .llm_interceptor
        .switch_mode(&session.session_id, &new_mode)
        .await?;

    session.mode = new_mode;
    state.save_jail(&jail)?;
    state.jails.insert(id.clone(), jail.clone());

    Ok(Json(ApiResponse::ok(jail.llm_session)))
}

// ── Helpers ────────────────────────────────────────────────────

fn copy_dir_recursive(src: &std::path::Path, dst: &std::path::Path) -> std::io::Result<()> {
    if !dst.exists() {
        std::fs::create_dir_all(dst)?;
    }
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let dest_path = dst.join(entry.file_name());
        if entry.file_type()?.is_dir() {
            copy_dir_recursive(&entry.path(), &dest_path)?;
        } else {
            std::fs::copy(entry.path(), &dest_path)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tempfile::TempDir;
    use tower::ServiceExt;

    fn test_app() -> (Router, Arc<AppState>, TempDir) {
        let tmp = TempDir::new().unwrap();
        let config = crate::config::Config {
            data_dir: tmp.path().to_path_buf(),
            ..crate::config::Config::default()
        };
        let state = AppState::new(config);
        let router = create_router(state.clone());
        (router, state, tmp)
    }

    #[tokio::test]
    async fn test_health_endpoint() {
        let (app, _, _tmp) = test_app();
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_create_jail_provisions_rootfs() {
        let (app, state, _tmp) = test_app();
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/jails")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::to_string(&serde_json::json!({
                            "name": "test-jail",
                            "llm_intercept": { "enabled": false, "provider": "openai" }
                        }))
                        .unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);

        // Verify rootfs was provisioned
        let jail = state.jails.iter().next().unwrap();
        let rootfs_lower = state.config.jail_rootfs_dir(&jail.id).join("lower");
        assert!(rootfs_lower.join("bin").exists());
        assert!(rootfs_lower.join("etc/hostname").exists());
    }

    #[tokio::test]
    async fn test_create_jail_empty_name() {
        let (app, _, _tmp) = test_app();
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/jails")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::to_string(&serde_json::json!({
                            "name": ""
                        }))
                        .unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_list_jails_empty() {
        let (app, _, _tmp) = test_app();
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/jails")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_get_nonexistent_jail() {
        let (app, _, _tmp) = test_app();
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/jails/nonexistent")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_jail_lifecycle() {
        let (_, state, _tmp) = test_app();

        // Create jail (no LLM interception for unit test)
        let jail = Jail::new(JailConfig {
            name: "lifecycle-test".into(),
            llm_intercept: crate::llm::LlmInterceptorConfig {
                enabled: false,
                ..Default::default()
            },
            ..JailConfig::default()
        });
        let id = jail.id.clone();

        // Provision rootfs
        let rootfs = state.storage.ensure_rootfs_dirs(&id).unwrap();
        state
            .rootfs_provider
            .create_minimal_rootfs(&rootfs.lower)
            .unwrap();

        state.jails.insert(id.clone(), jail.clone());
        state.save_jail(&jail).unwrap();

        // Start
        let resp = create_router(state.clone())
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/jails/{}/start", id))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        // Stop
        let resp = create_router(state.clone())
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/jails/{}/stop", id))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        // Destroy
        let resp = create_router(state.clone())
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri(format!("/jails/{}", id))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_fs_diff_with_upper_changes() {
        let (_, state, _tmp) = test_app();

        let jail = Jail::new(JailConfig {
            name: "diff-test".into(),
            llm_intercept: crate::llm::LlmInterceptorConfig {
                enabled: false,
                ..Default::default()
            },
            ..JailConfig::default()
        });
        let id = jail.id.clone();
        let rootfs = state.storage.ensure_rootfs_dirs(&id).unwrap();
        state
            .rootfs_provider
            .create_minimal_rootfs(&rootfs.lower)
            .unwrap();

        // Simulate a file written in the jail (appears in upper)
        std::fs::write(rootfs.upper.join("output.txt"), "hello from jail").unwrap();

        state.jails.insert(id.clone(), jail.clone());
        state.save_jail(&jail).unwrap();

        let resp = create_router(state.clone())
            .oneshot(
                Request::builder()
                    .uri(format!("/jails/{}/fs/diff", id))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let created = json["data"]["created"].as_array().unwrap();
        assert!(created
            .iter()
            .any(|f| f.as_str().unwrap().contains("output.txt")));
    }

    #[tokio::test]
    async fn test_report_aggregates_events() {
        let (_, state, _tmp) = test_app();

        let jail = Jail::new(JailConfig {
            name: "report-test".into(),
            llm_intercept: crate::llm::LlmInterceptorConfig {
                enabled: false,
                ..Default::default()
            },
            ..JailConfig::default()
        });
        let id = jail.id.clone();
        state.jails.insert(id.clone(), jail.clone());
        state.save_jail(&jail).unwrap();

        // Add some events
        use crate::types::*;
        state
            .storage
            .append_event(
                &id,
                &ObservationEvent::Syscall(SyscallEvent {
                    ts: 100,
                    pid: 1,
                    tid: 1,
                    comm: "python3".into(),
                    nr: 1,
                    args: [0; 6],
                    ret: 0,
                    dur_ns: 50,
                }),
            )
            .unwrap();
        state
            .storage
            .append_event(
                &id,
                &ObservationEvent::File(FileEvent {
                    ts: 200,
                    pid: 1,
                    op: FileOp::Create,
                    path: "/tmp/output.txt".into(),
                    bytes: Some(42),
                }),
            )
            .unwrap();

        let resp = create_router(state.clone())
            .oneshot(
                Request::builder()
                    .uri(format!("/jails/{}/report", id))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let report = &json["data"];
        assert!(!report["top_syscalls"].as_array().unwrap().is_empty());
        assert!(report["files_created"]
            .as_array()
            .unwrap()
            .iter()
            .any(|f| f.as_str().unwrap() == "/tmp/output.txt"));
    }

    #[tokio::test]
    async fn test_snapshot_copies_upper() {
        let (_, state, _tmp) = test_app();

        let jail = Jail::new(JailConfig {
            name: "snapshot-test".into(),
            llm_intercept: crate::llm::LlmInterceptorConfig {
                enabled: false,
                ..Default::default()
            },
            ..JailConfig::default()
        });
        let id = jail.id.clone();
        let rootfs = state.storage.ensure_rootfs_dirs(&id).unwrap();
        state
            .rootfs_provider
            .create_minimal_rootfs(&rootfs.lower)
            .unwrap();

        // Write a file to upper
        std::fs::write(rootfs.upper.join("data.txt"), "snapshot me").unwrap();

        state.jails.insert(id.clone(), jail.clone());
        state.save_jail(&jail).unwrap();

        // Create snapshot
        let resp = create_router(state.clone())
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/jails/{}/snapshot", id))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);

        // Verify snapshot has the file
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let fs_upper_path = json["data"]["fs_upper_path"].as_str().unwrap();
        let snap_file = std::path::PathBuf::from(fs_upper_path).join("data.txt");
        assert!(snap_file.exists());
        assert_eq!(std::fs::read_to_string(&snap_file).unwrap(), "snapshot me");
    }

    #[tokio::test]
    async fn test_llm_session_not_found() {
        let (_, state, _tmp) = test_app();

        let jail = Jail::new(JailConfig {
            name: "no-llm".into(),
            llm_intercept: crate::llm::LlmInterceptorConfig {
                enabled: false,
                ..Default::default()
            },
            ..JailConfig::default()
        });
        let id = jail.id.clone();
        state.jails.insert(id.clone(), jail);

        let resp = create_router(state.clone())
            .oneshot(
                Request::builder()
                    .uri(format!("/jails/{}/llm", id))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[test]
    fn test_copy_dir_recursive() {
        let tmp = TempDir::new().unwrap();
        let src = tmp.path().join("src");
        let dst = tmp.path().join("dst");

        std::fs::create_dir_all(src.join("sub")).unwrap();
        std::fs::write(src.join("file.txt"), "hello").unwrap();
        std::fs::write(src.join("sub/nested.txt"), "world").unwrap();

        copy_dir_recursive(&src, &dst).unwrap();

        assert!(dst.join("file.txt").exists());
        assert!(dst.join("sub/nested.txt").exists());
        assert_eq!(
            std::fs::read_to_string(dst.join("file.txt")).unwrap(),
            "hello"
        );
        assert_eq!(
            std::fs::read_to_string(dst.join("sub/nested.txt")).unwrap(),
            "world"
        );
    }
}
