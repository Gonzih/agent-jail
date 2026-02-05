//! Integration tests for agent-jail command execution and event capture.
//!
//! These tests verify that Python and Node.js scripts can be executed
//! and that filesystem, network, and process events are properly captured.

use agent_jail::api::create_router;
use agent_jail::config::Config;
use agent_jail::state::AppState;
use agent_jail::types::{ExecRequest, JailConfig, JailStatus, ObservationEvent};
use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::Value;
use std::sync::Arc;
use tempfile::TempDir;
use tower::ServiceExt;

/// Create test app state with temporary directory.
fn test_app() -> (axum::Router, Arc<AppState>, TempDir) {
    let tmp = TempDir::new().unwrap();
    let config = Config {
        data_dir: tmp.path().to_path_buf(),
        ..Config::default()
    };
    let state = AppState::new(config);
    let router = create_router(state.clone());
    (router, state, tmp)
}

/// Create and start a jail, returning the jail ID.
async fn create_and_start_jail(state: &Arc<AppState>, name: &str) -> String {
    use agent_jail::types::Jail;

    let jail = Jail::new(JailConfig {
        name: name.into(),
        llm_intercept: agent_jail::llm::LlmInterceptorConfig {
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
    state.storage.ensure_events_dir(&id).unwrap();

    // Save and start
    let mut jail = jail;
    jail.status = JailStatus::Running;
    jail.started_at = Some(chrono::Utc::now());
    state.save_jail(&jail).unwrap();
    state.jails.insert(id.clone(), jail);

    id
}

/// Execute a command in a jail and return the result.
async fn exec_in_jail(
    router: &axum::Router,
    jail_id: &str,
    cmd: Vec<&str>,
    timeout_secs: Option<u64>,
) -> (StatusCode, Value) {
    let req = ExecRequest {
        cmd: cmd.into_iter().map(String::from).collect(),
        env: None,
        cwd: None,
        timeout_secs,
    };

    let resp = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/jails/{}/exec", jail_id))
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&req).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    let status = resp.status();
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: Value = serde_json::from_slice(&body).unwrap_or_default();
    (status, json)
}

/// Get events for a jail.
async fn get_events(state: &Arc<AppState>, jail_id: &str) -> Vec<ObservationEvent> {
    state.storage.read_events(jail_id, None).unwrap_or_default()
}

// ── Python Tests ────────────────────────────────────────────────

#[tokio::test]
async fn test_python_echo() {
    let (router, state, _tmp) = test_app();
    let jail_id = create_and_start_jail(&state, "python-echo").await;

    let (status, json) = exec_in_jail(
        &router,
        &jail_id,
        vec!["python3", "-c", "print('hello from python')"],
        Some(10),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["data"]["exit_code"], 0);
    assert!(json["data"]["stdout"]
        .as_str()
        .unwrap()
        .contains("hello from python"));
}

#[tokio::test]
async fn test_python_filesystem_ops() {
    let (router, state, _tmp) = test_app();
    let jail_id = create_and_start_jail(&state, "python-fs").await;

    // Inline filesystem test
    let script = r#"
import tempfile, os, json
d = tempfile.mkdtemp()
f = os.path.join(d, 'test.txt')
with open(f, 'w') as fp:
    fp.write('data')
with open(f, 'r') as fp:
    content = fp.read()
os.remove(f)
os.rmdir(d)
print(json.dumps({'created': f, 'content': content, 'cleaned': True}))
"#;

    let (status, json) =
        exec_in_jail(&router, &jail_id, vec!["python3", "-c", script], Some(10)).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["data"]["exit_code"], 0);
    let stdout = json["data"]["stdout"].as_str().unwrap();
    let result: Value = serde_json::from_str(stdout.trim()).unwrap();
    assert_eq!(result["content"], "data");
    assert_eq!(result["cleaned"], true);
}

#[tokio::test]
async fn test_python_subprocess() {
    let (router, state, _tmp) = test_app();
    let jail_id = create_and_start_jail(&state, "python-subprocess").await;

    let script = r#"
import subprocess, os, json
p = subprocess.run(['echo', 'from subprocess'], capture_output=True, text=True)
print(json.dumps({'pid': os.getpid(), 'output': p.stdout.strip(), 'code': p.returncode}))
"#;

    let (status, json) =
        exec_in_jail(&router, &jail_id, vec!["python3", "-c", script], Some(10)).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["data"]["exit_code"], 0);
    let stdout = json["data"]["stdout"].as_str().unwrap();
    let result: Value = serde_json::from_str(stdout.trim()).unwrap();
    assert_eq!(result["output"], "from subprocess");
    assert_eq!(result["code"], 0);
}

// ── Node.js Tests ───────────────────────────────────────────────

#[tokio::test]
async fn test_node_echo() {
    let (router, state, _tmp) = test_app();
    let jail_id = create_and_start_jail(&state, "node-echo").await;

    let (status, json) = exec_in_jail(
        &router,
        &jail_id,
        vec!["node", "-e", "console.log('hello from node')"],
        Some(10),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["data"]["exit_code"], 0);
    assert!(json["data"]["stdout"]
        .as_str()
        .unwrap()
        .contains("hello from node"));
}

#[tokio::test]
async fn test_node_filesystem_ops() {
    let (router, state, _tmp) = test_app();
    let jail_id = create_and_start_jail(&state, "node-fs").await;

    let script = r#"
const fs = require('fs');
const os = require('os');
const path = require('path');
const d = fs.mkdtempSync(path.join(os.tmpdir(), 'jail-'));
const f = path.join(d, 'test.txt');
fs.writeFileSync(f, 'data');
const content = fs.readFileSync(f, 'utf-8');
fs.unlinkSync(f);
fs.rmdirSync(d);
console.log(JSON.stringify({created: f, content, cleaned: true}));
"#;

    let (status, json) =
        exec_in_jail(&router, &jail_id, vec!["node", "-e", script], Some(10)).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["data"]["exit_code"], 0);
    let stdout = json["data"]["stdout"].as_str().unwrap();
    let result: Value = serde_json::from_str(stdout.trim()).unwrap();
    assert_eq!(result["content"], "data");
    assert_eq!(result["cleaned"], true);
}

#[tokio::test]
async fn test_node_subprocess() {
    let (router, state, _tmp) = test_app();
    let jail_id = create_and_start_jail(&state, "node-subprocess").await;

    let script = r#"
const { execSync } = require('child_process');
const out = execSync('echo from subprocess', {encoding: 'utf-8'});
console.log(JSON.stringify({pid: process.pid, output: out.trim(), success: true}));
"#;

    let (status, json) =
        exec_in_jail(&router, &jail_id, vec!["node", "-e", script], Some(10)).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["data"]["exit_code"], 0);
    let stdout = json["data"]["stdout"].as_str().unwrap();
    let result: Value = serde_json::from_str(stdout.trim()).unwrap();
    assert_eq!(result["output"], "from subprocess");
    assert_eq!(result["success"], true);
}

// ── Event Capture Tests ─────────────────────────────────────────

#[tokio::test]
async fn test_exec_emits_process_events() {
    let (router, state, _tmp) = test_app();
    let jail_id = create_and_start_jail(&state, "process-events").await;

    // Execute a command
    let (status, _) = exec_in_jail(&router, &jail_id, vec!["echo", "test"], Some(5)).await;
    assert_eq!(status, StatusCode::OK);

    // Small delay for async event storage
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    // Check for process events
    let events = get_events(&state, &jail_id).await;
    let process_events: Vec<_> = events
        .iter()
        .filter(|e| matches!(e, ObservationEvent::Process(_)))
        .collect();

    // Should have at least exec and exit events
    assert!(
        process_events.len() >= 2,
        "Expected at least 2 process events, got {}",
        process_events.len()
    );
}

// ── Shell Script Tests ──────────────────────────────────────────

#[tokio::test]
async fn test_shell_pipeline() {
    let (router, state, _tmp) = test_app();
    let jail_id = create_and_start_jail(&state, "shell-pipeline").await;

    let (status, json) = exec_in_jail(
        &router,
        &jail_id,
        vec!["sh", "-c", "echo -e 'a\\nb\\nc' | wc -l"],
        Some(10),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["data"]["exit_code"], 0);
    let stdout = json["data"]["stdout"].as_str().unwrap().trim();
    assert_eq!(stdout, "3");
}

#[tokio::test]
async fn test_shell_env_vars() {
    let (router, state, _tmp) = test_app();
    let jail_id = create_and_start_jail(&state, "shell-env").await;

    // Set env var via request
    let req = ExecRequest {
        cmd: vec!["sh".into(), "-c".into(), "echo $MY_VAR".into()],
        env: Some(vec!["MY_VAR=test_value".into()]),
        cwd: None,
        timeout_secs: Some(5),
    };

    let resp = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/jails/{}/exec", jail_id))
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&req).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["data"]["exit_code"], 0);
    assert!(json["data"]["stdout"]
        .as_str()
        .unwrap()
        .contains("test_value"));
}

// ── Error Handling Tests ────────────────────────────────────────

#[tokio::test]
async fn test_command_not_found() {
    let (router, state, _tmp) = test_app();
    let jail_id = create_and_start_jail(&state, "cmd-not-found").await;

    let (status, _) = exec_in_jail(
        &router,
        &jail_id,
        vec!["nonexistent_command_xyz123"],
        Some(5),
    )
    .await;

    // Command not found should result in an error
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
}

#[tokio::test]
async fn test_command_timeout() {
    let (router, state, _tmp) = test_app();
    let jail_id = create_and_start_jail(&state, "timeout-test").await;

    let (status, _) = exec_in_jail(&router, &jail_id, vec!["sleep", "10"], Some(1)).await;

    // Should timeout
    assert_eq!(status, StatusCode::REQUEST_TIMEOUT);
}

#[tokio::test]
async fn test_exec_in_non_running_jail() {
    let (router, state, _tmp) = test_app();

    // Create jail but don't start it
    let jail = agent_jail::types::Jail::new(JailConfig {
        name: "not-started".into(),
        llm_intercept: agent_jail::llm::LlmInterceptorConfig {
            enabled: false,
            ..Default::default()
        },
        ..JailConfig::default()
    });
    let jail_id = jail.id.clone();
    state.save_jail(&jail).unwrap();
    state.jails.insert(jail_id.clone(), jail);

    let (status, _) = exec_in_jail(&router, &jail_id, vec!["echo", "test"], Some(5)).await;

    // Should fail because jail is not running
    assert_eq!(status, StatusCode::CONFLICT);
}

#[tokio::test]
async fn test_exec_in_nonexistent_jail() {
    let (router, _, _tmp) = test_app();

    let (status, _) = exec_in_jail(
        &router,
        "nonexistent_jail_id",
        vec!["echo", "test"],
        Some(5),
    )
    .await;

    assert_eq!(status, StatusCode::NOT_FOUND);
}

// ── Working Directory Tests ─────────────────────────────────────

#[tokio::test]
async fn test_exec_with_cwd() {
    let (router, state, _tmp) = test_app();
    let jail_id = create_and_start_jail(&state, "cwd-test").await;

    let req = ExecRequest {
        cmd: vec!["pwd".into()],
        env: None,
        cwd: Some("/tmp".into()),
        timeout_secs: Some(5),
    };

    let resp = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/jails/{}/exec", jail_id))
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&req).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["data"]["exit_code"], 0);
    // On macOS /tmp is a symlink to /private/tmp
    assert!(json["data"]["stdout"].as_str().unwrap().contains("tmp"));
}
