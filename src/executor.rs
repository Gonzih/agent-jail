//! Command executor for running processes inside jails.
//!
//! This module provides real command execution using tokio::process::Command.
//! For now it executes commands directly on the host (Phase 1 without full isolation).
//! Phase 2 will use namespaces to isolate the process.

use crate::error::ApiError;
use crate::types::{ExecRequest, ExecResult, ObservationEvent, ProcessEvent, ProcessOp};
use std::time::Instant;
use tokio::process::Command;
use tokio::sync::mpsc;

/// Execute a command and return the result.
///
/// # Arguments
/// * `req` - The execution request with command, env, cwd, timeout
/// * `jail_env` - Environment variables injected by the jail (e.g., LLM API keys) as (key, value) pairs
/// * `event_tx` - Optional channel to send process events to observers
/// * `jail_id` - The jail ID for event tracking
pub async fn execute(
    req: &ExecRequest,
    jail_env: &[(String, String)],
    event_tx: Option<&mpsc::UnboundedSender<ObservationEvent>>,
    _jail_id: &str,
) -> Result<ExecResult, ApiError> {
    if req.cmd.is_empty() {
        return Err(ApiError::BadRequest("Command cannot be empty".into()));
    }

    let program = &req.cmd[0];
    let args = if req.cmd.len() > 1 {
        &req.cmd[1..]
    } else {
        &[][..]
    };

    let mut cmd = Command::new(program);
    cmd.args(args);

    // Set working directory if specified
    if let Some(cwd) = &req.cwd {
        cmd.current_dir(cwd);
    }

    // Merge jail environment with request environment
    // Request env takes precedence
    for (k, v) in jail_env.iter() {
        cmd.env(k, v);
    }
    if let Some(env_vars) = &req.env {
        for var in env_vars {
            if let Some((k, v)) = var.split_once('=') {
                cmd.env(k, v);
            }
        }
    }

    // Capture stdout/stderr
    cmd.stdout(std::process::Stdio::piped());
    cmd.stderr(std::process::Stdio::piped());

    let start = Instant::now();
    let ts = chrono::Utc::now().timestamp_millis() as u64;

    // Emit process exec event
    if let Some(tx) = event_tx {
        let argv: Vec<String> = req.cmd.clone();
        let _ = tx.send(ObservationEvent::Process(ProcessEvent {
            ts,
            op: ProcessOp::Exec,
            pid: std::process::id(),
            ppid: 1, // Parent PID (init for jail context)
            uid: 0,  // UID (root for jail context)
            exe: program.clone(),
            argv,
            cwd: req.cwd.clone(),
            exit_code: None,
        }));
    }

    // Execute with timeout
    let timeout = std::time::Duration::from_secs(req.timeout_secs.unwrap_or(30));
    let output = match tokio::time::timeout(timeout, cmd.output()).await {
        Ok(Ok(output)) => output,
        Ok(Err(e)) => {
            return Err(ApiError::InternalError(format!(
                "Failed to execute command: {}",
                e
            )));
        }
        Err(_) => {
            return Err(ApiError::Timeout(format!(
                "Command timed out after {} seconds",
                timeout.as_secs()
            )));
        }
    };

    let duration_ms = start.elapsed().as_millis() as u64;
    let exit_code = output.status.code().unwrap_or(-1);

    // Emit process exit event
    if let Some(tx) = event_tx {
        let exit_ts = chrono::Utc::now().timestamp_millis() as u64;
        let _ = tx.send(ObservationEvent::Process(ProcessEvent {
            ts: exit_ts,
            op: ProcessOp::Exit,
            pid: std::process::id(),
            ppid: 1,
            uid: 0,
            exe: program.clone(),
            argv: Vec::new(),
            cwd: None,
            exit_code: Some(exit_code),
        }));
    }

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();

    Ok(ExecResult {
        exit_code,
        stdout,
        stderr,
        duration_ms,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_request(cmd: Vec<&str>) -> ExecRequest {
        ExecRequest {
            cmd: cmd.into_iter().map(String::from).collect(),
            env: None,
            cwd: None,
            timeout_secs: Some(5),
        }
    }

    #[tokio::test]
    async fn test_execute_echo() {
        let req = make_request(vec!["echo", "hello world"]);
        let result = execute(&req, &[], None, "test_jail").await;
        assert!(result.is_ok());
        let r = result.unwrap();
        assert_eq!(r.exit_code, 0);
        assert!(r.stdout.contains("hello world"));
    }

    #[tokio::test]
    async fn test_execute_with_env() {
        let req = ExecRequest {
            cmd: vec!["sh".into(), "-c".into(), "echo $TEST_VAR".into()],
            env: Some(vec!["TEST_VAR=hello_from_env".into()]),
            cwd: None,
            timeout_secs: Some(5),
        };
        let result = execute(&req, &[], None, "test_jail").await;
        assert!(result.is_ok());
        let r = result.unwrap();
        assert!(r.stdout.contains("hello_from_env"));
    }

    #[tokio::test]
    async fn test_execute_jail_env_override() {
        let jail_env = vec![("JAIL_VAR".into(), "jail_value".into())];

        let req = ExecRequest {
            cmd: vec!["sh".into(), "-c".into(), "echo $JAIL_VAR".into()],
            env: None,
            cwd: None,
            timeout_secs: Some(5),
        };
        let result = execute(&req, &jail_env, None, "test_jail").await;
        assert!(result.is_ok());
        let r = result.unwrap();
        assert!(r.stdout.contains("jail_value"));
    }

    #[tokio::test]
    async fn test_execute_nonexistent_command() {
        let req = make_request(vec!["nonexistent_command_xyz123"]);
        let result = execute(&req, &[], None, "test_jail").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_execute_exit_code() {
        let req = ExecRequest {
            cmd: vec!["sh".into(), "-c".into(), "exit 42".into()],
            env: None,
            cwd: None,
            timeout_secs: Some(5),
        };
        let result = execute(&req, &[], None, "test_jail").await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap().exit_code, 42);
    }

    #[tokio::test]
    async fn test_execute_stderr() {
        let req = ExecRequest {
            cmd: vec!["sh".into(), "-c".into(), "echo error >&2".into()],
            env: None,
            cwd: None,
            timeout_secs: Some(5),
        };
        let result = execute(&req, &[], None, "test_jail").await;
        assert!(result.is_ok());
        let r = result.unwrap();
        assert!(r.stderr.contains("error"));
    }

    #[tokio::test]
    async fn test_execute_timeout() {
        let req = ExecRequest {
            cmd: vec!["sleep".into(), "10".into()],
            env: None,
            cwd: None,
            timeout_secs: Some(1),
        };
        let result = execute(&req, &[], None, "test_jail").await;
        assert!(result.is_err());
        match result.unwrap_err() {
            ApiError::Timeout(_) => {}
            other => panic!("Expected Timeout, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_execute_with_cwd() {
        let req = ExecRequest {
            cmd: vec!["pwd".into()],
            env: None,
            cwd: Some("/tmp".into()),
            timeout_secs: Some(5),
        };
        let result = execute(&req, &[], None, "test_jail").await;
        assert!(result.is_ok());
        let r = result.unwrap();
        // On macOS /tmp is a symlink to /private/tmp
        assert!(r.stdout.contains("tmp"));
    }

    #[tokio::test]
    async fn test_execute_empty_command() {
        let req = ExecRequest {
            cmd: vec![],
            env: None,
            cwd: None,
            timeout_secs: Some(5),
        };
        let result = execute(&req, &[], None, "test_jail").await;
        assert!(result.is_err());
        match result.unwrap_err() {
            ApiError::BadRequest(_) => {}
            other => panic!("Expected BadRequest, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_execute_emits_process_events() {
        let (tx, mut rx) = mpsc::unbounded_channel();

        let req = make_request(vec!["echo", "test"]);
        let result = execute(&req, &[], Some(&tx), "test_jail").await;
        assert!(result.is_ok());

        // Should have exec event
        let event1 = rx.try_recv().unwrap();
        match event1 {
            ObservationEvent::Process(p) => {
                assert_eq!(p.op, ProcessOp::Exec);
                assert!(p.exe.contains("echo"));
            }
            _ => panic!("Expected Process event"),
        }

        // Should have exit event
        let event2 = rx.try_recv().unwrap();
        match event2 {
            ObservationEvent::Process(p) => {
                assert_eq!(p.op, ProcessOp::Exit);
                assert_eq!(p.exit_code, Some(0));
            }
            _ => panic!("Expected Process event"),
        }
    }

    #[tokio::test]
    async fn test_execute_python_script() {
        let req = ExecRequest {
            cmd: vec![
                "python3".into(),
                "-c".into(),
                "print('hello from python')".into(),
            ],
            env: None,
            cwd: None,
            timeout_secs: Some(10),
        };
        let result = execute(&req, &[], None, "test_jail").await;
        // This test is skipped if python3 is not available
        if result.is_ok() {
            let r = result.unwrap();
            assert_eq!(r.exit_code, 0);
            assert!(r.stdout.contains("hello from python"));
        }
    }

    #[tokio::test]
    async fn test_execute_node_script() {
        let req = ExecRequest {
            cmd: vec![
                "node".into(),
                "-e".into(),
                "console.log('hello from node')".into(),
            ],
            env: None,
            cwd: None,
            timeout_secs: Some(10),
        };
        let result = execute(&req, &[], None, "test_jail").await;
        // This test is skipped if node is not available
        if result.is_ok() {
            let r = result.unwrap();
            assert_eq!(r.exit_code, 0);
            assert!(r.stdout.contains("hello from node"));
        }
    }
}
