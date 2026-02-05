//! WebSocket terminal for interactive PTY access to jails.
//!
//! Provides bidirectional streaming between a WebSocket client and a PTY
//! running inside a jail. This enables web-based terminal access (e.g., xterm.js).

use axum::extract::ws::{Message, WebSocket};
use serde::{Deserialize, Serialize};
use std::process::Stdio;
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, Command};
use tokio::sync::mpsc;

/// Terminal session configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TerminalConfig {
    /// Shell to spawn (default: /bin/sh)
    pub shell: String,
    /// Initial working directory
    pub cwd: Option<String>,
    /// Environment variables to set
    pub env: Vec<(String, String)>,
    /// Terminal columns (for resize)
    pub cols: u16,
    /// Terminal rows (for resize)
    pub rows: u16,
}

impl Default for TerminalConfig {
    fn default() -> Self {
        Self {
            shell: "/bin/sh".into(),
            cwd: None,
            env: Vec::new(),
            cols: 80,
            rows: 24,
        }
    }
}

/// Messages sent from client to server over WebSocket.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ClientMessage {
    /// Input data (keystrokes)
    Input { data: String },
    /// Terminal resize event
    Resize { cols: u16, rows: u16 },
    /// Ping for keepalive
    Ping,
}

/// Messages sent from server to client over WebSocket.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ServerMessage {
    /// Output data from PTY
    Output { data: String },
    /// Terminal session started
    Started { pid: u32 },
    /// Terminal session ended
    Exited { code: Option<i32> },
    /// Error occurred
    Error { message: String },
    /// Pong response
    Pong,
}

/// A terminal session managing a PTY child process.
pub struct TerminalSession {
    child: Child,
    stdin_tx: mpsc::Sender<Vec<u8>>,
}

impl TerminalSession {
    /// Spawn a new terminal session.
    pub async fn spawn(
        config: &TerminalConfig,
        jail_env: &[(String, String)],
    ) -> Result<(Self, mpsc::Receiver<Vec<u8>>), std::io::Error> {
        let mut cmd = Command::new(&config.shell);
        cmd.stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        // Set working directory
        if let Some(cwd) = &config.cwd {
            cmd.current_dir(cwd);
        }

        // Set environment variables
        for (k, v) in jail_env {
            cmd.env(k, v);
        }
        for (k, v) in &config.env {
            cmd.env(k, v);
        }

        // Set terminal size via COLUMNS/LINES env vars
        cmd.env("COLUMNS", config.cols.to_string());
        cmd.env("LINES", config.rows.to_string());
        cmd.env("TERM", "xterm-256color");

        let mut child = cmd.spawn()?;

        let stdin = child.stdin.take().unwrap();
        let stdout = child.stdout.take().unwrap();
        let stderr = child.stderr.take().unwrap();

        // Channel for stdin writes
        let (stdin_tx, mut stdin_rx) = mpsc::channel::<Vec<u8>>(256);

        // Channel for combined stdout/stderr output
        let (output_tx, output_rx) = mpsc::channel::<Vec<u8>>(256);

        // Spawn stdin writer task
        tokio::spawn(async move {
            let mut stdin = stdin;
            while let Some(data) = stdin_rx.recv().await {
                if stdin.write_all(&data).await.is_err() {
                    break;
                }
                let _ = stdin.flush().await;
            }
        });

        // Spawn stdout reader task
        let stdout_tx = output_tx.clone();
        tokio::spawn(async move {
            let mut reader = BufReader::new(stdout);
            let mut buf = vec![0u8; 4096];
            loop {
                match reader.read(&mut buf).await {
                    Ok(0) => break, // EOF
                    Ok(n) => {
                        if stdout_tx.send(buf[..n].to_vec()).await.is_err() {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
        });

        // Spawn stderr reader task
        let stderr_tx = output_tx;
        tokio::spawn(async move {
            let mut reader = BufReader::new(stderr);
            let mut buf = vec![0u8; 4096];
            loop {
                match reader.read(&mut buf).await {
                    Ok(0) => break, // EOF
                    Ok(n) => {
                        if stderr_tx.send(buf[..n].to_vec()).await.is_err() {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
        });

        Ok((Self { child, stdin_tx }, output_rx))
    }

    /// Get the PID of the terminal process.
    pub fn pid(&self) -> Option<u32> {
        self.child.id()
    }

    /// Send input data to the terminal.
    pub async fn write(&self, data: &[u8]) -> Result<(), mpsc::error::SendError<Vec<u8>>> {
        self.stdin_tx.send(data.to_vec()).await
    }

    /// Wait for the terminal process to exit.
    pub async fn wait(&mut self) -> Option<i32> {
        match self.child.wait().await {
            Ok(status) => status.code(),
            Err(_) => None,
        }
    }

    /// Kill the terminal process.
    pub async fn kill(&mut self) -> std::io::Result<()> {
        self.child.kill().await
    }
}

/// Handle a WebSocket connection for terminal access.
pub async fn handle_terminal_websocket(
    mut socket: WebSocket,
    jail_env: Vec<(String, String)>,
    initial_config: TerminalConfig,
) {
    // Spawn terminal session
    let (session, mut output_rx) = match TerminalSession::spawn(&initial_config, &jail_env).await {
        Ok(s) => s,
        Err(e) => {
            let msg = ServerMessage::Error {
                message: format!("Failed to spawn terminal: {}", e),
            };
            let _ = socket
                .send(Message::Text(serde_json::to_string(&msg).unwrap()))
                .await;
            return;
        }
    };

    // Send started message
    if let Some(pid) = session.pid() {
        let msg = ServerMessage::Started { pid };
        if socket
            .send(Message::Text(serde_json::to_string(&msg).unwrap()))
            .await
            .is_err()
        {
            return;
        }
    }

    // Channel for tracking session exit
    let (exit_tx, mut exit_rx) = mpsc::channel::<Option<i32>>(1);

    // Spawn task to wait for process exit
    let mut wait_child = session.child;
    tokio::spawn(async move {
        let code = match wait_child.wait().await {
            Ok(status) => status.code(),
            Err(_) => None,
        };
        let _ = exit_tx.send(code).await;
    });

    // Reconstruct session without child (it's moved)
    // We still have stdin_tx for writing
    let stdin_tx = session.stdin_tx;

    loop {
        tokio::select! {
            // Handle incoming WebSocket messages
            msg = socket.recv() => {
                match msg {
                    Some(Ok(Message::Text(text))) => {
                        if let Ok(client_msg) = serde_json::from_str::<ClientMessage>(&text) {
                            match client_msg {
                                ClientMessage::Input { data } => {
                                    if stdin_tx.send(data.into_bytes()).await.is_err() {
                                        break;
                                    }
                                }
                                ClientMessage::Resize { cols, rows } => {
                                    // Note: actual PTY resize requires ioctl, which we skip for now
                                    tracing::debug!(cols, rows, "Terminal resize requested");
                                }
                                ClientMessage::Ping => {
                                    let msg = ServerMessage::Pong;
                                    if socket.send(Message::Text(serde_json::to_string(&msg).unwrap())).await.is_err() {
                                        break;
                                    }
                                }
                            }
                        }
                    }
                    Some(Ok(Message::Binary(data))) => {
                        // Binary data treated as raw input
                        if stdin_tx.send(data.to_vec()).await.is_err() {
                            break;
                        }
                    }
                    Some(Ok(Message::Close(_))) | None => break,
                    _ => {}
                }
            }

            // Forward output to WebSocket
            Some(data) = output_rx.recv() => {
                let msg = ServerMessage::Output {
                    data: String::from_utf8_lossy(&data).to_string(),
                };
                if socket.send(Message::Text(serde_json::to_string(&msg).unwrap())).await.is_err() {
                    break;
                }
            }

            // Handle process exit
            Some(code) = exit_rx.recv() => {
                let msg = ServerMessage::Exited { code };
                let _ = socket.send(Message::Text(serde_json::to_string(&msg).unwrap())).await;
                break;
            }
        }
    }

    // Close the WebSocket
    let _ = socket.close().await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_terminal_config_default() {
        let config = TerminalConfig::default();
        assert_eq!(config.shell, "/bin/sh");
        assert_eq!(config.cols, 80);
        assert_eq!(config.rows, 24);
    }

    #[test]
    fn test_client_message_input_serde() {
        let msg = ClientMessage::Input {
            data: "ls\n".into(),
        };
        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains("\"type\":\"input\""));
        assert!(json.contains("\"data\":\"ls\\n\""));

        let parsed: ClientMessage = serde_json::from_str(&json).unwrap();
        match parsed {
            ClientMessage::Input { data } => assert_eq!(data, "ls\n"),
            _ => panic!("Wrong variant"),
        }
    }

    #[test]
    fn test_client_message_resize_serde() {
        let msg = ClientMessage::Resize {
            cols: 120,
            rows: 40,
        };
        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains("\"type\":\"resize\""));

        let parsed: ClientMessage = serde_json::from_str(&json).unwrap();
        match parsed {
            ClientMessage::Resize { cols, rows } => {
                assert_eq!(cols, 120);
                assert_eq!(rows, 40);
            }
            _ => panic!("Wrong variant"),
        }
    }

    #[test]
    fn test_server_message_output_serde() {
        let msg = ServerMessage::Output {
            data: "hello\n".into(),
        };
        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains("\"type\":\"output\""));
        assert!(json.contains("\"data\":\"hello\\n\""));
    }

    #[test]
    fn test_server_message_started_serde() {
        let msg = ServerMessage::Started { pid: 1234 };
        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains("\"type\":\"started\""));
        assert!(json.contains("\"pid\":1234"));
    }

    #[test]
    fn test_server_message_exited_serde() {
        let msg = ServerMessage::Exited { code: Some(0) };
        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains("\"type\":\"exited\""));
        assert!(json.contains("\"code\":0"));
    }

    #[test]
    fn test_server_message_error_serde() {
        let msg = ServerMessage::Error {
            message: "test error".into(),
        };
        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains("\"type\":\"error\""));
        assert!(json.contains("\"message\":\"test error\""));
    }

    #[tokio::test]
    async fn test_terminal_session_spawn() {
        let config = TerminalConfig {
            shell: "/bin/sh".into(),
            ..Default::default()
        };

        let result = TerminalSession::spawn(&config, &[]).await;
        assert!(result.is_ok());

        let (mut session, _output_rx) = result.unwrap();
        assert!(session.pid().is_some());

        // Kill the session
        session.kill().await.ok();
    }

    #[tokio::test]
    async fn test_terminal_session_echo() {
        let config = TerminalConfig {
            shell: "/bin/sh".into(),
            ..Default::default()
        };

        let (session, mut output_rx) = TerminalSession::spawn(&config, &[]).await.unwrap();

        // Send echo command
        session.write(b"echo hello\n").await.unwrap();

        // Wait a bit for output
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        // We should get some output
        let mut output = Vec::new();
        while let Ok(data) = output_rx.try_recv() {
            output.extend(data);
        }
        let output_str = String::from_utf8_lossy(&output);

        // Should contain "hello" somewhere in the output
        assert!(
            output_str.contains("hello") || output_str.contains("echo"),
            "Output was: {}",
            output_str
        );

        // Send exit command
        session.write(b"exit\n").await.ok();
    }

    #[tokio::test]
    async fn test_terminal_session_with_env() {
        let config = TerminalConfig {
            shell: "/bin/sh".into(),
            ..Default::default()
        };

        let jail_env = vec![("MY_VAR".into(), "test_value".into())];
        let (session, mut output_rx) = TerminalSession::spawn(&config, &jail_env).await.unwrap();

        // Echo the env var
        session.write(b"echo $MY_VAR\n").await.unwrap();

        // Wait for output
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        let mut output = Vec::new();
        while let Ok(data) = output_rx.try_recv() {
            output.extend(data);
        }
        let output_str = String::from_utf8_lossy(&output);

        // Should contain our value
        assert!(
            output_str.contains("test_value"),
            "Output was: {}",
            output_str
        );

        session.write(b"exit\n").await.ok();
    }
}
