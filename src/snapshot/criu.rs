//! CRIU checkpoint/restore for Phase 1 snapshots.
//!
//! Snapshot: freeze cgroup → `criu dump` → copy OverlayFS upper
//! Restore: `criu restore` in fresh namespaces → remount OverlayFS
//!
//! Requires Linux with CRIU installed and CAP_SYS_ADMIN.

use crate::error::ApiError;
use std::path::Path;

pub struct CriuManager {
    criu_binary: String,
}

impl CriuManager {
    pub fn new() -> Self {
        Self {
            criu_binary: std::env::var("CRIU_BINARY").unwrap_or_else(|_| "criu".into()),
        }
    }

    /// Check if CRIU is available on this system.
    pub fn is_available(&self) -> bool {
        std::process::Command::new(&self.criu_binary)
            .arg("check")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }

    /// Checkpoint (dump) a process tree.
    /// Returns the dump directory path.
    pub async fn dump(&self, pid: u32, dump_dir: &Path) -> Result<(), ApiError> {
        std::fs::create_dir_all(dump_dir)
            .map_err(|e| ApiError::Internal(format!("Failed to create dump dir: {}", e)))?;

        let output = tokio::process::Command::new(&self.criu_binary)
            .args([
                "dump",
                "--tree",
                &pid.to_string(),
                "--images-dir",
                &dump_dir.to_string_lossy(),
                "--leave-stopped",
                "--shell-job",
            ])
            .output()
            .await
            .map_err(|e| ApiError::Internal(format!("CRIU dump failed: {}", e)))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(ApiError::Internal(format!("CRIU dump failed: {}", stderr)));
        }

        Ok(())
    }

    /// Restore a process tree from a CRIU dump.
    /// Returns the PID of the restored root process.
    pub async fn restore(&self, dump_dir: &Path, root_dir: Option<&Path>) -> Result<u32, ApiError> {
        let mut cmd = tokio::process::Command::new(&self.criu_binary);
        cmd.args([
            "restore",
            "--images-dir",
            &dump_dir.to_string_lossy(),
            "--shell-job",
            "--restore-detached",
        ]);

        if let Some(root) = root_dir {
            cmd.args(["--root", &root.to_string_lossy()]);
        }

        let output = cmd
            .output()
            .await
            .map_err(|e| ApiError::Internal(format!("CRIU restore failed: {}", e)))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(ApiError::Internal(format!(
                "CRIU restore failed: {}",
                stderr
            )));
        }

        // CRIU prints the restored PID
        let stdout = String::from_utf8_lossy(&output.stdout);
        let pid: u32 = stdout.trim().parse().unwrap_or(0);

        Ok(pid)
    }

    /// Copy OverlayFS upper directory for snapshot.
    pub async fn copy_upper(src: &Path, dst: &Path) -> Result<(), ApiError> {
        std::fs::create_dir_all(dst)
            .map_err(|e| ApiError::Internal(format!("Failed to create snapshot upper: {}", e)))?;

        // Try reflink copy first (btrfs/xfs), fall back to regular copy
        let output = tokio::process::Command::new("cp")
            .args([
                "--reflink=auto",
                "-a",
                &src.to_string_lossy(),
                &dst.to_string_lossy(),
            ])
            .output()
            .await
            .map_err(|e| ApiError::Internal(format!("Upper copy failed: {}", e)))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(ApiError::Internal(format!("Upper copy failed: {}", stderr)));
        }

        Ok(())
    }
}

impl Default for CriuManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_criu_manager_creation() {
        let mgr = CriuManager::new();
        assert_eq!(mgr.criu_binary, "criu");
    }

    #[test]
    fn test_criu_availability_check() {
        let mgr = CriuManager::new();
        // On macOS or systems without CRIU, this returns false
        let available = mgr.is_available();
        // We just verify it doesn't panic
        let _ = available;
    }
}
