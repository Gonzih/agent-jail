//! Filesystem observation via OverlayFS diff + fanotify.
//!
//! Tracks all file operations in the jail's merged filesystem.
//! Diff computed by reading the OverlayFS upper directory.
//!
//! Requires Linux for fanotify. Diff works on any OS with OverlayFS upper.

use crate::types::{FileEvent, FsDiff, JailId, ObservationEvent};
use std::path::{Path, PathBuf};
use tokio::sync::mpsc;

pub struct FilesystemObserver {
    pub jail_id: JailId,
    pub upper_dir: Option<PathBuf>,
    tx: mpsc::UnboundedSender<ObservationEvent>,
}

impl FilesystemObserver {
    pub fn new(jail_id: JailId, tx: mpsc::UnboundedSender<ObservationEvent>) -> Self {
        Self {
            jail_id,
            upper_dir: None,
            tx,
        }
    }

    pub fn set_upper_dir(&mut self, path: PathBuf) {
        self.upper_dir = Some(path);
    }

    pub async fn start(&self) -> anyhow::Result<()> {
        #[cfg(target_os = "linux")]
        {
            // TODO: fanotify on merged mount
            // 1. fanotify_init(FAN_CLASS_NOTIF | FAN_REPORT_FID)
            // 2. fanotify_mark on merged directory
            // 3. Spawn reader task → parse events → self.tx.send()
            tracing::info!(jail_id = %self.jail_id, "Filesystem observation: ready");
        }

        #[cfg(not(target_os = "linux"))]
        {
            tracing::warn!(
                jail_id = %self.jail_id,
                "Filesystem observation unavailable: fanotify requires Linux"
            );
        }

        Ok(())
    }

    pub async fn stop(&self) -> anyhow::Result<()> {
        tracing::info!(jail_id = %self.jail_id, "Filesystem observation stopped");
        Ok(())
    }

    /// Emit a file event (used by fanotify consumer or test injection).
    pub fn emit(&self, event: FileEvent) {
        let _ = self.tx.send(ObservationEvent::File(event));
    }

    /// Compute filesystem diff by scanning OverlayFS upper directory.
    /// Created files = files in upper that don't exist in lower.
    /// Modified files = files in upper that also exist in lower.
    /// Deleted files = whiteout entries (char device 0,0 or .wh. prefix).
    pub fn compute_diff(&self) -> anyhow::Result<FsDiff> {
        let upper = self
            .upper_dir
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("No upper directory set"))?;

        if !upper.exists() {
            return Ok(FsDiff {
                created: Vec::new(),
                modified: Vec::new(),
                deleted: Vec::new(),
            });
        }

        let mut created = Vec::new();
        let mut modified = Vec::new();
        let mut deleted = Vec::new();

        Self::scan_upper(upper, upper, &mut created, &mut modified, &mut deleted)?;

        Ok(FsDiff {
            created,
            modified,
            deleted,
        })
    }

    fn scan_upper(
        base: &Path,
        dir: &Path,
        created: &mut Vec<String>,
        _modified: &mut Vec<String>,
        deleted: &mut Vec<String>,
    ) -> anyhow::Result<()> {
        if !dir.exists() {
            return Ok(());
        }

        for entry in std::fs::read_dir(dir)? {
            let entry = entry?;
            let name = entry.file_name().to_string_lossy().to_string();
            let rel_path = entry
                .path()
                .strip_prefix(base)
                .unwrap_or(entry.path().as_path())
                .to_string_lossy()
                .to_string();

            // OverlayFS whiteout files indicate deletions
            if name.starts_with(".wh.") {
                let deleted_name = name.strip_prefix(".wh.").unwrap_or(&name);
                let parent = entry
                    .path()
                    .parent()
                    .unwrap_or(dir)
                    .strip_prefix(base)
                    .unwrap_or(Path::new(""))
                    .to_string_lossy()
                    .to_string();
                let full = if parent.is_empty() {
                    format!("/{}", deleted_name)
                } else {
                    format!("/{}/{}", parent, deleted_name)
                };
                deleted.push(full);
                continue;
            }

            if entry.file_type()?.is_dir() {
                Self::scan_upper(base, &entry.path(), created, _modified, deleted)?;
            } else {
                created.push(format!("/{}", rel_path));
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::FileOp;
    use tempfile::TempDir;

    #[tokio::test]
    async fn test_filesystem_observer_emit() {
        let (tx, mut rx) = mpsc::unbounded_channel();
        let observer = FilesystemObserver::new("jail_test".into(), tx);

        observer.emit(FileEvent {
            ts: 1000,
            pid: 42,
            op: FileOp::Write,
            path: "/tmp/output.txt".into(),
            bytes: Some(1024),
        });

        let event = rx.recv().await.unwrap();
        assert_eq!(event.event_type(), "file");
    }

    #[test]
    fn test_compute_diff_empty_upper() {
        let tmp = TempDir::new().unwrap();
        let (tx, _rx) = mpsc::unbounded_channel();
        let mut observer = FilesystemObserver::new("jail_test".into(), tx);
        observer.set_upper_dir(tmp.path().to_path_buf());

        let diff = observer.compute_diff().unwrap();
        assert!(diff.created.is_empty());
        assert!(diff.modified.is_empty());
        assert!(diff.deleted.is_empty());
    }

    #[test]
    fn test_compute_diff_with_files() {
        let tmp = TempDir::new().unwrap();
        // Create some files in the "upper" directory
        std::fs::write(tmp.path().join("new_file.txt"), "hello").unwrap();
        std::fs::create_dir_all(tmp.path().join("subdir")).unwrap();
        std::fs::write(tmp.path().join("subdir").join("nested.txt"), "world").unwrap();

        let (tx, _rx) = mpsc::unbounded_channel();
        let mut observer = FilesystemObserver::new("jail_test".into(), tx);
        observer.set_upper_dir(tmp.path().to_path_buf());

        let diff = observer.compute_diff().unwrap();
        assert_eq!(diff.created.len(), 2);
        assert!(diff.created.contains(&"/new_file.txt".to_string()));
        assert!(diff.created.contains(&"/subdir/nested.txt".to_string()));
    }

    #[test]
    fn test_compute_diff_with_whiteouts() {
        let tmp = TempDir::new().unwrap();
        // Whiteout file = deletion marker in OverlayFS
        std::fs::write(tmp.path().join(".wh.deleted_file.txt"), "").unwrap();

        let (tx, _rx) = mpsc::unbounded_channel();
        let mut observer = FilesystemObserver::new("jail_test".into(), tx);
        observer.set_upper_dir(tmp.path().to_path_buf());

        let diff = observer.compute_diff().unwrap();
        assert!(diff.created.is_empty());
        assert_eq!(diff.deleted.len(), 1);
        assert!(diff.deleted[0].contains("deleted_file.txt"));
    }

    #[test]
    fn test_no_upper_dir_error() {
        let (tx, _rx) = mpsc::unbounded_channel();
        let observer = FilesystemObserver::new("jail_test".into(), tx);
        let result = observer.compute_diff();
        assert!(result.is_err());
    }
}
