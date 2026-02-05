//! Branch from snapshot: fork execution at any point N times.
//!
//! Each branch gets:
//! - Own PID/mount/net namespaces
//! - Own copy of OverlayFS upper
//! - Own observation streams
//! - Independent execution from branch point

use crate::types::{Jail, JailStatus, Snapshot};
use std::path::Path;

/// Create a branch from a snapshot.
/// This produces a new Jail record that can be started independently.
pub fn branch_from_snapshot(snapshot: &Snapshot) -> Jail {
    let mut jail = Jail::new(snapshot.config.clone());
    jail.parent_snapshot = Some(snapshot.id.clone());
    jail.status = JailStatus::Creating;
    jail
}

/// Diff two OverlayFS upper directories.
/// Returns (only_in_a, only_in_b, in_both_but_different).
pub fn diff_uppers(upper_a: &Path, upper_b: &Path) -> anyhow::Result<UpperDiff> {
    let mut only_a = Vec::new();
    let mut only_b = Vec::new();
    let mut different = Vec::new();

    let files_a = collect_files(upper_a)?;
    let files_b = collect_files(upper_b)?;

    let set_a: std::collections::HashSet<_> = files_a.iter().map(|f| f.as_str()).collect();
    let set_b: std::collections::HashSet<_> = files_b.iter().map(|f| f.as_str()).collect();

    for f in &files_a {
        if !set_b.contains(f.as_str()) {
            only_a.push(f.clone());
        } else {
            // Both have it — check if contents differ
            let path_a = upper_a.join(f);
            let path_b = upper_b.join(f);
            if path_a.is_file() && path_b.is_file() {
                let content_a = std::fs::read(&path_a).unwrap_or_default();
                let content_b = std::fs::read(&path_b).unwrap_or_default();
                if content_a != content_b {
                    different.push(f.clone());
                }
            }
        }
    }

    for f in &files_b {
        if !set_a.contains(f.as_str()) {
            only_b.push(f.clone());
        }
    }

    Ok(UpperDiff {
        only_a,
        only_b,
        different,
    })
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct UpperDiff {
    pub only_a: Vec<String>,
    pub only_b: Vec<String>,
    pub different: Vec<String>,
}

fn collect_files(dir: &Path) -> anyhow::Result<Vec<String>> {
    let mut files = Vec::new();
    if !dir.exists() {
        return Ok(files);
    }
    collect_files_recursive(dir, dir, &mut files)?;
    Ok(files)
}

fn collect_files_recursive(base: &Path, dir: &Path, files: &mut Vec<String>) -> anyhow::Result<()> {
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let rel = entry
            .path()
            .strip_prefix(base)
            .unwrap_or(entry.path().as_path())
            .to_string_lossy()
            .to_string();

        if entry.file_type()?.is_dir() {
            collect_files_recursive(base, &entry.path(), files)?;
        } else {
            files.push(rel);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::JailConfig;
    use chrono::Utc;
    use tempfile::TempDir;

    #[test]
    fn test_branch_from_snapshot() {
        let snapshot = Snapshot {
            id: "snap_test123456".into(),
            jail_id: "jail_parent12345".into(),
            parent: None,
            created_at: Utc::now(),
            status: JailStatus::Snapshotted,
            config: JailConfig {
                name: "original".into(),
                ..JailConfig::default()
            },
            stats_at_snapshot: Default::default(),
            fs_upper_path: String::new(),
            criu_dump_path: String::new(),
        };

        let branch = branch_from_snapshot(&snapshot);
        assert!(branch.id.starts_with("jail_"));
        assert_ne!(branch.id, "jail_parent12345"); // New ID
        assert_eq!(branch.parent_snapshot, Some("snap_test123456".into()));
        assert_eq!(branch.config.name, "original");
        assert_eq!(branch.status, JailStatus::Creating);
    }

    #[test]
    fn test_diff_uppers_identical() {
        let dir_a = TempDir::new().unwrap();
        let dir_b = TempDir::new().unwrap();

        std::fs::write(dir_a.path().join("file.txt"), "hello").unwrap();
        std::fs::write(dir_b.path().join("file.txt"), "hello").unwrap();

        let diff = diff_uppers(dir_a.path(), dir_b.path()).unwrap();
        assert!(diff.only_a.is_empty());
        assert!(diff.only_b.is_empty());
        assert!(diff.different.is_empty());
    }

    #[test]
    fn test_diff_uppers_different_content() {
        let dir_a = TempDir::new().unwrap();
        let dir_b = TempDir::new().unwrap();

        std::fs::write(dir_a.path().join("file.txt"), "hello").unwrap();
        std::fs::write(dir_b.path().join("file.txt"), "world").unwrap();

        let diff = diff_uppers(dir_a.path(), dir_b.path()).unwrap();
        assert!(diff.only_a.is_empty());
        assert!(diff.only_b.is_empty());
        assert_eq!(diff.different.len(), 1);
        assert_eq!(diff.different[0], "file.txt");
    }

    #[test]
    fn test_diff_uppers_unique_files() {
        let dir_a = TempDir::new().unwrap();
        let dir_b = TempDir::new().unwrap();

        std::fs::write(dir_a.path().join("a_only.txt"), "a").unwrap();
        std::fs::write(dir_b.path().join("b_only.txt"), "b").unwrap();

        let diff = diff_uppers(dir_a.path(), dir_b.path()).unwrap();
        assert_eq!(diff.only_a.len(), 1);
        assert_eq!(diff.only_b.len(), 1);
        assert!(diff.different.is_empty());
    }

    #[test]
    fn test_diff_uppers_empty_dirs() {
        let dir_a = TempDir::new().unwrap();
        let dir_b = TempDir::new().unwrap();

        let diff = diff_uppers(dir_a.path(), dir_b.path()).unwrap();
        assert!(diff.only_a.is_empty());
        assert!(diff.only_b.is_empty());
        assert!(diff.different.is_empty());
    }

    #[test]
    fn test_diff_uppers_nested_files() {
        let dir_a = TempDir::new().unwrap();
        let dir_b = TempDir::new().unwrap();

        std::fs::create_dir_all(dir_a.path().join("sub")).unwrap();
        std::fs::write(dir_a.path().join("sub/nested.txt"), "data").unwrap();

        let diff = diff_uppers(dir_a.path(), dir_b.path()).unwrap();
        assert_eq!(diff.only_a.len(), 1);
        assert!(diff.only_a[0].contains("nested.txt"));
    }
}
