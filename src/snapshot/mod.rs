pub mod branch;
pub mod criu;

/// Snapshot manager orchestrates checkpoint/restore/branch operations.
pub struct SnapshotManager {
    pub data_dir: std::path::PathBuf,
}

impl SnapshotManager {
    pub fn new(data_dir: std::path::PathBuf) -> Self {
        Self { data_dir }
    }

    /// Path to a snapshot's CRIU dump directory.
    pub fn criu_dump_path(&self, jail_id: &str, snapshot_id: &str) -> std::path::PathBuf {
        self.data_dir
            .join("jails")
            .join(jail_id)
            .join("snapshots")
            .join(snapshot_id)
            .join("criu-dump")
    }

    /// Path to a snapshot's OverlayFS upper copy.
    pub fn fs_upper_path(&self, jail_id: &str, snapshot_id: &str) -> std::path::PathBuf {
        self.data_dir
            .join("jails")
            .join(jail_id)
            .join("snapshots")
            .join(snapshot_id)
            .join("fs-upper")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_snapshot_paths() {
        let mgr = SnapshotManager::new(PathBuf::from("/data"));
        let criu = mgr.criu_dump_path("jail_abc", "snap_xyz");
        assert_eq!(
            criu,
            PathBuf::from("/data/jails/jail_abc/snapshots/snap_xyz/criu-dump")
        );
        let upper = mgr.fs_upper_path("jail_abc", "snap_xyz");
        assert_eq!(
            upper,
            PathBuf::from("/data/jails/jail_abc/snapshots/snap_xyz/fs-upper")
        );
    }
}
