use crate::config::Config;
use crate::types::{Jail, ObservationEvent, Snapshot};
use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;

pub struct Storage {
    config: Config,
}

impl Storage {
    pub fn new(config: Config) -> Self {
        Self { config }
    }

    // ── Jail persistence ───────────────────────────────────────

    pub fn save_jail(&self, jail: &Jail) -> anyhow::Result<()> {
        let dir = self.config.jail_dir(&jail.id);
        fs::create_dir_all(&dir)?;
        let path = dir.join("jail.json");
        let json = serde_json::to_string_pretty(jail)?;
        fs::write(&path, json)?;
        Ok(())
    }

    pub fn load_jail(&self, id: &str) -> anyhow::Result<Option<Jail>> {
        let path = self.config.jail_dir(id).join("jail.json");
        if !path.exists() {
            return Ok(None);
        }
        let data = fs::read_to_string(&path)?;
        let jail: Jail = serde_json::from_str(&data)?;
        Ok(Some(jail))
    }

    pub fn load_all_jails(&self) -> anyhow::Result<Vec<Jail>> {
        let dir = self.config.jails_dir();
        if !dir.exists() {
            return Ok(Vec::new());
        }
        let mut jails = Vec::new();
        for entry in fs::read_dir(&dir)? {
            let entry = entry?;
            if entry.file_type()?.is_dir() {
                let id = entry.file_name().to_string_lossy().to_string();
                if let Some(jail) = self.load_jail(&id)? {
                    jails.push(jail);
                }
            }
        }
        Ok(jails)
    }

    pub fn delete_jail_dir(&self, id: &str) -> anyhow::Result<()> {
        let dir = self.config.jail_dir(id);
        if dir.exists() {
            fs::remove_dir_all(&dir)?;
        }
        Ok(())
    }

    // ── Event persistence (JSONL append-only) ──────────────────

    pub fn ensure_events_dir(&self, jail_id: &str) -> anyhow::Result<PathBuf> {
        let dir = self.config.jail_events_dir(jail_id);
        fs::create_dir_all(&dir)?;
        Ok(dir)
    }

    pub fn append_event(&self, jail_id: &str, event: &ObservationEvent) -> anyhow::Result<()> {
        let dir = self.ensure_events_dir(jail_id)?;
        let filename = match event {
            ObservationEvent::Syscall(_) => "syscalls.jsonl",
            ObservationEvent::File(_) => "filesystem.jsonl",
            ObservationEvent::Network(_) => "network.jsonl",
            ObservationEvent::Process(_) => "processes.jsonl",
        };
        let path = dir.join(filename);
        let mut file = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)?;
        let line = serde_json::to_string(event)?;
        writeln!(file, "{}", line)?;
        Ok(())
    }

    pub fn read_events(
        &self,
        jail_id: &str,
        event_type: Option<&str>,
    ) -> anyhow::Result<Vec<ObservationEvent>> {
        let dir = self.config.jail_events_dir(jail_id);
        if !dir.exists() {
            return Ok(Vec::new());
        }

        let files: Vec<(&str, &str)> = vec![
            ("syscall", "syscalls.jsonl"),
            ("file", "filesystem.jsonl"),
            ("network", "network.jsonl"),
            ("process", "processes.jsonl"),
        ];

        let mut events = Vec::new();
        for (etype, filename) in files {
            if let Some(filter) = event_type {
                if filter != etype {
                    continue;
                }
            }
            let path = dir.join(filename);
            if !path.exists() {
                continue;
            }
            let file = fs::File::open(&path)?;
            let reader = BufReader::new(file);
            for line in reader.lines() {
                let line = line?;
                if line.trim().is_empty() {
                    continue;
                }
                let event: ObservationEvent = serde_json::from_str(&line)?;
                events.push(event);
            }
        }

        events.sort_by_key(|e| e.timestamp());
        Ok(events)
    }

    // ── Snapshot persistence ───────────────────────────────────

    pub fn save_snapshot(&self, jail_id: &str, snapshot: &Snapshot) -> anyhow::Result<()> {
        let dir = self.config.jail_snapshots_dir(jail_id).join(&snapshot.id);
        fs::create_dir_all(&dir)?;
        let path = dir.join("metadata.json");
        let json = serde_json::to_string_pretty(snapshot)?;
        fs::write(&path, json)?;
        Ok(())
    }

    pub fn load_snapshot(
        &self,
        jail_id: &str,
        snapshot_id: &str,
    ) -> anyhow::Result<Option<Snapshot>> {
        let path = self
            .config
            .jail_snapshots_dir(jail_id)
            .join(snapshot_id)
            .join("metadata.json");
        if !path.exists() {
            return Ok(None);
        }
        let data = fs::read_to_string(&path)?;
        let snapshot: Snapshot = serde_json::from_str(&data)?;
        Ok(Some(snapshot))
    }

    pub fn list_snapshots(&self, jail_id: &str) -> anyhow::Result<Vec<Snapshot>> {
        let dir = self.config.jail_snapshots_dir(jail_id);
        if !dir.exists() {
            return Ok(Vec::new());
        }
        let mut snapshots = Vec::new();
        for entry in fs::read_dir(&dir)? {
            let entry = entry?;
            if entry.file_type()?.is_dir() {
                let sid = entry.file_name().to_string_lossy().to_string();
                if let Some(snap) = self.load_snapshot(jail_id, &sid)? {
                    snapshots.push(snap);
                }
            }
        }
        snapshots.sort_by(|a, b| a.created_at.cmp(&b.created_at));
        Ok(snapshots)
    }

    // ── Rootfs paths ───────────────────────────────────────────

    pub fn ensure_rootfs_dirs(&self, jail_id: &str) -> anyhow::Result<RootfsPaths> {
        let base = self.config.jail_rootfs_dir(jail_id);
        let paths = RootfsPaths {
            lower: base.join("lower"),
            upper: base.join("upper"),
            work: base.join("work"),
            merged: base.join("merged"),
        };
        fs::create_dir_all(&paths.lower)?;
        fs::create_dir_all(&paths.upper)?;
        fs::create_dir_all(&paths.work)?;
        fs::create_dir_all(&paths.merged)?;
        Ok(paths)
    }
}

#[derive(Debug, Clone)]
pub struct RootfsPaths {
    pub lower: PathBuf,
    pub upper: PathBuf,
    pub work: PathBuf,
    pub merged: PathBuf,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::*;
    use tempfile::TempDir;

    fn test_storage() -> (Storage, TempDir) {
        let tmp = TempDir::new().unwrap();
        let config = Config {
            data_dir: tmp.path().to_path_buf(),
            ..Config::default()
        };
        (Storage::new(config), tmp)
    }

    #[test]
    fn test_save_and_load_jail() {
        let (storage, _tmp) = test_storage();
        let jail = Jail::new(JailConfig {
            name: "test-jail".into(),
            ..JailConfig::default()
        });
        storage.save_jail(&jail).unwrap();
        let loaded = storage.load_jail(&jail.id).unwrap().unwrap();
        assert_eq!(loaded.id, jail.id);
        assert_eq!(loaded.config.name, "test-jail");
    }

    #[test]
    fn test_load_nonexistent_jail() {
        let (storage, _tmp) = test_storage();
        let result = storage.load_jail("nonexistent").unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_load_all_jails() {
        let (storage, _tmp) = test_storage();
        let j1 = Jail::new(JailConfig {
            name: "jail-1".into(),
            ..JailConfig::default()
        });
        let j2 = Jail::new(JailConfig {
            name: "jail-2".into(),
            ..JailConfig::default()
        });
        storage.save_jail(&j1).unwrap();
        storage.save_jail(&j2).unwrap();
        let all = storage.load_all_jails().unwrap();
        assert_eq!(all.len(), 2);
    }

    #[test]
    fn test_delete_jail_dir() {
        let (storage, _tmp) = test_storage();
        let jail = Jail::new(JailConfig::default());
        storage.save_jail(&jail).unwrap();
        storage.delete_jail_dir(&jail.id).unwrap();
        let loaded = storage.load_jail(&jail.id).unwrap();
        assert!(loaded.is_none());
    }

    #[test]
    fn test_append_and_read_events() {
        let (storage, _tmp) = test_storage();
        let jail_id = "jail_test123456";

        let e1 = ObservationEvent::Syscall(SyscallEvent {
            ts: 100,
            pid: 1,
            tid: 1,
            comm: "test".into(),
            nr: 1,
            args: [0; 6],
            ret: 0,
            dur_ns: 50,
        });
        let e2 = ObservationEvent::File(FileEvent {
            ts: 200,
            pid: 1,
            op: FileOp::Write,
            path: "/tmp/x".into(),
            bytes: Some(42),
        });
        let e3 = ObservationEvent::Network(NetworkEvent {
            ts: 150,
            pid: 1,
            dir: NetDirection::Egress,
            proto: "tcp".into(),
            src: "10.0.0.1:1234".into(),
            dst: "1.1.1.1:443".into(),
            bytes: 100,
        });

        storage.append_event(jail_id, &e1).unwrap();
        storage.append_event(jail_id, &e2).unwrap();
        storage.append_event(jail_id, &e3).unwrap();

        // Read all — sorted by timestamp
        let all = storage.read_events(jail_id, None).unwrap();
        assert_eq!(all.len(), 3);
        assert_eq!(all[0].timestamp(), 100); // syscall
        assert_eq!(all[1].timestamp(), 150); // network
        assert_eq!(all[2].timestamp(), 200); // file

        // Read filtered
        let syscalls = storage.read_events(jail_id, Some("syscall")).unwrap();
        assert_eq!(syscalls.len(), 1);

        let files = storage.read_events(jail_id, Some("file")).unwrap();
        assert_eq!(files.len(), 1);
    }

    #[test]
    fn test_save_and_load_snapshot() {
        let (storage, _tmp) = test_storage();
        let jail_id = "jail_test123456";
        let snapshot = Snapshot {
            id: new_snapshot_id(),
            jail_id: jail_id.into(),
            parent: None,
            created_at: chrono::Utc::now(),
            status: JailStatus::Snapshotted,
            config: JailConfig::default(),
            stats_at_snapshot: JailStats::default(),
            fs_upper_path: "/tmp/upper".into(),
            criu_dump_path: "/tmp/criu".into(),
        };
        storage.save_snapshot(jail_id, &snapshot).unwrap();
        let loaded = storage
            .load_snapshot(jail_id, &snapshot.id)
            .unwrap()
            .unwrap();
        assert_eq!(loaded.id, snapshot.id);
        assert_eq!(loaded.jail_id, jail_id);
    }

    #[test]
    fn test_list_snapshots() {
        let (storage, _tmp) = test_storage();
        let jail_id = "jail_test123456";
        for _ in 0..3 {
            let snapshot = Snapshot {
                id: new_snapshot_id(),
                jail_id: jail_id.into(),
                parent: None,
                created_at: chrono::Utc::now(),
                status: JailStatus::Snapshotted,
                config: JailConfig::default(),
                stats_at_snapshot: JailStats::default(),
                fs_upper_path: String::new(),
                criu_dump_path: String::new(),
            };
            storage.save_snapshot(jail_id, &snapshot).unwrap();
        }
        let all = storage.list_snapshots(jail_id).unwrap();
        assert_eq!(all.len(), 3);
    }

    #[test]
    fn test_ensure_rootfs_dirs() {
        let (storage, _tmp) = test_storage();
        let paths = storage.ensure_rootfs_dirs("jail_test123456").unwrap();
        assert!(paths.lower.exists());
        assert!(paths.upper.exists());
        assert!(paths.work.exists());
        assert!(paths.merged.exists());
    }
}
