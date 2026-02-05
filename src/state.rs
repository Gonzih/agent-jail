use crate::config::Config;
use crate::llm::{LlmInterceptor, LlmSession};
use crate::rootfs::RootfsProvider;
use crate::storage::Storage;
use crate::types::{Jail, JailId, Snapshot, SnapshotId};
use dashmap::DashMap;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::broadcast;

pub struct AppState {
    pub jails: DashMap<JailId, Jail>,
    pub snapshots: DashMap<SnapshotId, Snapshot>,
    pub llm_sessions: DashMap<JailId, LlmSession>,
    pub storage: Storage,
    pub config: Config,
    pub start_time: Instant,
    pub event_tx: broadcast::Sender<(JailId, String)>,
    pub llm_interceptor: LlmInterceptor,
    pub rootfs_provider: RootfsProvider,
}

impl AppState {
    pub fn new(config: Config) -> Arc<Self> {
        let (event_tx, _) = broadcast::channel(1024);
        let llm_interceptor = LlmInterceptor::new(config.mock_llm_url.clone());
        let rootfs_provider = RootfsProvider::new(config.data_dir.join("rootfs-cache"));
        Arc::new(Self {
            jails: DashMap::new(),
            snapshots: DashMap::new(),
            llm_sessions: DashMap::new(),
            storage: Storage::new(config.clone()),
            config,
            start_time: Instant::now(),
            event_tx,
            llm_interceptor,
            rootfs_provider,
        })
    }

    pub async fn load_from_disk(&self) -> anyhow::Result<usize> {
        let jails = self.storage.load_all_jails()?;
        let count = jails.len();
        for jail in jails {
            // Load snapshots for each jail
            if let Ok(snapshots) = self.storage.list_snapshots(&jail.id) {
                for snap in snapshots {
                    self.snapshots.insert(snap.id.clone(), snap);
                }
            }
            // Restore LLM session reference if present
            if let Some(ref session) = jail.llm_session {
                self.llm_sessions.insert(jail.id.clone(), session.clone());
            }
            self.jails.insert(jail.id.clone(), jail);
        }
        Ok(count)
    }

    pub fn save_jail(&self, jail: &Jail) -> anyhow::Result<()> {
        self.storage.save_jail(jail)
    }

    pub fn get_jail(&self, id: &str) -> Option<Jail> {
        self.jails.get(id).map(|j| j.clone())
    }

    pub fn subscribe_events(&self) -> broadcast::Receiver<(JailId, String)> {
        self.event_tx.subscribe()
    }

    /// Broadcast an observation event for a jail.
    pub fn broadcast_event(&self, jail_id: &JailId, event_json: &str) {
        let _ = self
            .event_tx
            .send((jail_id.clone(), event_json.to_string()));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::JailConfig;
    use tempfile::TempDir;

    fn test_state() -> (Arc<AppState>, TempDir) {
        let tmp = TempDir::new().unwrap();
        let config = Config {
            data_dir: tmp.path().to_path_buf(),
            ..Config::default()
        };
        (AppState::new(config), tmp)
    }

    #[test]
    fn test_state_insert_and_get() {
        let (state, _tmp) = test_state();
        let jail = Jail::new(JailConfig {
            name: "test".into(),
            ..JailConfig::default()
        });
        let id = jail.id.clone();
        state.jails.insert(id.clone(), jail);
        let got = state.get_jail(&id).unwrap();
        assert_eq!(got.config.name, "test");
    }

    #[test]
    fn test_state_save_and_reload() {
        let tmp = TempDir::new().unwrap();
        let config = Config {
            data_dir: tmp.path().to_path_buf(),
            ..Config::default()
        };

        // Save
        let state = AppState::new(config.clone());
        let jail = Jail::new(JailConfig {
            name: "persistent".into(),
            ..JailConfig::default()
        });
        state.jails.insert(jail.id.clone(), jail.clone());
        state.save_jail(&jail).unwrap();

        // Reload in new state
        let state2 = AppState::new(config);
        let rt = tokio::runtime::Runtime::new().unwrap();
        let count = rt.block_on(state2.load_from_disk()).unwrap();
        assert_eq!(count, 1);
        let loaded = state2.get_jail(&jail.id).unwrap();
        assert_eq!(loaded.config.name, "persistent");
    }

    #[test]
    fn test_event_broadcast() {
        let (state, _tmp) = test_state();
        let mut rx = state.subscribe_events();
        state.broadcast_event(&"jail_123".into(), r#"{"type":"syscall"}"#);
        let (id, msg) = rx.try_recv().unwrap();
        assert_eq!(id, "jail_123");
        assert!(msg.contains("syscall"));
    }

    #[test]
    fn test_llm_sessions_map() {
        let (state, _tmp) = test_state();
        assert!(state.llm_sessions.is_empty());

        let session = crate::llm::LlmSession {
            jail_id: "jail_test".into(),
            session_id: "sess-123".into(),
            api_key: "mlm_abc".into(),
            mode: crate::llm::LlmSessionMode::Record,
            provider: crate::llm::LlmProvider::Openai,
            recordings_count: 0,
            created_at: chrono::Utc::now(),
        };
        state.llm_sessions.insert("jail_test".into(), session);
        assert_eq!(state.llm_sessions.len(), 1);
    }
}
