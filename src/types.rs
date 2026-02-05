use crate::cost::{CostAccumulator, LlmUsageEvent};
use crate::llm::LlmInterceptorConfig;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

// ── Jail Identity ──────────────────────────────────────────────

pub type JailId = String;
pub type SnapshotId = String;

pub fn new_jail_id() -> JailId {
    format!(
        "jail_{}",
        &Uuid::new_v4().to_string().replace('-', "")[..12]
    )
}

pub fn new_snapshot_id() -> SnapshotId {
    format!(
        "snap_{}",
        &Uuid::new_v4().to_string().replace('-', "")[..12]
    )
}

// ── Jail Configuration ─────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JailConfig {
    pub name: String,
    pub rootfs_source: RootfsSource,
    pub resources: ResourceLimits,
    pub network: NetworkPolicy,
    pub observe: ObserveConfig,
    pub seccomp_profile: SeccompProfile,
    pub llm_intercept: LlmInterceptorConfig,
}

impl Default for JailConfig {
    fn default() -> Self {
        Self {
            name: "unnamed".into(),
            rootfs_source: RootfsSource::Default,
            resources: ResourceLimits::default(),
            network: NetworkPolicy::Isolated,
            observe: ObserveConfig::default(),
            seccomp_profile: SeccompProfile::Default,
            llm_intercept: LlmInterceptorConfig::default(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum RootfsSource {
    Default,
    NixFlake { flake_ref: String, profile: String },
    Directory { path: String },
    OciImage { image: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceLimits {
    pub cpu_shares: u64,
    pub memory_mb: u64,
    pub disk_mb: u64,
    pub max_pids: u64,
}

impl Default for ResourceLimits {
    fn default() -> Self {
        Self {
            cpu_shares: 256,
            memory_mb: 512,
            disk_mb: 1024,
            max_pids: 128,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum NetworkPolicy {
    Isolated,
    BridgedFiltered,
    FullAccess,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObserveConfig {
    pub syscalls: bool,
    pub filesystem: bool,
    pub network: bool,
    pub processes: bool,
}

impl Default for ObserveConfig {
    fn default() -> Self {
        Self {
            syscalls: true,
            filesystem: true,
            network: true,
            processes: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SeccompProfile {
    Default,
    Strict,
    Permissive,
    Custom { allowed_syscalls: Vec<String> },
}

// ── Jail Status ────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum JailStatus {
    Creating,
    Running,
    Paused,
    Stopped,
    Snapshotted,
    Failed,
    Destroyed,
}

// ── Jail Record ────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Jail {
    pub id: JailId,
    pub config: JailConfig,
    pub status: JailStatus,
    pub pid: Option<u32>,
    pub created_at: DateTime<Utc>,
    pub started_at: Option<DateTime<Utc>>,
    pub stopped_at: Option<DateTime<Utc>>,
    pub snapshot_ids: Vec<SnapshotId>,
    pub parent_snapshot: Option<SnapshotId>,
    pub stats: JailStats,
    /// LLM interceptor session (set when jail starts with llm_intercept enabled)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub llm_session: Option<crate::llm::LlmSession>,
    /// Environment variables injected into the jail
    #[serde(default)]
    pub env_vars: Vec<(String, String)>,
}

impl Jail {
    pub fn new(config: JailConfig) -> Self {
        Self {
            id: new_jail_id(),
            config,
            status: JailStatus::Creating,
            pid: None,
            created_at: Utc::now(),
            started_at: None,
            stopped_at: None,
            snapshot_ids: Vec::new(),
            parent_snapshot: None,
            stats: JailStats::default(),
            llm_session: None,
            env_vars: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct JailStats {
    pub event_count: u64,
    pub syscall_count: u64,
    pub file_ops_count: u64,
    pub net_ops_count: u64,
    pub process_count: u64,
    pub bytes_written: u64,
    pub bytes_read_net: u64,
    pub bytes_sent_net: u64,
    pub llm_requests: u64,
    pub llm_input_tokens: u64,
    pub llm_output_tokens: u64,
    pub llm_cost_usd: f64,
    #[serde(default)]
    pub cost_accumulator: CostAccumulator,
}

// ── Observation Events ─────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ObservationEvent {
    Syscall(SyscallEvent),
    File(FileEvent),
    Network(NetworkEvent),
    Process(ProcessEvent),
    LlmUsage(LlmUsageEvent),
}

impl ObservationEvent {
    pub fn timestamp(&self) -> u64 {
        match self {
            Self::Syscall(e) => e.ts,
            Self::File(e) => e.ts,
            Self::Network(e) => e.ts,
            Self::Process(e) => e.ts,
            Self::LlmUsage(e) => e.ts,
        }
    }

    pub fn event_type(&self) -> &'static str {
        match self {
            Self::Syscall(_) => "syscall",
            Self::File(_) => "file",
            Self::Network(_) => "network",
            Self::Process(_) => "process",
            Self::LlmUsage(_) => "llm_usage",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyscallEvent {
    pub ts: u64,
    pub pid: u32,
    pub tid: u32,
    pub comm: String,
    pub nr: u32,
    pub args: [u64; 6],
    pub ret: i64,
    pub dur_ns: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileEvent {
    pub ts: u64,
    pub pid: u32,
    pub op: FileOp,
    pub path: String,
    pub bytes: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum FileOp {
    Open,
    Read,
    Write,
    Close,
    Create,
    Delete,
    Rename,
    Chmod,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkEvent {
    pub ts: u64,
    pub pid: u32,
    pub dir: NetDirection,
    pub proto: String,
    pub src: String,
    pub dst: String,
    pub bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum NetDirection {
    Ingress,
    Egress,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessEvent {
    pub ts: u64,
    pub op: ProcessOp,
    pub pid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub exe: String,
    pub argv: Vec<String>,
    pub cwd: Option<String>,
    pub exit_code: Option<i32>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ProcessOp {
    Fork,
    Exec,
    Exit,
}

// ── Snapshots ──────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Snapshot {
    pub id: SnapshotId,
    pub jail_id: JailId,
    pub parent: Option<SnapshotId>,
    pub created_at: DateTime<Utc>,
    pub status: JailStatus,
    pub config: JailConfig,
    pub stats_at_snapshot: JailStats,
    pub fs_upper_path: String,
    pub criu_dump_path: String,
}

// ── Exec ───────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecRequest {
    pub cmd: Vec<String>,
    pub env: Option<Vec<String>>,
    pub cwd: Option<String>,
    pub timeout_secs: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecResult {
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
    pub duration_ms: u64,
}

// ── Reports ────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObservationReport {
    pub jail_id: JailId,
    pub duration_secs: f64,
    pub stats: JailStats,
    pub top_syscalls: Vec<(String, u64)>,
    pub files_modified: Vec<String>,
    pub files_created: Vec<String>,
    pub files_deleted: Vec<String>,
    pub network_connections: Vec<NetworkSummary>,
    pub process_tree: Vec<ProcessNode>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkSummary {
    pub dst: String,
    pub proto: String,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub connection_count: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessNode {
    pub pid: u32,
    pub ppid: u32,
    pub exe: String,
    pub children: Vec<ProcessNode>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FsDiff {
    pub created: Vec<String>,
    pub modified: Vec<String>,
    pub deleted: Vec<String>,
}

// ── API Request/Response Types ─────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct CreateJailRequest {
    pub name: Option<String>,
    pub rootfs_source: Option<RootfsSource>,
    pub resources: Option<ResourceLimits>,
    pub network: Option<NetworkPolicy>,
    pub observe: Option<ObserveConfig>,
    pub llm_intercept: Option<LlmInterceptorConfig>,
}

impl CreateJailRequest {
    pub fn into_config(self) -> JailConfig {
        let mut config = JailConfig::default();
        if let Some(name) = self.name {
            config.name = name;
        }
        if let Some(rootfs) = self.rootfs_source {
            config.rootfs_source = rootfs;
        }
        if let Some(resources) = self.resources {
            config.resources = resources;
        }
        if let Some(network) = self.network {
            config.network = network;
        }
        if let Some(observe) = self.observe {
            config.observe = observe;
        }
        if let Some(llm) = self.llm_intercept {
            config.llm_intercept = llm;
        }
        config
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct JailSummary {
    pub id: JailId,
    pub name: String,
    pub status: JailStatus,
    pub created_at: DateTime<Utc>,
    pub stats: JailStats,
}

impl From<&Jail> for JailSummary {
    fn from(jail: &Jail) -> Self {
        Self {
            id: jail.id.clone(),
            name: jail.config.name.clone(),
            status: jail.status.clone(),
            created_at: jail.created_at,
            stats: jail.stats.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_jail_id_format() {
        let id = new_jail_id();
        assert!(id.starts_with("jail_"));
        assert_eq!(id.len(), 17); // "jail_" + 12 hex chars
    }

    #[test]
    fn test_snapshot_id_format() {
        let id = new_snapshot_id();
        assert!(id.starts_with("snap_"));
        assert_eq!(id.len(), 17);
    }

    #[test]
    fn test_jail_default_config() {
        let config = JailConfig::default();
        assert_eq!(config.name, "unnamed");
        assert_eq!(config.resources.cpu_shares, 256);
        assert_eq!(config.resources.memory_mb, 512);
        assert_eq!(config.resources.disk_mb, 1024);
        assert_eq!(config.resources.max_pids, 128);
        assert_eq!(config.network, NetworkPolicy::Isolated);
        assert!(config.observe.syscalls);
        assert!(config.observe.filesystem);
        assert!(config.observe.network);
        assert!(config.observe.processes);
    }

    #[test]
    fn test_jail_new() {
        let jail = Jail::new(JailConfig::default());
        assert!(jail.id.starts_with("jail_"));
        assert_eq!(jail.status, JailStatus::Creating);
        assert!(jail.pid.is_none());
        assert!(jail.started_at.is_none());
        assert!(jail.stopped_at.is_none());
        assert!(jail.snapshot_ids.is_empty());
        assert_eq!(jail.stats.event_count, 0);
    }

    #[test]
    fn test_observation_event_type() {
        let syscall = ObservationEvent::Syscall(SyscallEvent {
            ts: 0,
            pid: 1,
            tid: 1,
            comm: "test".into(),
            nr: 1,
            args: [0; 6],
            ret: 0,
            dur_ns: 100,
        });
        assert_eq!(syscall.event_type(), "syscall");

        let file = ObservationEvent::File(FileEvent {
            ts: 0,
            pid: 1,
            op: FileOp::Write,
            path: "/tmp/test".into(),
            bytes: Some(1024),
        });
        assert_eq!(file.event_type(), "file");

        let net = ObservationEvent::Network(NetworkEvent {
            ts: 0,
            pid: 1,
            dir: NetDirection::Egress,
            proto: "tcp".into(),
            src: "10.0.0.1:1234".into(),
            dst: "93.184.216.34:443".into(),
            bytes: 512,
        });
        assert_eq!(net.event_type(), "network");

        let proc = ObservationEvent::Process(ProcessEvent {
            ts: 0,
            op: ProcessOp::Exec,
            pid: 42,
            ppid: 1,
            uid: 0,
            exe: "/usr/bin/curl".into(),
            argv: vec!["curl".into(), "https://example.com".into()],
            cwd: Some("/tmp".into()),
            exit_code: None,
        });
        assert_eq!(proc.event_type(), "process");
    }

    #[test]
    fn test_create_jail_request_into_config() {
        let req = CreateJailRequest {
            name: Some("test-jail".into()),
            rootfs_source: None,
            resources: Some(ResourceLimits {
                cpu_shares: 512,
                memory_mb: 1024,
                disk_mb: 2048,
                max_pids: 256,
            }),
            network: Some(NetworkPolicy::BridgedFiltered),
            observe: None,
            llm_intercept: None,
        };
        let config = req.into_config();
        assert_eq!(config.name, "test-jail");
        assert_eq!(config.resources.cpu_shares, 512);
        assert_eq!(config.resources.memory_mb, 1024);
        assert_eq!(config.network, NetworkPolicy::BridgedFiltered);
        assert!(config.observe.syscalls); // default
    }

    #[test]
    fn test_jail_summary_from_jail() {
        let jail = Jail::new(JailConfig {
            name: "my-jail".into(),
            ..JailConfig::default()
        });
        let summary = JailSummary::from(&jail);
        assert_eq!(summary.id, jail.id);
        assert_eq!(summary.name, "my-jail");
        assert_eq!(summary.status, JailStatus::Creating);
    }

    #[test]
    fn test_serialization_roundtrip() {
        let event = ObservationEvent::Syscall(SyscallEvent {
            ts: 1706000000000,
            pid: 42,
            tid: 42,
            comm: "python3".into(),
            nr: 1,
            args: [1, 140234567, 128, 0, 0, 0],
            ret: 128,
            dur_ns: 1234,
        });
        let json = serde_json::to_string(&event).unwrap();
        let parsed: ObservationEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.event_type(), "syscall");
        assert_eq!(parsed.timestamp(), 1706000000000);
    }

    #[test]
    fn test_fs_diff_serialization() {
        let diff = FsDiff {
            created: vec!["/tmp/new.txt".into()],
            modified: vec!["/etc/config".into()],
            deleted: vec!["/tmp/old.txt".into()],
        };
        let json = serde_json::to_string(&diff).unwrap();
        let parsed: FsDiff = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.created.len(), 1);
        assert_eq!(parsed.modified.len(), 1);
        assert_eq!(parsed.deleted.len(), 1);
    }

    #[test]
    fn test_resource_limits_default() {
        let limits = ResourceLimits::default();
        assert_eq!(limits.cpu_shares, 256);
        assert_eq!(limits.memory_mb, 512);
        assert_eq!(limits.disk_mb, 1024);
        assert_eq!(limits.max_pids, 128);
    }

    #[test]
    fn test_network_policy_serde() {
        let policies = vec![
            NetworkPolicy::Isolated,
            NetworkPolicy::BridgedFiltered,
            NetworkPolicy::FullAccess,
        ];
        for policy in policies {
            let json = serde_json::to_string(&policy).unwrap();
            let parsed: NetworkPolicy = serde_json::from_str(&json).unwrap();
            assert_eq!(parsed, policy);
        }
    }
}
