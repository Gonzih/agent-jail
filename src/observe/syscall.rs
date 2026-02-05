//! Syscall tracing via eBPF (Aya).
//!
//! Attaches to sys_enter/sys_exit tracepoints, filtered by cgroup ID.
//! Ring buffer → Rust consumer → ObservationEvent::Syscall.
//!
//! Requires Linux with CAP_BPF + CAP_SYS_ADMIN.

use crate::types::{JailId, ObservationEvent, SyscallEvent};
use tokio::sync::mpsc;

pub struct SyscallObserver {
    pub jail_id: JailId,
    pub cgroup_id: Option<u64>,
    tx: mpsc::UnboundedSender<ObservationEvent>,
}

impl SyscallObserver {
    pub fn new(jail_id: JailId, tx: mpsc::UnboundedSender<ObservationEvent>) -> Self {
        Self {
            jail_id,
            cgroup_id: None,
            tx,
        }
    }

    pub fn set_cgroup_id(&mut self, id: u64) {
        self.cgroup_id = Some(id);
    }

    /// Start tracing. Requires Linux + eBPF capabilities.
    pub async fn start(&self) -> anyhow::Result<()> {
        #[cfg(target_os = "linux")]
        {
            // TODO: Load eBPF program via Aya
            // 1. Load BTF-enabled BPF program
            // 2. Attach to raw_syscalls:sys_enter and sys_exit tracepoints
            // 3. Configure cgroup filter (self.cgroup_id)
            // 4. Create ring buffer consumer
            // 5. Spawn task to read ring buffer → self.tx.send()
            tracing::info!(
                jail_id = %self.jail_id,
                cgroup_id = ?self.cgroup_id,
                "eBPF syscall tracing: ready to attach"
            );
        }

        #[cfg(not(target_os = "linux"))]
        {
            tracing::warn!(
                jail_id = %self.jail_id,
                "Syscall tracing unavailable: not Linux"
            );
        }

        Ok(())
    }

    pub async fn stop(&self) -> anyhow::Result<()> {
        tracing::info!(jail_id = %self.jail_id, "Syscall tracing stopped");
        Ok(())
    }

    /// Emit a syscall event (used by eBPF ring buffer consumer or test injection).
    pub fn emit(&self, event: SyscallEvent) {
        let _ = self.tx.send(ObservationEvent::Syscall(event));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_syscall_observer_emit() {
        let (tx, mut rx) = mpsc::unbounded_channel();
        let observer = SyscallObserver::new("jail_test".into(), tx);

        observer.emit(SyscallEvent {
            ts: 1000,
            pid: 42,
            tid: 42,
            comm: "python3".into(),
            nr: 1, // write
            args: [1, 0x7fff0000, 128, 0, 0, 0],
            ret: 128,
            dur_ns: 500,
        });

        let event = rx.recv().await.unwrap();
        match event {
            ObservationEvent::Syscall(e) => {
                assert_eq!(e.pid, 42);
                assert_eq!(e.nr, 1);
                assert_eq!(e.ret, 128);
            }
            _ => panic!("Expected syscall event"),
        }
    }

    #[test]
    fn test_set_cgroup_id() {
        let (tx, _rx) = mpsc::unbounded_channel();
        let mut observer = SyscallObserver::new("jail_test".into(), tx);
        assert!(observer.cgroup_id.is_none());
        observer.set_cgroup_id(12345);
        assert_eq!(observer.cgroup_id, Some(12345));
    }
}
