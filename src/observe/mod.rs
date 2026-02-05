pub mod filesystem;
pub mod network;
pub mod process;
pub mod syscall;

use crate::types::{JailId, ObservationEvent, ObserveConfig};
use tokio::sync::mpsc;

/// Central observer orchestrator.
/// Collects events from all observation layers and dispatches them.
pub struct Observer {
    pub config: ObserveConfig,
    pub jail_id: JailId,
    pub tx: mpsc::UnboundedSender<ObservationEvent>,
    pub rx: mpsc::UnboundedReceiver<ObservationEvent>,
}

impl Observer {
    pub fn new(jail_id: JailId, config: ObserveConfig) -> Self {
        let (tx, rx) = mpsc::unbounded_channel();
        Self {
            config,
            jail_id,
            tx,
            rx,
        }
    }

    /// Get a sender handle for an observation layer to push events.
    pub fn sender(&self) -> mpsc::UnboundedSender<ObservationEvent> {
        self.tx.clone()
    }

    /// Start all enabled observation layers.
    /// On non-Linux, this is a no-op (layers require eBPF/fanotify).
    pub async fn start(&self) -> anyhow::Result<()> {
        if self.config.syscalls {
            tracing::info!(jail_id = %self.jail_id, "Syscall observation: enabled (requires Linux + eBPF)");
        }
        if self.config.filesystem {
            tracing::info!(jail_id = %self.jail_id, "Filesystem observation: enabled (requires Linux + fanotify)");
        }
        if self.config.network {
            tracing::info!(jail_id = %self.jail_id, "Network observation: enabled (requires Linux + eBPF TC)");
        }
        if self.config.processes {
            tracing::info!(jail_id = %self.jail_id, "Process observation: enabled (requires Linux + eBPF tracepoints)");
        }
        Ok(())
    }

    pub async fn stop(&self) -> anyhow::Result<()> {
        tracing::info!(jail_id = %self.jail_id, "Stopping observers");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{ObservationEvent, SyscallEvent};

    #[test]
    fn test_observer_creation() {
        let observer = Observer::new("jail_test".into(), ObserveConfig::default());
        assert_eq!(observer.jail_id, "jail_test");
        assert!(observer.config.syscalls);
    }

    #[tokio::test]
    async fn test_observer_event_channel() {
        let mut observer = Observer::new("jail_test".into(), ObserveConfig::default());
        let tx = observer.sender();

        let event = ObservationEvent::Syscall(SyscallEvent {
            ts: 100,
            pid: 1,
            tid: 1,
            comm: "test".into(),
            nr: 1,
            args: [0; 6],
            ret: 0,
            dur_ns: 50,
        });

        tx.send(event).unwrap();
        let received = observer.rx.recv().await.unwrap();
        assert_eq!(received.event_type(), "syscall");
        assert_eq!(received.timestamp(), 100);
    }
}
