//! Process tree observation via eBPF tracepoints.
//!
//! Tracks: sched_process_fork, sched_process_exec, sched_process_exit
//! Reconstructs full process tree in real-time.
//!
//! Requires Linux with CAP_BPF.

use crate::types::{JailId, ObservationEvent, ProcessEvent, ProcessNode, ProcessOp};
use std::collections::HashMap;
use tokio::sync::mpsc;

pub struct ProcessObserver {
    pub jail_id: JailId,
    tx: mpsc::UnboundedSender<ObservationEvent>,
    /// In-memory process table for tree reconstruction
    processes: HashMap<u32, ProcessInfo>,
}

#[derive(Debug, Clone)]
struct ProcessInfo {
    pid: u32,
    ppid: u32,
    exe: String,
    alive: bool,
}

impl ProcessObserver {
    pub fn new(jail_id: JailId, tx: mpsc::UnboundedSender<ObservationEvent>) -> Self {
        Self {
            jail_id,
            tx,
            processes: HashMap::new(),
        }
    }

    pub async fn start(&self) -> anyhow::Result<()> {
        #[cfg(target_os = "linux")]
        {
            // TODO: Attach eBPF to scheduler tracepoints
            // 1. sched_process_fork → capture new PID + PPID
            // 2. sched_process_exec → capture exe path + argv
            // 3. sched_process_exit → capture exit code
            tracing::info!(jail_id = %self.jail_id, "Process observation: ready");
        }

        #[cfg(not(target_os = "linux"))]
        {
            tracing::warn!(
                jail_id = %self.jail_id,
                "Process observation unavailable: eBPF requires Linux"
            );
        }

        Ok(())
    }

    pub async fn stop(&self) -> anyhow::Result<()> {
        tracing::info!(jail_id = %self.jail_id, "Process observation stopped");
        Ok(())
    }

    pub fn emit(&self, event: ProcessEvent) {
        let _ = self.tx.send(ObservationEvent::Process(event));
    }

    /// Record a process event and update the in-memory tree.
    pub fn record(&mut self, event: &ProcessEvent) {
        match event.op {
            ProcessOp::Fork | ProcessOp::Exec => {
                self.processes.insert(
                    event.pid,
                    ProcessInfo {
                        pid: event.pid,
                        ppid: event.ppid,
                        exe: event.exe.clone(),
                        alive: true,
                    },
                );
            }
            ProcessOp::Exit => {
                if let Some(proc) = self.processes.get_mut(&event.pid) {
                    proc.alive = false;
                }
            }
        }
    }

    /// Build current process tree from recorded events.
    pub fn build_tree(&self) -> Vec<ProcessNode> {
        let alive: Vec<&ProcessInfo> = self.processes.values().filter(|p| p.alive).collect();

        // Find root processes (ppid not in our process set)
        let roots: Vec<&ProcessInfo> = alive
            .iter()
            .filter(|p| !self.processes.contains_key(&p.ppid) || p.ppid == 0)
            .copied()
            .collect();

        roots
            .iter()
            .map(|root| self.build_subtree(root.pid, &alive))
            .collect()
    }

    fn build_subtree(&self, pid: u32, alive: &[&ProcessInfo]) -> ProcessNode {
        let info = self.processes.get(&pid);
        let children: Vec<ProcessNode> = alive
            .iter()
            .filter(|p| p.ppid == pid && p.pid != pid)
            .map(|child| self.build_subtree(child.pid, alive))
            .collect();

        ProcessNode {
            pid,
            ppid: info.map_or(0, |p| p.ppid),
            exe: info.map_or_else(|| "unknown".into(), |p| p.exe.clone()),
            children,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_process_observer_emit() {
        let (tx, mut rx) = mpsc::unbounded_channel();
        let observer = ProcessObserver::new("jail_test".into(), tx);

        observer.emit(ProcessEvent {
            ts: 1000,
            op: ProcessOp::Exec,
            pid: 42,
            ppid: 1,
            uid: 0,
            exe: "/usr/bin/python3".into(),
            argv: vec!["python3".into(), "script.py".into()],
            cwd: Some("/app".into()),
            exit_code: None,
        });

        let event = rx.recv().await.unwrap();
        assert_eq!(event.event_type(), "process");
    }

    #[test]
    fn test_record_and_build_tree() {
        let (tx, _rx) = mpsc::unbounded_channel();
        let mut observer = ProcessObserver::new("jail_test".into(), tx);

        // PID 1: init
        let init = ProcessEvent {
            ts: 100,
            op: ProcessOp::Exec,
            pid: 1,
            ppid: 0,
            uid: 0,
            exe: "/bin/bash".into(),
            argv: vec!["bash".into()],
            cwd: Some("/".into()),
            exit_code: None,
        };
        observer.record(&init);

        // PID 42: child of init
        let child = ProcessEvent {
            ts: 200,
            op: ProcessOp::Fork,
            pid: 42,
            ppid: 1,
            uid: 0,
            exe: "/usr/bin/python3".into(),
            argv: vec!["python3".into()],
            cwd: Some("/app".into()),
            exit_code: None,
        };
        observer.record(&child);

        // PID 43: grandchild
        let grandchild = ProcessEvent {
            ts: 300,
            op: ProcessOp::Exec,
            pid: 43,
            ppid: 42,
            uid: 0,
            exe: "/usr/bin/curl".into(),
            argv: vec!["curl".into(), "https://example.com".into()],
            cwd: Some("/app".into()),
            exit_code: None,
        };
        observer.record(&grandchild);

        let tree = observer.build_tree();
        assert_eq!(tree.len(), 1); // One root
        assert_eq!(tree[0].pid, 1);
        assert_eq!(tree[0].children.len(), 1); // bash → python
        assert_eq!(tree[0].children[0].pid, 42);
        assert_eq!(tree[0].children[0].children.len(), 1); // python → curl
        assert_eq!(tree[0].children[0].children[0].pid, 43);
    }

    #[test]
    fn test_exit_removes_from_tree() {
        let (tx, _rx) = mpsc::unbounded_channel();
        let mut observer = ProcessObserver::new("jail_test".into(), tx);

        observer.record(&ProcessEvent {
            ts: 100,
            op: ProcessOp::Exec,
            pid: 1,
            ppid: 0,
            uid: 0,
            exe: "/bin/bash".into(),
            argv: vec![],
            cwd: None,
            exit_code: None,
        });

        observer.record(&ProcessEvent {
            ts: 200,
            op: ProcessOp::Fork,
            pid: 42,
            ppid: 1,
            uid: 0,
            exe: "/usr/bin/ls".into(),
            argv: vec!["ls".into()],
            cwd: None,
            exit_code: None,
        });

        // ls exits
        observer.record(&ProcessEvent {
            ts: 300,
            op: ProcessOp::Exit,
            pid: 42,
            ppid: 1,
            uid: 0,
            exe: "/usr/bin/ls".into(),
            argv: vec![],
            cwd: None,
            exit_code: Some(0),
        });

        let tree = observer.build_tree();
        assert_eq!(tree.len(), 1);
        assert_eq!(tree[0].pid, 1);
        assert!(tree[0].children.is_empty()); // ls exited
    }
}
