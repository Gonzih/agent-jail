//! Network observation via eBPF TC/XDP hooks.
//!
//! Attaches to the jail's veth pair to capture all ingress/egress traffic.
//! Data: src/dst IP:port, protocol, bytes, direction, timestamp.
//!
//! Optional: transparent MITM proxy for TLS content inspection.
//!
//! Requires Linux with CAP_NET_ADMIN + CAP_BPF.

use crate::types::{JailId, NetDirection, NetworkEvent, NetworkSummary, ObservationEvent};
use std::collections::HashMap;
use tokio::sync::mpsc;

pub struct NetworkObserver {
    pub jail_id: JailId,
    pub veth_name: Option<String>,
    tx: mpsc::UnboundedSender<ObservationEvent>,
}

impl NetworkObserver {
    pub fn new(jail_id: JailId, tx: mpsc::UnboundedSender<ObservationEvent>) -> Self {
        Self {
            jail_id,
            veth_name: None,
            tx,
        }
    }

    pub fn set_veth(&mut self, name: String) {
        self.veth_name = Some(name);
    }

    pub async fn start(&self) -> anyhow::Result<()> {
        #[cfg(target_os = "linux")]
        {
            // TODO: Attach eBPF TC programs to veth
            // 1. Open TC hook on ingress + egress
            // 2. Parse packet headers (IP, TCP/UDP)
            // 3. Push to ring buffer → Rust consumer → self.tx.send()
            tracing::info!(
                jail_id = %self.jail_id,
                veth = ?self.veth_name,
                "Network observation: ready"
            );
        }

        #[cfg(not(target_os = "linux"))]
        {
            tracing::warn!(
                jail_id = %self.jail_id,
                "Network observation unavailable: eBPF TC requires Linux"
            );
        }

        Ok(())
    }

    pub async fn stop(&self) -> anyhow::Result<()> {
        tracing::info!(jail_id = %self.jail_id, "Network observation stopped");
        Ok(())
    }

    pub fn emit(&self, event: NetworkEvent) {
        let _ = self.tx.send(ObservationEvent::Network(event));
    }

    /// Summarize network events into connection summaries.
    pub fn summarize(events: &[NetworkEvent]) -> Vec<NetworkSummary> {
        let mut map: HashMap<(String, String), (u64, u64, u64)> = HashMap::new();

        for event in events {
            let key = (event.dst.clone(), event.proto.clone());
            let entry = map.entry(key).or_insert((0, 0, 0));
            match event.dir {
                NetDirection::Egress => entry.0 += event.bytes,
                NetDirection::Ingress => entry.1 += event.bytes,
            }
            entry.2 += 1;
        }

        map.into_iter()
            .map(|((dst, proto), (sent, received, count))| NetworkSummary {
                dst,
                proto,
                bytes_sent: sent,
                bytes_received: received,
                connection_count: count,
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_network_observer_emit() {
        let (tx, mut rx) = mpsc::unbounded_channel();
        let observer = NetworkObserver::new("jail_test".into(), tx);

        observer.emit(NetworkEvent {
            ts: 1000,
            pid: 42,
            dir: NetDirection::Egress,
            proto: "tcp".into(),
            src: "10.0.0.2:54321".into(),
            dst: "93.184.216.34:443".into(),
            bytes: 512,
        });

        let event = rx.recv().await.unwrap();
        assert_eq!(event.event_type(), "network");
    }

    #[test]
    fn test_summarize_network_events() {
        let events = vec![
            NetworkEvent {
                ts: 100,
                pid: 1,
                dir: NetDirection::Egress,
                proto: "tcp".into(),
                src: "10.0.0.2:1234".into(),
                dst: "1.1.1.1:443".into(),
                bytes: 100,
            },
            NetworkEvent {
                ts: 200,
                pid: 1,
                dir: NetDirection::Ingress,
                proto: "tcp".into(),
                src: "1.1.1.1:443".into(),
                dst: "10.0.0.2:1234".into(),
                bytes: 500,
            },
            NetworkEvent {
                ts: 300,
                pid: 1,
                dir: NetDirection::Egress,
                proto: "tcp".into(),
                src: "10.0.0.2:1234".into(),
                dst: "1.1.1.1:443".into(),
                bytes: 200,
            },
        ];

        let summaries = NetworkObserver::summarize(&events);
        // Two unique destinations
        assert_eq!(summaries.len(), 2);

        // Find the egress summary (dst = 1.1.1.1:443)
        let egress = summaries.iter().find(|s| s.dst == "1.1.1.1:443").unwrap();
        assert_eq!(egress.bytes_sent, 300); // 100 + 200
        assert_eq!(egress.bytes_received, 0);
        assert_eq!(egress.connection_count, 2);

        // Find the ingress summary (dst = 10.0.0.2:1234)
        let ingress = summaries.iter().find(|s| s.dst == "10.0.0.2:1234").unwrap();
        assert_eq!(ingress.bytes_sent, 0);
        assert_eq!(ingress.bytes_received, 500);
        assert_eq!(ingress.connection_count, 1);
    }

    #[test]
    fn test_set_veth() {
        let (tx, _rx) = mpsc::unbounded_channel();
        let mut observer = NetworkObserver::new("jail_test".into(), tx);
        assert!(observer.veth_name.is_none());
        observer.set_veth("veth_jail_test".into());
        assert_eq!(observer.veth_name, Some("veth_jail_test".into()));
    }
}
