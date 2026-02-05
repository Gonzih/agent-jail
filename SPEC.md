# Agent Jail Service — Design Specification

## Purpose

Observable sandbox for autonomous agents. Total microscope: every syscall, file op, network packet, and process fork is captured. Snapshot/branch enables forking execution at any point to explore divergent paths.

## Architecture

```
┌─────────────────────────────────────┐
│           Control Plane (Rust)       │
│  REST API · Session Mgmt · Snapshots │
├─────────────────────────────────────┤
│         Observability Layer          │
│  eBPF (Aya) · OverlayFS · Net Proxy │
├─────────────────────────────────────┤
│          Isolation Backend           │
│  Phase 1: namespaces + CRIU         │
│  Phase 2: Firecracker microVMs      │
├─────────────────────────────────────┤
│          Rootfs Provider             │
│  NixOS Flake → OCI Image / ext4     │
└─────────────────────────────────────┘
```

## Isolation Model

### Phase 1: Linux Namespaces + CRIU

- **PID namespace** — isolated process tree, PID 1 inside jail
- **Mount namespace** — OverlayFS rootfs (NixOS lower, writable upper)
- **Network namespace** — veth pair, bridged or isolated
- **UTS namespace** — isolated hostname
- **IPC namespace** — isolated System V IPC
- **User namespace** — UID/GID mapping
- **Cgroup v2** — CPU shares, memory limits, max PIDs, disk I/O
- **seccomp-bpf** — syscall allowlist (deny dangerous calls)
- **pivot_root** — switch rootfs into OverlayFS merged directory

### Phase 2: Firecracker microVMs (Future)

- Native snapshot via Firecracker API
- userfaultfd CoW cloning for near-instant branching
- Same control plane API, swappable backend via `JailBackend` trait

## Observability Layers

### Syscall Tracing (eBPF via Aya)

Tracepoints: `sys_enter_*` / `sys_exit_*`, filtered by cgroup ID.

Data per event:
- `syscall_nr` — syscall number
- `args[6]` — raw arguments
- `ret` — return value
- `duration_ns` — wall time
- `pid`, `tid`, `comm` — process identity
- `timestamp` — monotonic nanoseconds

Ring buffer → Rust consumer → JSONL append.

### Filesystem Tracking (OverlayFS + fanotify)

Rootfs = OverlayFS: `lower` (NixOS, read-only) + `upper` (writable).

- **fanotify** on merged mount — captures open/read/write/close/delete with PID
- **Diff** = read upper directory: new files, modified files, whiteout entries = deletions

### Network Capture (eBPF TC/XDP)

Attached to veth pair (ingress + egress):
- src/dst IP:port, protocol, byte count, direction, timestamp
- Optional: transparent MITM proxy for TLS content inspection

### Process Tree (eBPF tracepoints)

- `sched_process_fork` / `sched_process_exec` / `sched_process_exit`
- Reconstruct full process tree in real-time
- Data: pid, ppid, uid, exe, argv, cwd, start_time, exit_code

## Snapshot/Branch Mechanics

### Snapshot

1. Pause jail (freeze cgroup)
2. `criu dump` — checkpoint all processes
3. Copy OverlayFS upper directory
4. Store metadata (config, observation state, resource usage)

### Restore

1. Create fresh PID/mount/net namespaces
2. Mount OverlayFS with copied upper
3. `criu restore` — resume processes
4. Reattach observers

### Branch

Fork from any snapshot N times:
- Each branch gets own namespaces
- Own copy of OverlayFS upper (reflink on btrfs/xfs, or cp)
- Own observation streams
- Independent execution from branch point

### Diff

Compare OverlayFS uppers between:
- Snapshot ↔ current state
- Branch A ↔ Branch B
- Any two snapshots

## Data Format

All events stored as JSONL (one JSON object per line, append-only):

```json
{"type":"syscall","ts":1706000000000,"pid":42,"tid":42,"comm":"python3","nr":1,"args":[1,140234567,128,0,0,0],"ret":128,"dur_ns":1234}
{"type":"file","ts":1706000000001,"pid":42,"op":"write","path":"/tmp/output.txt","bytes":1024}
{"type":"net","ts":1706000000002,"pid":42,"dir":"egress","proto":"tcp","src":"10.0.0.2:54321","dst":"93.184.216.34:443","bytes":512}
{"type":"proc","ts":1706000000003,"op":"exec","pid":43,"ppid":42,"exe":"/usr/bin/curl","argv":["curl","https://example.com"]}
```

## Event Streaming

SSE endpoint `/jails/:id/events` pushes events in real-time:
- Filterable by event type
- Buffered ring for late-joining clients
- Backpressure via bounded channel

## NixOS Rootfs

Nix flake generating minimal rootfs:
- No systemd, no bootloader, no kernel (host kernel)
- Base: bash, coreutils, curl, ca-certificates
- Agent profiles: +python3, +node, +git, +build-essential
- Output: directory tree for OverlayFS lower
- Rust shells out to `nix build .#rootfs`

## API Surface

```
POST   /jails                     Create jail
GET    /jails                     List jails
GET    /jails/:id                 Status + stats
POST   /jails/:id/start           Start
POST   /jails/:id/stop            Stop
DELETE /jails/:id                 Destroy

POST   /jails/:id/exec            Run command in jail
WS     /jails/:id/terminal        Interactive terminal

GET    /jails/:id/events          SSE stream of all events
GET    /jails/:id/events?type=X   Filtered stream
GET    /jails/:id/report          Full observation report
GET    /jails/:id/fs/diff         Filesystem delta
GET    /jails/:id/network/log     Network log
GET    /jails/:id/processes       Process tree

POST   /jails/:id/snapshot        Snapshot running jail
GET    /jails/:id/snapshots       List snapshots
POST   /snapshots/:sid/restore    Restore → new jail
POST   /snapshots/:sid/branch     Branch → new jail
GET    /snapshots/:sid/diff       Diff snapshot vs current

GET    /health                    Health check
```

## Storage Layout

```
{DATA_DIR}/jails/{id}/
  jail.json                    Config + status
  events/
    syscalls.jsonl
    filesystem.jsonl
    network.jsonl
    processes.jsonl
  snapshots/{sid}/
    metadata.json
    criu-dump/
    fs-upper/
  rootfs/
    lower/
    upper/
    work/
    merged/
```

## Resource Defaults

| Resource | Default | Max |
|----------|---------|-----|
| CPU shares | 256 | 1024 |
| Memory | 512 MB | 8192 MB |
| Disk | 1024 MB | 16384 MB |
| Max PIDs | 128 | 4096 |
| Network | Isolated | FullAccess |

## Port

8082 (after id-service:8080, mock-llm-service:8081)
