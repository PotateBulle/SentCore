# SentCore

**SentCore** is a Linux endpoint telemetry and behavioral detection engine written in modern C++.
It is designed as a Blue Team / DFIR engineering project with predictable memory usage, bounded queues,
Linux-native collectors, structured telemetry, and an extensible detection layer.

> Status: **v0.1.0 / experimental**. SentCore is not a replacement for a production EDR.

## Features

- C++23 / CMake / Ninja
- procfs process-start collector
- inotify filesystem monitoring
- allocation-free bounded strings in the event hot path
- bounded preallocated event queue
- behavioral detection engine
- MITRE ATT&CK metadata on alerts
- JSONL telemetry and alert output
- ASan + UBSan development preset
- CTest detection tests
- detection micro-benchmark
- clang-format / clang-tidy configuration
- GitHub Actions CI

## Build

```bash
cmake --preset debug
cmake --build --preset debug
ctest --preset debug
```

Sanitized build:

```bash
cmake --preset sanitized
cmake --build --preset sanitized
ctest --preset sanitized
```

Release build:

```bash
cmake --preset release
cmake --build --preset release
```

## Usage

```bash
./build/debug/sentcore help
./build/debug/sentcore version
./build/debug/sentcore self-test
./build/debug/sentcore monitor
```

Monitoring writes:

- `events.jsonl` — normalized host telemetry
- `alerts.jsonl` — matching detections

Press `Ctrl+C` to stop monitoring.

## Built-in detections

| Rule | Description | Severity | ATT&CK |
|---|---|---:|---|
| SC-LNX-001 | Process executed from temporary directory | High | T1059 |
| SC-LNX-002 | Download-and-execute shell chain | Critical | T1105 / T1059 |
| SC-LNX-003 | Shell command references `/dev/tcp` | High | T1059.004 |
| SC-LNX-004 | Base64 decoding in process command line | Medium | T1140 |
| SC-LNX-005 | systemd persistence path modified | High | T1543.002 |
| SC-LNX-006 | SSH `authorized_keys` modified | High | T1098.004 |
| SC-LNX-007 | Executable file created in a temporary directory | High | T1105 |

## Design notes

SentCore intentionally favors a small, auditable architecture over premature complexity. The current queue uses a mutex-protected bounded ring with storage allocated once at startup. That gives predictable memory behavior while keeping the concurrency model easy to reason about and test. Lock-free structures should only be introduced after profiling proves contention is material.

The procfs collector is a bootstrap implementation. It can miss very short-lived processes; eBPF is the planned high-fidelity collector for later versions.

## Roadmap

- eBPF process and network telemetry
- Netlink network collector
- external YAML rule loader
- recursive filesystem watch management
- IOC store
- process tree / event correlation
- SQLite sink
- benchmark suite and profiling baselines

