# SentCore Architecture

SentCore v0.1.0 uses a deliberately small Linux-native pipeline:

1. `ProcessCollector` samples procfs and emits newly observed processes.
2. `FilesystemCollector` receives kernel file notifications through inotify.
3. Both collectors submit normalized, bounded `Event` objects to `EventQueue`.
4. The main engine writes telemetry to JSONL and evaluates built-in behavioral rules.
5. Matching rules produce `Alert` records, also written as JSONL.

## Memory model

The hot-path `Event` object uses bounded `FixedString` fields. This makes event size predictable and avoids per-event heap allocation for path and command-line data. The queue allocates its backing storage once during startup and is bounded to protect the agent from unbounded memory growth during bursts.

## Current limitations

Process collection is polling-based and can miss extremely short-lived processes. A future collector can replace procfs polling with eBPF without changing the normalized event interface. inotify watches are non-recursive in v0.1.0.
