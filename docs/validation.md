# Validation report — v0.1.0

The source package was validated before packaging with Clang 17, CMake 3.31 and Ninja 1.12 on Linux.

Validated operations:

- Debug configuration and build
- Detection unit tests through CTest
- AddressSanitizer + UndefinedBehaviorSanitizer build and tests
- Release build
- Built-in CLI self-test
- Live inotify monitoring smoke test
- JSONL alert generation smoke test
- Release detection-engine micro-benchmark

Observed release micro-benchmark on the validation host:

- `sizeof(Event)`: 1280 bytes
- 1,000,000 rule evaluations
- approximately 3.64 million evaluations/second

Benchmark numbers are machine-dependent and are included only as a smoke-test baseline, not as a performance guarantee.
