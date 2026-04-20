# Stratum v2 formal specs

TLA+ models of load-bearing invariants. Each spec accompanies a subsystem and
is exercised by TLC in CI.

## Current specs

| File             | Spec                  | Status  | Phase | Subject of ARCH |
|------------------|-----------------------|---------|-------|-----------------|
| `sync.tla`       | four-phase commit     | landed  | P1    | §3.7, §5.6      |
| `concurrency.tla`| MVCC + EBR + deltas   | landed  | P2    | §3.3, §3.4, §3.6|
| `nonce.tla`      | AEAD nonce uniqueness | stub    | P3    | §7.4            |
| `allocator.tla`  | refcount MVCC         | stub    | P3    | §6.4            |
| `merkle.tla`     | hash propagation      | stub    | P4    | §7.11, §7.12    |
| `quorum.tla`     | multi-device commit   | stub    | P5    | §5.6            |
| `structural.tla` | split atomicity + cascade | landed | P2 | §3.5         |
| `balanced.tla`   | parent-pivot update   | landed  | P2    | §3.5            |
| `merge.tla`      | empty-leaf reabsorb   | landed  | P2    | §3.5            |
| `allocator.tla`  | refcount + deferred-free | landed | P3 | §6.4, §6.7      |
| `namespace.tla`  | per-conn isolation    | stub    | P8    | §8.8            |

## Running TLC locally

1. Install TLA+ toolbox or just the command-line TLC:
   ```
   brew install tla-plus-tools         # macOS
   # or download tla2tools.jar: https://github.com/tlaplus/tlaplus/releases
   ```

2. Check a spec:
   ```
   tlc -config sync.cfg sync.tla
   ```

3. Interpret output. Green = all invariants hold across all explored states.
   Red = a counter-example trace; fix the spec or the implementation.

## SPEC-TO-CODE mapping

Specs are the source of truth for protocol-level invariants. The
implementation is an instance of the spec. The mapping from spec variables
to code structures lives in `../docs/specs/SPEC-TO-CODE.md` and is updated
in the same PR as the corresponding code changes.

## Running in CI

`ci/github-actions.yml` installs TLC and runs `tlc -config <spec>.cfg <spec>.tla`
on every PR touching `specs/` or the code under the spec's scope (per the
audit-trigger table).
