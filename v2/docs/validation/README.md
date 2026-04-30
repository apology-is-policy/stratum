# v2 validation artifacts

Empirical evidence that ROADMAP exit criteria are met. Distinct from
benchmarks (which characterize ongoing performance) — these are
one-shot validation runs against specific phase exit gates.

## Layout

Each artifact is a (csv, md) pair in this directory:

- `<milestone>-<date>.csv` — machine-readable raw data.
- `<milestone>-<date>.md` — interpretation: tip hash, environment, what
  was being validated, what the data shows.

Naming convention: lowercase milestone identifier + ISO date.
Examples: `p7val1-dedup-2026-04-30.csv`, `p9-zfs-comparison-2027-XX-XX.csv`.

## Artifacts

| Artifact | Date | Validates | Verdict |
|---|---|---|---|
| [p7val1-dedup-2026-04-30](p7val1-dedup-2026-04-30.md) | 2026-04-30 | ROADMAP §10.2 exit criterion 1 (3-5× dedup on VM-image set) | **MET** — 4 configurations all in 3.21×-4.47× band |
| [p7val2-reflink-2026-04-30](p7val2-reflink-2026-04-30.md) | 2026-04-30 | ROADMAP §10.2 exit criterion 4 (reflink O(extent count) not O(data size)) | **MET** — wall-clock independent of bytes (1.24× over 256× byte-volume change); grows with extent count (7.34× ns/extent ratio over 1024× extent-count change) |
| [p7val3-sendrecv-snap-2026-04-30](p7val3-sendrecv-snap-2026-04-30.md) | 2026-04-30 | ROADMAP §10.2 exit criterion 3 (send/recv preserves data + metadata + snapshots) | **MET** — 3 new integration tests exercise full + chained-incremental snapshot pipeline, HOT/COLD kind preservation, cross-ino dedup preservation; all green under default + ASan + TSan |

## Adding a new artifact

1. Run the bench / harness on a controlled environment.
2. Capture CSV output + record the tip hash + environment metadata.
3. Drop both into this directory under the naming convention.
4. Add a row to the table above.
5. If the artifact validates a phase exit criterion, update the
   corresponding `phase{N}-status.md` to mark that criterion as
   empirically met.
