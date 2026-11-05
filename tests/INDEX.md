# v2/tests INDEX

Quick reference for which test file covers which feature. Optimized
for context efficiency: when you need to read tests for a feature,
read just the file pointed at here.

## fs-layer suites

`tests/test_fs_common.{h,c}` — shared lifecycle helpers
(`make_tmp` / `default_format_opts` / `rw_mount_opts` /
`g_tmp_path` / `g_key_path` / TEST_DEVICE_BYTES). Linked into
both fs test executables.

### `tests/test_fs.c` — Phase 1-7 fs surface (~7100 lines, 159 tests)

| Section | First test | Approx line |
|---|---|---|
| Lifecycle | `fs_format_mount_unmount_roundtrip` | 30 |
| Basic I/O | `fs_io_write_read_roundtrip` | 330 |
| Scrub | `fs_io_scrub_production_cb_verifies_extents` | 620 |
| Truncate (extent) | `fs_truncate_inside_extent_shrinks_prefix` | 815 |
| Per-dataset DEK / keyschema | `fs_io_per_dataset_dek_rotation_roundtrip` | 1020 |
| Dataset creation | `fs_create_dataset_basic_write_read_roundtrip` | 1230 |
| Snapshot interaction | `fs_snap_chain_inversion_on_disk_refused_at_mount` | 1480 |
| Repair log | `fs_repair_log_persists_emit_across_mount` | 1545 |
| Reflink | `fs_reflink_basic_share` | 1610 |
| P7-CAS-2 migrate-to-cold | `fs_migrate_to_cold_basic_roundtrip` | 2010 |
| P7-CAS-3..17 (rest of Phase 7) | various `fs_p7cas*_*` | up through line 7000 |

### `tests/test_fs_phase8.c` — Phase 8 POSIX surface (~6200 lines, 163 tests)

P8-internal helpers (`p2b_alloc_root_dir` / `fs_p7a_now_sec` /
`p7a_seals_setup` / `p10b_setup_named_pair`) live inline at the
top of this file — they're only used here.

| Sub-chunk | First test | Approx line |
|---|---|---|
| P8-POSIX-2b lookup/create/mkdir/unlink/rmdir | `fs_p2b_lookup_returns_enoent_when_unlinked` | ~70 |
| P8-POSIX-3 stat/chmod/chown/utimens/link | `fs_p3_stat_basic` | ~550 |
| P8-POSIX-4 readdir cursor stability | `fs_p4_readdir_*` | ~840 |
| P8-POSIX-5 inline data | `fs_p5_inline_*` | ~1430 |
| P8-POSIX-6 xattr (fs-level) | `fs_p6_setxattr_*` | ~2330 |
| P8-POSIX-8 symlinks | `fs_p8_symlink_*` | ~2940 |
| P8-POSIX-10 truncate (inode-aware) | `fs_p10_truncate_*` | ~3170 |
| P8-POSIX-9 rename MVP | `fs_p9_rename_*` | ~3380 |
| P8-POSIX-7a-statx ctime/mtime/btime stamping | `fs_p7a_create_stamps_*` | ~3510 |
| P8-POSIX-7a-seals F_SEAL_* | `fs_p7a_seals_*` | ~3980 |
| P8-POSIX-7c file handles | `fs_p7c_handle_*` | ~4720 |
| P8-POSIX-10b copy_file_range / reflink stamping | `fs_p10b_*` | ~5360 |
| P8-POSIX-7a-anon O_TMPFILE | `fs_p7a_anon_*` | ~5730 |
| P8-POSIX-9b RENAME_EXCHANGE | `fs_p9b_rename_exchange_*` | ~6080 |

## Other test suites

| File | Coverage |
|---|---|
| `test_inode.c` | Inode allocator (P8-POSIX-1/1b + 7a-anon orphan tests) |
| `test_dirent.c` | Dirent layer (P8-POSIX-2/4 + 9b Swap) |
| `test_xattr.c` | Xattr layer (P8-POSIX-6) |
| `test_sync.c` | Single-device sync layer + commit |
| `test_sync_multi.c` | Multi-device commit / quorum |
| `test_extent.c` | Extent records |
| `test_extent_index.c` | Extent index Bε-tree |
| `test_cas_index.c` | CAS index |
| `test_send_recv.c` | Send/recv replication |
| `test_dataset.c` | Dataset hierarchy + properties |
| `test_snapshot.c` | Snapshot creation + dead-list |
| `test_scrub.c` | Scrubber + Merkle verification |
| `test_repair_log.c` | Repair log |
| `test_pool.c` | Pool / roster / multi-device |
| `test_p9.c` | 9P wire (deferred to Phase 9) |
| `test_janus.c` | Janus daemon |
| `test_keyschema_rotate.c` | Key rotation |
| `test_crash_inject.c` | Crash-injection fuzzer |
| `test_btree*` | Bε-tree primitives |
| `test_alloc*` | Allocator |
| `test_bdev*` | Block device |
| `test_crypto.c` / `test_hash.c` / `test_hybrid.c` | Crypto primitives |

## Conventions

- Every test executable runs in its own process (per-process state
  via globals; `make_tmp()` refreshes per-test).
- Each test names its tmpfile with a unique tag (PID + tag) to
  avoid cross-test interference.
- All tests format/mount/unmount per test (~150ms wall under
  ASan/TSan); a full single-suite run is ~40-50s wall.
- ctest timeout default is 60s; `test_fs`, `test_fs_phase8`, and
  `test_crash_inject` have explicit timeout extensions.
