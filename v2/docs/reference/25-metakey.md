# 25 — Type-Tagged Metadata Keys (`stm_metakey`)

## Purpose

`stm_metakey` is the **single chokepoint** for encoding the 1-byte
type-tag prefix that discriminates per-record-kind subspaces inside a
single per-dataset `btree_engine` instance.

Under Phase 9.7's D1 design, each dataset owns ONE `btree_engine`
holding four logically-distinct record kinds — inodes, dirents,
xattrs, extent records — co-resident in one keyspace. They are
disambiguated by a leading tag byte. The pool-global Phase 9.6
arrangement (four trees, each keyed by `(dataset_id, ...)` composite
keys) is retired in 9.7-impl-1c.

This file documents the lib that lands at **9.7-impl-1a** — the lib
itself with NO callers yet. The four metadata modules pick up the
new key shape at **9.7-impl-1c**.

## Where it sits

```
  inode / dirent / xattr / extent_index   (consumers — 9.7-impl-1c)
                  |
              stm_metakey               <-- this layer
                  |  (1-byte tag prefix)
                  V
           per-dataset btree_engine     (24-btree-engine.md)
```

The lib is a pure byte-shuffling library — no allocation, no crypto,
no I/O. It owns nothing beyond the wire-format of the tag byte. By
design, complexity that wants to live here belongs in the calling
module's per-kind body codec instead (e.g., inode value
encode/decode stays in `v2/src/inode/`, not here).

## Public API

`include/stratum/metakey.h`. Two functions, one enum.

### Enum

```c
typedef enum {
    STM_METAKEY_KIND_INODE   = 0x01,
    STM_METAKEY_KIND_DIRENT  = 0x02,
    STM_METAKEY_KIND_XATTR   = 0x03,
    STM_METAKEY_KIND_EXTENT  = 0x04,
} stm_metakey_kind;
```

Plus the constants `STM_METAKEY_KIND_MIN` (= INODE) and
`STM_METAKEY_KIND_MAX` (= EXTENT), and `STM_METAKEY_TAG_LEN` (= 1).

Tag values are STABLE across versions. Adding a kind:

1. Append the new enum value (keep INODE..EXTENT contiguous).
2. Extend `STM_METAKEY_KIND_MAX`.
3. The kind-validity check in both `stm_metakey_compose` and
   `stm_metakey_parse` picks up the new bound automatically.
4. Bump `STM_UB_VERSION` if the new kind affects on-disk layout.

### `stm_metakey_compose`

```c
stm_status stm_metakey_compose(stm_metakey_kind kind,
                                 const uint8_t *body, size_t body_len,
                                 uint8_t *out, size_t out_cap,
                                 size_t *out_len);
```

Writes the tag byte at `out[0]`, then copies `body[0..body_len)` to
`out[1..1+body_len)`. Returns the total length via `*out_len` on
success.

Refusals (writer-side bounds, symmetric to the parser):

- Kind outside `[STM_METAKEY_KIND_MIN, STM_METAKEY_KIND_MAX]` →
  `STM_EINVAL`.
- `out == NULL` or `out_len == NULL` → `STM_EINVAL`.
- `body == NULL && body_len > 0` → `STM_EINVAL`.
- `out_cap < STM_METAKEY_TAG_LEN + body_len` → `STM_ENOSPC` (no bytes
  written).

`body_len == 0` is legal — a degenerate "tag-only" key.

### `stm_metakey_parse`

```c
stm_status stm_metakey_parse(const uint8_t *in, size_t in_len,
                                stm_metakey_kind *out_kind,
                                const uint8_t **out_body,
                                size_t *out_body_len);
```

Reads the tag byte at `in[0]`, exposes the body via `*out_body` /
`*out_body_len`. The body pointer is a **non-owning view** into the
input buffer — caller MUST NOT outlive `in`.

Refusals (decoder-side bounds, symmetric to the composer):

- `in == NULL` → `STM_EINVAL`.
- `in_len < STM_METAKEY_TAG_LEN` → `STM_ECORRUPT` (no room for tag).
- `in[0]` outside `[STM_METAKEY_KIND_MIN, STM_METAKEY_KIND_MAX]` →
  `STM_ECORRUPT` (on-disk tag byte names a kind this binary doesn't
  know). R71 P1-1 doctrine carry — the decoder refuses-loud rather
  than mis-route to the wrong record-type's decoder.
- Any of `out_kind`/`out_body`/`out_body_len` NULL → `STM_EINVAL`.

## Invariants

### Symmetric bounds (R71 P1-1 doctrine)

Writer-side `stm_metakey_compose` and decoder-side `stm_metakey_parse`
consult the SAME `STM_METAKEY_KIND_MIN` / `STM_METAKEY_KIND_MAX`
constants. A future kind addition extends both gates in lockstep
(adding a value to the enum AND bumping `STM_METAKEY_KIND_MAX` is
one atomic source change).

The compose-side refusal class is `STM_EINVAL` (programmer error —
caller passed a foreign byte through the enum); the parse-side class
is `STM_ECORRUPT` (on-disk tampering or version mismatch). Different
return codes name different blame.

### Tag-byte dominates lex order

The tag byte is at offset 0. Lexicographic byte comparison on
composed keys sorts:

1. By tag (so all INODE keys precede all DIRENT keys precede all
   XATTR keys precede all EXTENT keys, regardless of body bytes).
2. Within a tag, by body bytes (whatever ordering the body imposes —
   inode keys are ordered by big-endian ino, etc.).

This is the property the engine's `scan_range` relies on to
enumerate one record kind at a time: `[0x01 ‖ 0]..[0x02 ‖ 0]` is
exactly the inode subspace of a dataset.

A unit test (`metakey_tag_dominates_lex_order`) pins this invariant
with a HIGH-body inode key against a LOW-body extent key — the tag
forces inode < extent.

### Non-owning body view

`stm_metakey_parse`'s `out_body` is `in + STM_METAKEY_TAG_LEN`. The
caller MUST NOT outlive the input buffer. Pattern at call sites:

```c
const uint8_t *body; size_t body_len;
stm_metakey_kind kind;
stm_status s = stm_metakey_parse(rec, rec_len, &kind, &body, &body_len);
if (s != STM_OK) return s;
switch (kind) {
case STM_METAKEY_KIND_INODE:
    return decode_inode_body(body, body_len, out_record);
/* ... */
}
```

The body is consumed inline within the same scope as the parse call;
no caching, no retaining.

## Wire format

```
  offset  size   field
  ------  -----  ------------------------------------
       0      1  tag byte
       1      N  body (kind-specific layout, opaque
                 to this lib)
```

The full key is `STM_METAKEY_TAG_LEN + N == 1 + N` bytes. The
`btree_engine` sees this as one opaque key; its lex-order discipline
holds because the tag byte is at offset 0.

### Per-kind body shapes (consumer responsibility)

Documented here for reference; the metakey lib doesn't know them.
The shapes are pinned by their respective consumer modules at
9.7-impl-1c.

| Kind | Body |
|---|---|
| INODE | `ino(8)` — inode id, big-endian |
| DIRENT | `dir_ino(8) ‖ hash(N)` — open-address chain |
| XATTR | `ino(8) ‖ hash(N)` — open-address chain |
| EXTENT | `ino(8) ‖ offset(8)` — both big-endian |

Big-endian throughout so lex byte order == logical order.

## Spec composition

The type-tag is part of the key the engine sees. `btree.tla` treats
keys as opaque byte strings; the lex-order invariant holds because
the tag byte dominates at offset 0.

No new spec is needed for this lib. The single byte's wire format is
self-evident from the test surface; the composition over `btree.tla`
is verified by the consumer modules' tests at 9.7-impl-1c.

## Tests

`v2/tests/test_metakey.c` — 16 test cases. Roundtrip across every
kind; refusal sweep across every invalid input class; lex-order
property assertion.

## Snapshot

| | |
|---|---|
| Tip | 9.7-impl-1a (foundation chunk) |
| LOC | ~60 lines of impl + ~50 lines of header docs |
| Tests | 16 in `test_metakey.c` |
| Callers | none yet (consumers wire in at 9.7-impl-1c) |
| Spec | composed under `btree.tla` (opaque-key contract) |
