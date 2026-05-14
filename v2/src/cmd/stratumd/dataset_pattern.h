/* SPDX-License-Identifier: ISC */
/*
 * Dataset pattern matcher (TLY-A2 — Thylacine multi-stratumd-per-pool).
 *
 * Implements the glob semantics negotiated at THYLACINE-V1-PLAN.md §0
 * Q4 + spelled out in `v2/docs/thylacine-multi-stratumd-design.md §7`:
 *
 *   Components are split on `/`.
 *   `*`  matches any single non-`/` component.
 *   `**` matches zero-or-more components (greedy).
 *   Everything else matches literally.
 *
 * Used in two places:
 *
 *   1. Per-user stratumd (client mode, TLY-A2-impl-2): validates the
 *      kernel's Tattach `aname` against the configured
 *      `--datasets-allowed` patterns BEFORE forwarding to the
 *      coordinator.
 *   2. Coordinator (this chunk, TLY-A2-impl-1): validates an
 *      incoming Tattach's `aname` against the
 *      `--user-policy uid=N:pat1,pat2,...` policy table, indexed by
 *      the SO_PEERCRED-derived uid of the dialing client.
 *
 * Trust boundaries (audit-trigger surface — R139):
 *   - Pure-text input. The `aname` arrives from a 9P client (the
 *     kernel-side mount, OR a peer stratumd in client mode). The
 *     wire layer has already validated the length, but THIS layer
 *     MUST refuse control bytes (R99 P2-1 carry — names containing
 *     bytes < 0x20 or == 0x7F or == 0x00 are refused before any
 *     pattern match runs). UTF-8 multi-byte (≥ 0x80) passes
 *     through unchanged.
 *   - Bounded by STM_DS_PATTERN_NAME_MAX (256 bytes) on both
 *     candidate and pattern. Oversize is refused.
 *   - First-match-wins across the policy's pattern list. The
 *     policy is a finite list of patterns; matching is O(P * N)
 *     where P is the pattern count and N the path component count.
 *     v1.0 expects single-digit pattern counts per uid; no need
 *     for compiled forms.
 */
#ifndef STRATUM_V2_CMD_STRATUMD_DATASET_PATTERN_H
#define STRATUM_V2_CMD_STRATUMD_DATASET_PATTERN_H

#include <stratum/types.h>

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Caps. */
#define STM_DS_PATTERN_NAME_MAX   256u
#define STM_DS_PATTERN_MAX_PER_POLICY  8u
#define STM_DS_PATTERN_MAX_POLICIES    16u

/* ────────────────────────────────────────────────────────────────────── */
/* Matcher.                                                                */
/* ────────────────────────────────────────────────────────────────────── */

/*
 * Match `name` against `pattern`. Both must be NUL-terminated
 * C strings of length ≤ STM_DS_PATTERN_NAME_MAX.
 *
 * Returns:
 *   true   on match.
 *   false  on no-match, OR on any of:
 *     - NULL pointer
 *     - oversize (length > STM_DS_PATTERN_NAME_MAX)
 *     - control byte in `name` (R99 P2-1 carry; pattern is operator-
 *       supplied so trusted, but `name` is wire-derived)
 *     - empty `name` (top-level "" doesn't match anything by design;
 *       use "" or "/" handling at the caller level if root needs
 *       special semantics)
 */
bool stm_ds_pattern_matches(const char *pattern, const char *name);

/*
 * Match `name` against any pattern in the `patterns` array
 * (NULL-terminated array of C strings, OR explicit `count`).
 *
 * Returns true iff at least one pattern matches.
 */
bool stm_ds_pattern_matches_any(const char *const *patterns,
                                  size_t count,
                                  const char *name);

/* ────────────────────────────────────────────────────────────────────── */
/* Policy table.                                                           */
/* ────────────────────────────────────────────────────────────────────── */

typedef struct {
    uid_t   uid;
    /* Pattern strings, owned by the policy. Max
     * STM_DS_PATTERN_MAX_PER_POLICY entries. */
    char   *patterns[STM_DS_PATTERN_MAX_PER_POLICY];
    size_t  n_patterns;
} stm_ds_policy_entry;

typedef struct stm_ds_policy_table {
    stm_ds_policy_entry entries[STM_DS_PATTERN_MAX_POLICIES];
    size_t              n_entries;
} stm_ds_policy_table;

/*
 * Parse one CLI policy string in the form
 * `uid=<N>:<pattern1>,<pattern2>,...` and append to the table.
 *
 * Examples:
 *   "uid=1001:users/michael,users/michael/(double-star)"
 *   "uid=0:system,system/(double-star)"
 * (parenthesised here because nested star-comments confuse clang;
 *  the real syntax is `**`)
 *
 * Refusals (STM_EINVAL):
 *   - NULL table or string
 *   - Missing "uid=" prefix
 *   - Non-numeric / overflow uid
 *   - Missing ":" separator
 *   - Empty pattern list
 *   - Oversize pattern (> STM_DS_PATTERN_NAME_MAX)
 *   - Pattern with control byte
 *   - Duplicate uid (caller must merge upstream)
 *   - Table full (> STM_DS_PATTERN_MAX_POLICIES)
 *   - Per-uid pattern count exceeds STM_DS_PATTERN_MAX_PER_POLICY
 *
 * On STM_OK the table owns the parsed pattern strings (heap-
 * allocated, freed by stm_ds_policy_table_close).
 */
STM_MUST_USE
stm_status stm_ds_policy_parse_cli(stm_ds_policy_table *table,
                                       const char *cli_string);

/*
 * Look up the policy entry for `uid`. Returns NULL if no entry
 * matches.
 */
const stm_ds_policy_entry *stm_ds_policy_lookup(const stm_ds_policy_table *table,
                                                     uid_t uid);

/*
 * Check whether `uid` is admitted to access dataset `name`. Returns:
 *   true  — uid has an entry AND one of its patterns matches name.
 *   false — uid has no entry, OR no pattern matches, OR name fails
 *           the validation in stm_ds_pattern_matches.
 */
bool stm_ds_policy_admits(const stm_ds_policy_table *table,
                              uid_t uid, const char *name);

/*
 * Release all heap allocations owned by the table. After this call
 * the table is zeroed and safe to discard. Safe on NULL.
 */
void stm_ds_policy_table_close(stm_ds_policy_table *table);

#ifdef __cplusplus
}
#endif
#endif /* STRATUM_V2_CMD_STRATUMD_DATASET_PATTERN_H */
