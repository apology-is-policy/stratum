/* SPDX-License-Identifier: ISC */
/*
 * Dataset pattern matcher implementation. See `dataset_pattern.h` for
 * semantics + trust boundaries.
 *
 * TLY-A2 — Thylacine multi-stratumd-per-pool. Composes against
 * `v2/specs/multi_stratumd.tla`'s `ClientAdmitsDataset` /
 * `CoordAdmitsDataset` actions.
 */

#include "dataset_pattern.h"

#include <stratum/types.h>

#include <ctype.h>
#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* Bound on the per-CLI-string length. The CLI itself is operator-
 * supplied so trusted, but bound-checks are cheap defense-in-depth. */
#define CLI_STRING_MAX  (STM_DS_PATTERN_MAX_PER_POLICY * \
                            STM_DS_PATTERN_NAME_MAX + 64u)

/* ────────────────────────────────────────────────────────────────────── */
/* Helpers.                                                                */
/* ────────────────────────────────────────────────────────────────────── */

/* Validate that every byte is ≥ 0x20 AND ≠ 0x7F AND ≠ 0x00. UTF-8
 * multi-byte (≥ 0x80) passes through. R99 P2-1 doctrine carry. */
static bool name_chars_valid(const char *s, size_t len)
{
    for (size_t i = 0; i < len; i++) {
        uint8_t b = (uint8_t)s[i];
        if (b == 0u || b < 0x20u || b == 0x7Fu) return false;
    }
    return true;
}

/* Find the next '/' (or end of string). Returns the index. */
static size_t next_slash(const char *s, size_t start, size_t end)
{
    for (size_t i = start; i < end; i++) {
        if (s[i] == '/') return i;
    }
    return end;
}

/* ────────────────────────────────────────────────────────────────────── */
/* Glob matcher.                                                           */
/*                                                                          */
/* The grammar:                                                             */
/*   pattern  ::= component ("/" component)*                                */
/*   component ::= "**" | "*" | literal                                     */
/*                                                                          */
/* The matcher is a simple recursive descent. "**" consumes zero-or-more    */
/* full components greedily; the recursion tries each consume length.       */
/* For typical patterns (≤4 components, ≤2 wildcards) this is O(N).         */
/* ────────────────────────────────────────────────────────────────────── */

static bool match_recursive(const char *pat, size_t pat_pos, size_t pat_end,
                             const char *name, size_t name_pos, size_t name_end);

static bool match_component(const char *pat, size_t pat_s, size_t pat_e,
                              const char *name, size_t name_s, size_t name_e)
{
    /* "**" wildcard component handled in the caller (recursive descent).
     * "*" matches any single non-empty component (i.e. name span is
     * non-empty + contains no '/' — which is guaranteed by next_slash). */
    if (pat_e - pat_s == 1 && pat[pat_s] == '*') {
        return (name_e - name_s) > 0;
    }
    /* Literal component — bytewise equality. */
    size_t pl = pat_e - pat_s;
    size_t nl = name_e - name_s;
    if (pl != nl) return false;
    return memcmp(pat + pat_s, name + name_s, pl) == 0;
}

static bool match_recursive(const char *pat, size_t pat_pos, size_t pat_end,
                             const char *name, size_t name_pos, size_t name_end)
{
    /* Both consumed → match. */
    if (pat_pos == pat_end && name_pos == name_end) return true;

    /* Pattern done but name remains → no match (unless pattern ended
     * on a `**` — handled below via the greedy split). */
    if (pat_pos == pat_end) return false;

    /* Find this component's end in both pat + name. */
    size_t pat_comp_end  = next_slash(pat, pat_pos, pat_end);
    /* If "**" — try every possible name-prefix length (zero up to all
     * remaining components). */
    bool is_double_star = (pat_comp_end - pat_pos == 2) &&
                            pat[pat_pos] == '*' && pat[pat_pos + 1] == '*';
    if (is_double_star) {
        /* Advance past "**" and the optional following '/'. */
        size_t next_pat = pat_comp_end;
        if (next_pat < pat_end && pat[next_pat] == '/') next_pat++;

        /* Try every possible split: ** matches 0 components, 1
         * component, ... up to all remaining components. */
        size_t cursor = name_pos;
        while (1) {
            if (match_recursive(pat, next_pat, pat_end,
                                  name, cursor, name_end)) {
                return true;
            }
            if (cursor >= name_end) break;
            /* Advance past next component. */
            size_t next_slash_pos = next_slash(name, cursor, name_end);
            cursor = next_slash_pos;
            if (cursor < name_end) cursor++; /* skip '/' */
        }
        return false;
    }

    /* Regular component: name must have a component here too. */
    if (name_pos == name_end) return false;
    size_t name_comp_end = next_slash(name, name_pos, name_end);
    if (!match_component(pat, pat_pos, pat_comp_end,
                            name, name_pos, name_comp_end)) {
        return false;
    }
    /* Both components consumed; if there's a '/' in pat, it MUST be
     * followed by another component in name. */
    size_t next_pat  = pat_comp_end;
    size_t next_name = name_comp_end;
    if (next_pat < pat_end && pat[next_pat] == '/') next_pat++;
    if (next_name < name_end && name[next_name] == '/') next_name++;
    return match_recursive(pat, next_pat, pat_end,
                              name, next_name, name_end);
}

bool stm_ds_pattern_matches(const char *pattern, const char *name)
{
    if (!pattern || !name) return false;

    size_t pat_len  = strnlen(pattern, STM_DS_PATTERN_NAME_MAX + 1u);
    size_t name_len = strnlen(name,    STM_DS_PATTERN_NAME_MAX + 1u);
    if (pat_len > STM_DS_PATTERN_NAME_MAX) return false;
    if (name_len > STM_DS_PATTERN_NAME_MAX) return false;
    if (name_len == 0) return false;

    /* Pattern is operator-supplied + already-validated at parse time;
     * we re-check name here only. */
    if (!name_chars_valid(name, name_len)) return false;

    return match_recursive(pattern, 0, pat_len, name, 0, name_len);
}

bool stm_ds_pattern_matches_any(const char *const *patterns, size_t count,
                                  const char *name)
{
    if (!patterns || !name) return false;
    for (size_t i = 0; i < count; i++) {
        if (stm_ds_pattern_matches(patterns[i], name)) return true;
    }
    return false;
}

/* ────────────────────────────────────────────────────────────────────── */
/* Policy table.                                                           */
/* ────────────────────────────────────────────────────────────────────── */

static char *dup_bounded(const char *s, size_t len)
{
    if (len > STM_DS_PATTERN_NAME_MAX) return NULL;
    char *p = malloc(len + 1u);
    if (!p) return NULL;
    memcpy(p, s, len);
    p[len] = '\0';
    return p;
}

const stm_ds_policy_entry *
stm_ds_policy_lookup(const stm_ds_policy_table *table, uid_t uid)
{
    if (!table) return NULL;
    for (size_t i = 0; i < table->n_entries; i++) {
        if (table->entries[i].uid == uid) return &table->entries[i];
    }
    return NULL;
}

bool stm_ds_policy_admits(const stm_ds_policy_table *table,
                              uid_t uid, const char *name)
{
    if (!table || !name) return false;
    const stm_ds_policy_entry *e = stm_ds_policy_lookup(table, uid);
    if (!e) return false;
    return stm_ds_pattern_matches_any((const char *const *)e->patterns,
                                          e->n_patterns, name);
}

void stm_ds_policy_table_close(stm_ds_policy_table *table)
{
    if (!table) return;
    for (size_t i = 0; i < table->n_entries; i++) {
        stm_ds_policy_entry *e = &table->entries[i];
        for (size_t j = 0; j < e->n_patterns; j++) {
            free(e->patterns[j]);
            e->patterns[j] = NULL;
        }
        e->n_patterns = 0;
    }
    table->n_entries = 0;
}

stm_status stm_ds_policy_parse_cli(stm_ds_policy_table *table,
                                       const char *cli_string)
{
    if (!table || !cli_string) return STM_EINVAL;

    size_t cli_len = strnlen(cli_string, CLI_STRING_MAX + 1u);
    if (cli_len > CLI_STRING_MAX) return STM_EINVAL;
    if (cli_len == 0) return STM_EINVAL;

    /* Must start with "uid=". */
    if (cli_len < 4 || memcmp(cli_string, "uid=", 4) != 0)
        return STM_EINVAL;

    /* Parse uid: digits only until ':'. */
    size_t cursor = 4;
    unsigned long long uid_val = 0;
    bool any_digit = false;
    while (cursor < cli_len && cli_string[cursor] != ':') {
        char ch = cli_string[cursor];
        if (ch < '0' || ch > '9') return STM_EINVAL;
        unsigned long long next = uid_val * 10ull + (unsigned)(ch - '0');
        if (next < uid_val) return STM_EOVERFLOW;
        uid_val = next;
        any_digit = true;
        cursor++;
    }
    if (!any_digit) return STM_EINVAL;
    if (uid_val > (unsigned long long)((uid_t)-2)) return STM_EOVERFLOW;
    if (cursor >= cli_len || cli_string[cursor] != ':') return STM_EINVAL;
    cursor++; /* skip ':' */

    if (cursor >= cli_len) return STM_EINVAL; /* empty pattern list */

    /* Duplicate-uid refusal. */
    if (stm_ds_policy_lookup(table, (uid_t)uid_val) != NULL)
        return STM_EEXIST;

    /* Table-full refusal. */
    if (table->n_entries >= STM_DS_PATTERN_MAX_POLICIES)
        return STM_ENOSPC;

    /* Parse the comma-separated pattern list into a fresh entry. We
     * stage patterns in a local scratch then copy on success — so a
     * mid-parse failure doesn't leave the table partially mutated. */
    char  *scratch[STM_DS_PATTERN_MAX_PER_POLICY] = {0};
    size_t n_scratch = 0;
    stm_status rc = STM_OK;

    size_t start = cursor;
    while (cursor <= cli_len) {
        bool at_end = (cursor == cli_len);
        if (cursor == cli_len || cli_string[cursor] == ',') {
            size_t plen = cursor - start;
            if (plen == 0) { rc = STM_EINVAL; goto out; }
            if (plen > STM_DS_PATTERN_NAME_MAX) {
                rc = STM_EINVAL; goto out;
            }
            if (!name_chars_valid(cli_string + start, plen)) {
                rc = STM_EINVAL; goto out;
            }
            if (n_scratch >= STM_DS_PATTERN_MAX_PER_POLICY) {
                rc = STM_ENOSPC; goto out;
            }
            scratch[n_scratch] = dup_bounded(cli_string + start, plen);
            if (!scratch[n_scratch]) { rc = STM_ENOMEM; goto out; }
            n_scratch++;
            cursor++;
            start = cursor;
            if (at_end) break;
        } else {
            cursor++;
        }
    }
    if (n_scratch == 0) { rc = STM_EINVAL; goto out; }

    /* Commit. */
    stm_ds_policy_entry *e = &table->entries[table->n_entries];
    e->uid = (uid_t)uid_val;
    e->n_patterns = n_scratch;
    for (size_t i = 0; i < n_scratch; i++) {
        e->patterns[i] = scratch[i];
        scratch[i] = NULL;
    }
    table->n_entries++;
    return STM_OK;

out:
    /* Rollback: free any staged patterns. */
    for (size_t i = 0; i < STM_DS_PATTERN_MAX_PER_POLICY; i++) {
        free(scratch[i]);
        scratch[i] = NULL;
    }
    return rc;
}
