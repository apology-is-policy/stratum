/* SPDX-License-Identifier: ISC */
/*
 * test_dataset_pattern — TLY-A2-impl-1 unit tests for the dataset
 * pattern matcher.
 *
 * Covers the glob semantics from
 * v2/docs/thylacine-multi-stratumd-design.md §7 + the policy-table
 * parsing surface from `dataset_pattern.h`.
 */

#include "tharness.h"

#include "../src/cmd/stratumd/dataset_pattern.h"

#include <stratum/types.h>

#include <string.h>
#include <sys/types.h>

/* ────────────────────────────────────────────────────────────────────── */
/* Matcher — literal patterns.                                             */
/* ────────────────────────────────────────────────────────────────────── */

STM_TEST(ds_pattern_literal_exact)
{
    STM_ASSERT(stm_ds_pattern_matches("users/michael", "users/michael"));
}

STM_TEST(ds_pattern_literal_no_substring)
{
    STM_ASSERT_FALSE(stm_ds_pattern_matches("users/michael",
                                              "users/michael2"));
    STM_ASSERT_FALSE(stm_ds_pattern_matches("users/michael",
                                              "users/michael/secret"));
    STM_ASSERT_FALSE(stm_ds_pattern_matches("users/michael", "users"));
    STM_ASSERT_FALSE(stm_ds_pattern_matches("users/michael", "users/"));
}

STM_TEST(ds_pattern_single_component)
{
    STM_ASSERT(stm_ds_pattern_matches("system", "system"));
    STM_ASSERT_FALSE(stm_ds_pattern_matches("system", "system/foo"));
    STM_ASSERT_FALSE(stm_ds_pattern_matches("system", "sys"));
}

/* ────────────────────────────────────────────────────────────────────── */
/* Matcher — single-star (*).                                              */
/* ────────────────────────────────────────────────────────────────────── */

STM_TEST(ds_pattern_star_one_level)
{
    STM_ASSERT(stm_ds_pattern_matches("users/*", "users/michael"));
    STM_ASSERT(stm_ds_pattern_matches("users/*", "users/susan"));
    /* Does NOT match deeper paths. */
    STM_ASSERT_FALSE(stm_ds_pattern_matches("users/*", "users/michael/secret"));
    /* Does NOT match the top-level alone. */
    STM_ASSERT_FALSE(stm_ds_pattern_matches("users/*", "users"));
    STM_ASSERT_FALSE(stm_ds_pattern_matches("users/*", "users/"));
}

STM_TEST(ds_pattern_star_in_middle)
{
    STM_ASSERT(stm_ds_pattern_matches("home/*/docs", "home/michael/docs"));
    STM_ASSERT(stm_ds_pattern_matches("home/*/docs", "home/susan/docs"));
    STM_ASSERT_FALSE(stm_ds_pattern_matches("home/*/docs",
                                              "home/michael/secrets"));
    STM_ASSERT_FALSE(stm_ds_pattern_matches("home/*/docs", "home/docs"));
    STM_ASSERT_FALSE(stm_ds_pattern_matches("home/*/docs",
                                              "home/m/n/docs"));
}

/* ────────────────────────────────────────────────────────────────────── */
/* Matcher — double-star (**).                                             */
/* ────────────────────────────────────────────────────────────────────── */

STM_TEST(ds_pattern_double_star_zero_components)
{
    /* `users/michael/(double-star)` matches `users/michael` (zero
     * trailing components) per the design doc. */
    STM_ASSERT(stm_ds_pattern_matches("users/michael/**", "users/michael"));
}

STM_TEST(ds_pattern_double_star_one_component)
{
    STM_ASSERT(stm_ds_pattern_matches("users/michael/**",
                                         "users/michael/notes"));
}

STM_TEST(ds_pattern_double_star_many_components)
{
    STM_ASSERT(stm_ds_pattern_matches("users/michael/**",
                                         "users/michael/a/b/c"));
}

STM_TEST(ds_pattern_double_star_refuses_sibling)
{
    STM_ASSERT_FALSE(stm_ds_pattern_matches("users/michael/**",
                                              "users/susan"));
    STM_ASSERT_FALSE(stm_ds_pattern_matches("users/michael/**",
                                              "users/susan/notes"));
}

STM_TEST(ds_pattern_top_level_double_star)
{
    /* `users/(double-star)` matches every user + every subpath. */
    STM_ASSERT(stm_ds_pattern_matches("users/**", "users/michael"));
    STM_ASSERT(stm_ds_pattern_matches("users/**", "users/michael/secret"));
    STM_ASSERT(stm_ds_pattern_matches("users/**", "users/anna/photos/2024"));
    /* But not sibling top-levels. */
    STM_ASSERT_FALSE(stm_ds_pattern_matches("users/**", "system"));
}

/* ────────────────────────────────────────────────────────────────────── */
/* Matcher — refusals.                                                     */
/* ────────────────────────────────────────────────────────────────────── */

STM_TEST(ds_pattern_refuses_null)
{
    STM_ASSERT_FALSE(stm_ds_pattern_matches(NULL, "users/michael"));
    STM_ASSERT_FALSE(stm_ds_pattern_matches("users/*", NULL));
    STM_ASSERT_FALSE(stm_ds_pattern_matches(NULL, NULL));
}

STM_TEST(ds_pattern_refuses_empty_name)
{
    STM_ASSERT_FALSE(stm_ds_pattern_matches("users/*", ""));
}

STM_TEST(ds_pattern_refuses_control_byte_in_name)
{
    char with_newline[] = "users/michael";
    with_newline[5] = '\n'; /* "users\nichael" */
    STM_ASSERT_FALSE(stm_ds_pattern_matches("users/*", with_newline));
}

STM_TEST(ds_pattern_utf8_passes_through)
{
    /* UTF-8 multi-byte (≥ 0x80) names allowed. */
    STM_ASSERT(stm_ds_pattern_matches("users/alic\xc3\xa9",
                                         "users/alic\xc3\xa9"));
}

/* ────────────────────────────────────────────────────────────────────── */
/* matches_any.                                                            */
/* ────────────────────────────────────────────────────────────────────── */

STM_TEST(ds_pattern_matches_any_first_match)
{
    const char *pats[] = { "users/michael", "users/michael/**", "system" };
    STM_ASSERT(stm_ds_pattern_matches_any(pats, 3, "users/michael"));
    STM_ASSERT(stm_ds_pattern_matches_any(pats, 3, "users/michael/notes"));
    STM_ASSERT(stm_ds_pattern_matches_any(pats, 3, "system"));
    STM_ASSERT_FALSE(stm_ds_pattern_matches_any(pats, 3, "users/susan"));
}

STM_TEST(ds_pattern_matches_any_empty)
{
    STM_ASSERT_FALSE(stm_ds_pattern_matches_any(NULL, 0, "anything"));
}

/* ────────────────────────────────────────────────────────────────────── */
/* Policy table — parse.                                                   */
/* ────────────────────────────────────────────────────────────────────── */

STM_TEST(ds_policy_parse_single)
{
    stm_ds_policy_table table = {0};
    STM_ASSERT_OK(stm_ds_policy_parse_cli(&table,
                    "uid=1001:users/michael,users/michael/**"));

    STM_ASSERT_EQ((long long)table.n_entries, 1LL);
    STM_ASSERT_EQ((long long)table.entries[0].uid, 1001LL);
    STM_ASSERT_EQ((long long)table.entries[0].n_patterns, 2LL);
    STM_ASSERT(strcmp(table.entries[0].patterns[0], "users/michael") == 0);
    STM_ASSERT(strcmp(table.entries[0].patterns[1], "users/michael/**") == 0);

    stm_ds_policy_table_close(&table);
}

STM_TEST(ds_policy_parse_multiple_uids)
{
    stm_ds_policy_table table = {0};
    STM_ASSERT_OK(stm_ds_policy_parse_cli(&table,
                    "uid=0:system,system/**"));
    STM_ASSERT_OK(stm_ds_policy_parse_cli(&table,
                    "uid=1001:users/michael,users/michael/**"));
    STM_ASSERT_OK(stm_ds_policy_parse_cli(&table,
                    "uid=1002:users/susan,users/susan/**"));
    STM_ASSERT_EQ((long long)table.n_entries, 3LL);
    stm_ds_policy_table_close(&table);
}

STM_TEST(ds_policy_parse_duplicate_uid_refused)
{
    stm_ds_policy_table table = {0};
    STM_ASSERT_OK(stm_ds_policy_parse_cli(&table, "uid=1001:a"));
    STM_ASSERT_ERR(stm_ds_policy_parse_cli(&table, "uid=1001:b"),
                   STM_EEXIST);
    STM_ASSERT_EQ((long long)table.n_entries, 1LL);
    stm_ds_policy_table_close(&table);
}

STM_TEST(ds_policy_parse_refusals)
{
    stm_ds_policy_table table = {0};
    STM_ASSERT_ERR(stm_ds_policy_parse_cli(&table, NULL), STM_EINVAL);
    STM_ASSERT_ERR(stm_ds_policy_parse_cli(NULL, "uid=1:a"), STM_EINVAL);
    STM_ASSERT_ERR(stm_ds_policy_parse_cli(&table, ""), STM_EINVAL);
    STM_ASSERT_ERR(stm_ds_policy_parse_cli(&table, "1001:a"), STM_EINVAL);
    STM_ASSERT_ERR(stm_ds_policy_parse_cli(&table, "uid=:a"), STM_EINVAL);
    STM_ASSERT_ERR(stm_ds_policy_parse_cli(&table, "uid=abc:a"), STM_EINVAL);
    STM_ASSERT_ERR(stm_ds_policy_parse_cli(&table, "uid=1001"), STM_EINVAL);
    STM_ASSERT_ERR(stm_ds_policy_parse_cli(&table, "uid=1001:"), STM_EINVAL);
    STM_ASSERT_ERR(stm_ds_policy_parse_cli(&table, "uid=1001:,a"), STM_EINVAL);
    STM_ASSERT_ERR(stm_ds_policy_parse_cli(&table, "uid=1001:a,"), STM_EINVAL);
    /* Control byte in pattern. */
    STM_ASSERT_ERR(stm_ds_policy_parse_cli(&table, "uid=1001:a\nb"),
                   STM_EINVAL);
    stm_ds_policy_table_close(&table);
}

/* ────────────────────────────────────────────────────────────────────── */
/* Policy admits.                                                          */
/* ────────────────────────────────────────────────────────────────────── */

STM_TEST(ds_policy_admits_basic)
{
    stm_ds_policy_table table = {0};
    STM_ASSERT_OK(stm_ds_policy_parse_cli(&table, "uid=0:system,system/**"));
    STM_ASSERT_OK(stm_ds_policy_parse_cli(&table,
                    "uid=1001:users/michael,users/michael/**"));

    STM_ASSERT(stm_ds_policy_admits(&table, 0, "system"));
    STM_ASSERT(stm_ds_policy_admits(&table, 0, "system/etc"));
    STM_ASSERT_FALSE(stm_ds_policy_admits(&table, 0, "users/michael"));

    STM_ASSERT(stm_ds_policy_admits(&table, 1001, "users/michael"));
    STM_ASSERT(stm_ds_policy_admits(&table, 1001, "users/michael/notes"));
    STM_ASSERT_FALSE(stm_ds_policy_admits(&table, 1001, "users/susan"));

    /* Unknown uid. */
    STM_ASSERT_FALSE(stm_ds_policy_admits(&table, 9999, "system"));

    /* NULL / empty name. */
    STM_ASSERT_FALSE(stm_ds_policy_admits(&table, 0, NULL));

    stm_ds_policy_table_close(&table);
}

STM_TEST(ds_policy_close_is_idempotent_and_null_safe)
{
    stm_ds_policy_table table = {0};
    STM_ASSERT_OK(stm_ds_policy_parse_cli(&table, "uid=1:x"));
    stm_ds_policy_table_close(&table);
    STM_ASSERT_EQ((long long)table.n_entries, 0LL);
    stm_ds_policy_table_close(&table); /* double-close ok */
    stm_ds_policy_table_close(NULL);   /* NULL ok */
}

STM_TEST_MAIN("dataset_pattern")
