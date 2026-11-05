/* SPDX-License-Identifier: ISC */
/*
 * Type-tagged metadata-key encoding — implementation.
 *
 * The single chokepoint for the 1-byte tag prefix per
 * docs/phase-9.7-design.md §2.1.
 *
 * Lockstep with stm_metakey_parse (decoder-side bounds check) per
 * the R71 P1-1 doctrine: a foreign tag byte at parse → STM_ECORRUPT.
 */
#include <stratum/metakey.h>

#include <string.h>

static bool metakey_kind_valid(unsigned k) {
    return k >= (unsigned)STM_METAKEY_KIND_MIN
        && k <= (unsigned)STM_METAKEY_KIND_MAX;
}

stm_status stm_metakey_compose(stm_metakey_kind kind,
                                 const uint8_t *body, size_t body_len,
                                 uint8_t *out, size_t out_cap,
                                 size_t *out_len) {
    if (out == NULL || out_len == NULL) return STM_EINVAL;
    if (body == NULL && body_len > 0) return STM_EINVAL;
    if (!metakey_kind_valid((unsigned)kind)) return STM_EINVAL;

    size_t need = STM_METAKEY_TAG_LEN + body_len;
    /* Defense-in-depth on size_t overflow: body_len near SIZE_MAX
     * would wrap need to a small value. The TAG_LEN==1 case can't
     * actually overflow before body_len itself overflows the caller's
     * buffer, but spelling the check keeps the chokepoint honest. */
    if (need < body_len) return STM_EINVAL;
    if (out_cap < need) return STM_ENOSPC;

    out[0] = (uint8_t)kind;
    if (body_len > 0) {
        memcpy(out + STM_METAKEY_TAG_LEN, body, body_len);
    }
    *out_len = need;
    return STM_OK;
}

stm_status stm_metakey_parse(const uint8_t *in, size_t in_len,
                                stm_metakey_kind *out_kind,
                                const uint8_t **out_body,
                                size_t *out_body_len) {
    if (in == NULL) return STM_EINVAL;
    if (out_kind == NULL || out_body == NULL || out_body_len == NULL) {
        return STM_EINVAL;
    }
    if (in_len < STM_METAKEY_TAG_LEN) return STM_ECORRUPT;

    unsigned tag = (unsigned)in[0];
    if (!metakey_kind_valid(tag)) return STM_ECORRUPT;

    *out_kind = (stm_metakey_kind)tag;
    *out_body = in + STM_METAKEY_TAG_LEN;
    *out_body_len = in_len - STM_METAKEY_TAG_LEN;
    return STM_OK;
}
