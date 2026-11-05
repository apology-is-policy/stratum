/* SPDX-License-Identifier: ISC */
/*
 * corvus_client — Thylacine corvus key-agent client (TLY-A3).
 *
 * Sibling to (NOT replacing) the existing janus client. Speaks
 * corvus's binary frame wire format with state-file magic `CRVS`
 * (distinct from janus's `JPAS`) per `CORVUS-DESIGN.md §6.4` +
 * `STRATUM-API-V1.md §5`.
 *
 * Surface (this header):
 *
 *   1. **UNWRAP codec** — encode a request frame (session token +
 *      dataset path + key_id + wrapped-DEK blob); decode a response
 *      frame (status byte + optional 32-byte DEK payload).
 *
 *   2. **WRAP codec** (TLY-A3-keyslot-wrap) — encode a request frame
 *      (session token + dataset path + key_id + 32-byte PLAINTEXT
 *      DEK to seal); decode a response frame (status byte + optional
 *      opaque DEK-envelope payload, ~1217 bytes). Provisioning-time
 *      counterpart to UNWRAP: WRAP *produces* the corvus-sealed
 *      envelope that a CORVUS keyslot stores and UNWRAP later
 *      *consumes*.
 *
 *   3. **Transport + retry** — synchronous AF_UNIX dial + bounded
 *      send/recv + the spec-fixed retry schedule, for both verbs.
 *
 *   4. **Session token loader** — read 33 bytes from a path,
 *      `mlock`(2) the buffer, `MADV_DONTDUMP` (Linux) to keep it
 *      out of core dumps. Caller `explicit_bzero`s + frees on
 *      shutdown.
 *
 * Out of scope: DEK caching — the live DEK is lifted into
 * `stm_sync` / per-dataset state by the mount + provisioning paths,
 * not this module.
 *
 * UNWRAP wire format (request — 4-byte versioned header):
 *
 *   [0]       verb_id          u8 = STM_CORVUS_VERB_UNWRAP (4)
 *   [1]       protocol_version u8 = STM_CORVUS_PROTO_V1 (1)
 *   [2..4)    payload_len      u16 LE (count of bytes [4..end))
 *   [4..37)   token            33 bytes ("s" prefix + 32 hex)
 *   [37]      dataset_len      u8 (0..255)
 *   [38..38+dl) dataset        dataset_len utf-8 bytes
 *   [38+dl..46+dl) key_id      u64 LE
 *   [46+dl..48+dl) wrapped_len u16 LE
 *   [48+dl..)  wrapped         wrapped_len opaque bytes
 *
 * UNWRAP wire format (response — 3-byte header, unversioned):
 *
 *   [0]       status           u8  (STM_CORVUS_STATUS_OK = 0, ...)
 *   [1..3)    payload_len      u16 LE
 *   [3..)     payload          on status=0: exactly 32 bytes (DEK)
 *                              else: 0 bytes
 *
 * WRAP wire format (request — same 4-byte versioned header):
 *
 *   [0]       verb_id          u8 = STM_CORVUS_VERB_WRAP (10)
 *   [1]       protocol_version u8 = STM_CORVUS_PROTO_V1 (1)
 *   [2..4)    payload_len      u16 LE (count of bytes [4..end))
 *   [4..37)   token            33 bytes (session token, verbatim)
 *   [37]      dataset_len      u8 (1..255 — a WRAP must bind a path)
 *   [38..38+dl) dataset        dataset_len utf-8 bytes
 *   [38+dl..46+dl) key_id      u64 LE
 *   [46+dl..48+dl) dek_len     u16 LE (always == 32)
 *   [48+dl..80+dl) dek         32 bytes — PLAINTEXT DEK to seal
 *
 * WRAP wire format (response — 3-byte header, unversioned):
 *
 *   [0]       status           u8  (same enum as UNWRAP)
 *   [1..3)    payload_len      u16 LE
 *   [3..)     payload          on status=0: the opaque DEK envelope
 *                              (~1217 bytes, ≤ STM_CORVUS_ENVELOPE_MAX);
 *                              else: 0 bytes
 *
 * Trust boundaries (audit-trigger surface — R144):
 *
 *   - Wire encode: bound-check every input length BEFORE building
 *     the frame; refuse oversize on dataset_len > 255 or
 *     wrapped_len > UINT16_MAX. Caller-cap on the output buffer.
 *
 *   - Wire decode: bound-check every length field as it's parsed;
 *     refuse if `payload_len` disagrees with the trailing buffer
 *     length (strict equality, no extra trailing bytes accepted —
 *     R111 doctrine carry).
 *
 *   - Token loader: 33 bytes exactly. Refuse if file is shorter
 *     (truncation) or longer (avoids reading a partial token
 *     concatenated with garbage). `mlock` best-effort; caller is
 *     responsible for explicit_bzero on shutdown.
 *
 *   - DEK output buffer (UNWRAP): exactly 32 bytes when status=0.
 *     Caller-owned; caller `explicit_bzero`s when done.
 *
 *   - WRAP request confidentiality (R138 doctrine extension): the
 *     WRAP request frame carries the PLAINTEXT DEK on the wire — an
 *     exposure UNWRAP never had (UNWRAP's request carries an opaque
 *     wrapped blob). The transport securely scrubs the encoded
 *     request buffer (token + DEK) before free (a non-elidable
 *     `volatile`-write loop — see corvus_client.c). The WRAP
 *     *response* envelope is a sealed blob — not secret, no scrub
 *     needed.
 *
 *   - No logging of token or DEK bytes. Status-string mappings in
 *     `util/status.c` mention "bad session token" generically.
 */
#ifndef STRATUM_V2_CORVUS_CLIENT_H
#define STRATUM_V2_CORVUS_CLIENT_H

#include <stratum/types.h>

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ────────────────────────────────────────────────────────────────────── */
/* Constants.                                                              */
/* ────────────────────────────────────────────────────────────────────── */

#define STM_CORVUS_VERB_UNWRAP           ((uint8_t)4)
#define STM_CORVUS_VERB_WRAP             ((uint8_t)10)
#define STM_CORVUS_PROTO_V1              ((uint8_t)1)

#define STM_CORVUS_TOKEN_LEN             33u
#define STM_CORVUS_DEK_LEN               32u
#define STM_CORVUS_DATASET_MAX           255u
#define STM_CORVUS_WRAPPED_MAX           65535u

/* Worst-case request frame size: 4 + 33 + 1 + 255 + 8 + 2 + 65535. */
#define STM_CORVUS_REQUEST_MAX  \
    (4u + STM_CORVUS_TOKEN_LEN + 1u + STM_CORVUS_DATASET_MAX \
     + 8u + 2u + STM_CORVUS_WRAPPED_MAX)

/* Response frame: 3 + 32 = 35 bytes (OK path); 3 bytes on error. */
#define STM_CORVUS_RESPONSE_MAX  (3u + STM_CORVUS_DEK_LEN)

/* Maximum WRAP-response DEK-envelope size Stratum will accept. corvus's
 * ML-KEM-768 + X25519 envelope is ~1217 bytes today; this cap leaves
 * headroom for envelope-format evolution. It is deliberately equal to
 * keyschema's STM_KEYSCHEMA_WRAPPED_MAX — the envelope is stored
 * verbatim as a CORVUS keyslot's `wrapped` blob, so the two caps MUST
 * agree (the provisioning path static-asserts it). A future envelope
 * exceeding this is a coordinated cap bump in both headers. */
#define STM_CORVUS_ENVELOPE_MAX          1280u

/* Worst-case WRAP request frame: 4 (header) + 33 (token) + 1 (ds_len)
 * + 255 (dataset) + 8 (key_id) + 2 (dek_len) + 32 (dek) = 335. The DEK
 * is fixed-size, so a WRAP request is far smaller than an UNWRAP one. */
#define STM_CORVUS_WRAP_REQUEST_MAX  \
    (4u + STM_CORVUS_TOKEN_LEN + 1u + STM_CORVUS_DATASET_MAX \
     + 8u + 2u + STM_CORVUS_DEK_LEN)

/* Worst-case WRAP response frame: 3 (header) + envelope. */
#define STM_CORVUS_WRAP_RESPONSE_MAX  (3u + STM_CORVUS_ENVELOPE_MAX)

/* corvus wire status byte values (verbatim from STRATUM-API-V1.md §5.2). */
typedef enum {
    STM_CORVUS_STATUS_OK              = 0,
    STM_CORVUS_STATUS_BAD_AUTH        = 1,
    STM_CORVUS_STATUS_PERM_DENIED     = 2,
    STM_CORVUS_STATUS_NOT_FOUND       = 3,
    STM_CORVUS_STATUS_RATE_LIMITED    = 4,
    STM_CORVUS_STATUS_BAD_FORMAT      = 5,
    STM_CORVUS_STATUS_INTERNAL_ERROR  = 6,
} stm_corvus_status;

/* ────────────────────────────────────────────────────────────────────── */
/* UNWRAP codec.                                                           */
/* ────────────────────────────────────────────────────────────────────── */

/*
 * Encode an UNWRAP request into `out_buf`.
 *
 * Inputs:
 *   token        — exactly STM_CORVUS_TOKEN_LEN bytes (33).
 *   dataset      — UTF-8 dataset name, length `dataset_len`.
 *                  Caller-validated; this codec does NOT inspect
 *                  the bytes beyond bound-checking the length.
 *   dataset_len  — ≤ STM_CORVUS_DATASET_MAX (255).
 *   key_id       — opaque u64 (corvus's key registry index).
 *   wrapped      — opaque AEAD-wrapped DEK blob.
 *   wrapped_len  — ≤ STM_CORVUS_WRAPPED_MAX (65535).
 *   out_buf      — caller-provided buffer of at least
 *                  STM_CORVUS_REQUEST_MAX bytes (or computable
 *                  via `stm_corvus_encode_unwrap_size`).
 *   out_cap      — capacity of `out_buf`.
 *   out_len      — populated with the actual encoded length on
 *                  success.
 *
 * Returns STM_OK on success, STM_EINVAL on NULL or oversize input,
 * STM_ENOSPC if `out_cap` is too small.
 *
 * The encoder does NOT zero `out_buf` on error.
 */
STM_MUST_USE
stm_status stm_corvus_encode_unwrap(const uint8_t token[STM_CORVUS_TOKEN_LEN],
                                       const char *dataset,
                                       size_t dataset_len,
                                       uint64_t key_id,
                                       const uint8_t *wrapped,
                                       size_t wrapped_len,
                                       uint8_t *out_buf,
                                       size_t out_cap,
                                       size_t *out_len);

/*
 * Compute the byte size an UNWRAP request would encode to. Useful
 * for caller-side buffer sizing without a trial encode.
 *
 * Returns the size on success, 0 on oversize inputs.
 */
size_t stm_corvus_encode_unwrap_size(size_t dataset_len, size_t wrapped_len);

/*
 * Decode a corvus response frame.
 *
 * Inputs:
 *   buf, len     — the on-wire response bytes. Caller is
 *                  responsible for framing (reading the right
 *                  number of bytes before calling here).
 *   out_status   — populated with the parsed status byte
 *                  (stm_corvus_status enum).
 *   out_dek      — when status == OK, populated with the 32-byte
 *                  unwrapped DEK. NULL → DEK is dropped (caller
 *                  doesn't want the bytes). NEVER populated on
 *                  non-OK status.
 *   out_dek_cap  — must be ≥ STM_CORVUS_DEK_LEN when out_dek is
 *                  non-NULL and status == OK; otherwise ignored.
 *
 * Returns:
 *   STM_OK                — response parsed; out_status valid.
 *                            CALLER MUST INSPECT out_status —
 *                            STM_OK on this function does NOT
 *                            mean the UNWRAP succeeded; it means
 *                            the FRAME was well-formed.
 *   STM_EPROTOCOL         — malformed frame (truncated, oversize,
 *                            unknown status code, payload_len
 *                            disagrees with status discipline).
 *   STM_EINVAL            — NULL args.
 *   STM_ENOSPC            — out_dek_cap < 32 when DEK present.
 *
 * On non-OK return, *out_status is set to a sentinel
 * (STM_CORVUS_STATUS_INTERNAL_ERROR + 1; outside enum range);
 * out_dek is NOT modified.
 */
STM_MUST_USE
stm_status stm_corvus_decode_response(const uint8_t *buf, size_t len,
                                          stm_corvus_status *out_status,
                                          uint8_t *out_dek,
                                          size_t out_dek_cap);

/*
 * Translate a corvus wire status to a stm_status. Convenience for
 * call sites that want to surface "the UNWRAP itself failed" up
 * the stack as a typed stratum error (see types.h
 * STM_ECORVUSAUTH..STM_ECORVUSRATELIMITED). STM_CORVUS_STATUS_OK
 * maps to STM_OK; unknown values map to STM_EPROTOCOL.
 */
stm_status stm_corvus_status_to_stm(stm_corvus_status s);

/* ────────────────────────────────────────────────────────────────────── */
/* WRAP codec (TLY-A3-keyslot-wrap).                                       */
/* ────────────────────────────────────────────────────────────────────── */

/*
 * Encode a WRAP request into `out_buf`.
 *
 * WRAP is the provisioning-time counterpart of UNWRAP: it asks corvus
 * to SEAL a freshly-generated plaintext DEK into an opaque envelope
 * bound (AEAD-AD) to the dataset path. The request therefore carries
 * the **plaintext DEK** — see the confidentiality note below.
 *
 * Inputs:
 *   token        — exactly STM_CORVUS_TOKEN_LEN bytes (33).
 *   dataset      — UTF-8 corvus dataset path ("users/<name>"), length
 *                  `dataset_len`. Caller-validated; this codec does
 *                  NOT inspect the bytes beyond bound-checking length.
 *   dataset_len  — 1..STM_CORVUS_DATASET_MAX (255). Unlike UNWRAP, a
 *                  zero-length dataset is REFUSED — a WRAP must bind
 *                  to a real dataset path.
 *   key_id       — opaque u64 (corvus's key registry index).
 *   dek          — exactly STM_CORVUS_DEK_LEN (32) bytes of plaintext
 *                  DEK to seal. Sensitive: caller's responsibility to
 *                  mlock + explicit_bzero around the call site.
 *   out_buf      — caller buffer of at least STM_CORVUS_WRAP_REQUEST_MAX
 *                  bytes (or `stm_corvus_encode_wrap_size`).
 *   out_cap      — capacity of `out_buf`.
 *   out_len      — populated with the actual encoded length on success.
 *
 * Returns STM_OK on success, STM_EINVAL on NULL / zero-length dataset
 * / oversize dataset, STM_ENOSPC if `out_cap` is too small.
 *
 * Confidentiality: `out_buf` holds the plaintext DEK after a
 * successful encode. The caller MUST securely zero it (e.g.
 * `stm_ct_memzero`) once the frame has been sent — the transport
 * functions below do this. The encoder does NOT zero `out_buf` on
 * error.
 */
STM_MUST_USE
stm_status stm_corvus_encode_wrap(const uint8_t token[STM_CORVUS_TOKEN_LEN],
                                     const char *dataset,
                                     size_t dataset_len,
                                     uint64_t key_id,
                                     const uint8_t dek[STM_CORVUS_DEK_LEN],
                                     uint8_t *out_buf,
                                     size_t out_cap,
                                     size_t *out_len);

/*
 * Compute the byte size a WRAP request would encode to. Returns the
 * size on success, 0 on a zero-length or oversize dataset_len.
 */
size_t stm_corvus_encode_wrap_size(size_t dataset_len);

/*
 * Decode a corvus WRAP response frame.
 *
 * Inputs:
 *   buf, len          — the on-wire response bytes. Caller frames.
 *   out_status        — populated with the parsed status byte
 *                       (stm_corvus_status enum).
 *   out_envelope      — when status == OK, populated with the opaque
 *                       DEK envelope. NULL → envelope dropped (caller
 *                       doesn't want the bytes). NEVER populated on
 *                       non-OK status.
 *   out_envelope_cap  — capacity of `out_envelope`; must be ≥ the
 *                       envelope length when out_envelope is non-NULL.
 *   out_envelope_len  — populated with the envelope length on
 *                       status == OK. MUST be non-NULL when
 *                       out_envelope is non-NULL (otherwise the caller
 *                       cannot know how many bytes landed). Set to 0
 *                       on every non-OK / error path.
 *
 * The envelope is OPAQUE to Stratum — corvus carries its own
 * `envelope_version` byte and the envelope may evolve. The decoder
 * accepts any non-empty payload up to STM_CORVUS_ENVELOPE_MAX; it does
 * NOT hard-check the current ~1217-byte size.
 *
 * Returns:
 *   STM_OK         — frame well-formed; inspect *out_status. STM_OK
 *                    here does NOT mean the WRAP succeeded.
 *   STM_EPROTOCOL  — malformed frame (truncated, oversize, unknown
 *                    status code, status/payload discipline violation,
 *                    empty envelope on status=OK).
 *   STM_EINVAL     — NULL buf/out_status, or out_envelope non-NULL
 *                    with out_envelope_len NULL.
 *   STM_ENOSPC     — out_envelope_cap < the envelope length.
 *
 * On non-OK return, *out_status is set to a sentinel
 * (STM_CORVUS_STATUS_INTERNAL_ERROR + 1); out_envelope is NOT
 * modified.
 */
STM_MUST_USE
stm_status stm_corvus_decode_wrap_response(const uint8_t *buf, size_t len,
                                              stm_corvus_status *out_status,
                                              uint8_t *out_envelope,
                                              size_t out_envelope_cap,
                                              size_t *out_envelope_len);

/* ────────────────────────────────────────────────────────────────────── */
/* Transport + retry (TLY-A3-impl-2).                                      */
/* ────────────────────────────────────────────────────────────────────── */

/*
 * Transport-layer policy knobs (TLY-A3-impl-2; STRATUM-API-V1.md §5.3 +
 * §5.5 Q9).
 *
 * v1.0 transport posture: synchronous AF_UNIX SOCK_STREAM dial +
 * write(request) + read(3-byte header) + read(payload). The corvus
 * spec text at §5.3 says "9P over the corvus Spoor"; the practical
 * v1.0 reading (matching the TLY-A4 notify socket's raw-bytes shape)
 * is raw Unix-socket. If real-corvus integration testing reveals a
 * 9P wrapper, this transport layer is the single refactor surface
 * (the codec module above is pure and unaffected).
 *
 * Retry policy is fixed at v1.0 per Q9: 3 retries with backoff
 * 100ms / 500ms / 2000ms. Retry-eligible classes (see
 * `stm_corvus_unwrap` doc):
 *   - Transport: STM_EBACKEND (connect failure, read short/timeout,
 *     write EPIPE).
 *   - Corvus wire: RATE_LIMITED, INTERNAL_ERROR.
 * Fatal classes (no retry; first observation is final):
 *   - Corvus wire: BAD_AUTH, PERM_DENIED, NOT_FOUND, BAD_FORMAT.
 *   - Wire-format violation in the response: STM_EPROTOCOL.
 *   - Argument validation: STM_EINVAL.
 *
 * Connect-timeout discipline (R140 P2-3 doctrine carry): the dial
 * uses O_NONBLOCK + poll(POLLOUT, connect_timeout_ms) so a wedged
 * corvus can't hang the caller. Steady-state I/O is bounded via
 * SO_RCVTIMEO / SO_SNDTIMEO at io_timeout_ms.
 */
typedef struct {
    /* AF_UNIX path of the corvus UNWRAP socket. v1.0 default is
     * "/srv/corvus/ops/unwrap". NULL/empty → STM_EINVAL. */
    const char *socket_path;

    /* Bounded connect timeout in milliseconds. 0 → a production-safe
     * 5000 ms default is substituted (R144 P2-1 — 0 NEVER means
     * "block forever"; a zero-initialized opts struct must not be
     * able to hang the caller against a wedged corvus). */
    uint32_t    connect_timeout_ms;

    /* Bounded steady-state read/write timeout (SO_RCVTIMEO /
     * SO_SNDTIMEO). 0 → same 5000 ms default substitution as
     * connect_timeout_ms (R144 P2-1). */
    uint32_t    io_timeout_ms;

    /* Number of retries on a retry-eligible class. The spec-fixed
     * schedule [100, 500, 2000] ms is hardcoded; `n_retries` may be
     * 0 (single attempt — no retry) up to 3 (full schedule). Values
     * > 3 are clamped to 3. */
    uint32_t    n_retries;
} stm_corvus_transport_opts;

/*
 * Single-attempt transport. Dials the corvus socket, sends the
 * encoded UNWRAP request, reads the response, decodes it.
 *
 * Inputs:
 *   t_opts       — transport configuration (socket path + timeouts).
 *                  n_retries is IGNORED here (single attempt).
 *   token        — exactly STM_CORVUS_TOKEN_LEN (33) bytes.
 *                  Sensitive: caller's responsibility to mlock +
 *                  explicit_bzero around the call site.
 *   dataset / dataset_len — caller-validated UTF-8 dataset path.
 *   key_id       — corvus's key registry index.
 *   wrapped / wrapped_len — opaque AEAD-wrapped DEK blob.
 *   out_status   — populated with the parsed corvus wire status on
 *                  STM_OK return (caller must inspect; STM_OK on
 *                  this function means the FRAME was well-formed,
 *                  NOT that the UNWRAP succeeded).
 *   out_dek      — populated with the 32-byte unwrapped DEK iff
 *                  *out_status == STM_CORVUS_STATUS_OK on STM_OK
 *                  return. Caller MUST `explicit_bzero` on dispose.
 *                  Caller's responsibility to mlock the buffer.
 *
 * Returns:
 *   STM_OK         — frame round-tripped; inspect *out_status.
 *   STM_EBACKEND   — transport failure (connect, write, read,
 *                    timeout). Retry-eligible per opts->n_retries
 *                    when called through stm_corvus_unwrap.
 *   STM_EPROTOCOL  — corvus's response was malformed (truncated,
 *                    oversize, unknown status code, status/payload
 *                    discipline violation). Fatal.
 *   STM_EINVAL     — argument validation failed (NULL ptrs, sizes
 *                    out of range).
 *   STM_ENOSPC     — out_dek buffer too small (unreachable when
 *                    caller passes the canonical [STM_CORVUS_DEK_LEN]).
 *   STM_ENOMEM     — request-frame allocation failed. Fatal (the
 *                    retry wrapper does NOT retry it).
 */
STM_MUST_USE
stm_status stm_corvus_unwrap_once(const stm_corvus_transport_opts *t_opts,
                                       const uint8_t token[STM_CORVUS_TOKEN_LEN],
                                       const char *dataset,
                                       size_t dataset_len,
                                       uint64_t key_id,
                                       const uint8_t *wrapped,
                                       size_t wrapped_len,
                                       stm_corvus_status *out_status,
                                       uint8_t out_dek[STM_CORVUS_DEK_LEN]);

/*
 * Composite transport with retry policy. Wraps stm_corvus_unwrap_once
 * with the spec-fixed retry schedule [100, 500, 2000] ms.
 *
 * Retry-eligible outcomes (try again after backoff):
 *   - stm_corvus_unwrap_once returns STM_EBACKEND (transport).
 *   - stm_corvus_unwrap_once returns STM_OK with status in
 *     { RATE_LIMITED, INTERNAL_ERROR }.
 *
 * Fatal outcomes (return immediately, no retry):
 *   - stm_corvus_unwrap_once returns STM_OK with status in
 *     { BAD_AUTH, PERM_DENIED, NOT_FOUND, BAD_FORMAT } — mapped to
 *     STM_ECORVUSAUTH / STM_ECORVUSPERM / STM_ECORVUSNOTFOUND /
 *     STM_ECORVUSBADFORMAT via stm_corvus_status_to_stm.
 *   - stm_corvus_unwrap_once returns STM_EPROTOCOL, STM_EINVAL,
 *     STM_ENOMEM, or STM_ENOSPC — all returned verbatim, no retry.
 *
 * On retries-exhausted (n_retries attempts all returned a
 * retry-eligible failure), this function returns the LAST observed
 * failure mapped to a typed stm_status:
 *   - Transport-class: STM_EBACKEND.
 *   - RATE_LIMITED: STM_ECORVUSRATELIMITED.
 *   - INTERNAL_ERROR: STM_ECORVUSINTERNAL.
 *
 * Success: returns STM_OK; out_dek is populated with the 32-byte
 * DEK. Caller MUST `explicit_bzero` + free out_dek when finished.
 *
 * NOTE: this function calls usleep() for the backoff intervals.
 * Callers that need to cooperate with a stop flag (e.g., a daemon
 * mid-startup that wants to bail on SIGTERM) SHOULD set a small
 * io_timeout_ms + check the stop flag between calls to
 * stm_corvus_unwrap_once. v1.0 does not thread a stop flag through
 * the retry wrapper; the spec's worst-case latency is ~2.6s which
 * is acceptable for v1.0 mount-time blocking.
 */
STM_MUST_USE
stm_status stm_corvus_unwrap(const stm_corvus_transport_opts *t_opts,
                                  const uint8_t token[STM_CORVUS_TOKEN_LEN],
                                  const char *dataset,
                                  size_t dataset_len,
                                  uint64_t key_id,
                                  const uint8_t *wrapped,
                                  size_t wrapped_len,
                                  uint8_t out_dek[STM_CORVUS_DEK_LEN]);

/*
 * Single-attempt WRAP transport. Dials the corvus socket, sends the
 * encoded WRAP request, reads the response, decodes it.
 *
 * Same shape + return-code contract as `stm_corvus_unwrap_once`, with
 * two differences:
 *   - the request carries a PLAINTEXT DEK (`dek`) instead of an
 *     opaque wrapped blob;
 *   - the response carries an opaque, variable-length DEK envelope
 *     instead of a fixed 32-byte DEK. `out_envelope` /
 *     `out_envelope_cap` / `out_envelope_len` receive it; all three
 *     are required (non-NULL) here.
 *
 * Confidentiality: the encoded request frame holds the session token
 * AND the plaintext DEK. This function securely scrubs that buffer
 * (a non-elidable `volatile`-write loop) after the send completes,
 * before freeing it (R138 doctrine extension). The DEK is never
 * logged.
 *
 * Returns STM_OK / STM_EBACKEND / STM_EPROTOCOL / STM_EINVAL /
 * STM_ENOSPC / STM_ENOMEM exactly as `stm_corvus_unwrap_once`. On
 * STM_OK the caller MUST inspect *out_status (STM_OK means the FRAME
 * was well-formed, not that the WRAP succeeded).
 */
STM_MUST_USE
stm_status stm_corvus_wrap_once(const stm_corvus_transport_opts *t_opts,
                                   const uint8_t token[STM_CORVUS_TOKEN_LEN],
                                   const char *dataset,
                                   size_t dataset_len,
                                   uint64_t key_id,
                                   const uint8_t dek[STM_CORVUS_DEK_LEN],
                                   stm_corvus_status *out_status,
                                   uint8_t *out_envelope,
                                   size_t out_envelope_cap,
                                   size_t *out_envelope_len);

/*
 * Composite WRAP transport with retry. Wraps `stm_corvus_wrap_once`
 * with the same spec-fixed retry schedule + retry-eligible vs fatal
 * split as `stm_corvus_unwrap` (STRATUM-API-V1.md §5.10 is silent on
 * a WRAP-specific policy; UNWRAP's §5.5 Q9 schedule is adopted
 * symmetrically — 3 retries, 100/500/2000 ms; transport / RATE_LIMITED
 * / INTERNAL_ERROR retry-eligible, BAD_AUTH / PERM_DENIED / NOT_FOUND
 * / BAD_FORMAT / EPROTOCOL fatal).
 *
 * On success: returns STM_OK; out_envelope holds the opaque DEK
 * envelope, *out_envelope_len its length. The envelope is NOT secret
 * (it is a sealed blob) — no explicit_bzero needed on it.
 *
 * On retries-exhausted / fatal status: returns the typed
 * STM_ECORVUS* / STM_EBACKEND / STM_EPROTOCOL exactly as
 * `stm_corvus_unwrap`; *out_envelope_len is 0.
 */
STM_MUST_USE
stm_status stm_corvus_wrap(const stm_corvus_transport_opts *t_opts,
                              const uint8_t token[STM_CORVUS_TOKEN_LEN],
                              const char *dataset,
                              size_t dataset_len,
                              uint64_t key_id,
                              const uint8_t dek[STM_CORVUS_DEK_LEN],
                              uint8_t *out_envelope,
                              size_t out_envelope_cap,
                              size_t *out_envelope_len);

/* ────────────────────────────────────────────────────────────────────── */
/* Session token loader.                                                   */
/* ────────────────────────────────────────────────────────────────────── */

/*
 * Read exactly STM_CORVUS_TOKEN_LEN (33) bytes from `path` into
 * `out_token`. `out_token` MUST be an mlock'd buffer of at least 33
 * bytes — typically caller allocates with malloc, calls mlock,
 * passes the pointer here. On platforms supporting MADV_DONTDUMP
 * (Linux), the loader also advises the buffer not to appear in
 * core dumps.
 *
 * The path is opened with O_RDONLY | O_CLOEXEC and stat()'d to
 * verify it's a regular file with length == 33 bytes (refuses
 * shorter or longer; mode bits NOT checked at this layer — caller
 * SHOULD verify 0400/0600 ownership before invoking).
 *
 * Returns STM_OK on success, STM_EINVAL on NULL args, STM_ENOENT
 * if path is missing or wrong type, STM_ERANGE if length != 33,
 * STM_EIO on read failure.
 *
 * The buffer is NOT zeroed on error; caller is responsible for
 * `explicit_bzero` regardless of return code.
 */
STM_MUST_USE
stm_status stm_corvus_load_token(const char *path,
                                     uint8_t out_token[STM_CORVUS_TOKEN_LEN]);

#ifdef __cplusplus
}
#endif
#endif /* STRATUM_V2_CORVUS_CLIENT_H */
