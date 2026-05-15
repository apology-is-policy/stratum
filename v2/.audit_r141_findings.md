# R141 audit — TLY-A2-impl-3 close on 0c16d91

Scope: `git diff 5942efd..0c16d91 -- v2/` — accept-time refusal in `serve.c::stm_stratumd_accept_loop`, downstream-side SO_PEERCRED check in `proxy_9p.c::stm_proxy_9p_serve_client`, new `peer_creds` copy in proxy_9p.c, new `--coordinator-uid` CLI flag in run.c, three new e2e tests, five R140-era tests retargeted to `getuid()`-keyed policies.

Methodology: trust-boundary survey of both new gates against each category in the audit prompt; cross-check `peer_creds` byte-equivalence; CLI input-validation edge probing (`strtoull` on empty / leading-`+` / whitespace); fd-leak survey on every refuse-close branch; spec-vs-impl wording-drift check against design §4; cross-reference R0..R140 closed list.

---

## P0 — actionable

(none)

---

## P1 — actionable

- **serve.c:573-590 vs 591-611 — `allow_unauthenticated_peer=true` + `user_policy` set + matching daemon-uid entry slips an unauth peer past the gate.** When SO_PEERCRED/getpeereid resolution fails and the operator has opted INTO the legacy relaxation, lines 587-588 assign `peer_uid = getuid()` (the daemon's own uid). The new accept-time gate at line 600-606 then looks up *that* uid. In a Thylacine multi-stratumd deployment the per-user stratumd's own uid IS likely to have a `--user-policy uid=<daemon-uid>:...` entry (it's how the daemon admits its own user). Result: a peer whose credentials can't be resolved (rare on Linux/BSD but reachable on the `#else` platform branch, or on a kernel that returns ENOPROTOOPT for SO_PEERCRED on certain socket shapes) gets the full pattern set of the daemon's own uid. This is the exact confused-deputy class the bilateral SO_PEERCRED layer is meant to close. Mitigations: (a) when `user_policy != NULL`, refuse the unauth fallback unconditionally (bilateral auth + opt-in unauthenticated trust are mutually exclusive), OR (b) skip the policy gate entirely under unauth fallback (treat the fallback uid as a sentinel that never matches), OR (c) document the interaction as "if you set `user_policy`, do NOT set `allow_unauthenticated_peer`" and refuse at CLI parse if both are set. Suggested: option (a) — under `user_policy`, the unauth fallback is incoherent with the design and should fail-closed regardless of the legacy opt-in. The default-off `allow_unauthenticated_peer` makes this a narrow window in practice, but production Thylacine deployments may carry the flag forward from test configs. Same fix at lines 740-755 (`stratumd_accept_proxy_loop`) — though that gate doesn't have the user_policy interaction, the unauth fallback at line 754 still pins peer_uid to daemon uid which is then handed to `stm_proxy_9p_serve_client` as the stamped peer for any future per-uid policy on the client-mode listen socket.

---

## P2 — actionable

- **run.c:295-309 — `--coordinator-uid ""` (empty string) silently accepted as uid 0.** `strtoull("", &end, 10)` returns 0 with `*end == '\0'`; the bound check `v > (uid_t)-2` passes; the flag is enabled with `coordinator_uid = 0`. A misconfigured shell expansion (`--coordinator-uid "$VAR"` with VAR unset) silently enables the check expecting root. Suggested: reject when `end == argv[i]` (no digits consumed) AND reject when `argv[i]` is empty. Same pattern would also reject leading whitespace (`"   42"` is accepted via `strtoull`'s implicit ws-skipping); minor concern. Negatives (`-1` → ULLONG_MAX) are correctly rejected by the bound.

- **run.c CLI — `--coordinator-uid` not gated to `--role client`.** Passed in `--role coord` mode it's parsed + stored but never consulted (only the client-mode `stratumd_run_client` plumbs it through `stratumd_accept_proxy_loop`). Silent no-op; misleading. Suggested: at the end of arg parsing, refuse if `coordinator_uid_check_enabled && opts.role != STM_STRATUMD_ROLE_CLIENT` with a stderr line pointing to the design doc.

- **serve.c:591-611 vs design §4 wording-drift — "OR be 0 (root, for `stratumd-system`)".** Design says "the dialing client's uid MUST match a configured per-user-uid allow-list, OR be 0 (root, for stratumd-system)". The impl removes the "OR be 0" — uid 0 only admits when the operator explicitly adds a `uid=0:...` entry. This is *stricter* than the design (correct posture), but the wording drift should be reconciled: either update the design to "MUST match a configured per-user-uid allow-list (operator MUST add `uid=0:...` for stratumd-system)" or relax the impl. The comment at serve.c:594-598 correctly explains the impl's posture; design §4 lines 134-135 should be edited to match. No test covers the uid=0-without-entry case (the prompt acknowledges this); a one-line addition to `test_stratumd_user_policy.c` would close it.

- **proxy_9p.c:107-110 — `peer_creds` second copy.** R140 P3-1 flagged the duplication; impl-3 adds a third caller-site (the proxy's downstream check is a NEW call into the same function) inside the second copy. Byte-equivalence with `serve.c:335-356` was verified by inspection (identical preprocessor branches, identical return shape, identical error-uid sentinel). But three call sites in serve.c plus one in proxy_9p.c is enough divergence-risk that the extract-to-shared-header chore has earned its keep. Suggested: extract to `v2/src/cmd/stratumd/peer_creds.{h,c}`; fold both copies; close the R140 P3-1 carry note in the same commit. Not blocking R141 — flagging because impl-3 doubles the future-skew surface.

- **proxy_9p.c:326-363 — coord-uid check fires AFTER setting upstream timeouts but BEFORE setting coord timeouts.** Minor ordering: if `peer_creds` itself blocks (it shouldn't on Linux/BSD — `getsockopt`/`getpeereid` are synchronous local syscalls — but defensive posture would treat all coord-fd ops as potentially-blocking), there's no timeout on the coord_fd at that moment. In practice unreachable since the syscalls complete in microseconds. Forward-note only.

---

## P3 — forward-notes

- **`peer_creds` `#else` branch returns `-ENOSYS` with sentinel uids `(uid_t)-1` / `(gid_t)-1`.** The fail-closed posture is correct (rc != 0 → refuse-close in both gates). But the sentinel uid `(uid_t)-1` happens to be the same value the strtoull bound at run.c:299 *just barely* permits below (the bound is `(uid_t)-2`, leaving `(uid_t)-1` as the unset sentinel). If a future relaxation of the strtoull bound to `(uid_t)-1` ever lands, and the platform fell back to the `#else` ENOSYS branch, the resolved uid and the operator-configured uid would both be `(uid_t)-1` and the mismatch check would silently pass. Forward-note: keep the bound at `(uid_t)-2` (current); add a defense-in-depth assertion at the check site that `got_uid != (uid_t)-1` even on rc==0.

- **`coordinator_uid_check_enabled` defaults to false.** Design §4 reads SO_PEERCRED on the coord socket as a non-optional layer (lines 121-122 "bilateral SO_PEERCRED"). The opt-in default is a posture drift toward back-compat / tests. Forward-note: v1.1 — flip default to true; require `--coordinator-uid` OR explicit `--no-coordinator-uid-check` (mirroring `--allow-empty-allowlist`). Acceptable at v1.0 because the proxy is gated behind operator deployment + the upstream layer-1 SO_PEERCRED still fires.

- **Spec `multi_stratumd.tla::TattachPatternEnforced` models per-Tattach admission only.** Accept-time refusal is observationally equivalent (every Tattach from an unknown-uid client would have failed at the matcher anyway) but the spec doesn't enumerate the connection-lifecycle states. Forward-note: spec extension (with `ConnectionRefusedAtAccept` action + invariant `NoSpawnedWorkerForUnknownUid`) would close the observational-equivalence argument formally. Not load-bearing at R141; design §4 + clause 15 in CLAUDE.md trigger row are the contract today.

- **`stm_ds_policy_lookup` no-lock read at serve.c:601-604.** Currently safe because the `user_policy` pointer is borrowed-immutable from `stm_cmd_stratumd_main` for the daemon's lifetime (verified at run.c:438 — `opts.user_policy = &user_policy_table;` is set ONCE; the table isn't mutated after parse-complete). Forward-note: if config-reload-without-restart lands (design §12 forward-noted), the table MUST move under a rwlock + readers acquire SH before lookup. The accept-loop's `prc = poll(...)` returning POLLIN is the natural release point for the SH-rdlock retake.

- **No log-line injection surface.** The stderr lines use `%u` for uid and `%s` for the coord_socket_path (operator-configured, not peer-supplied). No peer-controlled bytes reach the format. The "logged stderr line format" concern from the prompt is closed by inspection.
