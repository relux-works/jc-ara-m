# jc-ara-m improvement roadmap

**Scope:** prioritized roadmap derived from the bSIM comparison of jc-ara-m
with sysmocom aram-applet and the accepted multi-rule architecture.

**Baseline:** jc-ara-m `v0.1.1` behavior (`10b8f42`). Repository HEAD
`ea3c12d` additionally carries the project Apache-2.0 legal metadata. This is
a roadmap, not an implementation claim, CAP build, or CARD#5 mutation.

## Highlights / key takeaways

- **P0 / REQUIRED:** bounded many-to-many rule capacity and safe individual
  update/delete are required program scope. WP1 is accepted; WP2-WP4 carry
  retrieval, authenticated rollout/migration, and physical-release evidence.
- **P0:** `FF60` is the required multi-rule retrieval extension; it uses SEAC
  `9000` continuation, not ISO `61xx` chaining.
- **Do not regress the proven boundary:** atomic rule-plus-refresh publication,
  authenticated-only provisioning, raw-STORE denial, and a small predictable
  footprint remain release constraints.
- **Evidence still required:** acceptance of the full deterministic SHA-256
  simulator-vector contract, immutable CAP provenance, and physical CARD#5
  capacity/commit evidence. The current WP1 fixture is useful partial coverage,
  not proof that every P1 SHA-256 assertion has been exercised.
- **Bounded intentionally:** `FF50`, `F2`, `E7`, raw STORE/locks, and full
  SEAC v1.1 conformance are not opportunistic additions; ARA-C is deferred for
  a concrete delegated-owner requirement.

## Design invariants

Every PULL-IN below must preserve these constraints. They take precedence over
copying the wider sysmocom command surface.

1. **Atomic visible state.** A rule mutation and its `DF20` refresh tag publish
   together; the old valid catalog remains visible until the new state commits.
   This includes the caller-owned Java Card transaction path.
2. **Authenticated-only provisioning.** Rule mutation remains reachable only
   through authenticated Security Domain `Application.processData(...)`.
   Selected-applet raw `INS E2` stays rejected with `6982`.
3. **Small, predictable footprint.** Use a bounded flat record arena; do not
   introduce a dynamic object graph, persistent index, or a permanently
   duplicated whole catalog.
4. **Fail closed and retain no secrets.** A multi-command OTA reconciliation
   may leave a valid prefix state, but must never create a temporary over-grant.
   Roadmap evidence must not contain card identifiers, keys, certificate hashes,
   subscriber identifiers, or refresh-tag values.

## Architecture authority and work-package map

`TASK-260719-3r17pa: design-multi-rule-manyToMany-seac-architecture` was
accepted on the board. Its canonical design is
[`docs/architecture/multi-rule-seac-architecture.md`](docs/architecture/multi-rule-seac-architecture.md).
That design is authoritative for the implementation shape:

| Work package | Board task | Roadmap responsibility | Board status at this fact-check |
| --- | --- | --- | --- |
| WP1 — catalog and atomic mutation | `TASK-260719-166x32` | Bounded `R + 1` arena, exact-key `F0` upsert, required `F1` deletes, refresh/revision publication. It establishes the synthetic SHA-256 fixture but does not by itself close the P1 vector acceptance contract. | Accepted |
| WP2 — streaming retrieval | `TASK-260719-xzwuv5` | `FF40` full-length encoding and `FF60` continuation, with channel/revision safety. | Accepted |
| WP3 — authenticated OTA and migration | `TASK-260719-3g38q3` | Desired-state reconciliation, exact CAP provenance, canary/rollback controls. | Ready for review |
| WP4 — physical acceptance | `TASK-260719-109lj8` | CARD#5 capacity/transaction measurement, canary, migration, Android allow/deny, and rollback evidence. | Backlog |

The terms below are normative for this roadmap:

- **PULL-IN** — implement in the named package at the stated priority.
- **DEFER** — do not implement in this release; the stated trigger reopens it.
- **WONT-DO** — deliberately excluded from the bounded profile; a new product
  requirement and architecture review are required to revisit it.

## Prioritized pull-ins

| Priority | PULL-IN | Why it is required | Delivery / acceptance signal |
| --- | --- | --- | --- |
| P0 | Multi-rule capacity for many applets and many Android applications | This is the explicit product requirement. One rule is one exact `(AID-REF-DO, DeviceAppID-REF-DO)` pairing; the catalog supports a bounded many-to-many set, not an unbounded linked list. | WP1 implements the `R + 1` flat pool; WP4 validates the selected `R` on CARD#5. |
| P0 | Rule update and delete | This is the other explicit product requirement. `F0` is an exact-`REF-DO` idempotent upsert; `F1` deletes all, by AID, or by exact `REF-DO`. A policy whose key changes is a fail-closed `F1` then `F0` reconciliation. | WP1 proves mutation/refresh atomicity, no-op retry, capacity, and all required delete forms; WP3 performs desired-state reconciliation. |
| P0 | `GET DATA [Next]` (`FF60`) | The one-slot response currently fits one short APDU; a multi-rule catalog does not. AOSP consumes the advertised `FF40` length and continues with `FF60` until complete. | WP2 covers BER lengths, chunking, no-session and mutation-invalidation errors, and no `61xx` substitution. |
| P0 release gate | Exact CARD#5 EEPROM and transaction-capacity measurement | Formulae and CAP component sizes are only lower-bound/proxy evidence; they cannot prove physical capacity or Java Card journal headroom. | WP4 records selected `R`, CAP identity/toolchain manifest, and worst-case add/update/delete-all in both owned and caller-owned transaction paths. No multi-rule CARD#5 release without this evidence. |
| P1 | Deterministic SHA-256 certificate-bound simulator vector | CARD#5/Android acceptance already proves SHA-256 behavior. WP1 now contains a synthetic `C1 20` fixture and proves SHA-1/SHA-256 exact-key coexistence, but it does not yet document dedicated SHA-256 same-key replacement, refresh-change, and malformed-value assertions. Keep this PULL-IN open until those assertions run green while retaining SHA-1 interoperability coverage. | Extend the WP1 test surface (or its focused follow-up before release) with synthetic `C1 20` store, exact readback, replacement, refresh-change, and malformed-input assertions. Do not use the hardware proof as a substitute for this deterministic codec regression. |
| P1 | Immutable CAP release and rollback provenance | A source tag alone did not reproduce the historical installed archive digest. This is a release-engineering gap, not a reason to weaken the hardware proof. | WP3 retains the exact new and rollback CAPs, digests/signatures, and toolchain manifests before any standard-AID migration; WP4 consumes them. |

## Comparison decision ledger

This ledger assigns every still-open capability or evidence gap identified in
the comparison. `P0` and `P1` PULL-IN items above are repeated here for
traceability; closed evidence is listed separately in the next section.

| ID | Comparison gap | Decision | Priority, trigger, or rationale | Architecture cross-reference |
| --- | --- | --- | --- | --- |
| C1 | One 96-byte slot cannot represent independently managed rules for many applets/signers. | **PULL-IN** | **P0 / REQUIRED.** Use at most `R` active rules in an `R + 1` arena, with no dynamic linked list. | Sections 2-3; WP1, WP4. |
| C2 | No same-target update or individual rule deletion; sysmocom requires multi-command replacement. | **PULL-IN** | **P0 / REQUIRED.** Exact `REF-DO` identifies `F0` upsert; add `F1` all/AID/exact-`REF-DO` deletion. Do not make a key-changing replacement appear atomic across two commands. | Sections 4.2-4.5, 5, 7; WP1, WP3. |
| C3 | `FF40` has no continuation path once catalog output exceeds a short APDU. | **PULL-IN** | **P0.** Implement `FF60` raw-byte continuation with `9000`, channel binding, and revision invalidation. | Section 6; WP2. |
| C4 | No `FF50` GET-specific command. | **WONT-DO** | Deprecated by SEAC v1.1; Android consumes full catalog through `FF40`/`FF60`. Adding a second read model gives no target capability. | Section 9. |
| C5 | No `F2` refresh-only command. | **WONT-DO** | Every visible catalog change already publishes a new refresh tag atomically. A separate refresh lifecycle would weaken the invariant and has no external on-card owner. | Sections 4.4-4.5, 5, 9. |
| C6 | No `E7` Block-DO multi-session transfer. | **WONT-DO** | Every supported `REF-AR-DO` fits one short `F0`; N-rule OTA uses resumable, authenticated commands rather than a transfer buffer. | Sections 2.2, 4.1, 7, 9. |
| C7 | No ARA-C/delegated-owner configuration (`F6`, `F7`, `F8`). | **DEFER** | Reopen only for a signed requirement to install/register ARA-C owners or aggregate multiple independently owned rule sets. Current product has one centrally managed ARA-M and authenticated Security Domain path. | Sections 2.2 and 9; no WP in this release. |
| C8 | Sysmocom offers a raw STORE path plus proprietary lock controls. | **WONT-DO** | The safer jc-ara-m boundary is raw mutation permanently denied; a mutable lock around an enabled raw path is not an equivalent security model. | Sections 2.1, 4.1, 9. |
| C9 | No deterministic SHA-256 simulator regression despite hardware/Android proof. | **PULL-IN** | **P1.** WP1 now has a synthetic non-secret `C1 20` fixture and exact-key coexistence coverage. Keep the decision open until dedicated SHA-256 store/readback/replacement/refresh/malformed-input assertions run green; retain the accepted physical proof as a separate evidence layer. | Section 11; WP1 test surface or focused follow-up. |
| C10 | Exact installed CARD#5 EEPROM allocation and transaction headroom are unknown. | **PULL-IN** | **P0 release gate.** Do not turn lower-bound arithmetic into a hardware claim; measure physical limits at the selected `R`. | Sections 3.3, 8.2, 11; WP4. |
| C11 | Exact installed CAP was not retained as an immutable release artifact. | **PULL-IN** | **P1.** Produce/retain signed digest-bound CAPs and toolchain manifests for both migration and rollback. | Sections 8.2-8.4, 11; WP3, WP4. |
| C12 | Current profile is not complete SEAC v1.1 (including APDU-only rules, no NFC AR-DO, no delegated ARA-C). | **WONT-DO** | Keep a named bounded profile. Reopen only with a concrete NFC rule or delegated-owner product requirement, followed by a new architecture decision; do not claim full SEAC v1.1 conformance. | Sections 2.2 and 9. |

## Already closed — keep closed

These are historical comparison risks, not open roadmap work. They are listed
here to prevent a future comparison from reopening them by accident.

| Item | Status | Evidence to preserve |
| --- | --- | --- |
| Raw-STORE security boundary | **CLOSED — DONE.** Raw selected-applet `INS E2` returns `6982`; authenticated Security Domain personalization remains accepted. | `AraMJCApplet.java:35-60`; accepted CARD#5 evidence cited by the comparison. Re-run after any dispatch or provisioning change. |
| Certificate-bound hardware discrimination | **CLOSED — DONE.** Authenticated SHA-256 provisioning/readback, refresh change, matching-signer grant, and distinct-signer denial were accepted on CARD#5/Android. | Comparison section 5 and `TASK-260717-1rai59` evidence. Re-run after an applet, signing-policy, or Android integration change. |
| Project license declaration | **CLOSED — DONE.** The comparison correctly recorded its absence at the time; current HEAD `ea3c12d` adds `LICENSE` and `NOTICE` with Apache-2.0 metadata. | `git log` and tracked `LICENSE`/`NOTICE`; keep SPDX/copyright metadata aligned with future releases. |

## Implementation and release sequencing

1. **WP1 is accepted** as the invariant-bearing layer: bounded catalog,
   exact-key identity, F0/F1, and transaction-safe refresh publication. Keep
   its SHA-256 P1 acceptance criteria explicitly open until the dedicated
   vector assertions above are present and green.
2. Deliver **WP2** on top of the accepted catalog. Treat `FF60` as the SEAC/AOSP
   continuation contract, not ISO `61xx` chaining.
3. Deliver **WP3** only through the existing authenticated Security Domain
   path. It reconciles desired state deterministically and prepares immutable
   new/rollback release artifacts.
4. Treat **WP4** as the release gate, not an optional polish task: prove
   selected capacity and commit headroom, alternate-AID canary, rollback,
   standard-AID migration, and Android positive/negative behavior without
   storing secrets.

## Fact-check record

The roadmap was checked against the following pinned/local evidence on
2026-07-19. No live card operation, CAP mutation, or applet/host code change
was performed for this document.

| Claim | Verified evidence |
| --- | --- |
| The historical `v0.1.1` / `10b8f42` baseline was single-rule, accepted `C1` lengths 0/20/32, and atomically replaced its rule plus refresh tag. | Immutable source: `git show 10b8f42:jc/src/main/java/works/relux/jcaram/AraMApplet.java` (single `rule` buffer at lines 18-33; atomic `store` at lines 72-125; `C1` length validation at lines 145-153). This claim intentionally does not describe the mutable post-WP1 working tree. |
| Raw `INS E2` is rejected while `Application.processData(...)` carries authenticated personalization. | `jc/src/main/java/works/relux/jcaram/AraMJCApplet.java:37-69`; `AraMAppletTest.java:460-470`. |
| The historical v0.1.1 deterministic certificate fixture was SHA-1, while the current uncommitted WP1 test surface has a synthetic SHA-256 fixture but not the complete dedicated-vector acceptance set. | Immutable baseline: `git show 10b8f42:jc/src/test/java/works/relux/jcaram/AraMAppletTest.java` uses `C1 14`. Current source: `AraMAppletTest.java:42-49,451-458` defines synthetic `C1 20` and proves SHA-1/SHA-256 exact-key coexistence. No current test was found that makes the dedicated SHA-256 replacement/refresh/malformed-input assertions explicit. |
| Multi-rule command, storage, atomicity, OTA, migration, capacity and skip decisions have an accepted design. | `TASK-260719-3r17pa` (accepted) and `docs/architecture/multi-rule-seac-architecture.md`, especially sections 3-11. |
| `FF60` uses `9000` continuation, not `61xx`; `FF50` is not required for the bounded Android profile. | Comparison section 2 and architecture sections 6 and 9, backed there by SEAC v1.1 and pinned AOSP `AccessRuleApplet`. |
| CARD#5 EEPROM capacity is still an empirical gate, not a measured fact. | Comparison sections 2 and 5; architecture sections 3.3, 8.2, and 11; `UNRESOLVED_QUESTIONS.md`. |
| Legal metadata gap is no longer open. | `git log -1` identifies `ea3c12d docs: add Apache-2.0 LICENSE and NOTICE`; both files are tracked. |

## Sources

- bSIM comparison:
  [`/Users/alexis/src/bsim/.research/260718_our-vs-sysmocom-ara-m-comparison.md`](/Users/alexis/src/bsim/.research/260718_our-vs-sysmocom-ara-m-comparison.md).
- Accepted architecture:
  [`docs/architecture/multi-rule-seac-architecture.md`](docs/architecture/multi-rule-seac-architecture.md)
  (`TASK-260719-3r17pa`).
- GlobalPlatform, [Secure Element Access Control v1.1 public review](https://globalplatform.org/wp-content/uploads/2024/08/GPD_SE_Access_Control_v1.1.0.10_PublicRvw.pdf).
- AOSP, [pinned `AccessRuleApplet`](https://android.googlesource.com/platform/packages/apps/SecureElement/+/679fd5352c9d7e582df674a55ab86b301e4457fa/src/com/android/se/security/ara/AccessRuleApplet.java).
