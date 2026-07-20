# jc-ara-m vs the open-source ARA-M implementations

Comparison refreshed 2026-07-21, after the multi-rule release (WP1-WP3), the
physical CARD#5 / Android acceptance (WP4), and the hardening wave that followed
it (PERM-AR-DO and catch-all validation, install-time capacity, the independent
SEAC-parser oracle, the TLV fuzzers, and the Android `FF60` continuation proof).
It supersedes the single-rule-era comparison that produced the `C1`-`C12` ledger
in [IMPROVEMENTS.md](../IMPROVEMENTS.md). Where an earlier draft listed a gap as
open advice, that gap is now recorded as closed evidence below rather than
lingering as a recommendation.

Every claim about an external project was re-derived from its source at the
revision checked out locally, not from its README. Source analyses:
`.temp/TASK-260719-109lj8/research-oss-aram-{bmartel-sysmocom,cheeriotb}.md`.
Those revisions were re-verified for this refresh, not assumed.

## The comparison set

| Project | Revision analysed | License | Last commit | What it is |
| --- | --- | --- | --- | --- |
| **jc-ara-m** (ours) | `3e0561c` | Apache-2.0 | active | Bounded multi-rule ARA-M with a host provisioner |
| **bertrandmartel/aram-applet** | `d7f7a16` | MIT | 2018-02-27 | Original PoC, 11 commits, unmaintained |
| **sysmocom/aram-applet** (Osmocom) | `13930d5` | MIT | 2025-03-13 | Maintained fork of the above, 25 commits |
| **cheeriotb/aram-cardlet** | `83900b6` | GPL-2.0 | 2018-12-22 | Static read-only rule ROM for Android SE CTS |

Two of the four are effectively one codebase: `RuleEntry.java` and
`AramUtils.java` are byte-identical between bertrandmartel and sysmocom, as is
the entire test tree. The fork's whole functional contribution is a 32-byte hash
field and a proprietary lock (see "Fork delta" below).

cheeriotb is not a provisionable ARA-M at all. It has no `STORE DATA`, no write
path of any kind, and no `org.globalplatform` import; its 41 rules are a
`static final byte[]` literal of pre-encoded TLV compiled into the CAP. It is
listed here because its rule *data* is a valuable reference for real-world SEAC
encodings, not because it is a candidate implementation.

## Capability matrix

| | jc-ara-m | bmartel | sysmocom | cheeriotb |
| --- | --- | --- | --- | --- |
| Rule storage | `R+1` flat arena + active bitmap | linked list + free list | same | one static literal |
| Capacity | **bounded, `R` set at install** (default 16, compiled max 64) | unbounded until EEPROM exhaustion | same | 41, baked at build |
| Payload / rule | **~104 B** at `R=16` | 198 B fixed | 210 B fixed | variable (mean ~42 B) |
| `F0` store | upsert **keyed by exact REF-DO** | append-only | append-only | absent |
| `F1` delete | all / by AID / by exact REF-DO | all / by AID / by REF-DO; by REF-AR-DO partial | same | absent |
| `F2` refresh-only | absent *(deliberate)* | present | present | absent |
| `FF40` get-all | present, BER `81`/`82` lengths | present | present | present |
| `FF60` get-next | present | present | present | present |
| `FF50` get-specific | absent *(deprecated in v1.1)* | present | present | absent |
| `E7` / `F6` / `F7` / `F8` | absent | absent | absent | absent |
| Refresh tag on mutation | **automatic + atomic** | **only on explicit `F2`** | **only on explicit `F2`** | **never — hardcoded** |
| Raw unauthenticated STORE | **always `6982`** | **accepted** | accepted unless `A1` lock set | no write path |
| Caller-owned transaction | detected and joined safely | **unhandled** | unhandled | n/a |
| Multi-rule delete atomicity | one transaction | **per entry, inside the loop** | same | n/a |
| Commit-capacity preflight | `getUnusedCommitCapacity` | absent | absent | n/a |
| AR-DO content validated | strict: `D0` + optional 8-byte `DB` `PERM-AR-DO` | **not parsed at all** | not parsed | n/a (static) |
| `PERM-AR-DO` (carrier privilege) | **validated and storable** (`DB`, exactly 8 B) | stored opaquely, unvalidated | same | present in ROM |
| Catch-all AID (zero-length `4F`) | **accepted; grant policy host-guarded** | stored opaquely, unvalidated | same | present in ROM |
| Unit tests | **103 jCardSim + 41 Go host**, incl. independent SEAC-parser oracle and TLV fuzzers | 70 JUnit | same 70 | **none** |
| Physical-card evidence | **CARD#5 accepted** | optional PC/SC mode, none captured | none captured | none |
| Android evidence | **enforcer grant/deny captured** | absent | absent | absent |
| Host provisioning tooling | **Go provisioner + migration** | absent | absent | absent |

## Where jc-ara-m is materially ahead

**1. The refresh tag is correct.** This is the most consequential difference.
In both bmartel and sysmocom, `updateRefreshTag()` has exactly one call site —
the `F2` command DO. It is never called from `storeArDo()` or `deleteArDo()`,
and the constructor only allocates the array, so the tag is **all-zeroes after
install**. Their own test asserts two consecutive `DF20` reads are equal after a
delete-all. An Access Control Enforcer that caches on the refresh tag will
therefore keep serving stale rules after any `F0`/`F1` unless the provisioning
host remembers to send `F2`. cheeriotb is worse still: its tag is the constant
`0123456789ABCDEF` and can never change.

jc-ara-m regenerates an 8-byte `ALG_SECURE_RANDOM` tag and publishes it in the
same transaction as the catalog change, so a visible rule change and its tag can
never diverge. This session's Android run is the direct evidence: the enforcer
logged `Refresh tag has changed.` then `Read ARs from ARA` and re-read the whole
catalog before granting.

**2. `F0` is an idempotent upsert; theirs is append-only.** `storeArDo()`
performs no lookup before insertion, so storing the same `(AID, hash)` twice
silently creates two independent entries with the same key. Changing a rule
requires an explicit delete-then-add by the host, which is not atomic and leaves
a window where the rule is absent. jc-ara-m keys on the exact `REF-DO`, so a
repeated store is a no-op and a changed `AR-DO` is a single-command replacement.

**3. Mutation is genuinely atomic, including under a caller-owned
transaction.** Their delete loops open and commit a transaction *per removed
entry*, so a tear during a multi-rule delete leaves a partially deleted catalog.
Neither `abortTransaction` nor `getTransactionDepth` appears anywhere in their
source, which also means that if the Security Domain has already opened a
transaction before calling `processData()`, `beginTransaction()` raises
`TransactionException.IN_PROGRESS` and nothing catches it. jc-ara-m detects the
depth, joins the caller's transaction, journals the full candidate record on the
joined path, and preflights `getUnusedCommitCapacity()` before writing.

**4. The security boundary is structural, not optional.** bmartel routes raw
`INS E2` straight into the store path with no secure-channel check: anyone who
can select `A00000015141434C00` — including an app over OMAPI on the handset —
can add, delete, or wipe the entire access-rule catalog. sysmocom's `A1`/`A2`
lock improves this but is **unlocked by default**, is untested, is not
observable through any GET DATA, and is itself reachable over the raw path while
unlocked, so an attacker who selects the applet before personalization can lock
it pre-emptively and deny provisioning. jc-ara-m rejects raw `INS E2` with
`6982` unconditionally; there is no state in which raw mutation is possible.

**5. Footprint is bounded and predictable.** At `R=16` we occupy ~1 663 B for 16
usable rules (~104 B each) against sysmocom's 210 B fixed per rule — about half
the payload. More importantly, their storage is unbounded: allocation continues
until EEPROM is exhausted, at which point the JCRE throws mid-`STORE DATA` with
no graceful failure. We return a clean `6A84` at capacity, verified on CARD#5 by
filling all 16 slots and confirming the 17th is rejected without mutation.

**6. `FF60` cannot serve a torn catalog.** Ours binds the read session to a
logical channel and snapshots the catalog revision; a mutation mid-read
invalidates the session with `6984`, and `FF60` without a live `FF40` returns
`6985`. Theirs holds `dataOffset`/`nextLength` in applet fields with no
invalidation, and re-walks and re-serializes the entire rule list on every
chunk — O(n²) work overall. Their README also concedes `FF50` is incompatible
with `FF60`. cheeriotb has an outright defect here: its `GET DATA DF20` handler
decrements the shared `mRemainingData` cursor, so reading the refresh tag
between `FF40` and `FF60` silently corrupts the continuation offset.

**7. Nothing else ships host-side provisioning.** None of the three has any
host tooling. jc-ara-m ships a Go desired-state provisioner (plan/diff/reconcile
over the authenticated GP path), a guarded v0.1.1 migration with rollback, and
signed CAP artifacts with toolchain manifests.

**8. Evidence.** Ours is the only one of the four with captured physical-card
and Android AccessControlEnforcer evidence — capacity fill, interrupted-OTA
convergence, migration and rollback rehearsal, and a signer/AID access matrix.
bmartel's suite can be pointed at a real reader via a `testMode` property, but
no hardware run is captured in the repo.

## Where the open-source implementations are ahead, honestly

The 2026-07-20 draft listed a larger unit-test suite and two unstorable rule
shapes here. Both are now closed — see "Hardening closed since the last refresh"
below for the evidence. What genuinely remains in their favour is narrower.

**1. Unbounded rule count.** Our `R` is a hard ceiling, capped at a compiled
maximum of 64; theirs grows until EEPROM runs out. For a deployment needing more
rules than that compiled maximum on a large card, their model needs no rebuild
while ours needs a new CAP.

**2. ~~Capacity is compile-time for us too~~ — resolved, and now a
differentiator.** This previously read: the architecture doc calls `R` an
"installation-time capacity" but `AraMJCApplet.install()` ignores its install
parameters and `ACTIVE_RULE_CAPACITY` is a `static final short`. That is fixed.
`install()` now parses the GlobalPlatform application-specific parameter block
(`80 01 R`, optionally inside its `C9` container), defaults to 16 when absent,
and clamps to the compiled maximum of 64; every buffer is still allocated once,
at install, from that value. `R` is therefore field-configurable per instance
without a rebuild, up to the compiled ceiling — storage that is both bounded
*and* configurable, which no implementation in this comparison offers. See
`docs/architecture/multi-rule-seac-architecture.md` §3.2.

**3. They can still carry two rule shapes we reject — `NFC-AR-DO` and
`PKG-REF-DO`.** Because they never parse `AR-DO` contents (their README admits
"format of APDU-AR-DO, NFC-AR-DO is not checked"), they store arbitrary rule
bytes opaquely and can hold anything a future spec adds. We now validate and
store the two shapes that mattered most — `D0` APDU rules **and** the 8-byte
`DB` `PERM-AR-DO`, plus the zero-length catch-all `AID-REF-DO` — but our
validator still rejects:

  - `NFC-AR-DO` (`D1`): changes validation and merge semantics, deferred to a
    concrete NFC requirement (see C12 / R9 below);
  - `PKG-REF-DO` (`CA`): package names push a `REF-AR-DO` past the 96-byte
    record and force a capacity re-plan, deferred until a requirement exists.

  What we *can* express: APDU filter/mask pairs (`D0` of any multiple of 8),
  `Always`/`Never` (`D0 01 01` / `D0 01 00`), the 8-byte `PERM-AR-DO`, a
  zero-length `DeviceAppID` wildcard, the zero-length catch-all AID, and SHA-1
  or SHA-256 signer hashes. The Android carrier-privilege rule shape — the
  all-`FF` wildcard AID paired with `D0` + `PERM-AR-DO` — now validates and
  stores in full.

  **One honest caveat:** `PERM-AR-DO` support lives in code (`3e0561c`) but the
  pinned installed CAP is `v0.2.0-rc1` (`5b6e170`), which predates the
  `2e1abc4` PERM-AR-DO commit. So the *capability* is present and tested on the
  simulator, but no carrier-privilege `PERM-AR-DO` rule is deployed on the
  installed CAP yet. The remaining `D1`/`CA` gap is a deliberate
  safety-versus-expressiveness trade, reopened only by a concrete product
  requirement, not by comparison pressure.

**4. `FF50` and `F2` exist there and not here.** Both are deliberate skips —
`FF50` is deprecated in SEAC v1.1 and AOSP consumes the full catalog through
`FF40`/`FF60`, and automatic refresh is strictly stronger than a separate `F2`
lifecycle. They remain capability differences on paper.

## Fork delta: sysmocom vs bertrandmartel

Only three substantive changes, all in `AccessRuleMaster.java`:

1. `SIZE_HASH` 20 → 32, making room for SHA-256 signer hashes. Per-rule payload
   grows 198 → 210 B for every rule including SHA-1 ones. No test exercises it —
   all fixtures still use 20-byte hashes.
2. Proprietary `A1`/`A2` lock/unlock of the raw STORE DATA path. The check lives
   in `process()` rather than `processCmdStoreData()`, which is what makes the
   unlock reachable only through SD-authenticated personalization. Untested,
   unlocked by default, not observable through any command.
3. Named constants replacing `0xF0`/`0xF1`/`0xF2` literals — no behaviour change.

Everything else is build modernisation. Note that sysmocom's README upgrades the
conformance claim from SEAC v1.0 to **v1.1 with no accompanying command-set
change** — `E7`, `F6`, `F7`, `F8` remain absent and `delete REF-AR-DO` is still
unchecked in their own task list. jc-ara-m makes no v1.1 claim at all and
documents itself as a named bounded profile, which is the more defensible
position.

## Shared defects worth not inheriting

Both bmartel and sysmocom read TLV lengths through a **signed** byte
(`short len = buffer[ofs++]`), so a length ≥ `0x80` becomes negative, passes the
`len > maxLen` guard, and moves the cursor backwards; `AramUtils.buildRefArDo`
compounds this by returning `byte`. Rules longer than 127 bytes are therefore
mishandled despite `SIZE_RULE` being 162. jc-ara-m's `readLength` rejects any
long-form length outright, and caps a `REF-AR-DO` at 96 bytes by construction.

Their `processData()` also ignores its `offset` and `length` arguments and reads
`P1`/`P2`/`CDATA` at fixed buffer indices. On a Security Domain that hands over
the underlying APDU buffer — as CARD#5 does — this happens to work, which is
exactly why our own v0.1.1 worked before the contract was corrected in
`17bb1a6`. On a Security Domain that passes a trimmed copy it breaks. Ours now
parses `[offset, offset+length)` as the command data field, which is the
contract `org.globalplatform.Application` actually specifies.

## Ledger status after WP4

Against the `C1`-`C12` decision ledger in [IMPROVEMENTS.md](../IMPROVEMENTS.md):

| Item | Previous | Now |
| --- | --- | --- |
| C1 many-to-many capacity | PULL-IN P0 | **DONE** — arena shipped, `R=16` filled and `6A84` proven on CARD#5 |
| C2 keyed update / individual delete | PULL-IN P0 | **DONE** — `F0` upsert + `F1` forms, exercised on hardware |
| C3 `FF60` continuation | PULL-IN P0 | **DONE** — 816-byte catalog streamed in 3 continuations on CARD#5; and Android's own `AraController` now issues `FF60` on a 339-byte 6-rule catalog (`TASK-260720-1xkffz`) |
| C9 deterministic SHA-256 simulator vectors | PULL-IN P1 | **DONE** — `Sha256VectorTest` (8 tests, `c9b4880`) closes the dedicated store/byte-exact-readback/keyed-replacement/refresh-per-mutation/coexistence-delete/malformed-rejection contract; hardware SHA-256 grant *and* deny remain a separate evidence layer |
| C10 CARD#5 capacity/commit evidence | PULL-IN P0 gate | **DONE** — measured at `R=16`, both transaction paths exercised |
| C11 immutable CAP provenance | PULL-IN P1 | **DONE** — signed CAPs, digests, toolchain manifests |
| C4 `FF50`, C5 `F2`, C6 `E7`, C8 raw STORE/locks, C12 full v1.1 | WONT-DO | unchanged, and the analysis above reinforces C8 in particular |
| C7 ARA-C | DEFER | unchanged |

## Hardening closed since the 2026-07-20 refresh

The 2026-07-20 draft carried eight recommendations, R1-R8. All eight landed in
the hardening wave and are recorded here as evidence rather than left as open
advice. Only R9-R10 remain genuinely open (next section).

**R1 — Prove Android's own `FF60` loop. — DONE.** The standard 3-rule instance
(156 bytes) fits one response, so WP4's Android run only ever bracketed the rule
read with two `transmit()` calls (`DF20` + `FF40`) and never exercised `FF60`.
`TASK-260720-1xkffz` grew the standard AID to 6 rules (339-byte catalog) on
CARD#5 and re-ran the Android matrix: the enforcer trace now shows **three**
`transmit()` calls — `DF20`, `FF40` first block, then `FF60` continuation — with
Android's own `AraController` issuing the `FF60` because it could not read the
catalog in a single `FF40`. Grant/deny cross-pair isolation held on the enlarged
catalog. This closes the one seam where our design differed most from every
implementation Android had previously been tested against.

**R2 — Add an independent SEAC parser as a test oracle. — DONE.** `b5d43df`
adds `SeacParserOracleTest` (11 tests), which decodes the applet's
`FF40` + `FF60` stream with GlobalPlatformPro's `pro.javacard.gp.SEAccessControl`
— an unrelated third-party SEAC implementation — and asserts the recovered rule
set equals the provisioned one. It deliberately shares no encoding helper with
`AraMAppletTest` (whose expectations this repo builds itself), so a
self-consistent-but-wrong encoding that would be invisible against our own
expectations cannot pass the oracle. The dependency is `testImplementation` only
and cannot reach the CAP. This closes the comparison's one remaining
test-quality deficit; with it, our jCardSim + Go suites (103 + 41) now both
exceed and out-cover the 70-test OSS suite.

**R3 — Fuzz the TLV validator. — DONE.** `7e1570a` fuzzes **both**
attacker-influenced parsers with falsifiable oracles —
`AraMPersonalizationFuzzTest` (11 tests) over the STORE DATA rule bytes and
`AraMInstallParameterFuzzTest` (7 tests) over the install-parameter block — and
`aafc22d` makes the must-reject fixtures fail for the specific reason they name.
On any rejection the catalog and refresh tag stay bit-identical to the entry
state and no non-ISO exception escapes.

**R4 — Close C9. — DONE.** `c9b4880` adds `Sha256VectorTest` (8 tests): the
dedicated synthetic-`C1 20` store, byte-exact 32-octet readback, exact-`REF-DO`
replacement leaving neighbours untouched, one-refresh-tag-per-visible-mutation,
SHA-1/SHA-256 coexistence with individual deletion, and the malformed-width
rejection trio — all with catalog, refresh tag, and revision unchanged on
rejection. Ledger C9 is now DONE (see the ledger table above).

**R5 — Bind the manifest's capacity to the pinned release artifact. — DONE.**
`e25f1a8` cross-checks the desired-state `capacity` against the digest-pinned
release CAP rather than trusting the manifest, so a capacity mismatch is caught
at plan time instead of surfacing as a mid-rollout `6A84` at commit. Covered by
`host/capacity_binding_test.go`.

**R6 — Resolve the "installation-time capacity" discrepancy. — DONE.**
`7271f58`: `install()` reads `R` from the GlobalPlatform application-specific
parameter block (`80 01 R`, optionally inside its `C9` container), defaults to
16 when absent, and clamps to a compiled maximum of 64. Every buffer is still
allocated once, at install, from that value — bounded storage *and*
field-configurable capacity, which no implementation in this comparison has.
Covered by `InstallParametersTest`; format documented in
`docs/architecture/multi-rule-seac-architecture.md` §3.2.

**R7 — Accept `PERM-AR-DO` (`DB`, exactly 8 bytes) alongside `D0`. — DONE.**
`2e1abc4`: `validateArDo()` now accepts an optional `PERM-AR-DO` after the
`APDU-AR-DO`, validating SEAC member order and the exact 8-byte length rather
than accepting opaque bytes. This unlocks the Android carrier-privilege rule
shape, the most commonly cited real-world rule we could not store. Footprint
cost is nil — a carrier-privilege rule serialises to roughly 61 bytes, the worst
realistic case (two APDU filter/mask pairs plus `PERM-AR-DO`) to roughly 76,
both inside the 96-byte record. **Deployment caveat unchanged:** the pinned
installed CAP `v0.2.0-rc1` predates this commit, so the capability is present
and simulator-tested but no `PERM-AR-DO` rule is deployed on the installed CAP.

**R8 — Accept the zero-length `AID-REF-DO` catch-all. — DONE.** `3ca0b83`
(plan/reconcile) and `3e0561c` (migrate) accept the zero-length `4F` catch-all
as a storable `REF-DO`; `validateRefDo()` now permits `aidLength == 0`. The
safety guard lives host-side in the provisioner: a catch-all *allow* rule cannot
be planned without the explicit `--allow-catch-all` flag, so the card stays a
faithful SEAC store and the policy decision is reviewable and diffable in the
desired state.

## Remaining recommendations

Only the two footprint- and semantics-changing expressiveness items are still
open. Both preserve the design invariants in [IMPROVEMENTS.md](../IMPROVEMENTS.md)
and should be reopened by a concrete product requirement, not comparison pressure.

**R9 — `NFC-AR-DO` (`D1`).** Only behind a concrete requirement, with the same
discipline as C12: it changes validation and merge semantics and deserves its
own architecture decision rather than being added for parity.

**R10 — `PKG-REF-DO` (`CA`).** The only expressiveness item that genuinely costs
footprint, since package names push a `REF-AR-DO` past the 96-byte record and
force a capacity re-plan. Defer until a requirement exists.

### Explicitly do not adopt

Their append-only store, their `F2` refresh lifecycle, and sysmocom's `A1`/`A2`
lock. The lock is a retrofit onto an open raw-mutation path; our boundary is
closed by construction and a mutable lock state would weaken it, not strengthen
it. This reinforces ledger items C5 and C8 rather than reopening them.

## Bottom line

For a deployment that provisions rules over an authenticated channel and needs
them to be correct, jc-ara-m is the stronger implementation: it is the only one
of the four whose refresh tag cannot go stale, whose rule updates are keyed and
idempotent, whose multi-rule mutations are atomic under both transaction
ownership models, and whose raw mutation surface is closed by construction. It
is also the only one with host provisioning tooling and captured hardware and
Android evidence.

The open-source line retains two honest advantages: unbounded rule-count
headroom, and the ability to carry the two rule shapes we still reject
(`NFC-AR-DO`, `PKG-REF-DO`) because it validates nothing. The unit-test-breadth
and independent-parser-oracle advantages it held at the last refresh are gone —
our 103 jCardSim + 41 Go tests now exceed their 70, and we run the same
GlobalPlatformPro SEAC oracle plus TLV fuzzers they never had. sysmocom is the
only external project still maintained, and its `A1` lock is a genuine improvement
over upstream — but it is off by default and untested, so an unlocked
sysmocom ARA-M has an open write surface reachable from the handset. cheeriotb
should be read for its rule encodings and ignored as an implementation.
