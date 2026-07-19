# jc-ara-m multi-rule SEAC architecture

**Task:** `TASK-260719-3r17pa`  
**Decision status:** proposed for implementation review  
**Baseline:** jc-ara-m `v0.1.1` (`10b8f42` applet behavior; repository HEAD
`ea3c12d` adds licensing metadata only)  
**Target profile:** bounded multi-rule ARA-M for many customer applets and
Android application signers

This document makes the cross-cutting decisions required to evolve the proven
single-slot applet without implementing applet code in the architecture task.
It is mirrored at
`.research/260719_jc-ara-m-multi-rule-seac-architecture.md` in the bSIM
workspace.

## 1. Requirements and decision summary

The requirements below name the task acceptance criteria so follow-up board
work can cite them without inventing scope.

| ID | Requirement | Decision |
| --- | --- | --- |
| MR-1 | Store N applet-to-app authorization pairings with a Java Card Classic-feasible EEPROM budget. | Use a bounded flat record arena with `R + 1` physical records, at most `R` active rules, one inactive copy-on-write spare, and an atomic active bitmap. Do not use a linked object list or a persistent secondary index. |
| MR-2 | Add/update/delete individual rules and return all rules with continuation. | `F0` is an idempotent upsert keyed by exact `REF-DO`; `F1` supports AID, exact `REF-DO`, and all; `FF40` advertises the complete BER length and `FF60` returns raw continuation bytes. |
| MR-3 | Keep rule mutations and the ARA-M refresh tag atomic. | Write a new rule only into an inactive record, then atomically publish active bitmap + new refresh tag + revision. Non-atomic staging is allowed only when ARA-M owns the publication transaction; a caller-owned transaction uses an atomic candidate-record write. Delete publishes only metadata. |
| MR-4 | Provision N rules OTA through the authenticated Security Domain with deterministic, resumable behavior. | Reconcile normalized desired/current maps, send one complete rule per `F0`, use fail-closed ordering, and re-read/re-diff after interruption. Each command is atomic; an N-command manifest is resumable, not one card transaction. |
| MR-5 | Migrate CARD#5 from the single-slot release without bricking it. | Export the current rule, prove a multi-rule canary and a rollback artifact, then replace the standard-AID package in a maintenance window. Restore v0.1.1 and the exported rule on any failure. No in-place EEPROM schema conversion is assumed. |
| MR-6 | Decide which sysmocom / SEAC v1.1 features enter the bounded profile. | Adopt multi-rule, `F0`, the required `F1` subset, `FF40`, `FF60`, and `DF20`; skip deprecated `FF50`, ARA-C delegation (`F6`/`F7`), configuration negotiation, `F2`, `E7`, proprietary lock/unlock, and raw direct STORE for this release. |
| MR-7 | Back claims with source/spec evidence and retain no card secrets. | References identify the exact specification sections and source snapshots. The document contains no card identifier, subscriber identifier, key, certificate hash, or refresh value. |

The central choice is the `R + 1` record pool. It preserves the current
applet's strongest invariant—an old valid state remains visible until one
publication transaction commits—without duplicating every logical rule as a
permanent A/B pair. The small-commit fast path applies when ARA-M owns that
transaction; section 5 also defines the safe composition path when the Security
Domain already owns one.

## 2. Scope and invariants

### 2.1 Rule identity and many-to-many mapping

One active record represents one authorization pairing:

```text
RuleKey = (AID-REF-DO value, DeviceAppID-REF-DO value)
        = (customer applet AID, Android signing-certificate hash)
```

The active rule count is the number of populated pairings, not necessarily the
Cartesian product. For a fully populated N-by-M policy, `Rrequired = N * M`.
An additional SHA-1 or SHA-256 representation of the same signer is a distinct
`DeviceAppID` and therefore a distinct key if both are provisioned. Production
manifests should prefer SHA-256; SHA-1 and an empty `C1` remain codec-compatible
for migration and controlled interoperability.

The active catalog has these invariants:

1. At most `R` of `R + 1` physical records are active.
2. Exactly one active record exists for each exact `REF-DO`.
3. An inactive record is never serialized by `FF40`/`FF60`.
4. The active bitmap, refresh tag, and catalog revision describe one state and
   change in one Java Card transaction; any candidate write that could damage
   the transaction's rollback state is journaled in that same transaction.
5. Raw selected-applet `INS E2` remains permanently rejected with `6982`;
   mutation is reachable only through `Application.processData(...)` from the
   authenticated Security Domain flow.

### 2.2 Bounded profile

The first multi-rule release remains deliberately smaller than full SEAC v1.1:

- one complete short-APDU `REF-AR-DO` per `F0`, maximum 96 bytes including `E2`;
- `AID-REF-DO` length 5..16 and `DeviceAppID-REF-DO` length 0, 20, or 32;
- APDU access rules (`D0`) only, as in v0.1.1;
- no ARA-C aggregation or delegated owner;
- no promise that a whole N-rule manifest commits atomically.

Each accepted individual mutation is atomic. If a multi-command OTA run stops,
the card contains a valid prefix state whose refresh tag reflects every visible
change; reconciliation can resume from readback.

## 3. Storage model

### 3.1 Options considered

| Model | EEPROM predictability | Atomic mutation cost | Delete-all behavior | Decision |
| --- | --- | --- | --- | --- |
| Dynamic linked `RuleEntry` objects | Low: per-entry object, three arrays, links, deleted-list objects, and allocator behavior. | Rule payload and links participate in transactions; object creation/deletion complicates rollback and fragmentation. | sysmocom loops and commits each deletion separately, so catalog + refresh is not one atomic state. | Reject. Useful prior art for command breadth, not for the storage invariant. |
| One fixed 96-byte slot per rule, updated in place | High and compact. | Updating rule bytes + length + refresh consumes commit capacity proportional to the rule; clearing many slots is proportional to match count. | AID/all deletion can exceed a small commit buffer or require partial commits. | Reject. It does not preserve atomic bulk deletion across arbitrary `R`. |
| Full dual catalog banks | High. | Only bank selector + refresh need commit. | Atomic. | Reject for this profile: always doubles the complete catalog and rewrites all live rules for one mutation. |
| Fixed `R + 1` record pool with one inactive spare and active bitmap | High; three bounded persistent arrays/fields, no per-rule object graph. | Commit size is bitmap + refresh + revision, independent of rule length and number of deletions. | Clear any subset in a transient next bitmap, then publish once. | **Adopt.** |
| Fixed records plus persistent hash index | High but larger. | Index and catalog must be committed together. | Atomic but more metadata. | Reject. `R` is small enough for a linear scan, and an index adds a second consistency surface. |

The sysmocom snapshot proves a linked list can implement multi-rule reads and
deletes, but it allocates 16 AID bytes + 32 hash bytes + 162 rule bytes = 210
payload bytes per entry before object/array/link overhead
(`AccessRuleMaster.java:42-44`, `RuleEntry.java:34-57`). Its multi-match delete
methods commit one removed entry at a time (`RuleEntry.java:172-239`), and its
refresh update is a separate command (`AccessRuleMaster.java:419-422`). These
are exactly the properties the new jc-ara-m design avoids.

### 3.2 Persistent layout

Let `R` be the installed maximum number of active rules.

```text
recordArena[(R + 1) * 97]
  record i:
    length  : 1 byte, 0..96
    refArDo : 96 bytes, complete E2 stored verbatim

activeBitmap[ceil((R + 1) / 8)]
refreshTag[8]
catalogRevision: short (2 bytes)
schemaVersion: byte (1 byte)
```

The implementation allocates the arena as one byte array rather than `R + 1`
objects or arrays. Record bytes beyond `length` have no meaning. A transient
next bitmap and next refresh tag are used to stage metadata. Read cursor,
channel binding, and revision snapshot are transient and consume RAM, not
EEPROM.

`R` is an installation-time capacity in the release profile, with a documented
default and an allowed range. Allocation failure must fail applet installation;
runtime `F0` add at `R` active records returns `6A84` and changes nothing. The
production value for CARD#5 is a release gate measured by the physical
acceptance task, not an unverified EEPROM claim in this document.

### 3.3 Capacity math

The lower-bound persistent payload is:

```text
P(R) = (R + 1) * 97 + ceil((R + 1) / 8) + 8 + 2 + 1 bytes
```

This excludes Java Card implementation-specific object/array headers, allocator
granularity, package code, transaction journal, and other runtime overhead. It
is therefore sizing arithmetic, not CARD#5 EEPROM telemetry.

| Active capacity `R` | jc-ara-m lower bound | Bytes / usable rule at full capacity | sysmocom fixed payload | Payload reduction vs sysmocom |
| ---: | ---: | ---: | ---: | ---: |
| 8 | 886B | 110.75B | 1,680B | 47.3% |
| 16 | 1,663B | 103.94B | 3,360B | 50.5% |
| 32 | 3,217B | 100.53B | 6,720B | 52.1% |
| 64 | 6,325B | 98.83B | 13,440B | 52.9% |

When ARA-M enters `processData` at transaction depth zero, the explicit bytes
changed in its publication transaction are:

```text
Cowned(R) = ceil((R + 1) / 8) + 8 + 2 bytes
```

When the Security Domain already owns a transaction, an `F0` add/update must
also journal the complete 97-byte candidate record so a later command in the
same outer transaction cannot overwrite a record that abort would reactivate:

```text
Cjoined-F0(R) = 97 + Cowned(R) bytes
Cjoined-F1(R) = Cowned(R) bytes
```

Both formulas exclude JCRE journal overhead. For `R=16`, the explicit owned
fast path is 13 bytes and the joined `F0` path is 110 bytes. If several
callbacks share one outer transaction, journal usage accumulates for distinct
persistent locations; the implementation must check remaining commit capacity
before each joined write and propagate failure without a visible change.
Oracle documents that commit capacity is only approximate because
field-dependent overhead also occupies the buffer. The implementation and
physical gate must therefore exercise both paths on CARD#5; arithmetic alone
cannot prove either one.

### 3.4 Copy-on-write selection

For an add or update, scan active records for the exact `REF-DO`, then choose an
inactive physical record:

- update: the old record stays active while the new full rule is written to an
  inactive record;
- add: reject with `6A84` if active count is `R`, otherwise write any inactive
  record;
- choose inactive records by a rotating scan to spread low-frequency EEPROM
  writes where more than one free record exists.

At transaction depth zero, write `length=0`, then the bounded payload, then the
new length with non-atomic operations while the record is inactive. A tear can
corrupt only an unreachable record; ARA-M then begins the small metadata
transaction.

If `JCSystem.getTransactionDepth()` is already non-zero, non-atomic staging is
forbidden. A preceding callback in the same outer transaction may have made a
record inactive only provisionally, so abort could still reactivate it. Build
the complete 97-byte record in transient RAM, check remaining commit capacity,
and use an atomic persistent copy inside the caller-owned transaction. This
joined path costs more commit capacity but keeps rollback correct for one or
many callbacks. No objects are allocated during either path.

## 4. Command contract

### 4.1 Common security boundary

Runtime GET commands remain available to the selected ARA-M. Runtime raw
`INS E2` remains `6982`. `F0` and `F1` are accepted only when a Security Domain
delivers the full STORE DATA APDU buffer through
`Application.processData(...)` after authenticated `INSTALL [for
personalization]`.

The supported STORE shape remains a complete BER-TLV command in one block:

```text
CLA E2 90 00 Lc <F0-or-F1-command>
```

Each `F0` contains one complete `REF-AR-DO`, as required by SEAC v1.1 §5.1.1.1
“Storage of several rules.” Multiple rules may be sent in one personalization
session, but each rule is a separate STORE DATA command.

### 4.2 `F0` add/update (upsert)

Identity is the exact parsed `REF-DO`: AID length/value plus DeviceAppID
length/value.

1. Validate the complete `F0`/`E2`/`E1`/`E3`/`D0` structure, plus the optional
   `DB` `PERM-AR-DO` member, before any persistent write.
2. If no active record has the key, add it if capacity permits.
3. If one active record has the key, the APDU-only profile replaces its `D0`
   rule with the supplied rule. This is the applicable SEAC overwrite case for
   two APDU-only rules (§5.1.1.1, Table 5-3).
4. If the complete incoming `E2` is byte-identical to the active record, return
   `9000` without writing the arena, bitmap, refresh, or revision. This makes
   OTA retries idempotent; no access-control data changed.
5. Otherwise stage the new record and atomically switch visibility as described
   in section 5.

Changing the DeviceAppID changes the key; it is not an in-place update. The
provisioner performs an exact-key `F1` plus a new-key `F0` using the ordering in
section 7.

### 4.3 `F1` delete

The release adopts the three deletion forms required by the task:

| `F1` value | Effect | No-match result |
| --- | --- | --- |
| empty | Delete all active records. | Empty catalog is an idempotent `9000` no-op. |
| `AID-REF-DO` (`4F`) | Delete every active rule for that applet AID. | `6A88`; refresh unchanged. |
| complete `REF-DO` (`E1`) | Delete the one exact `(AID, DeviceAppID)` key. | `6A88`; refresh unchanged. |

All matching bits are cleared in a transient next bitmap, then the bitmap,
refresh, and revision are committed once. Stale record bytes remain inactive
and are overwritten before reuse.

The `F1` `REF-AR-DO` form for deleting only APDU/NFC sub-objects is not adopted
in the APDU-only profile. Return `6981` (data object not supported) for that
form rather than silently interpreting it as a whole-key delete.

### 4.4 `F2` refresh-only command

Do not expose `F2` in this release. Every accepted catalog mutation already
changes `DF20` atomically. There is no ARA-C or other on-card rule owner whose
out-of-band changes require a refresh-only signal. Unsupported `F2` returns
`6981`.

### 4.5 Status behavior

| Condition | Status |
| --- | --- |
| Accepted change or idempotent no-op | `9000` |
| Raw selected-applet STORE DATA | `6982` |
| Unsupported command DO (`F2`, `E7`, `F6`, `F7`, `F8`, `F1` partial AR delete) | `6981` |
| Malformed, duplicate-key-corrupt, or inconsistent TLV | `6A80` |
| Active capacity exhausted | `6A84` |
| Delete target not found (except empty delete-all) | `6A88` |
| Wrong STORE P1/P2 or block number | `6A86` |
| Transaction/runtime memory failure | `6581`; no visible change |

## 5. Atomic mutation and refresh semantics

The atomic unit is one accepted `F0` or `F1` command.

### 5.1 Add/update

1. Parse and validate the complete command.
2. Find the old active record, if any, and an inactive record.
3. Capture transaction ownership before writing the candidate:
   - at depth zero, write the candidate non-atomically into the committed-state
     spare;
   - at non-zero depth, preflight remaining commit capacity and atomically copy
     the full candidate record inside the caller-owned transaction.
4. Build `nextBitmap`, a new random 8-byte refresh tag different from the
   current tag, and `nextRevision = catalogRevision + 1` in transient RAM.
5. If no transaction was active, begin one. If the Security Domain already
   owns a transaction, reuse it and never commit or abort it locally.
6. Atomically copy the next bitmap and refresh, then set the revision.
7. Commit only if the applet began the transaction.

### 5.2 Delete

Steps are identical except no record payload is written: compute the full
post-delete bitmap in transient RAM and publish it with refresh/revision once.
Delete-by-AID and delete-all therefore do not loop over persistent commits.

### 5.3 Failure matrix

| Failure point | Visible catalog | Visible refresh/revision |
| --- | --- | --- |
| Validation or no-match rejection | Old | Old |
| Tear during owned-path non-atomic spare write | Old; torn record unreachable | Old |
| Tear during joined-path atomic candidate write | Outer transaction restores its entry state | Outer transaction restores its entry state |
| Exception before metadata transaction | Old | Old |
| Tear/exception during metadata transaction | JCRE rolls metadata back to old state | Old |
| Successful metadata commit | New | New, in the same commit |

If the applet owns the transaction and catches a failure, it aborts only that
owned transaction before mapping the error. If a Security Domain owns the
transaction, candidate and metadata writes are all atomic and the applet
propagates failure so the owner/JCRE can abort; it must not commit or abort
another component's transaction. The design therefore does not assume that an
INSTALL [for personalization] session maps to one transaction or one
transaction per callback.

This is stronger than sysmocom's separate rule and `F2` refresh operations and
directly implements SEAC v1.1 §5 lines 779-783 and §5.1.1.1 lines 846-850.

The mutation sequence is shown in
[`atomic-rule-mutation.puml`](../../diagrams/plantuml/sequence/atomic-rule-mutation.puml).

## 6. `FF40` and `FF60` retrieval

### 6.1 Serialization

`GET DATA [All]` serializes all active `E2` records in ascending physical-record
index. Order is not a rule identity and provisioners compare normalized sets,
not raw catalog byte order.

The `FF40` BER length is the full sum of active record lengths even when only a
prefix fits in the response. Encode short, `81`, or `82` length form as needed.
The first response contains:

```text
FF 40 <full BER length> <first bytes of concatenated active E2 records>
```

If bytes remain, bind one transient read session to the current logical channel
and record:

- next logical byte offset;
- total logical length;
- catalog revision at `FF40` start.

`GET DATA [Next]` (`FF60`) returns only the next raw bytes—no repeated `FF40`
tag or length—and `9000`. It streams from the arena by logical offset; it never
builds the entire catalog in RAM. Clear the session after the final byte.

### 6.2 Session errors and concurrent mutation

- `FF60` without a live preceding `FF40` returns `6985`.
- A second channel requesting a read while the one supported read session is
  active returns `6984`; the current Android flow uses one ARA-M channel.
- A mutation increments `catalogRevision` in the same metadata transaction.
- If `FF60` observes a revision different from its snapshot, it returns `6984`
  once and clears the session. The ACE must discard the prefix and restart with
  `FF40`.
- A new `FF40` on the bound channel restarts the session from offset zero.
- Reset/deselect clears transient retrieval state.

These rules implement SEAC v1.1 §4.1 lines 425-440, §4.1.1.1 lines 449-464,
and §4.1.2.1 lines 488-497. They also match AOSP `AccessRuleApplet`, which
decodes the full `FF40` value length and loops on `FF60` until it has that many
bytes.

## 7. OTA N-rule provisioning

### 7.1 Desired-state input

The TSM/provisioning service treats the desired catalog as a map keyed by exact
`REF-DO`.

Before card mutation it must:

1. parse and validate every complete rule;
2. reject duplicate keys in the manifest;
3. sort keys lexicographically by AID bytes, then DeviceAppID length and bytes;
4. read current `FF40` plus all `FF60` chunks and normalize it to the same map;
5. verify the final desired count is within the installed capacity;
6. compute add, exact-key update, and delete sets.

No card identifiers, subscriber identifiers, Security Domain keys, certificate
hashes, or refresh values are written to board notes or general logs.

### 7.2 Authenticated command sequence

Open the existing authenticated administrative channel, enter `INSTALL [for
personalization]`, and send separate last-block/block-zero STORE DATA commands.
One personalization session may contain multiple commands.

Ordering is fail-closed:

1. send byte-changing `F0` updates whose exact key already exists;
2. delete obsolete or broader keys with `F1` in canonical order;
3. add new keys with `F0` in canonical order;
4. close the administrative session;
5. read back `FF40`/`FF60` and `DF20`, normalize, and require exact desired-set
   equality.

When a policy changes key (for example empty DeviceAppID to a certificate hash),
SEAC's standard command set cannot replace both keys in one APDU. Delete-first
creates a temporary denial window but never a temporary over-grant. The design
chooses this fail-closed behavior. A future whole-catalog transaction would be
a distinct requirement, not hidden inside `F0`/`F1`.

### 7.3 Idempotency and interrupted sessions

- Identical `F0` returns `9000` without changing refresh/revision or consuming
  EEPROM endurance.
- The provisioner does not assume which command committed after a transport
  error. It reopens a channel, re-reads the effective catalog, and recomputes
  the diff.
- `F1 6A88` is accepted as convergence only after readback proves the key is
  absent; it is not globally converted to success.
- A failure midway leaves a valid catalog and a refresh tag consistent with its
  last committed mutation.
- Capacity is checked against the final desired set. Delete-before-add also
  frees records for key replacements at full capacity.

The flow is shown in
[`ota-rule-reconciliation.puml`](../../diagrams/plantuml/sequence/ota-rule-reconciliation.puml).

## 8. CARD#5 migration from v0.1.1

### 8.1 Why migration is export/reinstall/import

The installed v0.1.1 instance owns a single 96-byte array and has no schema
version or upgrade hook (`AraMApplet.java:18,30-45`). Loading the new CAP does
not provide a portable Java Card mechanism to reinterpret that instance's
private persistent objects, and the standard ARA-M package/instance AIDs cannot
be held by both versions simultaneously. The migration therefore does not
claim in-place object preservation.

### 8.2 Mandatory preflight

Do not delete the current package until all gates pass:

1. Read the current `FF40` rule and `DF20`; validate the rule and hold it only
   in the task-scoped secure migration input, not general logs.
2. Produce an immutable rollback CAP from `v0.1.1` / `10b8f42`, with digest,
   signature, and toolchain manifest. The historical CARD#5 install digest is
   evidence, but the mutable build path is not a rollback artifact.
3. Prove rollback install + authenticated rule restore on a sacrificial card or
   an alternate-AID canary build.
4. Build the multi-rule release in an alternate package and instance AID canary
   variant. Load it beside v0.1.1 on CARD#5 if capacity allows; test add,
   overwrite, delete, `FF40`/`FF60`, refresh changes, power/command failure
   recovery, owned and caller-owned transaction paths, and raw `E2=6982`
   without touching the standard ARA-M instance.
5. Record the chosen installed capacity and prove its worst-case metadata
   transaction against CARD#5. If the canary or rollback gate fails, keep
   v0.1.1 installed and stop.

### 8.3 Maintenance replacement

With CARD#5 removed from Android and a verified administrative recovery path:

1. Reconfirm the current rule export and known-good rollback assets.
2. Delete the v0.1.1 standard instance/package.
3. Load and install the multi-rule release at package
   `A00000015141434C` and instance `A00000015141434C00`, with the validated
   capacity.
4. Restore the exported rule first through authenticated personalization.
5. Reconcile the full desired N-rule catalog.
6. Verify SELECT, `FF40`/`FF60`, `DF20`, raw STORE denial, exact normalized
   catalog, and then Android positive/negative signer behavior.

Android is fail-closed while the standard ARA-M is absent or empty. This is a
planned maintenance interval, not an atomic package swap.

### 8.4 Rollback

On any load, install, personalization, readback, or Android acceptance failure:

1. delete the partial multi-rule package/instance if present;
2. reinstall the verified v0.1.1 rollback CAP at the standard identity;
3. restore the exported original rule through authenticated personalization;
4. verify `FF40`, `DF20`, raw STORE denial, and the previously accepted Android
   signer behavior;
5. stop rollout and retain evidence without secrets.

The state transitions are shown in
[`v011-to-multirule-migration.puml`](../../diagrams/plantuml/state/v011-to-multirule-migration.puml).

## 9. Adopt / skip matrix

| Feature | Decision | Rationale / behavior |
| --- | --- | --- |
| Multi-rule storage | **Adopt** | Core MR-1 requirement; bounded `R + 1` flat pool, not sysmocom's dynamic linked list. |
| `F0` store/update | **Adopt** | Core MR-2 requirement. Exact `REF-DO` is an idempotent upsert key; APDU-only overwrite follows SEAC Table 5-3. |
| `F1` delete | **Adopt subset** | AID, exact `REF-DO`, and all are required. Partial APDU/NFC sub-object deletion by `REF-AR-DO` is skipped in the APDU-only profile. |
| Automatic refresh with mutation | **Adopt** | Bitmap + random 8-byte `DF20` value + revision commit together for every real change. |
| `F2` update-refresh-only | **Skip** | No external rule owner exists; automatic refresh is sufficient and avoids a separate lifecycle step. |
| `FF40` GET all | **Adopt/extend** | Preserve existing command; add BER `81`/`82` lengths and streaming across all active records. |
| `FF60` GET next | **Adopt** | Required once `FF40` exceeds one APDU; raw continuation bytes, `9000`, and `6984` invalidation on mutation. |
| `FF50` GET specific | **Skip** | Deprecated by SEAC v1.1; Android/AOSP uses `FF40` + `FF60` and caches the full catalog. |
| ARA-C delegated owners | **Skip** | Target has one centrally managed ARA-M and one authenticated Security Domain path; no delegated multi-owner requirement. |
| `F6` Get Client AIDs | **Skip** | Only useful with registered ARA-Cs. |
| `F7` Register Client AIDs | **Skip** | Only useful with installed ARA-Cs and introduces owner/conflict aggregation. |
| `F8` / `DF21` config negotiation | **Skip** | Not required by the proven Android flow; continue as a bounded partial profile rather than claim full v1.1. |
| `E7` Block-DO / cross-session rule transfer | **Skip** | Each supported rule is at most 96 bytes and fits one short STORE DATA command. N rules use N commands. |
| sysmocom `A1`/`A2` raw-path lock | **Skip** | Raw mutation is never enabled, so a mutable lock state is unnecessary. |
| Direct raw STORE DATA | **Keep denied** | Preserve the v0.1.1 security boundary and CARD#5 evidence. |
| NFC AR-DO | **Skip for this release** | Current requirement and proven codec are APDU access. Adding NFC changes validation/merge/delete semantics and needs its own requirement. |
| `DB` PERM-AR-DO | **Adopt** | Validated optional `AR-DO` member in SEAC order after the mandatory `D0`: exactly 8 bytes, at most once, last. Unlocks the Android carrier-privilege rule shape (61B) with no capacity change; worst accepted shape is 86B against the 96B record. |

This is a named bounded profile, not a claim of complete SEAC v1.1
conformance.

## 10. Implementation work packages and dependencies

The smallest development decomposition after this decision is:

1. **WP1 — Multi-rule catalog and atomic mutation:** implement the flat arena,
   active bitmap, exact-key lookup, `F0`, required `F1` forms, refresh/revision
   transaction ownership paths, capacity errors, and simulator tear/failure
   invariants. Covers
   MR-1, MR-2 mutation, MR-3.
2. **WP2 — Streaming GET all/next:** implement BER lengths, arena streaming,
   session/channel binding, and revision invalidation. Depends on WP1. Covers
   MR-2 retrieval and MR-3 concurrency.
3. **WP3 — Authenticated desired-state provisioner and migration controls:**
   implement deterministic read/diff/F1/F0/readback reconciliation, canary build
   identity, rollback artifact checks, and the guarded replacement runbook.
   Depends on WP1 and WP2. Covers MR-4 and MR-5.
4. **WP4 — Physical CARD#5 acceptance:** measure the installed capacity/commit
   gate, exercise canary and rollback, migrate in the maintenance flow, then
   prove multi-rule Android allow/deny and interruption recovery. Depends on
   WP1-WP3. Covers MR-1 evidence, MR-3 hardware evidence, MR-4, MR-5, MR-7.

`FF50`, ARA-C/config, `F2`, and `E7` are explicit skips, so they do not justify
implementation tasks in this scope.

## 11. Verification gates

### Simulator / CAP

- storage invariants for empty, add, exact update, identical retry, delete by
  AID, delete by REF-DO, and delete all;
- SHA-1 and SHA-256 keys, duplicate prevention, capacity `6A84`;
- `PERM-AR-DO` store/exact-key readback/replace/`FF40` serialization, plus
  `6A80` without mutation for `DB` before `D0`, a `DB` length other than 8, a
  duplicate `DB`, a `DB` without `D0`, and trailing bytes after `DB`;
- injected failure before staging, during owned-path inactive write, during
  caller-owned atomic candidate write, before metadata publication, and during
  transaction abort leaves the old catalog/tag;
- repeated mutations inside one caller-owned transaction either commit as one
  valid state or abort to its exact entry state without spare-record damage;
- `FF40` lengths at 127/128/255/256 boundaries and multi-chunk `FF60`;
- `FF60` without `FF40`, after completion, and after mutation;
- raw STORE remains `6982`; malformed/unsupported commands do not mutate;
- Java Card 3.0.4 CAP conversion and verification remain green.

### Physical / Android

- exact CAP + digest/toolchain manifest retained for new and rollback releases;
- canary tests at selected capacity and worst-case metadata commit;
- authenticated N-rule reconciliation and interrupted-session resume;
- CARD#5 replacement and rollback rehearsal;
- Android grants each intended `(AID, signer)` pairing and denies non-matching
  signers/targets;
- no raw card secrets or full unredacted GP logs retained.

## 12. Traceability

| Task criterion | Sections |
| --- | --- |
| Storage model, Java Card feasibility, EEPROM budget vs 210B/rule | 3.1-3.4 |
| `F0` overwrite, `F1`, update, `FF60` | 4.2-4.5, 6 |
| Atomic refresh behavior | 5, atomic mutation diagram |
| OTA N-rule provisioning, idempotency, ordering | 7, OTA diagram |
| v0.1.1 migration without bricking CARD#5 | 8, migration diagram |
| Adopt/skip per relevant SEAC/sysmocom feature | 9 |
| Development-ready follow-up decomposition | 10 |
| Evidence and no-secret gates | 11, 13 |

## 13. Sources

Primary and pinned sources:

- GlobalPlatform, *Secure Element Access Control, Public Review v1.1.0.10*:
  §4.1 (`FF40`, `FF50`, `FF60`, refresh and retrieval/storage concurrency),
  §5 and §5.1 (secure-channel remote management, atomic updates, one rule per
  `F0`, overwrite behavior, `F1`, `F2`), §6.3 (`E7`), and Annex B tag table.
  <https://globalplatform.org/wp-content/uploads/2024/08/GPD_SE_Access_Control_v1.1.0.10_PublicRvw.pdf>
- Oracle Java Card API, `JCSystem`: transactions journal persistent updates;
  commit capacity includes implementation-dependent overhead; only one
  transaction depth is supported.
  <https://docs.oracle.com/cd/E59935_01/api/javacard/framework/JCSystem.html>
- Oracle Java Card API, `Util`: persistent `arrayCopy` is atomic and commit
  capacity-bound; non-atomic copy can leave a partial persistent destination
  after power loss.
  <https://docs.oracle.com/en/java/javacard/3.1/jc_api_srvc/api_classic/javacard/framework/Util.html>
- AOSP SecureElement, pinned `AccessRuleApplet`: parses the full `FF40` length
  and loops on `FF60` with `9000` responses.
  <https://android.googlesource.com/platform/packages/apps/SecureElement/+/679fd5352c9d7e582df674a55ab86b301e4457fa/src/com/android/se/security/ara/AccessRuleApplet.java>
- jc-ara-m `v0.1.1`, `AraMApplet.java:18,30-45,76-125,145-153` and
  `AraMJCApplet.java:34-74`: single 96-byte slot, refresh transaction,
  SHA-1/SHA-256 validation, authenticated callback, and raw STORE denial.
- sysmocom aram-applet snapshot `13930d5`,
  `AccessRuleMaster.java:42-49,120-190,248-338,343-422` and
  `RuleEntry.java:34-73,141-239`: 210-byte entry payload, linked/deleted lists,
  `FF50`/`FF60`, `F0`/`F1`/`F2`, and per-entry deletion transactions.

Project evidence and context:

- bSIM comparison:
  `.research/260718_our-vs-sysmocom-ara-m-comparison.md`.
- sysmocom source snapshot:
  `.temp/TASK-260716-3lnt9z/sources/sysmocom-aram-applet` at `13930d5`.
- extracted SEAC evidence used by the comparison:
  `.temp/TASK-260717-3264xj/seac-v1.1.txt`.

The exact available EEPROM and transaction capacity of CARD#5 remain
unmeasured. No claim in this document converts the lower-bound arithmetic into
physical telemetry.
