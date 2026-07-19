# jc-ara-m — bounded Java Card ARA-M applet

`jc-ara-m` is a bounded GlobalPlatform Secure Element Access Control (SEAC)
ARA-M applet. Its instance AID is the standard ARA-M AID
`A00000015141434C00`. The installed profile holds up to 16 active rules in a
17-record copy-on-write arena:

- idempotently upsert validated `REF-AR-DO` values by exact `REF-DO`;
- delete by AID, exact `REF-DO`, or the complete catalog;
- return active rules to Android's `AccessControlEnforcer`;
- mutate only through authenticated Security Domain personalization;
- receive personalization data through the standard
  `org.globalplatform.Application` contract;
- support empty, SHA-1, and SHA-256 `DeviceAppID-REF-DO` values without
  changing the persistent representation.

The applet implementation does not install anything on hardware. The repository
also ships a host provisioner whose default modes are read-only or offline
dry-runs. Physical authenticated mutation requires explicit `--execute`, a
0600 Security Domain credential file, and—during standard-AID migration—the
exact maintenance acknowledgement emitted by `migration-plan`.

## Architecture

The accepted multi-rule design is specified in
[`docs/architecture/multi-rule-seac-architecture.md`](docs/architecture/multi-rule-seac-architecture.md).
Its focused lifecycle diagrams live under [`diagrams/`](diagrams/README.md).
WP1 implements the bounded catalog, `F0`/`F1`, and atomic rule/refresh/revision
publication. WP2 streams that catalog through full-length `FF40` and raw
`FF60` continuation responses without allocating a second catalog buffer.

### Installation-time capacity

The active-rule capacity `R` is read at install time from the GlobalPlatform
application-specific install parameter block, so one CAP covers several capacity
profiles without a rebuild. The block carries the proprietary TLV `80 01 R`,
optionally still inside its `C9` container:

| Install parameters | Resulting `R` |
| --- | --- |
| absent or empty | 16 (default) |
| `80 01 R`, `1 <= R <= 64` | `R` |
| `80 01 R`, `R > 64` | 64 (compiled maximum, clamped) |
| anything else | rejected `6A80`, installation fails |

Every buffer is allocated once, in the constructor, from the resolved `R`; the
catalog never grows afterwards. The manifest `capacity` used by the host
provisioner must match the `R` the instance was installed with — a mismatch
surfaces as a `6A84` at commit time. Format and rationale:
[`docs/architecture/multi-rule-seac-architecture.md`](docs/architecture/multi-rule-seac-architecture.md)
§3.2.

## Project layout

```text
jc-ara-m/
├── diagrams/                    # PlantUML lifecycle views
├── docs/architecture/           # Architecture decisions
├── host/                        # Go desired-state provisioner + migration controls
├── scripts/
│   └── build-migration-assets.sh # signed rollback/release/canary CAP builder
├── README.md
├── UNRESOLVED_QUESTIONS.md      # Evidence gates not settled by design
└── jc/
    ├── build.gradle
    ├── cap-build.xml
    ├── build-cap.sh          # build the real CAP on the fly (artifacts are not stored)
    ├── gradlew
    └── src/
        ├── main/java/works/relux/jcaram/
        │   ├── AraMApplet.java
        │   └── AraMJCApplet.java
        └── test/java/works/relux/jcaram/AraMAppletTest.java
```

The CAP package AID is `A00000015141434C`; the installable applet instance AID
is `A00000015141434C00`.

## Host desired-state provisioner

`host/cmd/aram-provisioner` treats desired/current catalogs as maps keyed by
exact `REF-DO`. It validates complete bounded-profile `E2` rules, rejects
duplicate keys, sorts by AID bytes and then DeviceAppID length/bytes, and emits
the fail-closed order `updates -> deletes -> adds`. Every add/update is one
complete `F0`; every obsolete exact key is one `F1`. Output contains only
counts, lengths, and truncated SHA-256 identifiers—not AIDs, certificate
hashes, refresh values, APDUs, or Security Domain keys.

Manifest files contain policy material and must be regular, non-symlink files
with mode 0600. Their schema is:

```json
{
  "capacity": 16,
  "rules": [
    {"ref_ar_do": "<complete E2 REF-AR-DO hex>"}
  ]
}
```

Offline plan, with no reader access:

```bash
cd host
go run ./cmd/aram-provisioner plan \
  --current /secure/current.json \
  --desired /secure/desired.json
```

Read/re-diff from a card through `jc-harness`; add `--execute` and a secure
credential file only inside the authorized maintenance flow:

```bash
go run ./cmd/aram-provisioner reconcile \
  --desired /secure/desired.json \
  --reader OMNIKEY

go run ./cmd/aram-provisioner reconcile \
  --desired /secure/desired.json \
  --reader OMNIKEY \
  --execute \
  --credentials /secure/sd-credentials.json
```

### Catch-all guard

The applet stores the SEAC catch-all reference — a zero-length `AID-REF-DO`
(`4F 00`), matching every SE applet — like any other exact key. The policy
question of whether such a rule may *grant* access is answered on the host,
where it is reviewable and shows up in a manifest diff: `plan` and `reconcile`
refuse a desired rule with a zero-length AID whose `AR-DO` grants anything
(`D0 01 01` or an APDU filter list), naming the offending rule, unless
`--allow-catch-all` is passed. A catch-all *deny* (`D0 01 00`) needs no flag,
and an already-installed catch-all can always be diffed away without one.

The execution path opens one authenticated `gp-t0-helper secure-apdu` session,
enters `INSTALL [for personalization]`, and sends the deterministic N-command
manifest. If the process or transport fails, the command reports unknown state;
rerunning always re-reads `FF40`/`FF60` and recomputes the remaining diff. It
never replays an assumed suffix. Final readback must equal the normalized
desired set exactly.

## v0.1.1 migration controls

Build automation creates three signed, digest-pinned CAPs: `v0.1.1` rollback
from the immutable tag, the multi-rule standard-AID release, and an
alternate-AID canary. It also writes toolchain manifests, a canary-evidence
template whose physical gates are initially false, and a migration-config
template. `--dry-run` validates the asset plan without building or touching a
card:

```bash
scripts/build-migration-assets.sh \
  --output-dir .temp/migration-assets/release \
  --toolchain /abs/path/to/cap-toolchain \
  --signing-key /secure/path/release-signing.pem \
  --canary-package-aid A00000015141434D \
  --canary-instance-aid A00000015141434D00 \
  --dry-run
```

The guarded runbook is inspectable without hardware:

```bash
cd host
go run ./cmd/aram-provisioner migration-plan \
  --config /secure/migration-config.json \
  --desired /secure/desired.json
```

Execution is rejected until rollback/canary/release digests, detached
signatures, toolchain manifests, and every canary evidence check match the
configured capacity. Each toolchain manifest binds the CAP digest, source
commit plus working-tree diff digest, Java/Java Card toolchain identity,
expected package/applet AIDs, and the active-rule capacity `R` the CAP was
built with together with its compiled ceiling.

The capacity in a desired-state manifest is a claim about the applet that will
enforce it, so both `migration-plan` and `migrate` require `--desired` and
refuse to produce a plan when that claim disagrees with the pinned release CAP.
The check runs on the planning path, so a dry run catches the disagreement
before any card is mutated; without it the same mismatch only appears as a
mid-rollout `6A84`. `reconcile --migration-config FILE` applies the same binding
to steady-state runs. The forward path exports the current v0.1.1 rule to a
0600 task-scoped file, deletes/installs through authenticated
`gp-t0-helper delete-if-present`/`install`, restores the exported rule first,
then reconciles the full desired catalog. Any failure after standard-package
deletion runs the explicit rollback branch: remove a partial release, reinstall
v0.1.1, restore the exported rule through authenticated personalization, and
verify exact catalog plus raw selected-applet `E2=6982` denial. Rollback uses a
fresh bounded recovery context, independent of forward-operation cancellation
or deadline expiry, so a timed-out forward command cannot suppress recovery.

## Android/SEAC APDUs

Android selects the ARA-M and performs the refresh query before fetching all
rules.

| Operation | Command APDU | Successful response data |
| --- | --- | --- |
| SELECT ARA-M | `00 A4 04 00 09 A00000015141434C00` | empty |
| GET DATA [refresh tag] | `80 CA DF 20 00` | `DF 20 08 <8-byte tag>` |
| GET DATA [all] | `80 CA FF 40 00` | `FF 40 <full BER length> <first E2 bytes>` |
| GET DATA [next] | `80 CA FF 60 00` | next raw catalog bytes |

Raw `STORE DATA` is not a runtime ARA-M command. Sending
`80 E2 90 00 <Lc> <F0 command DO>` directly to the selected applet is rejected
with `6982` (`Security status not satisfied`) and cannot change the catalog or
refresh tag. Rule mutation is available only when an authenticated Security
Domain personalization flow delivers the same command buffer through
`Application.processData(...)`.

The implementation accepts the GlobalPlatform proprietary CLA ranges
`80`-`8F`, `C0`-`CF`, and `E0`-`EF`. Android currently uses `80`.

## Access-rule TLV layout

`GET DATA [all]` wraps the active rules in `Response-ALL-AR-DO`:

```text
FF40 <length>                         Response-ALL-AR-DO
  E2 <length>                         REF-AR-DO
    E1 <length>                       REF-DO
      4F <0|5..16> <target applet AID> AID-REF-DO
      C1 <0|20|32> <DeviceAppID>      DeviceAppID-REF-DO
    E3 <length>                       AR-DO
      D0 <length> <rule>              APDU-AR-DO       (mandatory)
      DB 08 <8-byte permission mask>  PERM-AR-DO       (optional)
```

`AR-DO` members are validated in SEAC member order. `D0` is mandatory and comes
first; `DB` is optional, must carry exactly eight bytes, and must be the last
member. Anything else — `DB` before `D0`, a `DB` length other than 8, a repeated
`DB`, a `DB` without `D0`, or trailing bytes after `DB` — is rejected with
`6A80` and changes neither the catalog nor the refresh tag. `NFC-AR-DO` (`D1`)
remains out of this profile.

A zero-length `4F` is the SEAC catch-all reference and is stored, replaced, and
deleted through its exact `REF-DO` like any other key; sub-AID lengths 1..4
remain `6A80`. The `F1` delete-by-AID selector still requires a real 5..16-byte
AID, because a zero-length selector would be an ambiguous second spelling of
the empty delete-all value.

For the phase-1 permissive rule:

- `C1 00` is the generic device-application reference;
- `D0 01 01` means APDU access is always allowed;
- the target `4F` value is the HelloApplet AID `F0000000AA01`.

The exact `REF-AR-DO` is:

```text
E2 11
  E1 0A
    4F 06 F0000000AA01
    C1 00
  E3 03
    D0 01 01
```

After provisioning, `GET DATA [all]` returns:

```text
FF 40 13 E2 11 E1 0A 4F 06 F0000000AA01 C1 00 E3 03 D0 01 01
```

`FF40` advertises the complete concatenated active-rule length in BER short,
`81`, or `82` form. Its first response carries as many catalog bytes as fit.
If bytes remain, Android repeats `FF60`; each successful response contains only
the next raw bytes and status `9000`, with no repeated `FF40` tag or length.

One transient continuation is bound to the originating logical channel. A
second channel receives `6984`; `FF60` without a live continuation receives
`6985`. A catalog mutation invalidates the continuation by revision: the next
bound-channel `FF60` returns `6984` once and clears it. A new same-channel
`FF40` restarts from offset zero, and reset/deselect clears transient read state.

The `DF20` refresh tag is eight bytes generated at installation and changed
atomically with every real catalog mutation. A byte-identical `F0` retry and an
empty `F1 00` retry are idempotent and leave refresh/revision unchanged.

## Authenticated STORE DATA provisioning APDUs

`STORE DATA` carries one complete `F0` upsert or `F1` delete command.
`P1=90` means the last BER-TLV-formatted block is present, and `P2=00` is block
zero. This implementation accepts one complete short-APDU block; the supported
rule forms are far below that limit.

The command buffer for the phase-1 permissive HelloApplet rule is:

```text
80 E2 90 00 15
  F0 13
    E2 11
      E1 0A
        4F 06 F0000000AA01
        C1 00
      E3 03
        D0 01 01
```

As one hex string:

```text
80E2900015F013E211E10A4F06F0000000AA01C100E303D00101
```

Send these two APDUs in one authenticated `gp-t0-helper secure-apdu` Security
Domain session. The first enters personalization for this ARA-M instance; the
second is the exact STORE DATA command above:

```text
80E620000F000009A00000015141434C00000000
80E2900015F013E211E10A4F06F0000000AA01C100E303D00101
```

`AraMJCApplet` implements `org.globalplatform.Application`, so the Security
Domain delivers the second command data to `processData(...)` only after the
authenticated `INSTALL [for personalization]` step succeeds. Do not select the
ARA-M instance and send the STORE DATA command directly: the applet's raw ISO
dispatch rejects `INS E2` with `6982` by design.

Sending the same exact `REF-DO` with `D0 01 00` replaces only that key's APDU
rule with `NEVER`:

```text
80E2900015F013E211E10A4F06F0000000AA01C100E303D00100
```

The phase-2 SHA-1 certificate-bound shape replaces `C1 00` with
`C1 14 <20-byte certificate hash>` and updates the enclosing lengths:

```text
80 E2 90 00 29
  F0 27
    E2 25
      E1 1E
        4F 06 F0000000AA01
        C1 14 <20-byte SHA-1 certificate hash>
      E3 03
        D0 01 01
```

For SHA-256, use `C1 20 <32-byte hash>`; the corresponding enclosing lengths
are `E1 2A`, `E2 31`, `F0 33`, and APDU `Lc=35`.

A rule may also carry the optional `PERM-AR-DO` after its `APDU-AR-DO`. This is
the Android carrier-privilege rule shape — a SHA-256 signing-certificate key
plus an eight-byte permission mask:

```text
80 E2 90 00 3F
  F0 3D
    E2 3B
      E1 2A
        4F 06 F0000000AA01
        C1 20 <32-byte SHA-256 certificate hash>
      E3 0D
        D0 01 01
        DB 08 <8-byte permission mask>
```

That rule serialises to 61 bytes. The worst shape this profile accepts — a
16-byte AID, a SHA-256 hash, two 8-byte APDU filter/mask pairs, and a
`PERM-AR-DO` — serialises to 86 bytes, still inside the 96-byte record.

Authenticated deletion uses these `F1` command forms:

```text
F1 00                              delete all rules
F1 <len> 4F <len> <AID>            delete every rule for one applet AID
F1 <len> E1 <len> 4F ... C1 ...    delete one exact REF-DO key
```

Adding a new key at 16 active rules returns `6A84`; exact-key overwrite still
uses the seventeenth copy-on-write spare. A targeted delete with no match
returns `6A88`. Neither rejection changes the catalog, refresh tag, or revision.

Within the authenticated personalization callback, the applet validates the
complete nested TLV before mutating persistent state. Malformed data returns
`6A80` and leaves the prior catalog and refresh tag unchanged. At transaction
depth zero the applet stages into an inactive record and owns the small metadata
transaction. Inside a caller/Security-Domain transaction it atomically journals
the complete candidate record and leaves commit/abort ownership with the caller.

In a hardware flow, send provisioning through an authenticated GlobalPlatform
administrative channel. The applet intentionally does not invent a second
proprietary authentication protocol around standard SEAC `STORE DATA`.

## Simulator tests

From `jc/`:

```bash
./gradlew clean test --no-daemon
```

The jCardSim suite proves:

- SELECT returns `9000`;
- the applet implements the Security Domain personalization contract;
- raw `INS E2` is rejected with `6982` without changing rules or refresh tag;
- the actual `Application.processData(...)` callback accepts full-buffer
  personalization and honors a non-zero buffer offset;
- unprovisioned GET DATA [all] returns `FF4000`;
- small catalogs complete in one `FF40` response, while large catalogs stream
  every active arena record through raw `FF60` responses with `9000`;
- `FF40` uses short/`81`/`82` BER lengths at 127/128/255/256 boundaries;
- continuation is logical-channel-bound, restarts on same-channel `FF40`, and
  clears on reset;
- mutation during a read returns `6984` once and invalidates the stale session;
- `FF60` before `FF40` or after a completed read returns `6985`;
- `F0` adds several exact keys, overwrites one key, and treats identical retries
  as no-ops;
- `F1` deletes by AID, exact `REF-DO`, and all, including no-match semantics;
- capacity rejects the seventeenth active key while allowing a full-catalog
  overwrite through the spare record;
- the installation-time capacity `R` defaults to 16 when absent, is honoured in
  range (bare or `C9`-wrapped), is clamped above the compiled maximum of 64, and
  fails installation on a malformed parameter block, with arena and bitmaps sized
  once from the resolved value (`InstallParametersTest`);
- every real mutation changes `DF20`, while rejected/no-op commands do not;
- caller-owned transaction composition leaves transaction ownership outside the
  applet;
- corruption of every inactive spare remains unreachable and a later upsert
  safely overwrites one spare;
- SHA-1 and SHA-256 certificate-bound keys coexist;
- the zero-length-AID catch-all is stored, replaced in place, and deleted by its
  exact `REF-DO`, while sub-AID lengths 1..4 and a zero-length `F1` AID selector
  are rejected with `6A80` without changing catalog metadata;
- malformed and unsupported personalization do not clobber existing state.

jCardSim 3.0.5.9 tracks transaction depth but does not journal array writes, so
it cannot prove outer-transaction rollback. JC304 CAP verification proves the
transactional APIs convert; real abort/tear behavior remains a physical-card
acceptance gate.

JUnit XML and HTML reports are written under `jc/build/test-results/test/` and
`jc/build/reports/tests/test/`.

## CAP build

Building a real CAP needs an external Java Card toolchain (`ant-javacard.jar`
plus an Oracle Java Card SDK kit). It is **not** vendored here. Point the build
at it via `-Dtoolchain.dir=/abs/path`, the `JC_CAP_TOOLCHAIN` env var, or a
local `jc/.toolchain/` directory (Ant resolves them in that order). The
toolchain layout `cap-build.xml` expects:

```text
<toolchain.dir>/
├── ant-javacard.jar
└── oracle_javacard_sdks/
    └── <jckit.name>/          # e.g. jc304_kit, jc320v25.1_kit
```

The target UICC uses Java Card 3.0.4. The CAP is a build artifact — it is **not
stored in the repo** (`artifacts/` is gitignored); build it on demand with the
wrapper script, which wires JDK 11 and the toolchain and runs the Ant target:

```bash
cd jc
JC_CAP_TOOLCHAIN=/abs/path/to/cap-toolchain ./build-cap.sh
# other kit/suffix: ./build-cap.sh --jckit jc320v25.1_kit --suffix ''
```

Or drive Ant directly:

```bash
cd jc
./gradlew --no-daemon prepareCapDependencies
JDK11=/opt/homebrew/opt/openjdk@11/libexec/openjdk.jdk/Contents/Home
JAVA_HOME="$JDK11" PATH="$JDK11/bin:$PATH" \
  JC_CAP_TOOLCHAIN=/abs/path/to/cap-toolchain \
  ant -f cap-build.xml \
    -Djckit.name=jc304_kit \
    -Dcap.suffix=-jc304 \
    -Dglobalplatform.javacard.jar="$PWD/build/cap-dependencies/javacard-1.1.jar" \
    dist
```

Outputs (created fresh under the gitignored `artifacts/caps/`):

- `jc/artifacts/caps/jc-ara-m-0.1-jc304.cap`;
- `jc/artifacts/caps/jc-ara-m-0.1-jc304.jca`.

`cap-build.xml` uses `ints="false"`. Main applet code has short-typed array
indices and sizes, no `System.arraycopy`, and no string-bearing exceptions.
Passing jCardSim is not treated as converter proof; the Ant target runs the
Java Card converter and CAP verifier.

## Tools

- Go (`host/`) — builds and tests the desired-state provisioner and migration
  controls. Run `go test ./...`, `go vet ./...`, and
  `go build ./cmd/aram-provisioner` from `host/`; normal Go build/test outputs
  stay in the Go cache, while an explicit `-o` output should go under `.temp/`.
- `jc-harness` — forced-T=0 read-only `SELECT`/`FF40`/`FF60`/`DF20` catalog
  access and raw-STORE-denial verification. Invoked by `aram-provisioner`; it
  does not implement GlobalPlatform secure-channel crypto.
- `gp-t0-helper` — forced-T=0 GlobalPlatform authenticated
  `secure-apdu`/`install`/`delete-if-present` operations. The provisioner never
  uses its unauthenticated raw `apdu` path for rule mutation.
- OpenSSL + `scripts/build-migration-assets.sh` — detached CAP signatures and
  public-key verification inputs. Generated release/rollback/canary assets and
  task evidence belong under task-scoped `.temp/`, not in git.

- Gradle wrapper (`jc/gradlew`) — compiles the applet against jCardSim and runs
  JUnit 5 tests, and resolves the GlobalPlatform Java Card API used by the CAP
  converter. Run `./gradlew clean test --no-daemon` from `jc/`; output goes to
  `jc/build/`.
- jCardSim (`com.klinec:jcardsim:3.0.5.9`) — simulator used by
  `AraMAppletTest`; Gradle resolves it from Maven Central.
- Ant + ant-javacard (`jc/cap-build.xml`) — converts and verifies a real Java
  Card Classic CAP. Run the JDK 11 command above; output goes to
  `jc/artifacts/caps/`.
- PlantUML (`diagrams/**/*.puml`) — validates and renders the multi-rule
  lifecycle views. Run
  `plantuml -checkonly diagrams/plantuml/sequence/*.puml diagrams/plantuml/state/*.puml`
  from the repository root; optional review renders go under
  `.temp/TASK-260719-3r17pa/plantuml/`.

## References

- [GlobalPlatform Secure Element Access Control v1.1 public review](https://globalplatform.org/wp-content/uploads/2024/08/GPD_SE_Access_Control_v1.1.0.10_PublicRvw.pdf)
- [AOSP AccessRuleApplet](https://android.googlesource.com/platform/packages/apps/SecureElement/+/refs/heads/main/src/com/android/se/security/ara/AccessRuleApplet.java)
- [AOSP AraController](https://android.googlesource.com/platform/packages/apps/SecureElement/+/refs/heads/main/src/com/android/se/security/ara/AraController.java)
- [AOSP UICC carrier privileges](https://source.android.com/docs/core/connect/uicc)
- [Multi-rule SEAC architecture](docs/architecture/multi-rule-seac-architecture.md)

## License

Apache License 2.0 — see [LICENSE](LICENSE) and [NOTICE](NOTICE).
