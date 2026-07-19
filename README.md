# jc-ara-m — minimal Java Card ARA-M applet

`jc-ara-m` is a single-rule GlobalPlatform Secure Element Access Control
(SEAC) ARA-M applet. Its instance AID is the standard ARA-M AID
`A00000015141434C00`. It is intentionally minimal — one rule slot — and scoped
to the phase-1/phase-2 access-control flow it was built for:

- store one validated `REF-AR-DO`;
- return that rule to Android's `AccessControlEnforcer`;
- replace the slot only through authenticated Security Domain personalization;
- receive personalization data through the standard
  `org.globalplatform.Application` contract;
- support empty, SHA-1, and SHA-256 `DeviceAppID-REF-DO` values without
  changing the persistent representation.

The implementation does not install anything on hardware. Physical
installation and secure-channel provisioning belong to the follow-up install
task.

## Project layout

```text
jc-ara-m/
├── README.md
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

## Android/SEAC APDUs

Android selects the ARA-M and performs the refresh query before fetching all
rules.

| Operation | Command APDU | Successful response data |
| --- | --- | --- |
| SELECT ARA-M | `00 A4 04 00 09 A00000015141434C00` | empty |
| GET DATA [refresh tag] | `80 CA DF 20 00` | `DF 20 08 <8-byte tag>` |
| GET DATA [all] | `80 CA FF 40 00` | `FF 40 <len> <zero or one E2>` |

Raw `STORE DATA` is not a runtime ARA-M command. Sending
`80 E2 90 00 <Lc> <F0 command DO>` directly to the selected applet is rejected
with `6982` (`Security status not satisfied`) and cannot change either the rule
or refresh tag. Rule mutation is available only when an authenticated Security
Domain personalization flow delivers the same command buffer through
`Application.processData(...)`.

The implementation accepts the GlobalPlatform proprietary CLA ranges
`80`-`8F`, `C0`-`CF`, and `E0`-`EF`. Android currently uses `80`.

## Access-rule TLV layout

`GET DATA [all]` wraps the stored rule in `Response-ALL-AR-DO`:

```text
FF40 <length>                         Response-ALL-AR-DO
  E2 <length>                         REF-AR-DO
    E1 <length>                       REF-DO
      4F <5..16> <target applet AID>  AID-REF-DO
      C1 <0|20|32> <DeviceAppID>      DeviceAppID-REF-DO
    E3 <length>                       AR-DO
      D0 <length> <rule>              APDU-AR-DO
```

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

The `DF20` refresh tag is eight bytes generated at installation and changed
atomically with every accepted rule replacement.

## Authenticated STORE DATA provisioning APDUs

`STORE DATA` carries one `Command-Store-REF-AR-DO` (`F0`) around the `E2`
rule. `P1=90` means the last BER-TLV-formatted block is present, and `P2=00` is
block zero. This implementation accepts one complete short-APDU block; the
supported rule forms are far below that limit.

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

Sending the same reference with `D0 01 00` replaces the APDU rule with
`NEVER`:

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

Within the authenticated personalization callback, the applet validates the
complete nested TLV before mutating persistent state. Malformed data returns
`6A80` and leaves the prior rule and refresh tag unchanged. Any accepted
callback replaces the project's single rule slot.

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
- the actual `Application.processData(...)` callback accepts personalization;
- unprovisioned GET DATA [all] returns `FF4000`;
- authenticated personalization provisions a permissive rule;
- GET DATA [all] returns the exact `FF40`/`E2` TLV;
- a second authenticated personalization replaces the same reference;
- GET DATA [refresh tag] is well formed and changes after provisioning;
- a future 20-byte certificate-bound `C1` shape is accepted;
- malformed personalization does not clobber the existing rule.

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

- Gradle wrapper (`jc/gradlew`) — compiles the applet against jCardSim and runs
  JUnit 5 tests, and resolves the GlobalPlatform Java Card API used by the CAP
  converter. Run `./gradlew clean test --no-daemon` from `jc/`; output goes to
  `jc/build/`.
- jCardSim (`com.klinec:jcardsim:3.0.5.9`) — simulator used by
  `AraMAppletTest`; Gradle resolves it from Maven Central.
- Ant + ant-javacard (`jc/cap-build.xml`) — converts and verifies a real Java
  Card Classic CAP. Run the JDK 11 command above; output goes to
  `jc/artifacts/caps/`.

## References

- [GlobalPlatform Secure Element Access Control v1.1 public review](https://globalplatform.org/wp-content/uploads/2024/08/GPD_SE_Access_Control_v1.1.0.10_PublicRvw.pdf)
- [AOSP AccessRuleApplet](https://android.googlesource.com/platform/packages/apps/SecureElement/+/refs/heads/main/src/com/android/se/security/ara/AccessRuleApplet.java)
- [AOSP AraController](https://android.googlesource.com/platform/packages/apps/SecureElement/+/refs/heads/main/src/com/android/se/security/ara/AraController.java)
- [AOSP UICC carrier privileges](https://source.android.com/docs/core/connect/uicc)

## License

Apache License 2.0 — see [LICENSE](LICENSE) and [NOTICE](NOTICE).
