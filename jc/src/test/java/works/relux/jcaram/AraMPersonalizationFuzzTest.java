package works.relux.jcaram;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import com.licel.jcardsim.smartcardio.CardSimulator;
import com.licel.jcardsim.utils.AIDUtil;
import javacard.framework.AID;
import javacard.framework.Applet;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.UncheckedIOException;
import java.lang.reflect.Field;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Random;
import java.util.Set;
import java.util.TreeMap;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import org.globalplatform.Application;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * Property/fuzz harness for the hand-rolled SEAC TLV validator behind the personalization
 * entry point.
 *
 * <p>{@code AraMApplet.store} and the helpers underneath it ({@code upsert}, {@code delete},
 * {@code validateRefDo}, {@code validateArDo}, {@code readLength}, {@code checkedEnd}) are the
 * only code in this applet that consumes attacker-influenced bytes. The whole security boundary
 * is the claim that they reject malformed input <em>without side effects</em>. This class drives
 * {@link Application#processData} — the real Security Domain personalization entry point, the
 * same one a card takes for STORE DATA — with a bounded, deterministic corpus and asserts three
 * invariants for every single case:
 *
 * <ol>
 *   <li><b>Only ISOException escapes.</b> A {@code NullPointerException},
 *       {@code ArrayIndexOutOfBoundsException}, {@code ArithmeticException} or any other
 *       {@code Throwable} out of the parser is a defect: on a real card those surface as
 *       {@code 6F00} at best and as an uncaught JCRE error at worst. The status word is also
 *       constrained to the small set the design admits, so a parser cannot leak a new oracle.
 *   <li><b>Rejection is bit-identical.</b> On any rejection the observable catalog (the byte
 *       stream {@code GET DATA [FF40]} would emit), the refresh tag, and the catalog revision
 *       are byte-for-byte what they were before the call. The input buffer must also come back
 *       untouched — the parser never writes to its caller's array, and offsets are exercised at
 *       a non-zero position inside a padded buffer so an off-by-one write would show up.
 *   <li><b>The applet stays usable.</b> After every rejection a well-formed store still
 *       succeeds, and the rule it stored can still be deleted, returning the catalog exactly to
 *       where it was. A validator that rejects by wedging the arena, the read session or the
 *       transaction would fail here rather than look clean.
 * </ol>
 *
 * <p>The corpus is seeded with real encodings, not only random bytes: {@code cts-seac-rules.txt}
 * holds all 41 REF-AR-DOs from cheeriotb/aram-cardlet's Android-CTS catalog, which is valuable
 * precisely because it contains shapes this applet deliberately rejects alongside ones it
 * accepts. Those seeds are extended with hand-written SEAC shapes we reject on purpose
 * (NFC-AR-DO, PKG-REF-DO, long-form BER lengths, member reordering) and then mutated by
 * truncation, length-field corruption, tag substitution, bit flips, byte insertion/deletion,
 * splicing and nesting-depth abuse.
 *
 * <p>Everything is derived from {@link #CORPUS_SEED}: the case list is built once, in a fixed
 * order, before any of it runs, so a failure reproduces exactly and prints the offending hex.
 */
final class AraMPersonalizationFuzzTest {

    /**
     * Fixed corpus seed. In the normal test task the harness is a regression gate, not a soak
     * test: it must produce the same cases on every machine and every run, so a failure
     * reproduces from the printed case alone.
     *
     * <p>Both knobs are overridable for deliberate soak runs, which is how new seeds get vetted
     * before one is promoted to the default:
     *
     * <p>Both are Gradle properties, not JVM properties: {@code build.gradle} forwards them into
     * the test JVM, so {@code -D} on the Gradle command line would only reach Gradle itself.
     *
     * <pre>./gradlew test --tests '*AraMPersonalizationFuzzTest*' \
     *     -Param.fuzz.seed=0x1234 -Param.fuzz.mutants=64</pre>
     */
    private static final long CORPUS_SEED = Long.getLong("aram.fuzz.seed", 0x5EAC0DEBADC0FFEEL);

    /** Mutants generated per base command. Keeps the whole run inside a normal test budget. */
    private static final int MUTANTS_PER_COMMAND = Integer.getInteger("aram.fuzz.mutants", 12);

    private static final String ARA_M_AID_HEX = "A00000015141434C00";

    private static final byte TAG_UPSERT = (byte) 0xF0;
    private static final byte TAG_DELETE = (byte) 0xF1;

    /**
     * Status words the design admits out of the personalization path. Anything else is either a
     * new failure mode or an unintended oracle, and both are worth failing the build over.
     */
    private static final Set<Integer> ALLOWED_STATUS_WORDS =
            new LinkedHashSet<Integer>(
                    Arrays.asList(
                            0x6700, // SW_WRONG_LENGTH
                            0x6581, // memory failure
                            0x6981, // data object not supported
                            0x6A80, // SW_WRONG_DATA - the generic malformed() verdict
                            0x6A84, // SW_FILE_FULL
                            0x6A88)); // reference data not found

    private static final byte[] BASELINE_ALLOW_RULE =
            hex("E211E10A4F06F0000000AA01C100E303D00101");
    private static final byte[] BASELINE_CERT_BOUND_RULE =
            hex(
                    "E225"
                            + "E11E"
                            + "4F06F0000000AA01"
                            + "C114000102030405060708090A0B0C0D0E0F10111213"
                            + "E303D00101");

    /** Stored and deleted again after every rejection to prove the applet is still alive. */
    private static final byte[] PROBE_RULE = hex("E211E10A4F06F0000000FE01C100E303D00101");

    /**
     * Tag bytes the substitution mutator draws from: every tag this parser knows, plus SEAC tags
     * it does not implement and two degenerate values. Substituting a known tag produces inputs
     * that stay structurally plausible far deeper into the parser than random bytes do.
     */
    private static final byte[] SUBSTITUTION_TAGS = {
        (byte) 0xF0, (byte) 0xF1, (byte) 0xF2, (byte) 0xF6, (byte) 0xE1, (byte) 0xE2,
        (byte) 0xE3, (byte) 0x4F, (byte) 0xC1, (byte) 0xCA, (byte) 0xD0, (byte) 0xD1,
        (byte) 0xDB, (byte) 0x00, (byte) 0xFF, (byte) 0x81
    };

    /** Shorthand for {@link RejectedShape#structure}: the encoding's own BER arithmetic is sound. */
    private static final String SELF_CONSISTENT = null;

    /**
     * The by-design rejection inventory: SEAC-plausible encodings this applet refuses on purpose,
     * each carrying the evidence that it is refused for the reason its name gives.
     *
     * <p>Each entry pins three independent facts, and each one falsifies the vacuity failure mode
     * on its own — see {@link RejectedShape} for why that mode is the thing to guard against.
     * Ordering is load-bearing only in that {@link #buildCorpus()} derives seed indices from it.
     */
    private static final RejectedShape[] REJECTED_SHAPES = {
        new RejectedShape(
                "nfc-ar-do-instead-of-apdu-ar-do",
                "NFC-AR-DO (D1) in the APDU-AR-DO's place: a real SEAC member we do not implement.",
                "E211E10A4F06F0000000AA01C100E303D10101",
                "E211E10A4F06F0000000AA01C100E303D00101",
                SELF_CONSISTENT,
                0x6A80,
                "requireTag<-validateArDo<-upsert<-store"),
        new RejectedShape(
                "nfc-ar-do-after-apdu-ar-do",
                "APDU-AR-DO plus NFC-AR-DO: the full two-member AR-DO from the SEAC spec.",
                "E214E10A4F06F0000000AA01C100E306D00101D10101",
                "E211E10A4F06F0000000AA01C100E303D00101",
                SELF_CONSISTENT,
                0x6A80,
                "requireTag<-validateArDo<-upsert<-store"),
        new RejectedShape(
                "pkg-ref-do-in-the-ref-do",
                "PKG-REF-DO (CA) inside the REF-DO: Android package-name reference, unsupported.",
                "E218E1114F06F0000000AA01C100CA05636F6D2E78E303D00101",
                "E211E10A4F06F0000000AA01C100E303D00101",
                SELF_CONSISTENT,
                0x6A80,
                "validateRefDo<-upsert<-store"),
        new RejectedShape(
                "perm-ar-do-before-apdu-ar-do",
                "PERM-AR-DO before APDU-AR-DO: right members, wrong SEAC order.",
                "E21BE10A4F06F0000000AA01C100E30DDB080000000000000001D00101",
                "E21BE10A4F06F0000000AA01C100E30DD00101DB080000000000000001",
                SELF_CONSISTENT,
                0x6A80,
                "requireTag<-validateArDo<-upsert<-store"),
        new RejectedShape(
                "perm-ar-do-without-apdu-ar-do",
                "AR-DO with no APDU-AR-DO at all, only the permission mask.",
                "E218E10A4F06F0000000AA01C100E30ADB080000000000000001",
                "E21BE10A4F06F0000000AA01C100E30DD00101DB080000000000000001",
                SELF_CONSISTENT,
                0x6A80,
                "requireTag<-validateArDo<-upsert<-store"),
        new RejectedShape(
                "long-form-length-where-the-short-form-fits",
                "Long-form BER length (81 xx) over a value the short form encodes: readLength"
                        + " refuses any length octet with the 0x80 bit set.",
                "E28111E10A4F06F0000000AA01C100E303D00101",
                "E211E10A4F06F0000000AA01C100E303D00101",
                SELF_CONSISTENT,
                0x6A80,
                "readLength<-upsert<-store"),
        new RejectedShape(
                "long-form-length-that-agrees-with-its-masked-value",
                "The self-consistent long-form: 0x8B sets the high bit over a value whose true"
                        + " length really is the masked 0x0B. This is the one shape that isolates"
                        + " readLength's 0x80 check from the structural `!= end` checks that follow"
                        + " every one of its call sites. Every other long-form case is caught"
                        + " downstream by a length disagreement, so a mutant that deletes the 0x80"
                        + " check survives them all; here the masked length agrees with the"
                        + " encoding and the rule is otherwise perfectly valid, so deleting that"
                        + " check turns this into an *accepted* rule. Confirmed by mutation run:"
                        + " without this shape the mutant survives the whole corpus.",
                "E28BE1044F00C100E303D00101",
                "E20BE1044F00C100E303D00101",
                "@0 tag E2: unusable long-form length 0x8B",
                0x6A80,
                "readLength<-upsert<-store"),
        new RejectedShape(
                "ref-do-without-the-device-app-id",
                "REF-DO without the mandatory DeviceAppID-REF-DO.",
                "E20FE1084F06F0000000AA01E303D00101",
                "E211E10A4F06F0000000AA01C100E303D00101",
                SELF_CONSISTENT,
                0x6A80,
                "requireTag<-validateRefDo<-upsert<-store"),
        new RejectedShape(
                "ref-do-members-in-reverse-order",
                "REF-DO members in reverse order.",
                "E211E10AC1004F06F0000000AA01E303D00101",
                "E211E10A4F06F0000000AA01C100E303D00101",
                SELF_CONSISTENT,
                0x6A80,
                "requireTag<-validateRefDo<-upsert<-store"),
        new RejectedShape(
                "aid-ref-do-of-four-bytes",
                "AID-REF-DO of 4 bytes: shorter than any real applet AID, longer than the"
                        + " zero-length catch-all.",
                "E20FE1084F04F0000000C100E303D00101",
                "E210E1094F05F000000000C100E303D00101",
                SELF_CONSISTENT,
                0x6A80,
                "validateRefDo<-upsert<-store"),
        new RejectedShape(
                "aid-ref-do-of-seventeen-bytes",
                "AID-REF-DO of 17 bytes: one over the ISO 7816-5 maximum.",
                "E21CE1154F11A000000476416E64726F696443545340FFC100E303D00101",
                "E21BE1144F10A000000476416E64726F696443545340C100E303D00101",
                SELF_CONSISTENT,
                0x6A80,
                "validateRefDo<-upsert<-store"),
        new RejectedShape(
                "device-app-id-of-nineteen-bytes",
                "DeviceAppID of 19 bytes: a truncated SHA-1 hash.",
                "E224E11D4F06F0000000AA01C113000102030405060708090A0B0C0D0E0F101112E303D00101",
                "E225E11E4F06F0000000AA01C114000102030405060708090A0B0C0D0E0F10111213E303D00101",
                SELF_CONSISTENT,
                0x6A80,
                "validateRefDo<-upsert<-store"),
        new RejectedShape(
                "apdu-ar-do-of-one-byte-that-is-neither-never-nor-always",
                "APDU-AR-DO of 1 byte carrying neither Never (00) nor Always (01).",
                "E211E10A4F06F0000000AA01C100E303D00102",
                "E211E10A4F06F0000000AA01C100E303D00101",
                SELF_CONSISTENT,
                0x6A80,
                "validateArDo<-upsert<-store"),
        new RejectedShape(
                "apdu-ar-do-of-four-bytes",
                "APDU-AR-DO of 4 bytes: half a filter/mask pair.",
                "E214E10A4F06F0000000AA01C100E306D004FFFF0000",
                "E218E10A4F06F0000000AA01C100E30AD008FFFF000000000000",
                SELF_CONSISTENT,
                0x6A80,
                "validateArDo<-upsert<-store"),
        new RejectedShape(
                "perm-ar-do-of-seven-bytes",
                "PERM-AR-DO of 7 bytes rather than the fixed 8.",
                "E21AE10A4F06F0000000AA01C100E30CD00101DB0700000000000001",
                "E21BE10A4F06F0000000AA01C100E30DD00101DB080000000000000001",
                SELF_CONSISTENT,
                0x6A80,
                "validateArDo<-upsert<-store"),
        new RejectedShape(
                "third-member-after-the-perm-ar-do",
                "A third AR-DO member behind the APDU-AR-DO/PERM-AR-DO pair. The grammar admits"
                        + " exactly two members, so the tail check after the optional PERM-AR-DO is"
                        + " the only thing stopping a third; nothing else in this list reaches it"
                        + " with both legal members already consumed.",
                "E21EE10A4F06F0000000AA01C100E310D00101DB080000000000000001D10101",
                "E21BE10A4F06F0000000AA01C100E30DD00101DB080000000000000001",
                SELF_CONSISTENT,
                0x6A80,
                "validateArDo<-upsert<-store"),
        new RejectedShape(
                "trailing-byte-after-the-ref-ar-do-value",
                "Trailing byte after a structurally complete REF-AR-DO value.",
                "E212E10A4F06F0000000AA01C100E303D0010100",
                "E211E10A4F06F0000000AA01C100E303D00101",
                "@19 tag 00: no length octet",
                0x6A80,
                "validateArDo<-upsert<-store"),
    };

    private ExposedCardSimulator simulator;
    private AID appletAid;
    private Application application;

    @BeforeEach
    void setUp() {
        simulator = new ExposedCardSimulator();
        appletAid = AIDUtil.create(ARA_M_AID_HEX);
        simulator.installApplet(appletAid, AraMJCApplet.class);
        simulator.selectApplet(appletAid);
        application = simulator.application(appletAid);
    }

    @Test
    void ctsSeedCorpusLoadsTheFullRealCatalog() {
        List<byte[]> seeds = loadCtsSeacRules();

        assertEquals(41, seeds.size(), "cheeriotb's CTS catalog holds exactly 41 REF-AR-DOs");
        for (byte[] seed : seeds) {
            assertEquals((byte) 0xE2, seed[0], "every seed is a top-level REF-AR-DO");
            assertEquals(seed.length - 2, seed[1] & 0xFF, "seed length octet matches its value");
        }
        // The shapes that make these seeds worth fuzzing rather than re-deriving.
        assertTrue(containing(seeds, "4F00C100"), "the zero-length catch-all reference");
        assertTrue(containing(seeds, "DB08"), "the carrier-privilege PERM-AR-DO");
        assertTrue(containing(seeds, "D010"), "a 16-byte APDU filter/mask pair");
        assertTrue(containing(seeds, "D008"), "an 8-byte APDU filter/mask pair");
        assertTrue(containing(seeds, "C114"), "a 20-byte DeviceAppID certificate hash");
    }

    @Test
    void personalizationHoldsItsInvariantsAcrossTheWholeMutatedCorpus() {
        List<FuzzCase> corpus = buildCorpus();
        assertTrue(corpus.size() > 1000, "a corpus this small would not be worth running");

        personalizeBaseline();

        TreeMap<Integer, Integer> statusWordHistogram = new TreeMap<Integer, Integer>();
        int accepted = 0;
        int rejected = 0;

        for (FuzzCase fuzzCase : corpus) {
            // Both buffer shapes: padded (a Security Domain handing over its APDU buffer) and
            // tight (the array ends where the command does, so an over-read cannot hide in slack).
            for (boolean tightBuffer : new boolean[] {false, true}) {
                Snapshot before = snapshot();
                PaddedInput input =
                        tightBuffer
                                ? PaddedInput.tight(fuzzCase.command)
                                : PaddedInput.wrap(fuzzCase.command, fuzzCase.padOffset);

                Integer statusWord = attemptPersonalization(fuzzCase, input);

                // Invariant 1 is enforced inside attemptPersonalization: anything that is not an
                // ISOException fails there, with the offending case printed.
                assertEquals(
                        (byte) 0,
                        JCSystem.getTransactionDepth(),
                        () -> "A transaction was left open by " + fuzzCase);
                assertArrayEquals(
                        input.expected,
                        input.buffer,
                        () -> "The parser wrote into its caller's buffer for " + fuzzCase);

                if (statusWord == null) {
                    accepted++;
                    // An accepted mutant legitimately mutates the catalog. Return to the known
                    // baseline so every later case starts from the same state and stays
                    // reproducible.
                    personalizeBaseline();
                    continue;
                }

                rejected++;
                increment(statusWordHistogram, statusWord.intValue());
                assertTrue(
                        ALLOWED_STATUS_WORDS.contains(statusWord),
                        () ->
                                "Unexpected status word "
                                        + hexOf(statusWord.intValue())
                                        + " from "
                                        + fuzzCase);

                // Invariant 2: a rejection is bit-identical.
                Snapshot after = snapshot();
                assertSnapshotUnchanged(before, after, fuzzCase);

                // Invariant 3: the applet is still usable.
                assertStillUsable(fuzzCase);
            }
        }

        assertTrue(rejected > 0, "the corpus must actually exercise the rejection path");
        System.out.println(
                "AraM personalization fuzz: "
                        + corpus.size()
                        + " cases, "
                        + rejected
                        + " rejected, "
                        + accepted
                        + " accepted, status words "
                        + renderHistogram(statusWordHistogram));
    }

    /**
     * The same three invariants with the catalog provisioned to capacity.
     *
     * <p>A full catalog is a materially different state for this parser, not just a bigger one:
     * {@code findExactRefDo} re-parses every one of the R active records through
     * {@code validatedRecordLength} on every upsert, so stored bytes join attacker bytes as
     * parser input, and the capacity check adds {@code SW_FILE_FULL} as a fourth way out. The
     * corpus is sampled rather than replayed whole — each case here costs an arena-wide scan.
     */
    @Test
    void personalizationHoldsItsInvariantsWithTheCatalogAtCapacity() {
        List<byte[]> provisioned = personalizeToCapacity();
        boolean sawFileFull = false;

        List<FuzzCase> corpus = buildCorpus();
        for (int index = 0; index < corpus.size(); index += 7) {
            FuzzCase fuzzCase = corpus.get(index);
            Snapshot before = snapshot();
            PaddedInput input = PaddedInput.wrap(fuzzCase.command, fuzzCase.padOffset);

            Integer statusWord = attemptPersonalization(fuzzCase, input);

            assertEquals(
                    (byte) 0,
                    JCSystem.getTransactionDepth(),
                    () -> "A transaction was left open by " + fuzzCase);
            assertArrayEquals(
                    input.expected,
                    input.buffer,
                    () -> "The parser wrote into its caller's buffer for " + fuzzCase);

            if (statusWord == null) {
                provisioned = personalizeToCapacity();
                continue;
            }

            sawFileFull |= statusWord.intValue() == 0x6A84;
            assertTrue(
                    ALLOWED_STATUS_WORDS.contains(statusWord),
                    () ->
                            "Unexpected status word "
                                    + hexOf(statusWord.intValue())
                                    + " from "
                                    + fuzzCase);
            assertSnapshotUnchanged(before, snapshot(), fuzzCase);
            assertStillUsableAtCapacity(provisioned.get(0), fuzzCase);
        }

        assertTrue(sawFileFull, "a full catalog must have refused at least one new rule as 6A84");
    }

    /**
     * The same corpus with a transaction the applet does not own already open.
     *
     * <p>This is a different write path through the same attacker bytes, not just a different
     * caller: {@code upsert} branches on {@code JCSystem.getTransactionDepth()}, and with a depth
     * of one it skips the non-atomic staging entirely, copies the candidate record into the arena
     * with the transactional {@code Util.arrayCopy} and publishes inside the caller's transaction.
     * A Security Domain that wraps STORE DATA in its own transaction takes exactly this path, so
     * leaving it out of the corpus would leave the joined-commit half of the parser's write side
     * unfuzzed.
     *
     * <p>It also pins a fourth invariant the other runs cannot see: the applet must never commit
     * or abort a transaction it did not open. A rejection that swallowed the caller's transaction
     * would silently publish whatever the caller had staged, which is worse than the malformed
     * input it was rejecting.
     *
     * <p>Rejections are checked <em>through</em> a commit rather than through an abort. That is
     * deliberate and is the stronger claim: committing the caller's transaction publishes anything
     * the applet staged inside it, so an unchanged catalog after the commit proves the rejection
     * wrote nothing at all. It is also the only honest check available here — jCardSim 3.0.5.9
     * does not journal persistent array writes, so {@code abortTransaction} does not roll them
     * back and an abort-based assertion would pass for reasons that have nothing to do with this
     * applet. Do not rewrite this around an abort.
     */
    @Test
    void personalizationHoldsItsInvariantsInsideACallerTransaction() {
        personalizeBaseline();

        List<FuzzCase> corpus = buildCorpus();
        int rejected = 0;
        int accepted = 0;

        // Sampled, and offset off the other runs' stride so this pass sees different cases.
        for (int index = 3; index < corpus.size(); index += 11) {
            FuzzCase fuzzCase = corpus.get(index);
            Snapshot before = snapshot();
            PaddedInput input = PaddedInput.wrap(fuzzCase.command, fuzzCase.padOffset);

            Integer statusWord;
            JCSystem.beginTransaction();
            try {
                statusWord = attemptPersonalization(fuzzCase, input);

                assertEquals(
                        (byte) 1,
                        JCSystem.getTransactionDepth(),
                        () ->
                                "The applet committed or aborted a transaction it does not own"
                                        + " for "
                                        + fuzzCase);
                assertArrayEquals(
                        input.expected,
                        input.buffer,
                        () -> "The parser wrote into its caller's buffer for " + fuzzCase);
                if (statusWord != null) {
                    assertTrue(
                            ALLOWED_STATUS_WORDS.contains(statusWord),
                            () ->
                                    "Unexpected status word "
                                            + hexOf(statusWord.intValue())
                                            + " from "
                                            + fuzzCase);
                    // Invariant 2 still holds while the caller's transaction is open: a rejection
                    // must not have written anything the caller would go on to commit.
                    assertSnapshotUnchanged(before, snapshot(), fuzzCase);
                }
            } finally {
                if (JCSystem.getTransactionDepth() != (byte) 0) {
                    JCSystem.commitTransaction();
                }
            }

            if (statusWord == null) {
                accepted++;
                // An accepted mutant legitimately published inside the caller's transaction.
                personalizeBaseline();
                continue;
            }

            rejected++;
            // Invariant 2 through the commit: the caller published its transaction and the
            // rejected input still contributed nothing to it.
            assertSnapshotUnchanged(before, snapshot(), fuzzCase);
            // Invariant 3, outside any transaction: the applet still takes a well-formed store.
            assertStillUsable(fuzzCase);
        }

        assertTrue(rejected > 0, "the sampled corpus must exercise the rejection path");
        assertTrue(
                accepted > 0,
                "the sampled corpus must also reach the joined-commit path with a valid rule");
    }

    @Test
    void catalogAndRefreshTagStayReadableOverApduAfterTheCorpus() {
        personalizeBaseline();
        byte[] catalogBefore = getAllRulesOverApdu();
        byte[] refreshTagBefore = getRefreshTagOverApdu();
        assertEquals(11, refreshTagBefore.length, "DF20 08 plus the eight tag bytes");

        boolean anyAccepted = false;
        for (FuzzCase fuzzCase : buildCorpus()) {
            PaddedInput input = PaddedInput.wrap(fuzzCase.command, fuzzCase.padOffset);
            if (attemptPersonalization(fuzzCase, input) == null) {
                anyAccepted = true;
                personalizeBaseline();
            }
        }

        // Whatever the corpus did, the surviving state is the baseline it was reset to, and the
        // externally visible read paths still serve it. Compared as a rule multiset rather than a
        // byte stream: rebuilding the baseline re-provisions from a different catalog revision,
        // and record placement rotates with that counter, so the same rule set legitimately comes
        // back in a different order. Byte-exactness across a re-provisioning is not a property
        // this applet has or needs — the refresh tag, asserted below, is what tells a host the
        // catalog moved.
        assertSameRuleMultiset(catalogBefore, getAllRulesOverApdu(), "after the whole corpus");
        if (anyAccepted) {
            // Rebuilding the baseline republishes, so the tag a host caches must have moved.
            assertFalse(
                    Arrays.equals(refreshTagBefore, getRefreshTagOverApdu()),
                    "a republished catalog must carry a new refresh tag");
        }

        // And a fresh well-formed provisioning round still works end to end.
        personalizeCommand(upsert(PROBE_RULE));
        assertTrue(
                indexOf(getAllRulesOverApdu(), PROBE_RULE) >= 0,
                "a well-formed rule must still reach the catalog after the whole corpus");
        personalizeCommand(deleteByRefDo(refDoOf(PROBE_RULE)));
        assertSameRuleMultiset(
                catalogBefore, getAllRulesOverApdu(), "after the probe round-trip");
    }

    /**
     * Compares two catalog values as unordered multisets of REF-AR-DOs.
     *
     * <p>Use this — and only this — when the two catalogs are separated by a re-provisioning.
     * {@code findInactiveRecord} starts its scan at {@code catalogRevision % recordCount}, so the
     * slot a rule lands in depends on how many mutations happened before it, and the read order
     * follows slot order. Comparisons that stay inside one provisioning generation (a rejection,
     * or a probe store followed by its delete) must keep using {@code assertArrayEquals}: there
     * the neighbouring records genuinely must not move.
     */
    private static void assertSameRuleMultiset(byte[] expected, byte[] actual, String context) {
        List<String> expectedRules = renderedRulesOf(expected);
        List<String> actualRules = renderedRulesOf(actual);
        java.util.Collections.sort(expectedRules);
        java.util.Collections.sort(actualRules);
        assertEquals(
                expectedRules,
                actualRules,
                "The catalog holds a different rule set " + context);
    }

    /** Splits a catalog value into its top-level REF-AR-DOs, rendered as hex for comparison. */
    private static List<String> renderedRulesOf(byte[] catalog) {
        List<String> rules = new ArrayList<String>();
        int cursor = 0;
        while (cursor < catalog.length) {
            assertEquals((byte) 0xE2, catalog[cursor], "every catalog element is a REF-AR-DO");
            int length = catalog[cursor + 1] & 0xFF;
            int end = cursor + 2 + length;
            assertTrue(end <= catalog.length, "a catalog element overran the catalog value");
            rules.add(hexOf(Arrays.copyOfRange(catalog, cursor, end)));
            cursor = end;
        }
        return rules;
    }

    /**
     * Named regression for the catalog-ordering contract.
     *
     * <p>This pins what a soak run at {@code -Param.fuzz.seed=0x1234} exposed as a harness bug:
     * the corpus test was comparing a re-provisioned catalog byte-for-byte against the original,
     * and it only ever passed because the default seed happened to leave the catalog revision on a
     * value that reproduced the original slot order. It is the assertion that was wrong, not the
     * applet — {@code findInactiveRecord} starts its scan at {@code catalogRevision % recordCount}
     * so that writes spread across the arena instead of hammering one cell, which means the slot a
     * rule lands in is a function of how many mutations preceded it.
     *
     * <p>The contract that follows is worth holding still in both directions. The catalog is a
     * <em>set</em> of rules: re-provisioning the same rules may return them in a different order,
     * and no host may key on that order. What must not change is that every rule survives intact
     * and stays individually addressable by its exact REF-DO regardless of the slot it landed in.
     */
    @Test
    void reprovisionedCatalogKeepsItsRuleSetAndAddressabilityRegardlessOfSlotOrder() {
        personalizeBaseline();
        byte[] firstGeneration = getAllRulesOverApdu();
        boolean sawADifferentOrder = false;

        // Every round advances the catalog revision by a constant six mutations — two for the
        // churn pair, three to rebuild the baseline, one for the addressability delete below —
        // and six is coprime with the seventeen record slots, so eighteen rounds walk the
        // rotation through every residue. Reversal is a narrow window: the two baseline rules
        // land on consecutive slots, so the read order only flips on the round where the first
        // of them lands on the last slot and the second wraps to zero.
        for (int round = 1; round <= 18; round++) {
            personalizeCommand(upsert(PROBE_RULE));
            personalizeCommand(deleteByRefDo(refDoOf(PROBE_RULE)));
            personalizeBaseline();

            byte[] generation = getAllRulesOverApdu();
            assertSameRuleMultiset(firstGeneration, generation, "after re-provisioning round " + round);
            sawADifferentOrder |= !Arrays.equals(firstGeneration, generation);

            // Slot order may move; addressability may not. Each rule must still be reachable by
            // its own REF-DO, and deleting one must leave the other exactly where it was.
            byte[] survivor = BASELINE_CERT_BOUND_RULE;
            personalizeCommand(deleteByRefDo(refDoOf(BASELINE_ALLOW_RULE)));
            byte[] afterDelete = getAllRulesOverApdu();
            assertEquals(1, countRules(afterDelete), "exactly one rule must survive the delete");
            assertTrue(
                    indexOf(afterDelete, survivor) >= 0,
                    "deleting one rule must not disturb the other, in round " + round);
        }

        assertTrue(
                sawADifferentOrder,
                "re-provisioning never reordered the catalog, so this regression is vacuous and"
                        + " the rotation in findInactiveRecord must have changed");
    }

    /**
     * Named boundary case at the record-size edge, where SEAC validity and storage capacity
     * disagree: a REF-AR-DO can be perfectly well-formed and still not fit a record. Mutation
     * lands near this edge only by luck, so both sides of it are pinned here — 96 bytes must be
     * stored, 97 must be refused without a trace. The APDU-AR-DO filter is what makes a rule
     * this long legal at all; AID and DeviceAppID alone top out at 61 bytes.
     */
    @Test
    void refArDoAtAndOverTheRecordSizeBoundary() {
        personalizeBaseline();

        byte[] largestStorable = ruleOfSize(12, 32, 40);
        assertEquals(AraMApplet.MAX_REF_AR_DO_LENGTH, largestStorable.length);
        personalizeCommand(upsert(largestStorable));
        assertTrue(
                indexOf(snapshot().catalog, largestStorable) >= 0,
                "a 96-byte REF-AR-DO fills a record exactly and must be stored");

        Snapshot before = snapshot();
        byte[] oversized = ruleOfSize(13, 32, 40);
        assertEquals(AraMApplet.MAX_REF_AR_DO_LENGTH + 1, oversized.length);
        FuzzCase oversizedCase =
                new FuzzCase("regression:oversized-ref-ar-do", upsert(oversized), 0);

        Integer statusWord =
                attemptPersonalization(
                        oversizedCase, PaddedInput.wrap(oversizedCase.command, 0));

        assertEquals(Integer.valueOf(0x6700), statusWord);
        assertSnapshotUnchanged(before, snapshot(), oversizedCase);
        assertStillUsable(oversizedCase);
    }

    /**
     * Named regression for the harness's own blind spot: over-acceptance.
     *
     * <p>Every other test here asserts that a <em>rejection</em> is clean. None of them asserts
     * that anything must be rejected at all, so a parser that grew more permissive would sail
     * through the whole corpus — the accepted branch just resets the baseline and moves on. A
     * mutation run proved it: deleting the long-form BER length check from {@code readLength}
     * (so {@code 81 xx} is silently read as length {@code xx & 0x7F}) survived the entire corpus.
     *
     * <p>{@link #REJECTED_SHAPES} is exactly the right oracle for this, because every entry there
     * is SEAC-plausible and documented as refused <em>by design</em> rather than by accident:
     * unimplemented members (NFC-AR-DO, PKG-REF-DO), wrong member order, out-of-range lengths,
     * long-form lengths, trailing bytes. Pinning them turns that comment into a contract. A shape
     * that becomes legitimately supported should move out of that list, not be silently accepted
     * here.
     *
     * <p>Rejection alone is a weak assertion, though, and the weakness is not theoretical: three
     * entries of the first version of this list were thrown out by the outer length arithmetic in
     * {@code upsert} and never reached the member rule they were written to pin. So this asserts
     * the <em>rejection site</em> — the {@code AraMApplet} frames that were on the stack when the
     * refusal was raised — and the exact status word, not membership of a six-element admit set.
     * A shape refused upstream reports {@code checkedEnd<-upsert<-store} and fails here.
     */
    @Test
    void shapesRejectedByDesignAreStillRejectedAtTheRuleTheyName() {
        personalizeBaseline();

        for (RejectedShape shape : REJECTED_SHAPES) {
            FuzzCase shapeCase =
                    new FuzzCase(
                            "by-design-rejected[" + shape.name + "]", upsert(shape.encoding()), 0);

            for (boolean tightBuffer : new boolean[] {false, true}) {
                Snapshot before = snapshot();
                PaddedInput input =
                        tightBuffer
                                ? PaddedInput.tight(shapeCase.command)
                                : PaddedInput.wrap(shapeCase.command, 0);

                Rejection rejection = attemptPersonalizationForRejection(shapeCase, input);

                assertEquals(
                        hexOf(shape.statusWord),
                        hexOf(rejection.statusWord),
                        () -> "Wrong status word from " + shapeCase);
                assertEquals(
                        shape.site,
                        rejection.site,
                        () ->
                                "Rejected somewhere other than the rule this entry names.\n"
                                        + "  entry: "
                                        + shape.name
                                        + "\n  claim: "
                                        + shape.claim
                                        + "\n  case:  "
                                        + shapeCase);
                assertSnapshotUnchanged(before, snapshot(), shapeCase);
            }
        }

        assertStillUsable(new FuzzCase("by-design-rejected:all", new byte[0], 0));
    }

    /**
     * Vacuity guard: a by-design-rejected entry must be rejected by the grammar, not by its own
     * broken length arithmetic.
     *
     * <p>This is the assertion the list was missing. Three entries used to declare BER lengths that
     * disagreed with their own content — {@code E2} claiming 26 over 25 bytes, {@code E3} claiming
     * 15 over 12 — so {@code upsert}'s {@code checkedEnd} threw them out before the member rule
     * named in the comment was ever consulted. They passed for the wrong reason, and would have
     * kept passing with that rule deleted.
     *
     * <p>So every entry's own encoding is walked here as BER and its declared lengths must span
     * exactly their content. Two entries legitimately do not: their named defect <em>is</em> the
     * length encoding, and each of those pins the exact disagreement rather than being waved
     * through.
     */
    @Test
    void byDesignRejectedShapesCarryOnlyTheStructuralDefectTheyName() {
        for (RejectedShape shape : REJECTED_SHAPES) {
            assertEquals(
                    shape.structure,
                    berLengthDisagreement(shape.encoding()),
                    () ->
                            "The rejected encoding's BER arithmetic is not what "
                                    + shape.name
                                    + " declares. An unintended disagreement means this entry is"
                                    + " refused by the outer length check instead of by the rule it"
                                    + " names.");
            assertEquals(
                    SELF_CONSISTENT,
                    berLengthDisagreement(shape.repaired()),
                    () -> "The repaired encoding of " + shape.name + " is not well-formed BER");
        }
    }

    /**
     * Attribution: each entry's repair, which touches only the property the entry names, must be
     * accepted.
     *
     * <p>{@link #byDesignRejectedShapesCarryOnlyTheStructuralDefectTheyName()} proves the shape is
     * not refused upstream and {@link #shapesRejectedByDesignAreStillRejectedAtTheRuleTheyName()}
     * proves where it is refused. Neither proves the refusal is caused by the named property rather
     * than by some second flaw that happens to live in the same method. This one does: repairing
     * only that property flips the verdict, so the property is what the parser objected to.
     */
    @Test
    void byDesignRejectedShapesAreAcceptedOnceTheirNamedPropertyIsRepaired() {
        for (RejectedShape shape : REJECTED_SHAPES) {
            personalizeCommand(new byte[] {TAG_DELETE, (byte) 0x00});

            byte[] repaired = shape.repaired();
            try {
                personalizeCommand(upsert(repaired));
            } catch (ISOException refused) {
                fail(
                        "Repairing "
                                + shape.name
                                + " at the property it names left the rule rejected with "
                                + hexOf(refused.getReason() & 0xFFFF)
                                + ", so the entry's rejection is not attributable to that"
                                + " property: "
                                + hexOf(repaired));
            }
            assertTrue(
                    indexOf(snapshot().catalog, repaired) >= 0,
                    () -> "The repaired form of " + shape.name + " did not reach the catalog");
        }
    }

    /**
     * Inventory guard, deliberately not a completeness claim.
     *
     * <p>An earlier version of this test asserted the list was "expected to be complete". It never
     * was and could not be: the rejection surface is every shape the grammar refuses, which is
     * unbounded, and nothing here enumerates it. What the count actually buys is that an entry
     * cannot be dropped in passing — deleting one to make a red build green has to touch this
     * number, and reviewers see it.
     *
     * <p>What the list does cover, and all it claims: at least one entry landing at each distinct
     * rejection site the parser has, so no site is left with no by-design witness at all.
     */
    @Test
    void theByDesignRejectionInventoryIsPinnedAndCoversEveryRejectionSite() {
        assertEquals(
                17,
                REJECTED_SHAPES.length,
                "Entries may be added, but dropping one has to be a deliberate, visible edit");

        Set<String> names = new LinkedHashSet<String>();
        Set<String> sites = new LinkedHashSet<String>();
        for (RejectedShape shape : REJECTED_SHAPES) {
            assertTrue(names.add(shape.name), () -> "Duplicate entry name: " + shape.name);
            sites.add(shape.site);
        }

        assertEquals(
                new LinkedHashSet<String>(
                        Arrays.asList(
                                "readLength<-upsert<-store",
                                "requireTag<-validateRefDo<-upsert<-store",
                                "validateRefDo<-upsert<-store",
                                "requireTag<-validateArDo<-upsert<-store",
                                "validateArDo<-upsert<-store")),
                sites,
                "Every rejection site the personalization grammar has needs a by-design witness;"
                        + " a new site with no entry is an unguarded piece of the surface");
    }

    // ---------------------------------------------------------------------------------------
    // Corpus construction
    // ---------------------------------------------------------------------------------------

    private static List<FuzzCase> buildCorpus() {
        Random rng = new Random(CORPUS_SEED);
        List<byte[]> seeds = new ArrayList<byte[]>(loadCtsSeacRules());
        seeds.addAll(handWrittenRejectedShapes());

        List<FuzzCase> corpus = new ArrayList<FuzzCase>();
        int seedIndex = 0;
        for (byte[] seed : seeds) {
            String origin = "seed[" + seedIndex + "]";
            addCommandFamily(corpus, rng, origin + ":upsert", upsert(seed));
            byte[] refDo = tryRefDoOf(seed);
            if (refDo != null) {
                addCommandFamily(corpus, rng, origin + ":delete-by-ref-do", deleteByRefDo(refDo));
                byte[] aid = tryAidOf(refDo);
                if (aid != null) {
                    addCommandFamily(
                            corpus, rng, origin + ":delete-by-aid", deleteByAid(aid));
                }
            }
            seedIndex++;
        }

        addCommandFamily(corpus, rng, "delete-all", new byte[] {TAG_DELETE, (byte) 0x00});
        corpus.addAll(nestingAbuseCases());
        corpus.addAll(spliceCases(rng, seeds));
        corpus.addAll(degenerateCases());
        return corpus;
    }

    /** The base command plus its deterministic mutants, all at deterministic buffer offsets. */
    private static void addCommandFamily(
            List<FuzzCase> corpus, Random rng, String origin, byte[] command) {
        corpus.add(new FuzzCase(origin, command, rng.nextInt(4)));
        for (int index = 0; index < MUTANTS_PER_COMMAND; index++) {
            Mutation mutation = Mutation.values()[index % Mutation.values().length];
            byte[] mutant = mutation.apply(command, rng);
            if (mutant == null || mutant.length == 0) {
                continue;
            }
            corpus.add(new FuzzCase(origin + "/" + mutation + "#" + index, mutant, rng.nextInt(4)));
        }
    }

    /**
     * SEAC-plausible encodings this applet rejects by design. Random mutation reaches these
     * shapes only by accident; naming them keeps the rejection surface explicit and gives the
     * mutators a second family of structurally deep starting points.
     */
    private static List<byte[]> handWrittenRejectedShapes() {
        List<byte[]> shapes = new ArrayList<byte[]>();
        for (RejectedShape shape : REJECTED_SHAPES) {
            shapes.add(shape.encoding());
        }
        return shapes;
    }

    /**
     * Nesting-depth abuse. The parser is deliberately non-recursive and fixed-depth, so this is
     * an assertion about that property rather than a search for a stack overflow: repeated
     * wrappers must be rejected at the layer that first sees an unexpected tag, at every depth.
     */
    private static List<FuzzCase> nestingAbuseCases() {
        List<FuzzCase> cases = new ArrayList<FuzzCase>();
        byte[] catchAll = hex("E20BE1044F00C100E303D00101");
        byte[] refDo = hex("E1044F00C100");
        byte[] arDo = hex("E303D00101");

        byte[] nestedRule = catchAll;
        byte[] nestedRefDo = refDo;
        byte[] nestedArDo = arDo;
        for (int depth = 1; depth <= 5; depth++) {
            nestedRule = tlvOrNull((byte) 0xE2, nestedRule);
            nestedRefDo = tlvOrNull((byte) 0xE1, nestedRefDo);
            nestedArDo = tlvOrNull((byte) 0xE3, nestedArDo);
            if (nestedRule != null) {
                cases.add(new FuzzCase("nesting:E2^" + depth, upsert(nestedRule), depth % 4));
            }
            if (nestedRefDo != null) {
                byte[] rule = tlvOrNull((byte) 0xE2, concat(nestedRefDo, arDo));
                if (rule != null) {
                    cases.add(new FuzzCase("nesting:E1^" + depth, upsert(rule), depth % 4));
                }
            }
            if (nestedArDo != null) {
                byte[] rule = tlvOrNull((byte) 0xE2, concat(refDo, nestedArDo));
                if (rule != null) {
                    cases.add(new FuzzCase("nesting:E3^" + depth, upsert(rule), depth % 4));
                }
            }
            // The same abuse one level up, wrapping the command DO itself.
            byte[] nestedCommand = upsert(catchAll);
            for (int wrap = 0; wrap < depth; wrap++) {
                nestedCommand = tlvOrNull(TAG_UPSERT, nestedCommand);
                if (nestedCommand == null) {
                    break;
                }
            }
            if (nestedCommand != null) {
                cases.add(new FuzzCase("nesting:F0^" + depth, nestedCommand, depth % 4));
            }
        }
        return cases;
    }

    /** Prefix of one real rule, suffix of another: valid fragments joined at an invalid seam. */
    private static List<FuzzCase> spliceCases(Random rng, List<byte[]> seeds) {
        List<FuzzCase> cases = new ArrayList<FuzzCase>();
        for (int index = 0; index < 120; index++) {
            byte[] left = seeds.get(rng.nextInt(seeds.size()));
            byte[] right = seeds.get(rng.nextInt(seeds.size()));
            int cut = 1 + rng.nextInt(left.length - 1);
            int resume = rng.nextInt(right.length);
            byte[] spliced =
                    concat(
                            Arrays.copyOf(left, cut),
                            Arrays.copyOfRange(right, resume, right.length));
            byte[] command = upsertOrNull(spliced);
            if (command != null) {
                cases.add(new FuzzCase("splice#" + index, command, rng.nextInt(4)));
            }
        }
        return cases;
    }

    /** Boundary inputs that no mutator would reliably produce. */
    private static List<FuzzCase> degenerateCases() {
        List<FuzzCase> cases = new ArrayList<FuzzCase>();
        cases.add(new FuzzCase("degenerate:empty", new byte[0], 0));
        cases.add(new FuzzCase("degenerate:single-F0", new byte[] {TAG_UPSERT}, 1));
        cases.add(new FuzzCase("degenerate:single-F1", new byte[] {TAG_DELETE}, 2));
        cases.add(new FuzzCase("degenerate:single-zero", new byte[] {(byte) 0x00}, 3));
        cases.add(new FuzzCase("degenerate:F0-zero-length", hex("F000"), 0));
        cases.add(new FuzzCase("degenerate:F0-max-length-claim", hex("F07F"), 1));
        cases.add(new FuzzCase("degenerate:F1-max-length-claim", hex("F17F"), 2));
        cases.add(new FuzzCase("degenerate:unknown-command-DO", hex("F6034F0100"), 3));
        cases.add(new FuzzCase("degenerate:ara-c-command-DO", hex("F700"), 0));
        // Exactly at, and one over, the STORE DATA data-field limit the adapter enforces.
        cases.add(new FuzzCase("degenerate:127-bytes", filled(127, (byte) 0xE2), 0));
        cases.add(new FuzzCase("degenerate:128-bytes", filled(128, (byte) 0xE2), 0));
        cases.add(new FuzzCase("degenerate:255-bytes", filled(255, (byte) 0xF0), 0));
        // A well-formed upsert whose command length octet under- and over-states its value.
        byte[] rule = hex("E20BE1044F00C100E303D00101");
        cases.add(
                new FuzzCase(
                        "degenerate:command-length-short",
                        concat(new byte[] {TAG_UPSERT, (byte) (rule.length - 1)}, rule),
                        1));
        cases.add(
                new FuzzCase(
                        "degenerate:command-length-long",
                        concat(new byte[] {TAG_UPSERT, (byte) (rule.length + 1)}, rule),
                        2));
        return cases;
    }

    /** The deterministic mutation strategies applied to every base command. */
    private enum Mutation {
        TRUNCATE {
            @Override
            byte[] apply(byte[] input, Random rng) {
                if (input.length < 2) {
                    return null;
                }
                return Arrays.copyOf(input, 1 + rng.nextInt(input.length - 1));
            }
        },
        CORRUPT_LENGTH {
            @Override
            byte[] apply(byte[] input, Random rng) {
                if (input.length == 0) {
                    return null;
                }
                byte[] mutant = input.clone();
                int index = rng.nextInt(mutant.length);
                int original = mutant[index] & 0xFF;
                switch (rng.nextInt(5)) {
                    case 0:
                        mutant[index] = (byte) (original + 1);
                        break;
                    case 1:
                        mutant[index] = (byte) (original - 1);
                        break;
                    case 2:
                        mutant[index] = (byte) 0x00;
                        break;
                    case 3:
                        mutant[index] = (byte) 0x7F;
                        break;
                    default:
                        // Set the BER long-form bit: readLength must refuse it outright.
                        mutant[index] = (byte) (original | 0x80);
                        break;
                }
                return mutant;
            }
        },
        SUBSTITUTE_TAG {
            @Override
            byte[] apply(byte[] input, Random rng) {
                if (input.length == 0) {
                    return null;
                }
                byte[] mutant = input.clone();
                mutant[rng.nextInt(mutant.length)] =
                        SUBSTITUTION_TAGS[rng.nextInt(SUBSTITUTION_TAGS.length)];
                return mutant;
            }
        },
        FLIP_BIT {
            @Override
            byte[] apply(byte[] input, Random rng) {
                if (input.length == 0) {
                    return null;
                }
                byte[] mutant = input.clone();
                int index = rng.nextInt(mutant.length);
                mutant[index] = (byte) (mutant[index] ^ (1 << rng.nextInt(8)));
                return mutant;
            }
        },
        INSERT_BYTE {
            @Override
            byte[] apply(byte[] input, Random rng) {
                byte[] mutant = new byte[input.length + 1];
                int index = rng.nextInt(input.length + 1);
                System.arraycopy(input, 0, mutant, 0, index);
                mutant[index] = SUBSTITUTION_TAGS[rng.nextInt(SUBSTITUTION_TAGS.length)];
                System.arraycopy(input, index, mutant, index + 1, input.length - index);
                return mutant;
            }
        },
        DELETE_BYTE {
            @Override
            byte[] apply(byte[] input, Random rng) {
                if (input.length < 2) {
                    return null;
                }
                byte[] mutant = new byte[input.length - 1];
                int index = rng.nextInt(input.length);
                System.arraycopy(input, 0, mutant, 0, index);
                System.arraycopy(input, index + 1, mutant, index, input.length - index - 1);
                return mutant;
            }
        };

        abstract byte[] apply(byte[] input, Random rng);
    }

    // ---------------------------------------------------------------------------------------
    // Invariant machinery
    // ---------------------------------------------------------------------------------------

    /**
     * Drives the personalization entry point once and enforces invariant 1.
     *
     * @return the rejection status word, or {@code null} when the input was accepted
     */
    private Integer attemptPersonalization(FuzzCase fuzzCase, PaddedInput input) {
        try {
            application.processData(input.buffer, input.offset, input.length);
            return null;
        } catch (ISOException rejected) {
            return Integer.valueOf(rejected.getReason() & 0xFFFF);
        } catch (Throwable unexpected) {
            // Anything other than ISOException is the defect this harness exists to find.
            fail(
                    "Personalization threw "
                            + unexpected.getClass().getName()
                            + " instead of ISOException for "
                            + fuzzCase,
                    unexpected);
            throw new AssertionError("unreachable");
        }
    }

    /**
     * Drives the personalization entry point once for an input that must be rejected, and reports
     * both the status word and where in the parser the refusal came from.
     */
    private Rejection attemptPersonalizationForRejection(FuzzCase fuzzCase, PaddedInput input) {
        try {
            application.processData(input.buffer, input.offset, input.length);
        } catch (ISOException rejected) {
            return new Rejection(rejected.getReason() & 0xFFFF, rejectionSite(rejected));
        } catch (Throwable unexpected) {
            fail(
                    "Personalization threw "
                            + unexpected.getClass().getName()
                            + " instead of ISOException for "
                            + fuzzCase,
                    unexpected);
            throw new AssertionError("unreachable");
        }
        fail("A shape documented as rejected by design was accepted: " + fuzzCase);
        throw new AssertionError("unreachable");
    }

    /**
     * The applet frames that were on the stack when the refusal was raised, innermost first, as
     * {@code readLength<-upsert<-store}.
     *
     * <p>jCardSim's {@code ISOException.throwIt} constructs the exception at the throw point, so
     * the trace names the real refusal site rather than a cached one. {@code malformed} is dropped
     * because it is a shared one-liner every site funnels through and carries no information.
     */
    private static String rejectionSite(ISOException rejected) {
        StringBuilder site = new StringBuilder();
        for (StackTraceElement frame : rejected.getStackTrace()) {
            if (!AraMApplet.class.getName().equals(frame.getClassName())
                    || "malformed".equals(frame.getMethodName())) {
                continue;
            }
            if (site.length() > 0) {
                site.append("<-");
            }
            site.append(frame.getMethodName());
        }
        return site.toString();
    }

    /**
     * Walks a byte array as BER and returns the first place a declared length does not exactly
     * span its content, or {@code null} when the whole array walks cleanly.
     *
     * <p>Deliberately independent of the applet: it accepts the long-form lengths the applet
     * refuses, because its job is to say whether an encoding is <em>structurally</em> sound, not
     * whether this parser likes it. That separation is the point — an entry can then be structurally
     * sound and still rejected, which is exactly the property a by-design rejection needs.
     */
    private static String berLengthDisagreement(byte[] value) {
        return berLengthDisagreement(value, 0, value.length);
    }

    private static String berLengthDisagreement(byte[] value, int offset, int end) {
        int cursor = offset;
        while (cursor < end) {
            int tag = value[cursor] & 0xFF;
            if (cursor + 1 >= end) {
                return "@" + cursor + " tag " + String.format("%02X", tag) + ": no length octet";
            }
            int declared = value[cursor + 1] & 0xFF;
            int headerLength = 2;
            if ((declared & 0x80) != 0) {
                int lengthOctets = declared & 0x7F;
                if (lengthOctets < 1 || lengthOctets > 2 || cursor + 2 + lengthOctets > end) {
                    return "@"
                            + cursor
                            + " tag "
                            + String.format("%02X", tag)
                            + ": unusable long-form length 0x"
                            + String.format("%02X", declared);
                }
                declared = 0;
                for (int index = 0; index < lengthOctets; index++) {
                    declared = (declared << 8) | (value[cursor + 2 + index] & 0xFF);
                }
                headerLength = 2 + lengthOctets;
            }
            int contentStart = cursor + headerLength;
            int contentEnd = contentStart + declared;
            if (contentEnd > end) {
                return "@"
                        + cursor
                        + " tag "
                        + String.format("%02X", tag)
                        + ": declares "
                        + declared
                        + " over the "
                        + (end - contentStart)
                        + " bytes available";
            }
            if (isConstructedTag(tag)) {
                String nested = berLengthDisagreement(value, contentStart, contentEnd);
                if (nested != null) {
                    return nested;
                }
            }
            cursor = contentEnd;
        }
        return SELF_CONSISTENT;
    }

    /** The SEAC containers whose value is itself a sequence of TLVs. */
    private static boolean isConstructedTag(int tag) {
        return tag == 0xE1 || tag == 0xE2 || tag == 0xE3 || tag == 0xF0 || tag == 0xF1;
    }

    private void assertSnapshotUnchanged(Snapshot before, Snapshot after, FuzzCase fuzzCase) {
        assertArrayEquals(
                before.catalog,
                after.catalog,
                () -> "Rejection mutated the rule catalog for " + fuzzCase);
        assertArrayEquals(
                before.refreshTag,
                after.refreshTag,
                () -> "Rejection mutated the refresh tag for " + fuzzCase);
        assertEquals(
                before.revision,
                after.revision,
                () -> "Rejection bumped the catalog revision for " + fuzzCase);
    }

    /**
     * Invariant 3: after a rejection a well-formed store still lands, and undoing it returns the
     * catalog to exactly where the rejection left it. Both halves must republish the refresh tag,
     * which is what a host uses to notice the catalog moved.
     */
    private void assertStillUsable(FuzzCase fuzzCase) {
        Snapshot before = snapshot();

        personalizeCommand(upsert(PROBE_RULE));
        Snapshot stored = snapshot();
        assertTrue(
                indexOf(stored.catalog, PROBE_RULE) >= 0,
                () -> "A well-formed store did not reach the catalog after " + fuzzCase);
        assertFalse(
                Arrays.equals(before.refreshTag, stored.refreshTag),
                () -> "A real mutation must publish a new refresh tag after " + fuzzCase);

        personalizeCommand(deleteByRefDo(refDoOf(PROBE_RULE)));
        Snapshot restored = snapshot();
        assertArrayEquals(
                before.catalog,
                restored.catalog,
                () -> "Probe store/delete did not round-trip after " + fuzzCase);
        assertFalse(
                Arrays.equals(stored.refreshTag, restored.refreshTag),
                () -> "The probe delete must publish a new refresh tag after " + fuzzCase);
    }

    /**
     * Invariant 3 with no free slot left: the probe cannot be a new rule, so it evicts and
     * restores an existing one instead. Record placement rotates with the revision counter, so
     * the catalog is compared as a multiset of rules rather than as a byte stream.
     */
    private void assertStillUsableAtCapacity(byte[] evictable, FuzzCase fuzzCase) {
        int rulesBefore = countRules(snapshot().catalog);

        personalizeCommand(deleteByRefDo(refDoOf(evictable)));
        assertEquals(
                rulesBefore - 1,
                countRules(snapshot().catalog),
                () -> "A well-formed delete did not take effect after " + fuzzCase);

        personalizeCommand(upsert(evictable));
        Snapshot restored = snapshot();
        assertEquals(
                rulesBefore,
                countRules(restored.catalog),
                () -> "A well-formed store did not refill the freed slot after " + fuzzCase);
        assertTrue(
                indexOf(restored.catalog, evictable) >= 0,
                () -> "The restored rule is missing from the catalog after " + fuzzCase);
    }

    /** Walks a catalog value as a sequence of top-level REF-AR-DOs and counts them. */
    private static int countRules(byte[] catalog) {
        int count = 0;
        int cursor = 0;
        while (cursor < catalog.length) {
            assertEquals(
                    (byte) 0xE2, catalog[cursor], "every catalog element is a REF-AR-DO");
            int length = catalog[cursor + 1] & 0xFF;
            cursor += 2 + length;
            count++;
        }
        assertEquals(catalog.length, cursor, "the catalog value must walk exactly");
        return count;
    }

    private List<byte[]> personalizeToCapacity() {
        personalizeCommand(new byte[] {TAG_DELETE, (byte) 0x00});
        List<byte[]> rules = new ArrayList<byte[]>();
        for (int index = 0; index < AraMApplet.DEFAULT_ACTIVE_RULE_CAPACITY; index++) {
            byte[] aid =
                    new byte[] {
                        (byte) 0xF0, (byte) 0x00, (byte) 0x00, (byte) 0x00,
                        (byte) 0xCC, (byte) index
                    };
            byte[] refDo =
                    tlv(
                            (byte) 0xE1,
                            concat(tlv((byte) 0x4F, aid), tlv((byte) 0xC1, new byte[0])));
            byte[] rule = tlv((byte) 0xE2, concat(refDo, tlv((byte) 0xE3, hex("D00101"))));
            rules.add(rule);
            personalizeCommand(upsert(rule));
        }
        assertEquals(
                AraMApplet.DEFAULT_ACTIVE_RULE_CAPACITY,
                countRules(snapshot().catalog),
                "the catalog must actually be at capacity");
        return rules;
    }

    private void personalizeBaseline() {
        personalizeCommand(new byte[] {TAG_DELETE, (byte) 0x00});
        personalizeCommand(upsert(BASELINE_ALLOW_RULE));
        personalizeCommand(upsert(BASELINE_CERT_BOUND_RULE));
    }

    private void personalizeCommand(byte[] commandDo) {
        application.processData(commandDo, (short) 0, (short) commandDo.length);
    }

    /**
     * The applet state a host can observe: the exact byte stream {@code GET DATA [FF40]} emits
     * as its value, the refresh tag, and the revision the read session keys on. Read by
     * reflection rather than over APDU so the per-case cost stays negligible; the APDU path is
     * checked separately by {@code catalogAndRefreshTagStayReadableOverApduAfterTheCorpus}.
     */
    private Snapshot snapshot() {
        try {
            AraMApplet logic = logic();
            byte[] arena = (byte[]) field("recordArena").get(logic);
            byte[] bitmap = (byte[]) field("activeBitmap").get(logic);
            byte[] refreshTag = (byte[]) field("refreshTag").get(logic);
            short revision = field("catalogRevision").getShort(logic);

            int recordSize = 1 + AraMApplet.MAX_REF_AR_DO_LENGTH;
            int recordCount = arena.length / recordSize;
            ByteArrayOutputStream catalog = new ByteArrayOutputStream();
            for (int index = 0; index < recordCount; index++) {
                int mask = 1 << (index & 7);
                if ((bitmap[index >> 3] & mask) == 0) {
                    continue;
                }
                int base = index * recordSize;
                int length = arena[base] & 0xFF;
                catalog.write(arena, base + 1, length);
            }
            return new Snapshot(catalog.toByteArray(), refreshTag.clone(), revision);
        } catch (ReflectiveOperationException failure) {
            throw new AssertionError("Could not inspect applet state", failure);
        }
    }

    private static Field field(String name) throws ReflectiveOperationException {
        Field declared = AraMApplet.class.getDeclaredField(name);
        declared.setAccessible(true);
        return declared;
    }

    private AraMApplet logic() throws ReflectiveOperationException {
        AraMJCApplet applet = (AraMJCApplet) simulator.applet(appletAid);
        Field logicField = AraMJCApplet.class.getDeclaredField("logic");
        logicField.setAccessible(true);
        return (AraMApplet) logicField.get(applet);
    }

    // ---------------------------------------------------------------------------------------
    // APDU-level reads
    // ---------------------------------------------------------------------------------------

    private byte[] getAllRulesOverApdu() {
        ResponseAPDU first = getData(0xFF, 0x40);
        assertEquals(0x9000, first.getSW());
        byte[] firstData = first.getData();
        int lengthOctets = berLengthOctets(firstData);
        int headerLength = 2 + lengthOctets;
        int catalogLength = decodeBerLength(firstData);

        ByteArrayOutputStream value = new ByteArrayOutputStream();
        value.write(firstData, headerLength, firstData.length - headerLength);
        while (value.size() < catalogLength) {
            ResponseAPDU next = getData(0xFF, 0x60);
            assertEquals(0x9000, next.getSW());
            value.write(next.getData(), 0, next.getData().length);
        }
        assertEquals(catalogLength, value.size());
        return value.toByteArray();
    }

    private byte[] getRefreshTagOverApdu() {
        ResponseAPDU response = getData(0xDF, 0x20);
        assertEquals(0x9000, response.getSW());
        return response.getData();
    }

    private ResponseAPDU getData(int p1, int p2) {
        return simulator.transmitCommand(new CommandAPDU(0x80, 0xCA, p1, p2, 256));
    }

    private static int berLengthOctets(byte[] encoded) {
        int first = encoded[2] & 0xFF;
        if (first <= 0x7F) {
            return 1;
        }
        if (first == 0x81) {
            return 2;
        }
        if (first == 0x82) {
            return 3;
        }
        throw new AssertionError("Unsupported BER length form");
    }

    private static int decodeBerLength(byte[] encoded) {
        int first = encoded[2] & 0xFF;
        if (first <= 0x7F) {
            return first;
        }
        if (first == 0x81) {
            return encoded[3] & 0xFF;
        }
        if (first == 0x82) {
            return ((encoded[3] & 0xFF) << 8) | (encoded[4] & 0xFF);
        }
        throw new AssertionError("Unsupported BER length form");
    }

    // ---------------------------------------------------------------------------------------
    // Fixtures and small helpers
    // ---------------------------------------------------------------------------------------

    private static List<byte[]> loadCtsSeacRules() {
        List<byte[]> rules = new ArrayList<byte[]>();
        InputStream stream =
                AraMPersonalizationFuzzTest.class.getResourceAsStream("cts-seac-rules.txt");
        if (stream == null) {
            throw new AssertionError("cts-seac-rules.txt is missing from the test resources");
        }
        BufferedReader reader =
                new BufferedReader(new InputStreamReader(stream, StandardCharsets.UTF_8));
        try {
            String line;
            while ((line = reader.readLine()) != null) {
                String trimmed = line.trim();
                if (trimmed.isEmpty() || trimmed.startsWith("#")) {
                    continue;
                }
                rules.add(hex(trimmed));
            }
        } catch (IOException failure) {
            throw new UncheckedIOException(failure);
        } finally {
            closeQuietly(reader);
        }
        return rules;
    }

    private static void closeQuietly(BufferedReader reader) {
        try {
            reader.close();
        } catch (IOException ignored) {
            // Nothing useful to do with a failure to close a classpath resource.
        }
    }

    private static boolean containing(List<byte[]> seeds, String hexFragment) {
        byte[] needle = hex(hexFragment);
        for (byte[] seed : seeds) {
            if (indexOf(seed, needle) >= 0) {
                return true;
            }
        }
        return false;
    }

    private static int indexOf(byte[] haystack, byte[] needle) {
        outer:
        for (int start = 0; start + needle.length <= haystack.length; start++) {
            for (int index = 0; index < needle.length; index++) {
                if (haystack[start + index] != needle[index]) {
                    continue outer;
                }
            }
            return start;
        }
        return -1;
    }

    /**
     * A well-formed REF-AR-DO of an exact size, for the record-size boundary cases. Its total
     * length is {@code 12 + aidLength + deviceAppIdLength + apduFilterLength}; the filter length
     * must be a multiple of eight, which is the only member that can grow a rule past 61 bytes.
     */
    private static byte[] ruleOfSize(int aidLength, int deviceAppIdLength, int apduFilterLength) {
        byte[] aid = new byte[aidLength];
        aid[0] = (byte) 0xF0;
        for (int index = 1; index < aidLength; index++) {
            aid[index] = (byte) index;
        }
        byte[] deviceAppId = new byte[deviceAppIdLength];
        for (int index = 0; index < deviceAppIdLength; index++) {
            deviceAppId[index] = (byte) index;
        }
        byte[] apduFilter = new byte[apduFilterLength];
        for (int index = 0; index < apduFilterLength; index++) {
            apduFilter[index] = (byte) (0xA0 + index);
        }
        byte[] refDo =
                tlv((byte) 0xE1, concat(tlv((byte) 0x4F, aid), tlv((byte) 0xC1, deviceAppId)));
        return tlv((byte) 0xE2, concat(refDo, tlv((byte) 0xE3, tlv((byte) 0xD0, apduFilter))));
    }

    private static byte[] upsert(byte[] refArDo) {
        return tlv(TAG_UPSERT, refArDo);
    }

    private static byte[] upsertOrNull(byte[] refArDo) {
        return tlvOrNull(TAG_UPSERT, refArDo);
    }

    private static byte[] deleteByRefDo(byte[] refDo) {
        return tlv(TAG_DELETE, refDo);
    }

    private static byte[] deleteByAid(byte[] aid) {
        return tlv(TAG_DELETE, tlv((byte) 0x4F, aid));
    }

    /** The REF-DO of a well-formed REF-AR-DO, or {@code null} when the seed is not one. */
    private static byte[] tryRefDoOf(byte[] refArDo) {
        if (refArDo.length < 4 || refArDo[0] != (byte) 0xE2 || refArDo[2] != (byte) 0xE1) {
            return null;
        }
        int refDoLength = 2 + (refArDo[3] & 0xFF);
        if (2 + refDoLength > refArDo.length) {
            return null;
        }
        return Arrays.copyOfRange(refArDo, 2, 2 + refDoLength);
    }

    private static byte[] refDoOf(byte[] refArDo) {
        byte[] refDo = tryRefDoOf(refArDo);
        if (refDo == null) {
            throw new AssertionError("Not a well-formed REF-AR-DO");
        }
        return refDo;
    }

    /** The AID value inside a REF-DO, or {@code null} when there is no usable one. */
    private static byte[] tryAidOf(byte[] refDo) {
        if (refDo.length < 4 || refDo[2] != (byte) 0x4F) {
            return null;
        }
        int aidLength = refDo[3] & 0xFF;
        if (aidLength == 0 || 4 + aidLength > refDo.length) {
            return null;
        }
        return Arrays.copyOfRange(refDo, 4, 4 + aidLength);
    }

    private static byte[] tlv(byte tag, byte[] value) {
        byte[] encoded = tlvOrNull(tag, value);
        if (encoded == null) {
            throw new AssertionError("Value does not fit a short-form BER length");
        }
        return encoded;
    }

    private static byte[] tlvOrNull(byte tag, byte[] value) {
        if (value.length > 0x7F) {
            return null;
        }
        return concat(new byte[] {tag, (byte) value.length}, value);
    }

    private static byte[] filled(int length, byte value) {
        byte[] result = new byte[length];
        Arrays.fill(result, value);
        return result;
    }

    private static byte[] concat(byte[] left, byte[] right) {
        byte[] result = new byte[left.length + right.length];
        System.arraycopy(left, 0, result, 0, left.length);
        System.arraycopy(right, 0, result, left.length, right.length);
        return result;
    }

    private static byte[] hex(String value) {
        byte[] result = new byte[value.length() / 2];
        for (int index = 0; index < value.length(); index += 2) {
            result[index / 2] =
                    (byte)
                            ((Character.digit(value.charAt(index), 16) << 4)
                                    | Character.digit(value.charAt(index + 1), 16));
        }
        return result;
    }

    private static String hexOf(byte[] value) {
        StringBuilder text = new StringBuilder(value.length * 2);
        for (byte element : value) {
            text.append(String.format("%02X", element));
        }
        return text.toString();
    }

    private static String hexOf(int statusWord) {
        return String.format("%04X", statusWord);
    }

    private static void increment(TreeMap<Integer, Integer> histogram, int key) {
        Integer previous = histogram.get(Integer.valueOf(key));
        histogram.put(
                Integer.valueOf(key),
                Integer.valueOf(previous == null ? 1 : previous.intValue() + 1));
    }

    private static String renderHistogram(TreeMap<Integer, Integer> histogram) {
        StringBuilder text = new StringBuilder("{");
        boolean first = true;
        for (java.util.Map.Entry<Integer, Integer> entry : histogram.entrySet()) {
            if (!first) {
                text.append(", ");
            }
            text.append(hexOf(entry.getKey().intValue())).append('=').append(entry.getValue());
            first = false;
        }
        return text.append('}').toString();
    }

    /**
     * One SEAC-plausible encoding the applet refuses on purpose, plus the evidence that it is
     * refused for the reason its name gives.
     *
     * <p>The extra fields exist because of a real defect in the first version of this list. Three
     * entries declared BER lengths that disagreed with their own content, so {@code upsert}'s outer
     * {@code checkedEnd} threw them out before the member rule named in the comment was ever
     * consulted. Each was green, and each would have stayed green with the rule it claimed to guard
     * deleted from the applet — a must-reject entry that passes for the wrong reason is the same
     * false comfort this harness exists to remove. Three independent facts now have to hold, and
     * any one of them falsifies that failure mode on its own.
     */
    private static final class RejectedShape {

        /** Stable identifier, used in failure messages instead of a list index. */
        private final String name;

        /** What the entry claims the parser objects to. Printed when the site assertion fails. */
        private final String claim;

        private final String encodingHex;

        /**
         * The same shape with only the named property put right. Must be accepted, which is what
         * attributes the rejection to that property rather than to some neighbouring flaw.
         */
        private final String repairedHex;

        /**
         * The expected result of walking {@link #encodingHex} as BER: {@link
         * AraMPersonalizationFuzzTest#SELF_CONSISTENT} for every entry whose defect is grammatical,
         * or the exact disagreement for the two entries whose named defect <em>is</em> the length
         * encoding.
         */
        private final String structure;

        private final int statusWord;

        /** Expected {@code AraMApplet} frames at the refusal, innermost first. */
        private final String site;

        private RejectedShape(
                String name,
                String claim,
                String encodingHex,
                String repairedHex,
                String structure,
                int statusWord,
                String site) {
            this.name = name;
            this.claim = claim;
            this.encodingHex = encodingHex;
            this.repairedHex = repairedHex;
            this.structure = structure;
            this.statusWord = statusWord;
            this.site = site;
        }

        byte[] encoding() {
            return hex(encodingHex);
        }

        byte[] repaired() {
            return hex(repairedHex);
        }
    }

    /** A refusal out of the personalization path: what it reported and where it came from. */
    private static final class Rejection {
        private final int statusWord;
        private final String site;

        private Rejection(int statusWord, String site) {
            this.statusWord = statusWord;
            this.site = site;
        }
    }

    /** One reproducible corpus entry: what it is, the bytes, and where in the buffer they sit. */
    private static final class FuzzCase {
        private final String label;
        private final byte[] command;
        private final int padOffset;

        private FuzzCase(String label, byte[] command, int padOffset) {
            this.label = label;
            this.command = command;
            this.padOffset = padOffset;
        }

        @Override
        public String toString() {
            return label + " [" + hexOf(command) + "]";
        }
    }

    /**
     * The command placed at a non-zero offset inside a larger buffer with guard padding on both
     * sides, mirroring how a Security Domain hands over the APDU buffer with {@code offset ==
     * ISO7816.OFFSET_CDATA}. {@code expected} is the pristine copy every case is compared back
     * against.
     */
    private static final class PaddedInput {
        private final byte[] buffer;
        private final byte[] expected;
        private final short offset;
        private final short length;

        private PaddedInput(byte[] buffer, short offset, short length) {
            this.buffer = buffer;
            this.expected = buffer.clone();
            this.offset = offset;
            this.length = length;
        }

        static PaddedInput wrap(byte[] command, int padOffset) {
            int lead = padOffset * 5;
            byte[] buffer = new byte[lead + command.length + 7];
            Arrays.fill(buffer, (byte) 0xA5);
            System.arraycopy(command, 0, buffer, lead, command.length);
            return new PaddedInput(buffer, (short) lead, (short) command.length);
        }

        /**
         * The same command in a buffer that ends exactly where the command does.
         *
         * <p>This is the shape that actually tests the parser's bounds arithmetic. In the padded
         * shape above, a read past the logical command end still lands inside the allocated array
         * and returns a {@code 0xA5} guard byte — whose top bit is set, so {@code readLength}
         * rejects it and the over-read is laundered into a clean-looking {@code 6A80}. A mutation
         * run proved that: dropping the {@code end > limit} check from {@code checkedEnd}, and
         * dropping the bounds check from {@code readLength}, both survived the entire padded
         * corpus. With no trailing slack the same over-read is an
         * {@code ArrayIndexOutOfBoundsException}, which invariant 1 catches. Every case is run in
         * both shapes for that reason — do not drop the tight one.
         */
        static PaddedInput tight(byte[] command) {
            return new PaddedInput(command.clone(), (short) 0, (short) command.length);
        }
    }

    private static final class Snapshot {
        private final byte[] catalog;
        private final byte[] refreshTag;
        private final short revision;

        private Snapshot(byte[] catalog, byte[] refreshTag, short revision) {
            this.catalog = catalog;
            this.refreshTag = refreshTag;
            this.revision = revision;
        }
    }

    private static final class ExposedCardSimulator extends CardSimulator {

        Application application(AID aid) {
            return (Application) applet(aid);
        }

        Applet applet(AID aid) {
            return runtime.lookupApplet(aid).getApplet();
        }
    }
}
