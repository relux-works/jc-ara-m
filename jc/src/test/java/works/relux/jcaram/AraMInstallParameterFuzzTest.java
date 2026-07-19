package works.relux.jcaram;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import com.licel.jcardsim.smartcardio.CardSimulator;
import com.licel.jcardsim.utils.AIDUtil;
import javacard.framework.AID;
import javacard.framework.Applet;
import javacard.framework.ISOException;
import javacard.framework.SystemException;
import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.UncheckedIOException;
import java.lang.reflect.Field;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Random;
import java.util.TreeMap;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * Property/fuzz harness for the <em>second</em> attacker-influenced parser in this applet:
 * {@link AraMJCApplet#resolveActiveRuleCapacity}, which reads the active-rule capacity R out of
 * the GlobalPlatform installation parameter array.
 *
 * <p>{@code AraMPersonalizationFuzzTest} covers the STORE DATA path. This one covers install time,
 * and the invariant is <em>inverted</em>. On the personalization path a rejection must be a no-op:
 * the catalog is already live, so refusing malformed input has to leave it bit-identical. Here
 * there is no prior state to preserve — the danger is the opposite one, a malformed parameter
 * block that is quietly tolerated and silently yields some default capacity nobody asked for. An
 * operator who requested R=48 and got R=16 because a byte was mangled in transit would not find
 * out until the seventeenth rule failed to store on a card already in the field. So the contract
 * is that a malformed block fails installation <em>loudly</em> and registers nothing.
 *
 * <p>Four invariants, asserted over a bounded deterministic corpus:
 *
 * <ol>
 *   <li><b>Only ISOException escapes.</b> Same claim as the personalization harness, same reason:
 *       anything else surfaces as an uncaught JCRE error during install.
 *   <li><b>A returned capacity is always in range.</b> Never {@code 0}, never above
 *       {@code MAX_ACTIVE_RULE_CAPACITY}, never negative. A capacity of zero would produce a
 *       one-record arena and a catalog that can never hold a rule; an oversized one would
 *       over-allocate EEPROM on a card that cannot spare it.
 *   <li><b>Rejection means nothing gets registered.</b> A block the parser refuses must also fail
 *       the real jCardSim installation and leave no instance behind — no half-installed applet
 *       answering SELECT with a capacity nobody chose.
 *   <li><b>Acceptance is consistent.</b> Whatever capacity the parser returns is exactly the
 *       capacity the installed instance reports, and its arena and bitmaps are sized from it.
 *   </ol>
 *
 * <p>Every case runs in two buffer shapes, padded and tight. That is the lesson carried over from
 * the personalization harness, where guard padding was found to launder over-reads into
 * clean-looking rejections: with trailing slack a read past the declared end returns a guard byte
 * instead of throwing, so bounds bugs hide. Here the tight shape matters even more, because the
 * JCRE hands {@code install()} an array whose length is exactly the parameter block.
 */
final class AraMInstallParameterFuzzTest {

    private static final long DEFAULT_CORPUS_SEED = 0x157A11ADD1C7EDL;

    /**
     * Mutants per seed. Higher than the personalization harness's 12 on purpose: this parser has a
     * much smaller natural seed set (ten well-formed parameter blocks against fifty-six SEAC
     * rules), so density per seed is where the coverage has to come from. Each case is a plain
     * static call, so the whole corpus still costs single-digit milliseconds.
     */
    private static final int DEFAULT_MUTANTS_PER_SEED = 40;

    /** Fixed seed: in the normal test task this is a regression gate, not a soak. */
    private static final long CORPUS_SEED = Long.getLong("aram.fuzz.seed", DEFAULT_CORPUS_SEED);

    private static final int MUTANTS_PER_SEED =
            Integer.getInteger("aram.fuzz.mutants", DEFAULT_MUTANTS_PER_SEED);

    /**
     * The pinned accept/reject verdict of the default corpus. See
     * {@link #theCorpusAcceptRejectDecisionMatchesItsPinnedGoldenVector()} for why this exists and
     * what to do when it fails.
     */
    private static final String GOLDEN_DECISION_SUMMARY =
            "cases=422 executions=844 accepted=406 rejected=438"
                    + " capacities={1=46, 16=152, 17=42, 32=2, 48=32, 64=132}"
                    + " statusWords={6A80=438}"
                    + " digest=421000f541c9381603223470a295c4699c13012b30adc3ab2590cbb071acf0cf";

    /** The same verdict, per case, so a mismatch can name which inputs moved rather than a hash. */
    private static final String GOLDEN_DECISIONS_RESOURCE =
            "works/relux/jcaram/install-fuzz-golden-decisions.txt";

    /** Cap on the named differences in a failure message. */
    private static final int REPORTED_DECISION_DIFFERENCES = 12;

    private static final String ARA_M_AID_HEX = "A00000015141434C00";
    private static final byte[] ARA_M_AID = hex("A00000015141434C00");
    private static final byte[] PRIVILEGES = hex("00");

    private static final int RECORD_SIZE = 1 + AraMApplet.MAX_REF_AR_DO_LENGTH;

    /**
     * Tags the substitution mutator draws from: the two this parser knows ({@code C9} container,
     * {@code 80} capacity), plus neighbours and degenerates that keep the input structurally
     * plausible deeper into the parser than random bytes would.
     */
    private static final byte[] SUBSTITUTION_TAGS = {
        (byte) 0xC9, (byte) 0x80, (byte) 0x81, (byte) 0x00, (byte) 0xFF, (byte) 0x01,
        (byte) 0x40, (byte) 0x7F, (byte) 0xC8, (byte) 0xCA
    };

    private ExposedCardSimulator simulator;
    private AID appletAid;

    @BeforeEach
    void setUp() {
        simulator = new ExposedCardSimulator();
        appletAid = AIDUtil.create(ARA_M_AID_HEX);
    }

    /**
     * The whole corpus through the parser entry point, asserting invariants 1 and 2.
     *
     * <p>Driven directly rather than through {@code installApplet} because jCardSim's
     * {@code Simulator.createApplet} wraps any install-time throw in a {@code SystemException},
     * which would erase exactly the distinction invariant 1 exists to make — an {@code ISOException}
     * and a {@code NullPointerException} would look identical from the outside. Invariant 3 pays
     * for the real installation separately, on a sampled subset.
     */
    @Test
    void installParameterParsingHoldsItsInvariantsAcrossTheWholeMutatedCorpus() {
        List<FuzzCase> corpus = buildCorpus();
        assertTrue(corpus.size() > 300, "a corpus this small would not be worth running");

        TreeMap<Integer, Integer> statusWordHistogram = new TreeMap<Integer, Integer>();
        int accepted = 0;
        int rejected = 0;

        for (FuzzCase fuzzCase : corpus) {
            for (boolean tightBuffer : new boolean[] {false, true}) {
                PaddedInput input =
                        tightBuffer
                                ? PaddedInput.tight(fuzzCase.installData)
                                : PaddedInput.wrap(fuzzCase.installData, fuzzCase.padOffset);

                Short capacity = attemptResolve(fuzzCase, input);

                assertArrayEquals(
                        input.expected,
                        input.buffer,
                        () -> "The parser wrote into its caller's buffer for " + fuzzCase);

                if (capacity == null) {
                    rejected++;
                    increment(statusWordHistogram, lastStatusWord);
                    continue;
                }

                accepted++;
                // Invariant 2: a returned capacity is always usable.
                assertTrue(
                        capacity.shortValue() >= (short) 1,
                        () -> "Capacity " + capacity + " is not usable, from " + fuzzCase);
                assertTrue(
                        capacity.shortValue() <= AraMApplet.MAX_ACTIVE_RULE_CAPACITY,
                        () ->
                                "Capacity "
                                        + capacity
                                        + " exceeds the compiled maximum, from "
                                        + fuzzCase);
            }
        }

        assertTrue(rejected > 0, "the corpus must actually exercise the rejection path");
        assertTrue(accepted > 0, "the corpus must also exercise the accepting path");
        System.out.println(
                "AraM install-parameter fuzz: "
                        + corpus.size()
                        + " cases, "
                        + rejected
                        + " rejected, "
                        + accepted
                        + " accepted, status words "
                        + renderHistogram(statusWordHistogram));
    }

    /**
     * Invariants 3 and 4 through a real jCardSim installation.
     *
     * <p>Sampled rather than replayed whole: each case here allocates an arena and registers (or
     * fails to register) an applet instance, which is orders of magnitude more expensive than a
     * parser call. The stride is coprime with nothing in particular — it just has to walk the
     * corpus rather than cluster in it.
     */
    @Test
    void everyRejectedBlockLeavesNothingInstalledAndEveryAcceptedOneIsHonoured() {
        List<FuzzCase> corpus = buildCorpus();
        int installed = 0;
        int refused = 0;

        for (int index = 0; index < corpus.size(); index += 5) {
            FuzzCase fuzzCase = corpus.get(index);
            byte[] installData = fuzzCase.installData;
            if (installData.length > 255) {
                continue;
            }

            // A fresh simulator per case: an install must be judged on its own, not on whatever
            // a previous case left registered.
            simulator = new ExposedCardSimulator();

            Short expected;
            try {
                expected =
                        Short.valueOf(
                                AraMJCApplet.resolveActiveRuleCapacity(
                                        installData, (short) 0, (byte) installData.length));
            } catch (ISOException rejectedByParser) {
                expected = null;
            }

            if (expected == null) {
                refused++;
                // Invariant 3: the installation fails and leaves nothing behind.
                final byte[] refusedData = installData;
                assertThrows(
                        SystemException.class,
                        () ->
                                simulator.installApplet(
                                        appletAid,
                                        AraMJCApplet.class,
                                        refusedData,
                                        (short) 0,
                                        (byte) refusedData.length),
                        () -> "A block the parser refused still installed: " + fuzzCase);
                assertFalse(
                        simulator.isInstalled(appletAid),
                        () -> "An instance survived a failed install: " + fuzzCase);
                continue;
            }

            installed++;
            simulator.installApplet(
                    appletAid, AraMJCApplet.class, installData, (short) 0, (byte) installData.length);
            assertTrue(
                    simulator.isInstalled(appletAid),
                    () -> "A block the parser accepted did not install: " + fuzzCase);

            // Invariant 4: the instance is sized from exactly the capacity the parser resolved.
            short capacity = expected.shortValue();
            short recordCount = (short) (capacity + 1);
            assertEquals(
                    capacity,
                    logic().activeRuleCapacity(),
                    () -> "The instance reports a different capacity than the parser resolved for "
                            + fuzzCase);
            assertEquals(
                    recordCount * RECORD_SIZE,
                    field("recordArena").length,
                    () -> "The arena is not sized from the resolved capacity for " + fuzzCase);
            assertEquals(
                    (recordCount + 7) / 8,
                    field("activeBitmap").length,
                    () -> "The bitmap is not sized from the resolved capacity for " + fuzzCase);
        }

        assertTrue(refused > 0, "the sampled corpus must exercise the failed-install path");
        assertTrue(installed > 0, "the sampled corpus must exercise the successful-install path");
    }

    /**
     * Named regression for the clamp, as a property rather than the two examples
     * {@code InstallParametersTest} already pins.
     *
     * <p>Every encodable capacity byte is walked, so the boundary cannot be missed by sampling:
     * {@code 0} must be refused, {@code 1..64} honoured exactly, {@code 65..255} clamped to the
     * compiled maximum. The clamp matters because it is the one place this parser deliberately does
     * <em>not</em> fail loudly — silently honouring an oversized request would over-allocate EEPROM
     * on a card that cannot spare it, and refusing it would strand an operator whose provisioning
     * script asks for more than this build supports.
     */
    @Test
    void everyEncodableCapacityByteIsRefusedHonouredOrClamped() {
        for (int requested = 0; requested <= 0xFF; requested++) {
            byte[] installData = installArray(capacityParameter(requested));
            final int value = requested;

            if (requested == 0) {
                ISOException refusal =
                        assertThrows(
                                ISOException.class,
                                () ->
                                        AraMJCApplet.resolveActiveRuleCapacity(
                                                installData, (short) 0, (byte) installData.length),
                                "a zero capacity must be refused, not clamped up");
                assertEquals(0x6A80, refusal.getReason() & 0xFFFF);
                continue;
            }

            short resolved =
                    AraMJCApplet.resolveActiveRuleCapacity(
                            installData, (short) 0, (byte) installData.length);
            short expected =
                    requested > AraMApplet.MAX_ACTIVE_RULE_CAPACITY
                            ? AraMApplet.MAX_ACTIVE_RULE_CAPACITY
                            : (short) requested;
            assertEquals(expected, resolved, () -> "Capacity byte " + value + " resolved wrongly");
        }
    }

    /**
     * Named regression against the failure mode this harness exists to prevent: a malformed block
     * that is tolerated and silently yields the default.
     *
     * <p>An absent application-specific block legitimately means "use the default", so
     * {@code DEFAULT_ACTIVE_RULE_CAPACITY} is a correct answer for exactly one input shape. For a
     * block that is present but malformed it is the <em>wrong</em> answer, and an especially
     * dangerous one, because it looks like a successful install. Each case below carries a
     * capacity request that is present and corrupt; none may come back as the default.
     */
    @Test
    void aPresentButMalformedBlockNeverSilentlyYieldsTheDefaultCapacity() {
        List<byte[]> malformedBlocks = new ArrayList<byte[]>();
        // Right tag, wrong value width.
        malformedBlocks.add(hex("800230"));
        malformedBlocks.add(hex("8000"));
        // Truncated capacity TLV.
        malformedBlocks.add(hex("8001"));
        malformedBlocks.add(hex("80"));
        // Unknown parameter tag carrying a plausible capacity.
        malformedBlocks.add(hex("810130"));
        malformedBlocks.add(hex("000130"));
        // Trailing bytes after a complete capacity TLV.
        malformedBlocks.add(hex("80013000"));
        malformedBlocks.add(hex("801030"));
        // C9 container whose length disagrees with its content.
        malformedBlocks.add(hex("C90480013000"));
        malformedBlocks.add(hex("C902800130"));
        malformedBlocks.add(hex("C9FF800130"));
        // C9 container with a zero capacity inside.
        malformedBlocks.add(hex("C903800100"));

        for (byte[] block : malformedBlocks) {
            byte[] installData = installArray(block);
            FuzzCase malformedCase = new FuzzCase("malformed-block:" + hexOf(block), installData, 0);

            ISOException refusal =
                    assertThrows(
                            ISOException.class,
                            () ->
                                    AraMJCApplet.resolveActiveRuleCapacity(
                                            installData, (short) 0, (byte) installData.length),
                            () ->
                                    "A present-but-malformed block was tolerated instead of"
                                            + " failing loudly: "
                                            + malformedCase);
            assertEquals(
                    0x6A80,
                    refusal.getReason() & 0xFFFF,
                    () -> "Unexpected refusal status word for " + malformedCase);

            // And it must not install.
            simulator = new ExposedCardSimulator();
            assertThrows(
                    SystemException.class,
                    () ->
                            simulator.installApplet(
                                    appletAid,
                                    AraMJCApplet.class,
                                    installData,
                                    (short) 0,
                                    (byte) installData.length),
                    () -> "A malformed block still installed: " + malformedCase);
            assertFalse(
                    simulator.isInstalled(appletAid),
                    () -> "An instance survived a malformed block: " + malformedCase);
        }
    }

    /**
     * The over-acceptance gate: the whole corpus's accept/reject verdict, pinned.
     *
     * <p>Every other test here is an <em>upper</em> bound on what the parser may do — if it
     * accepts, the capacity must be in range; if it rejects, nothing may install. None of them is a
     * <em>lower</em> bound, so a parser that gradually stops rejecting things stays green. That is
     * not hypothetical: relaxing {@code resolveActiveRuleCapacity}'s "no parameters length byte"
     * refusal into a {@code return DEFAULT_ACTIVE_RULE_CAPACITY} — a one-line edit a maintainer
     * might well reach for, given the neighbouring comment already tolerates trailing bytes — moves
     * twenty cases from rejected to accepted and every other assertion in this class still passes.
     * A silently defaulted capacity is exactly the failure this harness exists to catch.
     *
     * <p>So the corpus's decision is itself the assertion. Cases run in a fixed order, each in both
     * buffer shapes, and each execution contributes either {@code A<capacity>} or
     * {@code R<statusWord>} to a vector that is counted, histogrammed and digested. Any verdict
     * that flips in either direction changes the summary and fails the build.
     *
     * <p><b>When this fails.</b> It is not a flake and there is no correct way to "just re-run" it.
     * Either the parser changed its mind about an input — in which case decide whether that change
     * is intended and, if it is, re-pin the constant in the same commit as the parser change — or
     * the corpus construction changed, in which case re-pin and say so. The failure message prints
     * the observed summary ready to paste. Never re-pin to make red go green without naming which
     * inputs moved and why.
     *
     * <p>Only meaningful for the committed corpus, so a soak run under {@code -Param.fuzz.seed} or
     * {@code -Param.fuzz.mutants} skips it rather than failing on a corpus it was never pinned to.
     *
     * <p><b>Diagnostics.</b> A summary line and a digest can only say <em>that</em> something moved,
     * which leaves "identify which inputs moved" as an unaided manual bisect against an opaque
     * hash — in practice an invitation to re-pin the constant and move on, which is the one thing
     * this test asks you not to do. So the per-execution verdicts are pinned too, in
     * {@code {@value #GOLDEN_DECISIONS_RESOURCE}}, and the failure names the first
     * {@value #REPORTED_DECISION_DIFFERENCES} cases that changed their mind, with the label that
     * reproduces each one. The full observed vector is written to
     * {@code build/reports/install-fuzz-observed-decisions.txt} ready to be copied over the
     * resource once the movement is understood and intended.
     */
    @Test
    void theCorpusAcceptRejectDecisionMatchesItsPinnedGoldenVector() {
        assumeTrue(
                CORPUS_SEED == DEFAULT_CORPUS_SEED && MUTANTS_PER_SEED == DEFAULT_MUTANTS_PER_SEED,
                "The golden vector is pinned to the committed corpus; a soak run has its own shape");

        List<FuzzCase> corpus = buildCorpus();
        StringBuilder decisionVector = new StringBuilder();
        List<String> decisions = new ArrayList<String>();
        TreeMap<Integer, Integer> capacities = new TreeMap<Integer, Integer>();
        TreeMap<Integer, Integer> statusWords = new TreeMap<Integer, Integer>();
        int accepted = 0;
        int rejected = 0;
        int executions = 0;

        for (FuzzCase fuzzCase : corpus) {
            for (boolean tightBuffer : new boolean[] {false, true}) {
                PaddedInput input =
                        tightBuffer
                                ? PaddedInput.tight(fuzzCase.installData)
                                : PaddedInput.wrap(fuzzCase.installData, fuzzCase.padOffset);
                executions++;
                String verdict;
                try {
                    short capacity =
                            AraMJCApplet.resolveActiveRuleCapacity(
                                    input.buffer, input.offset, input.length);
                    accepted++;
                    increment(capacities, capacity);
                    verdict = "A" + capacity;
                } catch (ISOException refusal) {
                    int statusWord = refusal.getReason() & 0xFFFF;
                    rejected++;
                    increment(statusWords, statusWord);
                    verdict = "R" + hexOf(statusWord);
                }
                decisionVector.append(verdict).append(',');
                decisions.add(
                        verdict
                                + " "
                                + fuzzCase.label
                                + (tightBuffer ? " [tight]" : " [padded]"));
            }
        }

        String observed =
                "cases="
                        + corpus.size()
                        + " executions="
                        + executions
                        + " accepted="
                        + accepted
                        + " rejected="
                        + rejected
                        + " capacities="
                        + renderDecimalHistogram(capacities)
                        + " statusWords="
                        + renderHistogram(statusWords)
                        + " digest="
                        + sha256Of(decisionVector.toString());

        String observedPath = writeObservedDecisions(decisions);
        String differences =
                describeDecisionDifferences(loadGoldenDecisions(), decisions, observedPath);
        if (differences != null) {
            fail(differences);
        }

        assertEquals(
                GOLDEN_DECISION_SUMMARY,
                observed,
                "The corpus changed its accept/reject verdict. Identify which inputs moved and why"
                        + " before re-pinning GOLDEN_DECISION_SUMMARY to:\n"
                        + observed);
    }

    /**
     * Names the cases whose verdict moved, or {@code null} when the vectors agree.
     *
     * <p>Reports at most {@value #REPORTED_DECISION_DIFFERENCES} of them: enough to see whether one
     * shape family moved or the corpus construction shifted wholesale, without burying that signal
     * in hundreds of lines when every case shifts by one position.
     */
    private static String describeDecisionDifferences(
            List<String> golden, List<String> observed, String observedPath) {
        StringBuilder report = new StringBuilder();
        int shared = Math.min(golden.size(), observed.size());
        int differing = 0;
        for (int index = 0; index < shared; index++) {
            if (golden.get(index).equals(observed.get(index))) {
                continue;
            }
            differing++;
            if (differing <= REPORTED_DECISION_DIFFERENCES) {
                report.append("\n  #")
                        .append(index)
                        .append("  was ")
                        .append(golden.get(index))
                        .append("\n      now ")
                        .append(observed.get(index));
            }
        }
        if (differing == 0 && golden.size() == observed.size()) {
            return null;
        }

        StringBuilder message = new StringBuilder();
        message.append("The corpus changed its accept/reject verdict per case.");
        if (golden.size() != observed.size()) {
            message.append("\nThe corpus itself changed shape: pinned ")
                    .append(golden.size())
                    .append(" executions, ran ")
                    .append(observed.size())
                    .append(". Verdict positions below are only comparable up to the shorter one.");
        }
        message.append("\n")
                .append(differing)
                .append(" of ")
                .append(shared)
                .append(" comparable executions moved");
        if (differing > REPORTED_DECISION_DIFFERENCES) {
            message.append("; first ").append(REPORTED_DECISION_DIFFERENCES).append(" shown");
        }
        message.append(':').append(report);
        message.append("\n\nEach line is <verdict> <case label> <buffer shape>; the label"
                        + " reproduces the case from the pinned seed. Decide whether the movement"
                        + " is intended, then copy\n  ")
                .append(observedPath)
                .append("\nover src/test/resources/")
                .append(GOLDEN_DECISIONS_RESOURCE)
                .append(" in the same commit as the parser change.");
        return message.toString();
    }

    private static List<String> loadGoldenDecisions() {
        InputStream stream =
                AraMInstallParameterFuzzTest.class
                        .getClassLoader()
                        .getResourceAsStream(GOLDEN_DECISIONS_RESOURCE);
        if (stream == null) {
            fail(
                    "Missing pinned decision vector "
                            + GOLDEN_DECISIONS_RESOURCE
                            + ". The observed vector has been written to"
                            + " build/reports/install-fuzz-observed-decisions.txt; copy it into"
                            + " src/test/resources/ once you are satisfied it is correct.");
        }
        List<String> decisions = new ArrayList<String>();
        BufferedReader reader =
                new BufferedReader(new InputStreamReader(stream, StandardCharsets.UTF_8));
        try {
            String line = reader.readLine();
            while (line != null) {
                String trimmed = line.trim();
                if (!trimmed.isEmpty() && !trimmed.startsWith("#")) {
                    decisions.add(trimmed);
                }
                line = reader.readLine();
            }
        } catch (IOException failure) {
            throw new UncheckedIOException(failure);
        } finally {
            try {
                reader.close();
            } catch (IOException ignored) {
                // Nothing useful to do while closing a classpath resource.
            }
        }
        return decisions;
    }

    /** Writes the observed vector next to the build reports so a re-pin is a copy, not a retype. */
    private static String writeObservedDecisions(List<String> decisions) {
        Path path = Paths.get("build", "reports", "install-fuzz-observed-decisions.txt");
        try {
            Files.createDirectories(path.getParent());
            Files.write(path, decisions, StandardCharsets.UTF_8);
        } catch (IOException failure) {
            throw new UncheckedIOException(failure);
        }
        return path.toAbsolutePath().toString();
    }

    /**
     * Named regression for the outer-guard half of the same over-acceptance risk.
     *
     * <p>{@link #aPresentButMalformedBlockNeverSilentlyYieldsTheDefaultCapacity()} covers blocks
     * that are present and corrupt. It does not cover an array that ends <em>before</em> the
     * application-specific block starts, which is the shape a truncated APDU produces and the one a
     * relaxed "no parameters length byte" refusal would silently default. Every prefix of a
     * well-formed array that stops short of the parameters length byte must be refused, so the
     * default capacity can never be reached by losing bytes off the end.
     *
     * <p>The bare {@code C9} block is folded in here rather than given its own test: it is the same
     * class of defect one nesting level deeper — a container tag that is the last byte of the
     * block, so the length that would bound it never arrives.
     */
    @Test
    void anInstallArrayTruncatedBeforeTheParameterBlockIsRejectedRatherThanDefaulted() {
        byte[] wellFormed = installArray(capacityParameter(48));
        // The two leading LV fields: instance AID (1 + 9) and privileges (1 + 1). Every prefix from
        // one byte up to and including that point lacks the parameters length byte.
        int prefixLimit = 1 + ARA_M_AID.length + 1 + PRIVILEGES.length;

        List<byte[]> truncated = new ArrayList<byte[]>();
        for (int length = 1; length <= prefixLimit; length++) {
            truncated.add(Arrays.copyOf(wellFormed, length));
        }
        // A container tag with no length byte behind it, at the end of an otherwise sound array.
        truncated.add(installArray(hex("C9")));

        for (byte[] installData : truncated) {
            FuzzCase truncatedCase =
                    new FuzzCase("truncated:" + installData.length + "B", installData, 0);

            ISOException refusal =
                    assertThrows(
                            ISOException.class,
                            () ->
                                    AraMJCApplet.resolveActiveRuleCapacity(
                                            installData, (short) 0, (byte) installData.length),
                            () ->
                                    "A truncated install array was tolerated instead of failing"
                                            + " loudly: "
                                            + truncatedCase);
            assertEquals(
                    0x6A80,
                    refusal.getReason() & 0xFFFF,
                    () -> "Unexpected refusal status word for " + truncatedCase);

            simulator = new ExposedCardSimulator();
            assertThrows(
                    SystemException.class,
                    () ->
                            simulator.installApplet(
                                    appletAid,
                                    AraMJCApplet.class,
                                    installData,
                                    (short) 0,
                                    (byte) installData.length),
                    () -> "A truncated install array still installed: " + truncatedCase);
            assertFalse(
                    simulator.isInstalled(appletAid),
                    () -> "An instance survived a truncated install array: " + truncatedCase);
        }
    }

    /**
     * The defensive guards at the head of the parser, which the corpus cannot reach.
     *
     * <p>Mutation and truncation only ever produce well-formed <em>arguments</em> — a real array, a
     * small non-negative offset, a length that matches. These four branches guard against a caller
     * that is itself wrong rather than against a malformed parameter block, so they are reachable
     * only by calling the parser directly. They are worth pinning anyway: on a card the arguments
     * come from the JCRE, and "the JCRE would never do that" is exactly the assumption that makes
     * a missing check invisible until some Security Domain does do that.
     */
    @Test
    void theCallerFacingGuardsRejectRatherThanTrustTheirArguments() {
        byte[] wellFormed = installArray(capacityParameter(32));

        // A null array with a non-zero declared length.
        assertEquals(
                0x6A80,
                refusalReasonOf(null, (short) 0, (byte) 4),
                "a null install array must be refused, not dereferenced");

        // A negative offset.
        assertEquals(
                0x6A80,
                refusalReasonOf(wellFormed, (short) -1, (byte) wellFormed.length),
                "a negative offset must be refused");

        // A declared length running past the end of the array.
        assertEquals(
                0x6A80,
                refusalReasonOf(wellFormed, (short) 0, (byte) (wellFormed.length + 1)),
                "a length overrunning the array must be refused");

        // An offset high enough that offset + length wraps the short.
        assertEquals(
                0x6A80,
                refusalReasonOf(wellFormed, (short) 32760, (byte) 100),
                "an offset+length that wraps the short must be refused");

        // A zero declared length is the documented "no parameters" case, not an error.
        assertEquals(
                AraMApplet.DEFAULT_ACTIVE_RULE_CAPACITY,
                AraMJCApplet.resolveActiveRuleCapacity(wellFormed, (short) 0, (byte) 0),
                "a zero length means an absent block, which yields the default");
    }

    /** The 6A80 reason of a refusal, failing the test if the call did not refuse at all. */
    private static int refusalReasonOf(byte[] installData, short offset, byte length) {
        ISOException refusal =
                assertThrows(
                        ISOException.class,
                        () -> AraMJCApplet.resolveActiveRuleCapacity(installData, offset, length),
                        "the parser accepted arguments it should have refused");
        return refusal.getReason() & 0xFFFF;
    }

    // -------------------------------------------------------------------------------------------
    // Corpus construction
    // -------------------------------------------------------------------------------------------

    private static List<FuzzCase> buildCorpus() {
        Random rng = new Random(CORPUS_SEED);
        List<FuzzCase> corpus = new ArrayList<FuzzCase>();

        // Well-formed seeds across the shapes a real Security Domain produces.
        List<byte[]> blocks = new ArrayList<byte[]>();
        blocks.add(new byte[0]); // absent block: the documented default
        blocks.add(capacityParameter(1)); // smallest
        blocks.add(capacityParameter(16)); // the default, stated explicitly
        blocks.add(capacityParameter(17)); // one over the default
        blocks.add(capacityParameter(64)); // the compiled maximum
        blocks.add(capacityParameter(65)); // one over: must clamp
        blocks.add(capacityParameter(255)); // largest encodable: must clamp
        blocks.add(wrapInC9(capacityParameter(48))); // still in its C9 container
        blocks.add(wrapInC9(new byte[0])); // empty C9 container
        blocks.add(wrapInC9(capacityParameter(64)));

        int seedIndex = 0;
        for (byte[] block : blocks) {
            addFamily(corpus, rng, "block[" + seedIndex + "]", installArray(block));
            seedIndex++;
        }

        corpus.addAll(degenerateCases());
        return corpus;
    }

    private static void addFamily(
            List<FuzzCase> corpus, Random rng, String origin, byte[] installData) {
        corpus.add(new FuzzCase(origin, installData, rng.nextInt(4)));
        for (int index = 0; index < MUTANTS_PER_SEED; index++) {
            Mutation mutation = Mutation.values()[index % Mutation.values().length];
            byte[] mutant = mutation.apply(installData, rng);
            if (mutant == null || mutant.length == 0 || mutant.length > 255) {
                continue;
            }
            corpus.add(new FuzzCase(origin + "/" + mutation + "#" + index, mutant, rng.nextInt(4)));
        }
    }

    /** Boundary shapes no mutator would reliably produce. */
    private static List<FuzzCase> degenerateCases() {
        List<FuzzCase> cases = new ArrayList<FuzzCase>();
        cases.add(new FuzzCase("degenerate:empty", new byte[0], 0));
        cases.add(new FuzzCase("degenerate:single-zero", hex("00"), 1));
        cases.add(new FuzzCase("degenerate:single-FF", hex("FF"), 2));
        // The three LV fields, each claiming more than the array holds.
        cases.add(new FuzzCase("degenerate:aid-overruns", hex("FF00"), 0));
        cases.add(new FuzzCase("degenerate:privileges-overrun", hex("00FF"), 1));
        cases.add(new FuzzCase("degenerate:parameters-overrun", hex("0000FF"), 2));
        // Well-formed prefix, no parameter length byte at all.
        cases.add(new FuzzCase("degenerate:no-parameter-length", hex("0000"), 3));
        cases.add(new FuzzCase("degenerate:empty-everything", hex("000000"), 0));
        // A capacity TLV that forgot its container length.
        cases.add(new FuzzCase("degenerate:bare-capacity-tlv", hex("800130"), 1));
        // Maximum-length parameter block of a single repeated byte.
        cases.add(new FuzzCase("degenerate:long-run-80", filled(200, (byte) 0x80), 0));
        cases.add(new FuzzCase("degenerate:long-run-C9", filled(200, (byte) 0xC9), 0));
        cases.add(new FuzzCase("degenerate:long-run-00", filled(200, (byte) 0x00), 0));
        return cases;
    }

    /** The same deterministic mutation strategies the personalization harness uses. */
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
                        mutant[index] = (byte) 0xFF;
                        break;
                    default:
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

    // -------------------------------------------------------------------------------------------
    // Invariant machinery
    // -------------------------------------------------------------------------------------------

    /** Status word of the most recent rejection, for the histogram. */
    private int lastStatusWord;

    /**
     * Drives the parser once and enforces invariant 1.
     *
     * @return the resolved capacity, or {@code null} when the block was rejected
     */
    private Short attemptResolve(FuzzCase fuzzCase, PaddedInput input) {
        try {
            return Short.valueOf(
                    AraMJCApplet.resolveActiveRuleCapacity(
                            input.buffer, input.offset, input.length));
        } catch (ISOException rejected) {
            lastStatusWord = rejected.getReason() & 0xFFFF;
            return null;
        } catch (Throwable unexpected) {
            fail(
                    "Install-parameter parsing threw "
                            + unexpected.getClass().getName()
                            + " instead of ISOException for "
                            + fuzzCase,
                    unexpected);
            throw new AssertionError("unreachable");
        }
    }

    // -------------------------------------------------------------------------------------------
    // Fixtures and small helpers
    // -------------------------------------------------------------------------------------------

    /** JCRE installation parameter array: instance AID, privileges, app-specific block. */
    private static byte[] installArray(byte[] applicationSpecificParameters) {
        return concat(
                concat(lengthValue(ARA_M_AID), lengthValue(PRIVILEGES)),
                lengthValue(applicationSpecificParameters));
    }

    private static byte[] lengthValue(byte[] value) {
        return concat(new byte[] {(byte) value.length}, value);
    }

    private static byte[] capacityParameter(int capacity) {
        return new byte[] {AraMJCApplet.TAG_ACTIVE_RULE_CAPACITY, (byte) 0x01, (byte) capacity};
    }

    private static byte[] wrapInC9(byte[] value) {
        return concat(new byte[] {(byte) 0xC9, (byte) value.length}, value);
    }

    private byte[] field(String name) {
        try {
            Field declared = AraMApplet.class.getDeclaredField(name);
            declared.setAccessible(true);
            return (byte[]) declared.get(logic());
        } catch (ReflectiveOperationException failure) {
            throw new AssertionError("Could not read " + name, failure);
        }
    }

    private AraMApplet logic() {
        try {
            AraMJCApplet applet = (AraMJCApplet) simulator.applet(appletAid);
            Field logicField = AraMJCApplet.class.getDeclaredField("logic");
            logicField.setAccessible(true);
            return (AraMApplet) logicField.get(applet);
        } catch (ReflectiveOperationException failure) {
            throw new AssertionError("Could not reach the catalog logic", failure);
        }
    }

    private static byte[] filled(int length, byte value) {
        byte[] result = new byte[length];
        Arrays.fill(result, value);
        return result;
    }

    private static byte[] concat(byte[] left, byte[] right) {
        ByteArrayOutputStream output = new ByteArrayOutputStream(left.length + right.length);
        output.write(left, 0, left.length);
        output.write(right, 0, right.length);
        return output.toByteArray();
    }

    private static byte[] hex(String value) {
        byte[] result = new byte[value.length() / 2];
        for (int index = 0; index < result.length; index++) {
            result[index] = (byte) Integer.parseInt(value.substring(index * 2, index * 2 + 2), 16);
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

    /** Histogram of decimal keys, for the accepted-capacity spread. */
    private static String renderDecimalHistogram(TreeMap<Integer, Integer> histogram) {
        StringBuilder text = new StringBuilder("{");
        boolean first = true;
        for (java.util.Map.Entry<Integer, Integer> entry : histogram.entrySet()) {
            if (!first) {
                text.append(", ");
            }
            text.append(entry.getKey()).append('=').append(entry.getValue());
            first = false;
        }
        return text.append('}').toString();
    }

    private static String sha256Of(String value) {
        try {
            byte[] digest =
                    MessageDigest.getInstance("SHA-256")
                            .digest(value.getBytes(StandardCharsets.UTF_8));
            return hexOf(digest).toLowerCase(java.util.Locale.ROOT);
        } catch (NoSuchAlgorithmException impossible) {
            throw new AssertionError("SHA-256 is mandatory on every JRE", impossible);
        }
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

    /** One reproducible corpus entry. */
    private static final class FuzzCase {
        private final String label;
        private final byte[] installData;
        private final int padOffset;

        private FuzzCase(String label, byte[] installData, int padOffset) {
            this.label = label;
            this.installData = installData;
            this.padOffset = padOffset;
        }

        @Override
        public String toString() {
            return label + " [" + hexOf(installData) + "]";
        }
    }

    /**
     * The parameter array at an offset inside a larger buffer, and the same array with no slack.
     *
     * <p>The tight shape is the one that tests the parser's bounds arithmetic. With trailing
     * padding a read past the declared end returns a guard byte instead of throwing, which is
     * exactly how the personalization harness was found to be laundering over-reads into
     * clean-looking rejections. The JCRE hands {@code install()} an array sized to the parameter
     * block, so the tight shape is also the realistic one — do not drop it.
     */
    private static final class PaddedInput {
        private final byte[] buffer;
        private final byte[] expected;
        private final short offset;
        private final byte length;

        private PaddedInput(byte[] buffer, short offset, byte length) {
            this.buffer = buffer;
            this.expected = buffer.clone();
            this.offset = offset;
            this.length = length;
        }

        static PaddedInput wrap(byte[] installData, int padOffset) {
            int lead = padOffset * 3;
            byte[] buffer = new byte[lead + installData.length + 5];
            Arrays.fill(buffer, (byte) 0xA5);
            System.arraycopy(installData, 0, buffer, lead, installData.length);
            return new PaddedInput(buffer, (short) lead, (byte) installData.length);
        }

        static PaddedInput tight(byte[] installData) {
            return new PaddedInput(installData.clone(), (short) 0, (byte) installData.length);
        }
    }

    private static final class ExposedCardSimulator extends CardSimulator {

        Applet applet(AID aid) {
            return runtime.lookupApplet(aid).getApplet();
        }

        boolean isInstalled(AID aid) {
            return runtime.lookupApplet(aid) != null;
        }
    }
}
