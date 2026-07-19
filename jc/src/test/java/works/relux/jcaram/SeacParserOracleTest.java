package works.relux.jcaram;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.licel.jcardsim.smartcardio.CardSimulator;
import com.licel.jcardsim.utils.AIDUtil;
import com.payneteasy.tlv.BerTlvBuilder;
import javacard.framework.AID;
import javacard.framework.Applet;
import java.io.ByteArrayOutputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import org.globalplatform.Application;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import pro.javacard.gp.SEAccessControl;

/**
 * Decodes the applet's GET DATA [FF40] + [FF60] stream with GlobalPlatformPro's
 * {@code pro.javacard.gp.SEAccessControl}, an unrelated third-party SEAC implementation, and
 * asserts that the recovered rule set equals the provisioned one.
 *
 * <p>{@link AraMAppletTest} compares the stream against byte arrays this repository builds
 * itself, so a systematic encoding mistake would be invisible there: the expectation and the
 * applet would be wrong in exactly the same way. This class deliberately keeps its own tiny
 * fixture helpers instead of sharing them with that test, so the oracle path shares no encoding
 * assumption with the path it validates. The only shared bytes are the REF-AR-DOs we provision,
 * which are the input to both sides.
 *
 * <p>The dependency is {@code testImplementation} only. The CAP is converted from
 * {@code src/main/java} plus the {@code globalPlatformApi} configuration, so nothing here can
 * reach the card; {@code verifyCapDependenciesAreMinimal} in build.gradle keeps that true.
 *
 * <p>Two limitations of the oracle, both from reading GlobalPlatformPro 19.06.16:
 *
 * <ul>
 *   <li>Its {@code AR-DO} model holds only APDU-AR-DO (D0) and NFC-AR-DO (D1). A PERM-AR-DO (DB)
 *       member is dropped silently on parse, so rules carrying one are deliberately not routed
 *       through this oracle - it would report a false mismatch rather than a real one.
 *   <li>Its {@code getAcrListData} continuation branch copies into {@code previousData.getData()},
 *       which is a defensive copy, so FF60 chunks are discarded. We therefore reassemble chunks
 *       the way a host does and use that method only for its first-response length decode.
 * </ul>
 */
final class SeacParserOracleTest {

    private static final String ARA_M_AID_HEX = "A00000015141434C00";

    private static final byte[] PERMISSIVE_ALLOW_REF_AR_DO =
            hex("E211E10A4F06F0000000AA01C100E303D00101");
    private static final byte[] PERMISSIVE_DENY_REF_AR_DO =
            hex("E211E10A4F06F0000000AA01C100E303D00100");
    private static final byte[] SHA1_CERT_BOUND_REF_AR_DO =
            hex(
                    "E225"
                            + "E11E"
                            + "4F06F0000000AA01"
                            + "C114000102030405060708090A0B0C0D0E0F10111213"
                            + "E303D00101");
    private static final byte[] SHA256_CERT_BOUND_REF_AR_DO =
            hex(
                    "E231"
                            + "E12A"
                            + "4F06F0000000AA01"
                            + "C120000102030405060708090A0B0C0D0E0F10111213"
                            + "1415161718191A1B1C1D1E1F"
                            + "E303D00101");

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
    void emptyCatalogDecodesToNoRulesThroughTheIndependentParser() throws Exception {
        CatalogRead read = readCatalogStream();

        assertEquals("FF4000", toHex(read.stream));
        assertEquals(Collections.emptyList(), decodeRefArDos(read.stream));
    }

    @Test
    void mixedRuleShapesRoundTripThroughTheIndependentParser() throws Exception {
        List<byte[]> provisioned =
                provision(
                        PERMISSIVE_ALLOW_REF_AR_DO,
                        SHA1_CERT_BOUND_REF_AR_DO,
                        SHA256_CERT_BOUND_REF_AR_DO);

        CatalogRead read = readCatalogStream();

        assertEquals(1, read.responseCount, "This catalog must fit one FF40 response");
        assertRecovers(provisioned, read);
    }

    @Test
    void shortFormCatalogLengthDecodesThroughTheIndependentParser() throws Exception {
        List<byte[]> provisioned = provisionCatalogOfLength(127);

        CatalogRead read = readCatalogStream();

        assertEquals("FF407F", toHex(Arrays.copyOf(read.stream, 3)));
        assertEquals(127, gpDeclaredCatalogLength(read.firstResponse));
        assertRecovers(provisioned, read);
    }

    @Test
    void form81CatalogLengthDecodesThroughTheIndependentParser() throws Exception {
        List<byte[]> provisioned = provisionCatalogOfLength(128);

        CatalogRead read = readCatalogStream();

        assertEquals("FF408180", toHex(Arrays.copyOf(read.stream, 4)));
        assertEquals(128, gpDeclaredCatalogLength(read.firstResponse));
        assertRecovers(provisioned, read);
    }

    @Test
    void form81UpperBoundCatalogLengthDecodesThroughTheIndependentParser() throws Exception {
        List<byte[]> provisioned = provisionCatalogOfLength(255);

        CatalogRead read = readCatalogStream();

        assertEquals("FF4081FF", toHex(Arrays.copyOf(read.stream, 4)));
        assertEquals(255, gpDeclaredCatalogLength(read.firstResponse));
        assertTrue(read.responseCount > 1, "A 255-byte catalog cannot fit one response");
        assertRecovers(provisioned, read);
    }

    @Test
    void form82CatalogLengthDecodesThroughTheIndependentParser() throws Exception {
        List<byte[]> provisioned = provisionCatalogOfLength(256);

        CatalogRead read = readCatalogStream();

        assertEquals("FF40820100", toHex(Arrays.copyOf(read.stream, 5)));
        assertEquals(256, gpDeclaredCatalogLength(read.firstResponse));
        assertTrue(read.responseCount > 1, "A 256-byte catalog cannot fit one response");
        assertRecovers(provisioned, read);
    }

    @Test
    void multiChunkFf60SequenceReassemblesIntoTheProvisionedRuleSet() throws Exception {
        List<byte[]> provisioned = new ArrayList<byte[]>();
        for (short index = (short) 0; index < AraMApplet.ACTIVE_RULE_CAPACITY; index++) {
            provisioned.add(largeRule(index));
        }
        provision(provisioned.toArray(new byte[0][]));

        CatalogRead read = readCatalogStream();

        assertTrue(
                read.responseCount >= 4,
                "A full catalog of large rules must span several FF60 responses, was "
                        + read.responseCount);
        assertEquals(0x82, read.stream[2] & 0xFF, "A full catalog must use the 82 length form");
        assertEquals(read.catalogLength, gpDeclaredCatalogLength(read.firstResponse));
        assertRecovers(provisioned, read);
    }

    @Test
    void independentParserRecoversTheApduRuleSemantics() throws Exception {
        provision(PERMISSIVE_ALLOW_REF_AR_DO);
        String allow = decodeRefArDos(readCatalogStream().stream).get(0).toString();

        provision(PERMISSIVE_DENY_REF_AR_DO);
        String deny = decodeRefArDos(readCatalogStream().stream).get(0).toString();

        assertTrue(allow.contains("F0000000AA01"), "AID must survive the round trip: " + allow);
        assertTrue(allow.contains("ALWAYS"), "Allow rule must decode as ALWAYS: " + allow);
        assertTrue(deny.contains("NEVER"), "Deny rule must decode as NEVER: " + deny);
    }

    @Test
    void independentParserRecoversTheCertificateHash() throws Exception {
        provision(SHA1_CERT_BOUND_REF_AR_DO);

        String recovered = decodeRefArDos(readCatalogStream().stream).get(0).toString();

        assertTrue(
                recovered.contains("000102030405060708090A0B0C0D0E0F10111213"),
                "Hash-REF-DO must survive the round trip: " + recovered);
    }

    @Test
    void understatedCatalogLengthIsRejectedByTheIndependentParser() throws Exception {
        List<byte[]> provisioned = provision(PERMISSIVE_ALLOW_REF_AR_DO, SHA1_CERT_BOUND_REF_AR_DO);
        CatalogRead read = readCatalogStream();

        byte[] corrupted = read.stream.clone();
        corrupted[2] = (byte) ((corrupted[2] & 0xFF) - 1);

        assertNotEquals(
                sortedHex(provisioned),
                decodeQuietly(corrupted),
                "A wrong FF40 length must not decode back to the provisioned rule set");
    }

    @Test
    void truncatedCatalogStreamIsRejectedByTheIndependentParser() throws Exception {
        List<byte[]> provisioned = provision(PERMISSIVE_ALLOW_REF_AR_DO, SHA1_CERT_BOUND_REF_AR_DO);
        CatalogRead read = readCatalogStream();

        byte[] truncated = Arrays.copyOf(read.stream, read.stream.length - 4);

        assertNotEquals(
                sortedHex(provisioned),
                decodeQuietly(truncated),
                "A truncated stream must not decode back to the provisioned rule set");
    }

    /**
     * Parses the stream with GlobalPlatformPro, re-encodes every recovered rule through that same
     * third-party model, and compares the result with what we provisioned. Re-encoding, rather
     * than field inspection, keeps the assertion on GlobalPlatformPro's public API.
     */
    private void assertRecovers(List<byte[]> provisioned, CatalogRead read) throws Exception {
        List<SEAccessControl.RefArDo> recovered = decodeRefArDos(read.stream);

        assertEquals(
                provisioned.size(), recovered.size(), "Recovered rule count must match: " + recovered);
        assertEquals(sortedHex(provisioned), sortedHex(reencode(recovered)));
    }

    private static List<SEAccessControl.RefArDo> decodeRefArDos(byte[] stream) throws Exception {
        return SEAccessControl.AcrListResponse.fromBytes(stream).acrList;
    }

    /** Returns the sorted rule hexes, or {@code null} when the third-party parser rejects. */
    private static List<String> decodeQuietly(byte[] stream) {
        try {
            return sortedHex(reencode(decodeRefArDos(stream)));
        } catch (Exception rejected) {
            return null;
        }
    }

    private static List<byte[]> reencode(List<SEAccessControl.RefArDo> rules) {
        List<byte[]> encoded = new ArrayList<byte[]>(rules.size());
        for (SEAccessControl.RefArDo rule : rules) {
            encoded.add(new BerTlvBuilder().addBerTlv(rule.toTlv()).buildArray());
        }
        return encoded;
    }

    /** Runs GlobalPlatformPro's own FF40 length decoder over the first GET DATA response. */
    private static int gpDeclaredCatalogLength(byte[] firstResponse) throws Exception {
        return SEAccessControl.AcrListResponse.getAcrListData(null, firstResponse).getLength();
    }

    private List<byte[]> provision(byte[]... refArDos) {
        personalizeCommand(hex("F100"));
        List<byte[]> provisioned = new ArrayList<byte[]>(refArDos.length);
        for (byte[] refArDo : refArDos) {
            personalizeCommand(tlv((byte) 0xF0, refArDo));
            provisioned.add(refArDo);
        }
        return provisioned;
    }

    /**
     * Provisions rules whose REF-AR-DOs sum to exactly {@code totalLength}, so the FF40 header
     * lands on the intended BER length form.
     */
    private List<byte[]> provisionCatalogOfLength(int totalLength) {
        List<byte[]> rules = new ArrayList<byte[]>();
        int remaining = totalLength;
        short index = (short) 0;
        // Rules of 18 bytes (6-byte AID) until the tail, which absorbs the remainder with a
        // longer AID. AID lengths stay inside the 5..16 range the applet accepts.
        while (remaining > 28) {
            rules.add(ruleWithLength(index++, 18));
            remaining -= 18;
        }
        rules.add(ruleWithLength(index, remaining));
        assertEquals(totalLength, totalLength(rules), "Fixture must hit the requested length");
        return provision(rules.toArray(new byte[0][]));
    }

    private static int totalLength(List<byte[]> rules) {
        int total = 0;
        for (byte[] rule : rules) {
            total += rule.length;
        }
        return total;
    }

    private static byte[] ruleWithLength(short index, int recordLength) {
        int aidLength = recordLength - 13;
        if (aidLength < 5 || aidLength > 16) {
            throw new IllegalArgumentException("Unsupported test record length " + recordLength);
        }
        byte[] aid = new byte[aidLength];
        aid[0] = (byte) 0xF0;
        aid[aid.length - 1] = (byte) index;
        byte[] rule = ruleFor(aid, new byte[0]);
        assertEquals(recordLength, rule.length);
        return rule;
    }

    private static byte[] largeRule(short index) {
        byte[] aid = new byte[16];
        aid[0] = (byte) 0xF0;
        aid[15] = (byte) index;
        return ruleFor(aid, new byte[32]);
    }

    private static byte[] ruleFor(byte[] aid, byte[] deviceAppId) {
        byte[] refDo =
                tlv((byte) 0xE1, concat(tlv((byte) 0x4F, aid), tlv((byte) 0xC1, deviceAppId)));
        return tlv((byte) 0xE2, concat(refDo, hex("E303D00101")));
    }

    private void personalizeCommand(byte[] commandDo) {
        application.processData(commandDo, (short) 0, (short) commandDo.length);
    }

    /** Reassembles the FF40 response and every FF60 continuation exactly as a host would. */
    private CatalogRead readCatalogStream() {
        ResponseAPDU first = getData(0xFF, 0x40);
        assertEquals(0x9000, first.getSW());
        byte[] firstData = first.getData();
        assertTrue(firstData.length >= 3);

        int lengthOctets = berLengthOctets(firstData[2] & 0xFF);
        int headerLength = 2 + lengthOctets;
        int catalogLength = decodeBerLength(firstData);

        ByteArrayOutputStream stream = new ByteArrayOutputStream();
        stream.write(firstData, 0, firstData.length);
        int collected = firstData.length - headerLength;
        int responseCount = 1;

        while (collected < catalogLength) {
            ResponseAPDU next = getData(0xFF, 0x60);
            assertEquals(0x9000, next.getSW());
            byte[] chunk = next.getData();
            assertTrue(chunk.length > 0);
            stream.write(chunk, 0, chunk.length);
            collected += chunk.length;
            responseCount++;
        }

        assertEquals(catalogLength, collected, "Reassembled value must match the declared length");
        return new CatalogRead(stream.toByteArray(), catalogLength, responseCount, firstData);
    }

    private ResponseAPDU getData(int p1, int p2) {
        return simulator.transmitCommand(new CommandAPDU(0x80, 0xCA, p1, p2, 256));
    }

    private static int berLengthOctets(int first) {
        if (first <= 0x7F) {
            return 1;
        }
        if (first == 0x81) {
            return 2;
        }
        if (first == 0x82) {
            return 3;
        }
        throw new AssertionError("Unsupported BER length form " + first);
    }

    private static int decodeBerLength(byte[] encoded) {
        int first = encoded[2] & 0xFF;
        if (first <= 0x7F) {
            return first;
        }
        if (first == 0x81) {
            return encoded[3] & 0xFF;
        }
        return ((encoded[3] & 0xFF) << 8) | (encoded[4] & 0xFF);
    }

    private static List<String> sortedHex(List<byte[]> values) {
        List<String> hexes = new ArrayList<String>(values.size());
        for (byte[] value : values) {
            hexes.add(toHex(value));
        }
        Collections.sort(hexes);
        return hexes;
    }

    private static String toHex(byte[] value) {
        StringBuilder text = new StringBuilder(value.length * 2);
        for (byte item : value) {
            text.append(String.format("%02X", item & 0xFF));
        }
        return text.toString();
    }

    private static byte[] tlv(byte tag, byte[] value) {
        return concat(new byte[] {tag, (byte) value.length}, value);
    }

    private static byte[] concat(byte[] left, byte[] right) {
        byte[] result = Arrays.copyOf(left, left.length + right.length);
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

    private static final class CatalogRead {
        private final byte[] stream;
        private final int catalogLength;
        private final int responseCount;
        private final byte[] firstResponse;

        private CatalogRead(
                byte[] stream, int catalogLength, int responseCount, byte[] firstResponse) {
            this.stream = stream;
            this.catalogLength = catalogLength;
            this.responseCount = responseCount;
            this.firstResponse = firstResponse;
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
