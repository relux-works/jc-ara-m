package works.relux.jcaram;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.licel.jcardsim.smartcardio.CardSimulator;
import com.licel.jcardsim.utils.AIDUtil;
import javacard.framework.AID;
import javacard.framework.Applet;
import javacard.framework.ISOException;
import java.io.ByteArrayOutputStream;
import java.lang.reflect.Field;
import java.util.Arrays;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import org.globalplatform.Application;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * Deterministic simulator vectors for 32-byte (SHA-256) DeviceAppID references,
 * closing ledger item C9.
 *
 * <p>Physical CARD#5/Android runs already demonstrate SHA-256 grant and deny, but
 * that is a separate evidence layer. This class is the reproducible on-simulator
 * contract: a 32-byte DeviceAppID is stored and read back byte-exact, is replaced
 * and deleted only by its own exact REF-DO, publishes a new refresh tag on every
 * visible mutation, coexists with a SHA-1 rule for the same AID, and cannot be
 * malformed into the catalog.
 *
 * <p>Every rule here uses the plain {@code D0} APDU-AR-DO shape; the optional
 * PERM-AR-DO member is exercised by {@link AraMAppletTest}.
 *
 * <p>All hashes below are synthetic non-secret test vectors.
 */
final class Sha256VectorTest {

    private static final String ARA_M_AID_HEX = "A00000015141434C00";
    private static final byte[] APPLET_AID = hex("F0000000AA01");
    private static final byte[] OTHER_APPLET_AID = hex("F0000000BB01");

    private static final byte[] APDU_ALLOW_AR_DO_VALUE = hex("D00101");
    private static final byte[] APDU_DENY_AR_DO_VALUE = hex("D00100");

    /** SHA-1 width (20 octets), for the coexistence vector. */
    private static final byte[] SHA1_DEVICE_APP_ID =
            hex("000102030405060708090A0B0C0D0E0F10111213");

    /**
     * SHA-256 width (32 octets). Deliberately non-patterned and distinct from every
     * other fixture in the suite, so a byte-exact readback assertion cannot pass by
     * coincidentally matching some other stored value.
     */
    private static final byte[] SHA256_DEVICE_APP_ID =
            hex(
                    "A1B2C3D4E5F60718293A4B5C6D7E8F90"
                            + "0F1E2D3C4B5A69788796A5B4C3D2E1F0");

    /** Trailing octets of a rule after the DeviceAppID: {@code E3 03 D0 01 xx}. */
    private static final int AR_DO_TRAILER_LENGTH = 5;

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
    void sha256DeviceAppIdRuleIsStoredAndReadBackByteExact() {
        byte[] rule = ruleFor(APPLET_AID, SHA256_DEVICE_APP_ID, true);
        // E2 + len, E1 + len, 4F + len + 6 AID, C1 + len + 32 hash, E3 + len + 3.
        assertEquals(51, rule.length);
        byte[] refreshBeforeStore = getRefreshTag();

        personalize(rule);

        byte[] catalog = getAllRules();
        assertArrayEquals(allRules(rule), catalog);
        // The 32 octets survive storage verbatim rather than being truncated or
        // zero-padded to SHA-1 width.
        int hashEnd = catalog.length - AR_DO_TRAILER_LENGTH;
        assertArrayEquals(
                SHA256_DEVICE_APP_ID,
                Arrays.copyOfRange(catalog, hashEnd - SHA256_DEVICE_APP_ID.length, hashEnd));
        assertChanged(refreshBeforeStore, getRefreshTag());
    }

    @Test
    void sha256RuleIsReplacedByItsExactRefDoWithoutTouchingNeighbours() {
        byte[] neighbour = ruleFor(OTHER_APPLET_AID, new byte[0], true);
        byte[] sha256Allow = ruleFor(APPLET_AID, SHA256_DEVICE_APP_ID, true);
        personalize(neighbour);
        personalize(sha256Allow);
        byte[] refreshBeforeReplace = getRefreshTag();
        short revisionBeforeReplace = catalogRevision();

        byte[] sha256Deny = ruleFor(APPLET_AID, SHA256_DEVICE_APP_ID, false);
        personalize(sha256Deny);

        assertArrayEquals(allRules(neighbour, sha256Deny), getAllRules());
        assertChanged(refreshBeforeReplace, getRefreshTag());
        assertEquals((short) (revisionBeforeReplace + 1), catalogRevision());
    }

    @Test
    void aSha1RuleForTheSameAidIsNotReplacedByItsSha256Sibling() {
        byte[] sha1Rule = ruleFor(APPLET_AID, SHA1_DEVICE_APP_ID, true);
        byte[] sha256Rule = ruleFor(APPLET_AID, SHA256_DEVICE_APP_ID, false);
        personalize(sha1Rule);

        personalize(sha256Rule);

        // Same AID, different DeviceAppID width: two distinct keys, not an overwrite.
        assertArrayEquals(allRules(sha1Rule, sha256Rule), getAllRules());
    }

    @Test
    void everyVisibleSha256MutationPublishesANewRefreshTag() {
        byte[] allow = ruleFor(APPLET_AID, SHA256_DEVICE_APP_ID, true);
        byte[] deny = ruleFor(APPLET_AID, SHA256_DEVICE_APP_ID, false);

        byte[] refreshBeforeStore = getRefreshTag();
        personalize(allow);
        byte[] refreshAfterStore = getRefreshTag();
        personalize(deny);
        byte[] refreshAfterReplace = getRefreshTag();
        personalize(deny);
        byte[] refreshAfterIdenticalRetry = getRefreshTag();
        personalizeCommand(deleteByRefDo(refDoOf(deny)));
        byte[] refreshAfterDelete = getRefreshTag();

        assertChanged(refreshBeforeStore, refreshAfterStore);
        assertChanged(refreshAfterStore, refreshAfterReplace);
        // A byte-identical retry is not a visible mutation.
        assertArrayEquals(refreshAfterReplace, refreshAfterIdenticalRetry);
        assertChanged(refreshAfterIdenticalRetry, refreshAfterDelete);
        assertArrayEquals(hex("FF4000"), getAllRules());
    }

    @Test
    void sha1AndSha256RulesForOneAidAreIndividuallyDeletable() {
        byte[] sha1Rule = ruleFor(APPLET_AID, SHA1_DEVICE_APP_ID, true);
        byte[] sha256Rule = ruleFor(APPLET_AID, SHA256_DEVICE_APP_ID, true);
        byte[] otherAppRule = ruleFor(OTHER_APPLET_AID, new byte[0], true);
        personalize(sha1Rule);
        personalize(sha256Rule);
        personalize(otherAppRule);

        assertArrayEquals(allRules(sha1Rule, sha256Rule, otherAppRule), getAllRules());

        byte[] refreshBeforeSha256Delete = getRefreshTag();
        personalizeCommand(deleteByRefDo(refDoOf(sha256Rule)));

        assertArrayEquals(allRules(sha1Rule, otherAppRule), getAllRules());
        assertChanged(refreshBeforeSha256Delete, getRefreshTag());

        byte[] refreshBeforeSha1Delete = getRefreshTag();
        personalizeCommand(deleteByRefDo(refDoOf(sha1Rule)));

        assertArrayEquals(allRules(otherAppRule), getAllRules());
        assertChanged(refreshBeforeSha1Delete, getRefreshTag());
    }

    @Test
    void offWidthDeviceAppIdHashReturns6A80WithoutMutation() {
        personalize(ruleFor(APPLET_AID, SHA256_DEVICE_APP_ID, true));

        // 31 and 33 octets are neither SHA-1 nor SHA-256 width.
        assertWrongDataWithoutMutation(upsert(ruleFor(APPLET_AID, new byte[31], true)));
        assertWrongDataWithoutMutation(upsert(ruleFor(APPLET_AID, new byte[33], true)));
    }

    @Test
    void c1LengthMismatchOnSha256HashReturns6A80WithoutMutation() {
        personalize(ruleFor(APPLET_AID, SHA256_DEVICE_APP_ID, true));

        // C1 claims SHA-256 width but the REF-DO only carries a SHA-1 sized value,
        // so the declared value runs past the end of the REF-DO.
        assertWrongDataWithoutMutation(
                upsert(ruleWithDeclaredDeviceAppIdLength(APPLET_AID, new byte[20], 0x20)));
        // C1 claims SHA-1 width while a full SHA-256 hash follows it. The width itself
        // is legal, so this is caught by the trailing-bytes check instead.
        assertWrongDataWithoutMutation(
                upsert(ruleWithDeclaredDeviceAppIdLength(APPLET_AID, new byte[32], 0x14)));
    }

    @Test
    void truncatedSha256RuleReturns6A80WithoutMutation() {
        personalize(ruleFor(APPLET_AID, SHA256_DEVICE_APP_ID, true));
        byte[] full = ruleFor(APPLET_AID, SHA256_DEVICE_APP_ID, true);

        // Declared E2/E1/C1 lengths stay intact while the hash itself is cut short.
        assertWrongDataWithoutMutation(upsert(Arrays.copyOf(full, full.length - 8)));
        assertWrongDataWithoutMutation(upsert(Arrays.copyOf(full, full.length - 20)));
    }

    private void personalize(byte[] refArDo) {
        personalizeCommand(upsert(refArDo));
    }

    private void personalizeCommand(byte[] commandDo) {
        application.processData(commandDo, (short) 0, (short) commandDo.length);
    }

    private static byte[] upsert(byte[] refArDo) {
        return tlv((byte) 0xF0, refArDo);
    }

    private static byte[] deleteByRefDo(byte[] refDo) {
        return tlv((byte) 0xF1, refDo);
    }

    private static byte[] refDoOf(byte[] refArDo) {
        int refDoLength = 2 + (refArDo[3] & 0xFF);
        return Arrays.copyOfRange(refArDo, 2, 2 + refDoLength);
    }

    private static byte[] ruleFor(byte[] aid, byte[] deviceAppId, boolean allow) {
        byte[] refDoValue =
                concat(tlv((byte) 0x4F, aid), tlv((byte) 0xC1, deviceAppId));
        byte[] refDo = tlv((byte) 0xE1, refDoValue);
        byte[] arDoValue = allow ? APDU_ALLOW_AR_DO_VALUE : APDU_DENY_AR_DO_VALUE;
        return tlv((byte) 0xE2, concat(refDo, tlv((byte) 0xE3, arDoValue)));
    }

    /**
     * Builds a REF-AR-DO whose C1 length octet is declared independently of the
     * DeviceAppID bytes that actually follow it. The enclosing E1/E2 lengths stay
     * consistent with the real value, so only the C1 claim is wrong.
     */
    private static byte[] ruleWithDeclaredDeviceAppIdLength(
            byte[] aid, byte[] deviceAppId, int declaredLength) {
        byte[] deviceAppIdDo =
                concat(new byte[] {(byte) 0xC1, (byte) declaredLength}, deviceAppId);
        byte[] refDo = tlv((byte) 0xE1, concat(tlv((byte) 0x4F, aid), deviceAppIdDo));
        return tlv(
                (byte) 0xE2, concat(refDo, tlv((byte) 0xE3, APDU_ALLOW_AR_DO_VALUE)));
    }

    private static byte[] allRules(byte[]... rules) {
        ByteArrayOutputStream value = new ByteArrayOutputStream();
        for (byte[] rule : rules) {
            value.write(rule, 0, rule.length);
        }
        byte[] encoded = value.toByteArray();
        assertTrue(
                encoded.length <= 0x7F,
                "C9 vectors are sized to stay within one short-form FF40 response");
        return concat(hex("FF40"), concat(new byte[] {(byte) encoded.length}, encoded));
    }

    /**
     * Reads the catalog through a single FF40 response and asserts no continuation
     * is left live. Every catalog built in this class is small enough for that; if a
     * future vector outgrows it the short-form assertion fails loudly rather than
     * silently returning a truncated catalog.
     */
    private byte[] getAllRules() {
        ResponseAPDU response = getData(0xFF, 0x40);
        assertEquals(0x9000, response.getSW());
        byte[] data = response.getData();
        assertTrue(data.length >= 3);
        assertEquals(0xFF, data[0] & 0xFF);
        assertEquals(0x40, data[1] & 0xFF);
        int catalogLength = data[2] & 0xFF;
        assertTrue(catalogLength <= 0x7F, "Catalog outgrew a single short-form response");
        assertEquals(catalogLength + 3, data.length);
        assertEquals(0x6985, getData(0xFF, 0x60).getSW(), "FF40 must have completed");
        return data;
    }

    private byte[] getRefreshTag() {
        ResponseAPDU response = getData(0xDF, 0x20);
        assertEquals(0x9000, response.getSW());
        assertEquals(11, response.getData().length);
        assertArrayEquals(hex("DF2008"), Arrays.copyOf(response.getData(), 3));
        return response.getData();
    }

    private ResponseAPDU getData(int p1, int p2) {
        return simulator.transmitCommand(new CommandAPDU(0x80, 0xCA, p1, p2, 256));
    }

    private static void assertChanged(byte[] before, byte[] after) {
        assertFalse(Arrays.equals(before, after), "A real mutation must publish a new DF20 tag");
    }

    private void assertWrongDataWithoutMutation(byte[] commandDo) {
        byte[] rulesBefore = getAllRules();
        byte[] refreshBefore = getRefreshTag();
        short revisionBefore = catalogRevision();

        ISOException rejected =
                assertThrows(ISOException.class, () -> personalizeCommand(commandDo));

        assertEquals(0x6A80, rejected.getReason() & 0xFFFF);
        assertArrayEquals(rulesBefore, getAllRules());
        assertArrayEquals(refreshBefore, getRefreshTag());
        assertEquals(revisionBefore, catalogRevision());
    }

    private short catalogRevision() {
        try {
            Field revisionField = AraMApplet.class.getDeclaredField("catalogRevision");
            revisionField.setAccessible(true);
            return revisionField.getShort(logic());
        } catch (ReflectiveOperationException failure) {
            throw new AssertionError("Could not inspect catalog revision", failure);
        }
    }

    private AraMApplet logic() throws ReflectiveOperationException {
        AraMJCApplet applet = (AraMJCApplet) simulator.applet(appletAid);
        Field logicField = AraMJCApplet.class.getDeclaredField("logic");
        logicField.setAccessible(true);
        return (AraMApplet) logicField.get(applet);
    }

    private static byte[] tlv(byte tag, byte[] value) {
        return concat(new byte[] {tag, (byte) value.length}, value);
    }

    private static byte[] concat(byte[] left, byte[] right) {
        ByteArrayOutputStream output = new ByteArrayOutputStream(left.length + right.length);
        output.write(left, 0, left.length);
        output.write(right, 0, right.length);
        return output.toByteArray();
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

    private static final class ExposedCardSimulator extends CardSimulator {

        Application application(AID aid) {
            return (Application) applet(aid);
        }

        Applet applet(AID aid) {
            return runtime.lookupApplet(aid).getApplet();
        }
    }
}
