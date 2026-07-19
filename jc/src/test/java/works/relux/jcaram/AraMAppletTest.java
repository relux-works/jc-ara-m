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
import javacard.framework.JCSystem;
import java.io.ByteArrayOutputStream;
import java.lang.reflect.Field;
import java.util.Arrays;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import org.globalplatform.Application;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

final class AraMAppletTest {

    private static final String ARA_M_AID_HEX = "A00000015141434C00";
    private static final String OTHER_ARA_M_AID_HEX = "A00000015141434C01";
    private static final byte[] ARA_M_AID = hex(ARA_M_AID_HEX);
    private static final byte[] APPLET_AID = hex("F0000000AA01");
    private static final byte[] OTHER_APPLET_AID = hex("F0000000BB01");

    private static final byte[] PERMISSIVE_ALLOW_REF_AR_DO =
            hex("E211E10A4F06F0000000AA01C100E303D00101");
    private static final byte[] PERMISSIVE_DENY_REF_AR_DO =
            hex("E211E10A4F06F0000000AA01C100E303D00100");
    private static final byte[] CERT_BOUND_ALLOW_REF_AR_DO =
            hex(
                    "E225"
                            + "E11E"
                            + "4F06F0000000AA01"
                            + "C114000102030405060708090A0B0C0D0E0F10111213"
                            + "E303D00101");
    private static final byte[] SHA256_CERT_BOUND_ALLOW_REF_AR_DO =
            hex(
                    "E231"
                            + "E12A"
                            + "4F06F0000000AA01"
                            + "C120000102030405060708090A0B0C0D0E0F10111213"
                            + "1415161718191A1B1C1D1E1F"
                            + "E303D00101");
    private static final byte[] OTHER_APP_ALLOW_REF_AR_DO =
            ruleFor(OTHER_APPLET_AID, new byte[0], true);

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
    void selectReturnsSuccess() {
        ResponseAPDU response =
                simulator.transmitCommand(new CommandAPDU(0x00, 0xA4, 0x04, 0x00, ARA_M_AID));

        assertEquals(0x9000, response.getSW());
        assertEquals(0, response.getData().length);
    }

    @Test
    void implementsSecurityDomainPersonalizationContract() {
        assertTrue(Application.class.isAssignableFrom(AraMJCApplet.class));
    }

    @Test
    void getDataAllReturnsAnEmptyResponseAllDoBeforeProvisioning() {
        assertArrayEquals(hex("FF4000"), getAllRules());
    }

    @Test
    void smallCatalogUsesOneFf40ResponseAndLeavesNoContinuation() {
        ResponseAPDU beforeRead = getData(0x80, 0xFF, 0x60);
        assertEquals(0x6985, beforeRead.getSW());

        personalize(PERMISSIVE_ALLOW_REF_AR_DO);

        ResponseAPDU all = getData(0x80, 0xFF, 0x40);
        assertEquals(0x9000, all.getSW());
        assertArrayEquals(allRules(PERMISSIVE_ALLOW_REF_AR_DO), all.getData());

        ResponseAPDU afterCompleteRead = getData(0x80, 0xFF, 0x60);
        assertEquals(0x6985, afterCompleteRead.getSW());
    }

    @Test
    void ff40UsesShort81And82LengthsAtBerBoundaries() {
        assertCatalogLength(
                127,
                hex("FF407F"),
                18,
                18,
                18,
                18,
                18,
                18,
                19);
        assertCatalogLength(
                128,
                hex("FF408180"),
                18,
                18,
                18,
                18,
                18,
                18,
                20);
        assertCatalogLength(
                255,
                hex("FF4081FF"),
                18,
                18,
                18,
                18,
                18,
                18,
                18,
                18,
                18,
                18,
                18,
                18,
                18,
                21);
        assertCatalogLength(
                256,
                hex("FF40820100"),
                18,
                18,
                18,
                18,
                18,
                18,
                18,
                18,
                18,
                18,
                18,
                18,
                18,
                22);
    }

    @Test
    void largeCatalogStreamsEveryActiveRecordAcrossSeveralFf60Responses() {
        byte[][] rules = personalizeLargeCatalog();

        CatalogRead read = readAllRules(0x80);

        assertArrayEquals(allRules(rules), read.encoded);
        assertTrue(read.responseCount >= 4, "Large catalog must require several FF60 calls");
    }

    @Test
    void mutationDuringContinuationReturns6984OnceAndInvalidatesSession() {
        personalizeLargeCatalog();
        ResponseAPDU first = getData(0x80, 0xFF, 0x40);
        assertEquals(0x9000, first.getSW());

        personalize(largeRule((short) 0, false));

        ResponseAPDU invalidated = getData(0x80, 0xFF, 0x60);
        assertEquals(0x6984, invalidated.getSW());
        assertEquals(0, invalidated.getData().length);

        ResponseAPDU noLongerLive = getData(0x80, 0xFF, 0x60);
        assertEquals(0x6985, noLongerLive.getSW());
        assertArrayEquals(allRulesAfterLargeRuleOverwrite(), getAllRules());
    }

    @Test
    void continuationIsBoundToLogicalChannelAndSameChannelCanRestart() {
        personalizeLargeCatalog();
        ResponseAPDU first = getData(0x80, 0xFF, 0x40);
        assertEquals(0x9000, first.getSW());

        ResponseAPDU otherChannelRestart = getData(0x81, 0xFF, 0x40);
        assertEquals(0x6984, otherChannelRestart.getSW());
        ResponseAPDU otherChannelNext = getData(0x81, 0xFF, 0x60);
        assertEquals(0x6984, otherChannelNext.getSW());

        ResponseAPDU boundChannelNext = getData(0x80, 0xFF, 0x60);
        assertEquals(0x9000, boundChannelNext.getSW());
        assertTrue(boundChannelNext.getData().length > 0);

        ResponseAPDU restarted = getData(0x80, 0xFF, 0x40);
        assertEquals(0x9000, restarted.getSW());
        assertArrayEquals(first.getData(), restarted.getData());
    }

    @Test
    void resetClearsContinuationSession() {
        personalizeLargeCatalog();
        assertEquals(0x9000, getData(0x80, 0xFF, 0x40).getSW());

        simulator.reset();
        simulator.selectApplet(appletAid);

        ResponseAPDU afterReset = getData(0x80, 0xFF, 0x60);
        assertEquals(0x6985, afterReset.getSW());
    }

    @Test
    void deselectClearsContinuationSession() {
        personalizeLargeCatalog();
        assertEquals(0x9000, getData(0x80, 0xFF, 0x40).getSW());

        AID otherAppletAid = AIDUtil.create(OTHER_ARA_M_AID_HEX);
        simulator.installApplet(otherAppletAid, AraMJCApplet.class);
        simulator.selectApplet(otherAppletAid);
        simulator.selectApplet(appletAid);

        ResponseAPDU afterDeselect = getData(0x80, 0xFF, 0x60);
        assertEquals(0x6985, afterDeselect.getSW());
    }

    @Test
    void upsertNewPublishesMultipleRulesAndChangesRefreshForEachMutation() {
        byte[] refreshBefore = getRefreshTag();

        personalize(PERMISSIVE_ALLOW_REF_AR_DO);
        byte[] refreshAfterFirst = getRefreshTag();
        personalize(OTHER_APP_ALLOW_REF_AR_DO);
        byte[] refreshAfterSecond = getRefreshTag();

        assertArrayEquals(
                allRules(PERMISSIVE_ALLOW_REF_AR_DO, OTHER_APP_ALLOW_REF_AR_DO),
                getAllRules());
        assertChanged(refreshBefore, refreshAfterFirst);
        assertChanged(refreshAfterFirst, refreshAfterSecond);
    }

    @Test
    void upsertOverwriteSameExactRefDoReplacesOnlyThatRule() {
        personalize(PERMISSIVE_ALLOW_REF_AR_DO);
        personalize(OTHER_APP_ALLOW_REF_AR_DO);
        byte[] refreshBeforeOverwrite = getRefreshTag();

        personalize(PERMISSIVE_DENY_REF_AR_DO);

        assertArrayEquals(
                allRules(OTHER_APP_ALLOW_REF_AR_DO, PERMISSIVE_DENY_REF_AR_DO),
                getAllRules());
        assertChanged(refreshBeforeOverwrite, getRefreshTag());
    }

    @Test
    void byteIdenticalUpsertIsIdempotent() {
        personalize(PERMISSIVE_ALLOW_REF_AR_DO);
        byte[] rulesBeforeRetry = getAllRules();
        byte[] refreshBeforeRetry = getRefreshTag();

        personalize(PERMISSIVE_ALLOW_REF_AR_DO);

        assertArrayEquals(rulesBeforeRetry, getAllRules());
        assertArrayEquals(refreshBeforeRetry, getRefreshTag());
    }

    @Test
    void catalogRevisionAdvancesOnlyForRealMutations() {
        assertEquals(0, catalogRevision());

        personalize(PERMISSIVE_ALLOW_REF_AR_DO);
        assertEquals(1, catalogRevision());

        personalize(PERMISSIVE_ALLOW_REF_AR_DO);
        assertEquals(1, catalogRevision());

        personalize(PERMISSIVE_DENY_REF_AR_DO);
        assertEquals(2, catalogRevision());

        personalizeCommand(deleteAll());
        assertEquals(3, catalogRevision());
    }

    @Test
    void deleteByAidRemovesEveryRuleForThatAidInOnePublication() {
        personalize(PERMISSIVE_ALLOW_REF_AR_DO);
        personalize(CERT_BOUND_ALLOW_REF_AR_DO);
        personalize(OTHER_APP_ALLOW_REF_AR_DO);
        byte[] refreshBeforeDelete = getRefreshTag();

        personalizeCommand(deleteByAid(APPLET_AID));

        assertArrayEquals(allRules(OTHER_APP_ALLOW_REF_AR_DO), getAllRules());
        assertChanged(refreshBeforeDelete, getRefreshTag());
    }

    @Test
    void deleteByExactRefDoRemovesOnlyThatKey() {
        personalize(PERMISSIVE_ALLOW_REF_AR_DO);
        personalize(CERT_BOUND_ALLOW_REF_AR_DO);
        personalize(OTHER_APP_ALLOW_REF_AR_DO);
        byte[] refreshBeforeDelete = getRefreshTag();

        personalizeCommand(deleteByRefDo(refDoOf(PERMISSIVE_ALLOW_REF_AR_DO)));

        assertArrayEquals(
                allRules(CERT_BOUND_ALLOW_REF_AR_DO, OTHER_APP_ALLOW_REF_AR_DO),
                getAllRules());
        assertChanged(refreshBeforeDelete, getRefreshTag());
    }

    @Test
    void deleteAllClearsCatalogAndEmptyRetryIsIdempotent() {
        personalize(PERMISSIVE_ALLOW_REF_AR_DO);
        personalize(OTHER_APP_ALLOW_REF_AR_DO);
        byte[] refreshBeforeDelete = getRefreshTag();

        personalizeCommand(deleteAll());
        byte[] refreshAfterDelete = getRefreshTag();
        personalizeCommand(deleteAll());

        assertArrayEquals(hex("FF4000"), getAllRules());
        assertChanged(refreshBeforeDelete, refreshAfterDelete);
        assertArrayEquals(refreshAfterDelete, getRefreshTag());
    }

    @Test
    void deleteNoMatchReturns6A88WithoutPublishingMetadata() {
        personalize(PERMISSIVE_ALLOW_REF_AR_DO);
        byte[] rulesBeforeDelete = getAllRules();
        byte[] refreshBeforeDelete = getRefreshTag();

        ISOException rejected =
                assertThrows(
                        ISOException.class,
                        () -> personalizeCommand(deleteByAid(OTHER_APPLET_AID)));

        assertEquals(0x6A88, rejected.getReason() & 0xFFFF);
        assertArrayEquals(rulesBeforeDelete, getAllRules());
        assertArrayEquals(refreshBeforeDelete, getRefreshTag());
    }

    @Test
    void capacityFullRejectsNewKeyWithoutChangingRefresh() {
        for (short index = (short) 0;
                index < AraMApplet.ACTIVE_RULE_CAPACITY;
                index++) {
            personalize(uniqueRule(index, true));
        }
        byte[] refreshAtCapacity = getRefreshTag();

        ISOException rejected =
                assertThrows(
                        ISOException.class,
                        () ->
                                personalize(
                                        uniqueRule(AraMApplet.ACTIVE_RULE_CAPACITY, true)));

        assertEquals(0x6A84, rejected.getReason() & 0xFFFF);
        assertArrayEquals(refreshAtCapacity, getRefreshTag());

        personalize(uniqueRule((short) 0, false));
        assertChanged(refreshAtCapacity, getRefreshTag());
    }

    @Test
    void callerOwnedTransactionCommitsSeveralMutationsAsOneComposition() {
        JCSystem.beginTransaction();
        try {
            personalize(PERMISSIVE_ALLOW_REF_AR_DO);
            personalize(PERMISSIVE_DENY_REF_AR_DO);
            personalize(OTHER_APP_ALLOW_REF_AR_DO);
            assertEquals(1, JCSystem.getTransactionDepth());
            JCSystem.commitTransaction();
        } finally {
            abortOpenTransaction();
        }

        assertArrayEquals(
                allRules(PERMISSIVE_DENY_REF_AR_DO, OTHER_APP_ALLOW_REF_AR_DO),
                getAllRules());
    }

    @Test
    void tornOwnedPathInactiveRecordLeavesPriorCatalogAndRefreshIntact() {
        personalize(PERMISSIVE_ALLOW_REF_AR_DO);
        byte[] entryRules = getAllRules();
        byte[] entryRefresh = getRefreshTag();

        corruptEveryInactiveRecord();

        assertArrayEquals(entryRules, getAllRules());
        assertArrayEquals(entryRefresh, getRefreshTag());

        personalize(OTHER_APP_ALLOW_REF_AR_DO);
        assertArrayEquals(
                allRules(PERMISSIVE_ALLOW_REF_AR_DO, OTHER_APP_ALLOW_REF_AR_DO),
                getAllRules());
    }

    @Test
    void authenticatedCallbackHonorsNonZeroBufferOffset() {
        byte[] command = storeCommand(upsert(PERMISSIVE_ALLOW_REF_AR_DO));
        byte[] padded = new byte[command.length + 4];
        System.arraycopy(command, 0, padded, 2, command.length);

        application.processData(padded, (short) 2, (short) command.length);

        assertArrayEquals(allRules(PERMISSIVE_ALLOW_REF_AR_DO), getAllRules());
    }

    @Test
    void malformedPersonalizationDoesNotReplaceExistingRule() {
        personalize(PERMISSIVE_ALLOW_REF_AR_DO);
        byte[] refreshBeforeMalformedStore = getRefreshTag();

        byte[] missingArDo = hex("E20CE10A4F06F0000000AA01C100");
        ISOException rejected =
                assertThrows(ISOException.class, () -> personalize(missingArDo));

        assertEquals(0x6A80, rejected.getReason() & 0xFFFF);
        assertArrayEquals(allRules(PERMISSIVE_ALLOW_REF_AR_DO), getAllRules());
        assertArrayEquals(refreshBeforeMalformedStore, getRefreshTag());
    }

    @Test
    void zeroLengthAidUpsertReturns6A80WithoutMutation() {
        personalize(PERMISSIVE_ALLOW_REF_AR_DO);
        byte[] invalidRule = ruleFor(new byte[0], new byte[0], true);

        assertWrongDataWithoutMutation(upsert(invalidRule));
    }

    @Test
    void zeroLengthAidExactDeleteReturns6A80WithoutMutation() {
        personalize(PERMISSIVE_ALLOW_REF_AR_DO);
        byte[] invalidRule = ruleFor(new byte[0], new byte[0], true);

        assertWrongDataWithoutMutation(deleteByRefDo(refDoOf(invalidRule)));
    }

    @Test
    void unsupportedF1PartialRefArDoReturns6981WithoutMutation() {
        personalize(PERMISSIVE_ALLOW_REF_AR_DO);
        byte[] rulesBefore = getAllRules();
        byte[] refreshBefore = getRefreshTag();
        byte[] partialDelete = tlv((byte) 0xF1, PERMISSIVE_ALLOW_REF_AR_DO);

        ISOException rejected =
                assertThrows(
                        ISOException.class, () -> personalizeCommand(partialDelete));

        assertEquals(0x6981, rejected.getReason() & 0xFFFF);
        assertArrayEquals(rulesBefore, getAllRules());
        assertArrayEquals(refreshBefore, getRefreshTag());
    }

    @Test
    void sha1AndSha256ExactReferenceKeysCanCoexist() {
        personalize(CERT_BOUND_ALLOW_REF_AR_DO);
        personalize(SHA256_CERT_BOUND_ALLOW_REF_AR_DO);

        assertArrayEquals(
                allRules(CERT_BOUND_ALLOW_REF_AR_DO, SHA256_CERT_BOUND_ALLOW_REF_AR_DO),
                getAllRules());
    }

    @Test
    void rawStoreDataIsRejectedWithoutMutatingCatalogOrRefreshTag() {
        byte[] rulesBefore = getAllRules();
        byte[] refreshBefore = getRefreshTag();

        ResponseAPDU response = rawStore(PERMISSIVE_ALLOW_REF_AR_DO);

        assertEquals(0x6982, response.getSW());
        assertEquals(0, response.getData().length);
        assertArrayEquals(rulesBefore, getAllRules());
        assertArrayEquals(refreshBefore, getRefreshTag());
    }

    private byte[] getAllRules() {
        return readAllRules(0x80).encoded;
    }

    private byte[] getRefreshTag() {
        ResponseAPDU response = getData(0xDF, 0x20);
        assertEquals(0x9000, response.getSW());
        assertEquals(11, response.getData().length);
        assertArrayEquals(hex("DF2008"), Arrays.copyOf(response.getData(), 3));
        return response.getData();
    }

    private ResponseAPDU getData(int p1, int p2) {
        return getData(0x80, p1, p2);
    }

    private ResponseAPDU getData(int cla, int p1, int p2) {
        return simulator.transmitCommand(new CommandAPDU(cla, 0xCA, p1, p2, 256));
    }

    private ResponseAPDU rawStore(byte[] refArDo) {
        return simulator.transmitCommand(new CommandAPDU(storeCommand(upsert(refArDo))));
    }

    private void personalize(byte[] refArDo) {
        personalizeCommand(upsert(refArDo));
    }

    private void personalizeCommand(byte[] commandDo) {
        byte[] command = storeCommand(commandDo);
        application.processData(command, (short) 0, (short) command.length);
    }

    private static byte[] upsert(byte[] refArDo) {
        return tlv((byte) 0xF0, refArDo);
    }

    private static byte[] deleteByAid(byte[] aid) {
        return tlv((byte) 0xF1, tlv((byte) 0x4F, aid));
    }

    private static byte[] deleteByRefDo(byte[] refDo) {
        return tlv((byte) 0xF1, refDo);
    }

    private static byte[] deleteAll() {
        return hex("F100");
    }

    private static byte[] storeCommand(byte[] commandDo) {
        return concat(
                hex("80E29000"),
                concat(new byte[] {(byte) commandDo.length}, commandDo));
    }

    private static byte[] refDoOf(byte[] refArDo) {
        int refDoLength = 2 + (refArDo[3] & 0xFF);
        return Arrays.copyOfRange(refArDo, 2, 2 + refDoLength);
    }

    private static byte[] uniqueRule(short index, boolean allow) {
        byte[] aid =
                new byte[] {
                    (byte) 0xF0,
                    (byte) 0x00,
                    (byte) 0x00,
                    (byte) 0x00,
                    (byte) 0xCC,
                    (byte) index
                };
        return ruleFor(aid, new byte[0], allow);
    }

    private byte[][] personalizeLargeCatalog() {
        byte[][] rules = new byte[AraMApplet.ACTIVE_RULE_CAPACITY][];
        for (short index = (short) 0;
                index < AraMApplet.ACTIVE_RULE_CAPACITY;
                index++) {
            rules[index] = largeRule(index, true);
            personalize(rules[index]);
        }
        return rules;
    }

    private static byte[] largeRule(short index, boolean allow) {
        byte[] aid = new byte[16];
        aid[0] = (byte) 0xF0;
        aid[1] = (byte) 0x00;
        aid[2] = (byte) 0x00;
        aid[3] = (byte) 0x00;
        aid[15] = (byte) index;
        return ruleFor(aid, new byte[32], allow);
    }

    private static byte[] allRulesAfterLargeRuleOverwrite() {
        byte[][] rules = new byte[AraMApplet.ACTIVE_RULE_CAPACITY][];
        for (short index = (short) 1;
                index < AraMApplet.ACTIVE_RULE_CAPACITY;
                index++) {
            rules[(short) (index - (short) 1)] = largeRule(index, true);
        }
        rules[(short) (AraMApplet.ACTIVE_RULE_CAPACITY - (short) 1)] =
                largeRule((short) 0, false);
        return allRules(rules);
    }

    private void assertCatalogLength(int expectedLength, byte[] header, int... recordLengths) {
        personalizeCommand(deleteAll());
        int total = 0;
        for (int index = 0; index < recordLengths.length; index++) {
            byte[] rule = ruleWithLength((short) index, recordLengths[index]);
            total += rule.length;
            personalize(rule);
        }
        assertEquals(expectedLength, total);

        CatalogRead read = readAllRules(0x80);

        assertEquals(expectedLength, read.catalogLength);
        assertArrayEquals(header, Arrays.copyOf(read.encoded, header.length));
        if (expectedLength <= 128) {
            assertEquals(1, read.responseCount);
        } else {
            assertTrue(read.responseCount > 1);
        }
    }

    private static byte[] ruleWithLength(short index, int recordLength) {
        int aidLength = recordLength - 13;
        if (aidLength < 5 || aidLength > 16) {
            throw new IllegalArgumentException("Unsupported test record length");
        }
        byte[] aid = new byte[aidLength];
        aid[0] = (byte) 0xF0;
        aid[aid.length - 1] = (byte) index;
        byte[] rule = ruleFor(aid, new byte[0], true);
        assertEquals(recordLength, rule.length);
        return rule;
    }

    private static byte[] ruleFor(byte[] aid, byte[] deviceAppId, boolean allow) {
        byte[] refDoValue =
                concat(tlv((byte) 0x4F, aid), tlv((byte) 0xC1, deviceAppId));
        byte[] refDo = tlv((byte) 0xE1, refDoValue);
        byte[] arDo = hex(allow ? "E303D00101" : "E303D00100");
        return tlv((byte) 0xE2, concat(refDo, arDo));
    }

    private static byte[] allRules(byte[]... rules) {
        ByteArrayOutputStream value = new ByteArrayOutputStream();
        for (byte[] rule : rules) {
            value.write(rule, 0, rule.length);
        }
        return concat(hex("FF40"), concat(berLength(value.size()), value.toByteArray()));
    }

    private CatalogRead readAllRules(int cla) {
        ResponseAPDU first = getData(cla, 0xFF, 0x40);
        assertEquals(0x9000, first.getSW());
        byte[] firstData = first.getData();
        assertTrue(firstData.length >= 3);
        assertEquals(0xFF, firstData[0] & 0xFF);
        assertEquals(0x40, firstData[1] & 0xFF);

        int lengthOctets = berLengthOctets(firstData);
        int headerLength = 2 + lengthOctets;
        int catalogLength = decodeBerLength(firstData);
        ByteArrayOutputStream value = new ByteArrayOutputStream(catalogLength);
        value.write(firstData, headerLength, firstData.length - headerLength);
        int responseCount = 1;

        while (value.size() < catalogLength) {
            ResponseAPDU next = getData(cla, 0xFF, 0x60);
            assertEquals(0x9000, next.getSW());
            assertTrue(next.getData().length > 0);
            assertTrue(value.size() + next.getData().length <= catalogLength);
            value.write(next.getData(), 0, next.getData().length);
            responseCount++;
        }

        assertEquals(catalogLength, value.size());
        byte[] encoded =
                concat(Arrays.copyOf(firstData, headerLength), value.toByteArray());
        return new CatalogRead(encoded, catalogLength, responseCount);
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

    private static byte[] berLength(int length) {
        if (length <= 0x7F) {
            return new byte[] {(byte) length};
        }
        if (length <= 0xFF) {
            return new byte[] {(byte) 0x81, (byte) length};
        }
        return new byte[] {(byte) 0x82, (byte) (length >> 8), (byte) length};
    }

    private static byte[] tlv(byte tag, byte[] value) {
        return concat(new byte[] {tag, (byte) value.length}, value);
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

    private static void abortOpenTransaction() {
        if (JCSystem.getTransactionDepth() != (byte) 0) {
            JCSystem.abortTransaction();
        }
    }

    private void corruptEveryInactiveRecord() {
        try {
            AraMApplet logic = logic();

            Field arenaField = AraMApplet.class.getDeclaredField("recordArena");
            arenaField.setAccessible(true);
            byte[] arena = (byte[]) arenaField.get(logic);

            Field bitmapField = AraMApplet.class.getDeclaredField("activeBitmap");
            bitmapField.setAccessible(true);
            byte[] bitmap = (byte[]) bitmapField.get(logic);

            int recordSize = 1 + AraMApplet.MAX_REF_AR_DO_LENGTH;
            int recordCount = AraMApplet.ACTIVE_RULE_CAPACITY + 1;
            for (int recordIndex = 0; recordIndex < recordCount; recordIndex++) {
                int mask = 1 << (recordIndex & 7);
                boolean active = (bitmap[recordIndex >> 3] & mask) != 0;
                if (!active) {
                    Arrays.fill(
                            arena,
                            recordIndex * recordSize,
                            (recordIndex + 1) * recordSize,
                            (byte) 0xA5);
                }
            }
        } catch (ReflectiveOperationException failure) {
            throw new AssertionError("Could not inject an inactive-record tear", failure);
        }
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

    private static final class CatalogRead {
        private final byte[] encoded;
        private final int catalogLength;
        private final int responseCount;

        private CatalogRead(byte[] encoded, int catalogLength, int responseCount) {
            this.encoded = encoded;
            this.catalogLength = catalogLength;
            this.responseCount = responseCount;
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
