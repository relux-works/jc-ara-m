package works.relux.jcaram;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

import com.licel.jcardsim.smartcardio.CardSimulator;
import com.licel.jcardsim.utils.AIDUtil;
import javacard.framework.AID;
import java.io.ByteArrayOutputStream;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

final class AraMAppletTest {

    private static final String ARA_M_AID_HEX = "A00000015141434C00";
    private static final byte[] ARA_M_AID = hex(ARA_M_AID_HEX);

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

    private CardSimulator simulator;
    private AID appletAid;

    @BeforeEach
    void setUp() {
        simulator = new CardSimulator();
        appletAid = AIDUtil.create(ARA_M_AID_HEX);
        simulator.installApplet(appletAid, AraMJCApplet.class);
        simulator.selectApplet(appletAid);
    }

    @Test
    void selectReturnsSuccess() {
        ResponseAPDU response =
                simulator.transmitCommand(new CommandAPDU(0x00, 0xA4, 0x04, 0x00, ARA_M_AID));

        assertEquals(0x9000, response.getSW());
        assertEquals(0, response.getData().length);
    }

    @Test
    void getDataAllReturnsAnEmptyResponseAllDoBeforeProvisioning() {
        ResponseAPDU response = getData(0xFF, 0x40);

        assertEquals(0x9000, response.getSW());
        assertArrayEquals(hex("FF4000"), response.getData());
    }

    @Test
    void storeDataProvisionsPermissiveRuleReturnedByGetDataAll() {
        ResponseAPDU storeResponse = store(PERMISSIVE_ALLOW_REF_AR_DO);
        ResponseAPDU getResponse = getData(0xFF, 0x40);

        assertEquals(0x9000, storeResponse.getSW());
        assertEquals(0, storeResponse.getData().length);
        assertEquals(0x9000, getResponse.getSW());
        assertArrayEquals(
                concat(hex("FF4013"), PERMISSIVE_ALLOW_REF_AR_DO), getResponse.getData());
    }

    @Test
    void storeDataReplacesRuleWithTheSameReference() {
        assertEquals(0x9000, store(PERMISSIVE_ALLOW_REF_AR_DO).getSW());
        assertEquals(0x9000, store(PERMISSIVE_DENY_REF_AR_DO).getSW());

        ResponseAPDU response = getData(0xFF, 0x40);

        assertEquals(0x9000, response.getSW());
        assertArrayEquals(
                concat(hex("FF4013"), PERMISSIVE_DENY_REF_AR_DO), response.getData());
    }

    @Test
    void refreshTagIsWellFormedAndChangesAfterStoreData() {
        ResponseAPDU before = getData(0xDF, 0x20);
        assertEquals(0x9000, before.getSW());
        assertEquals(11, before.getData().length);
        assertEquals((byte) 0xDF, before.getData()[0]);
        assertEquals((byte) 0x20, before.getData()[1]);
        assertEquals((byte) 0x08, before.getData()[2]);

        assertEquals(0x9000, store(PERMISSIVE_ALLOW_REF_AR_DO).getSW());
        ResponseAPDU after = getData(0xDF, 0x20);

        assertEquals(0x9000, after.getSW());
        assertEquals(11, after.getData().length);
        assertFalse(
                java.util.Arrays.equals(before.getData(), after.getData()),
                "STORE DATA must update the ARA-M refresh tag");
    }

    @Test
    void storeDataAcceptsFutureSha1CertificateBoundRuleShape() {
        ResponseAPDU storeResponse = store(CERT_BOUND_ALLOW_REF_AR_DO);
        ResponseAPDU getResponse = getData(0xFF, 0x40);

        assertEquals(0x9000, storeResponse.getSW());
        assertEquals(0x9000, getResponse.getSW());
        assertArrayEquals(
                concat(hex("FF4027"), CERT_BOUND_ALLOW_REF_AR_DO), getResponse.getData());
    }

    @Test
    void malformedStoreDataDoesNotReplaceExistingRule() {
        assertEquals(0x9000, store(PERMISSIVE_ALLOW_REF_AR_DO).getSW());
        byte[] refreshBeforeMalformedStore = getData(0xDF, 0x20).getData();

        byte[] missingArDo = hex("E20CE10A4F06F0000000AA01C100");
        ResponseAPDU rejected = store(missingArDo);
        ResponseAPDU getResponse = getData(0xFF, 0x40);
        ResponseAPDU refreshAfterMalformedStore = getData(0xDF, 0x20);

        assertEquals(0x6A80, rejected.getSW());
        assertArrayEquals(
                concat(hex("FF4013"), PERMISSIVE_ALLOW_REF_AR_DO), getResponse.getData());
        assertArrayEquals(
                refreshBeforeMalformedStore,
                refreshAfterMalformedStore.getData(),
                "Rejected STORE DATA must not update the refresh tag");
    }

    private ResponseAPDU getData(int p1, int p2) {
        return simulator.transmitCommand(new CommandAPDU(0x80, 0xCA, p1, p2, 256));
    }

    private ResponseAPDU store(byte[] refArDo) {
        byte[] commandStoreRefArDo = concat(new byte[] {(byte) 0xF0, (byte) refArDo.length}, refArDo);
        return simulator.transmitCommand(
                new CommandAPDU(0x80, 0xE2, 0x90, 0x00, commandStoreRefArDo));
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
}
