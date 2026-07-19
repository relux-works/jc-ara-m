package works.relux.jcaram;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.licel.jcardsim.smartcardio.CardSimulator;
import com.licel.jcardsim.utils.AIDUtil;
import javacard.framework.AID;
import javacard.framework.Applet;
import javacard.framework.ISOException;
import javacard.framework.SystemException;
import java.io.ByteArrayOutputStream;
import java.lang.reflect.Field;
import org.globalplatform.Application;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * Installation-time capacity contract.
 *
 * <p>{@code R} is read from the GlobalPlatform application-specific install parameter
 * block, defaulted when absent and clamped to the compiled maximum. Every buffer is still
 * allocated exactly once, in the constructor, from the resolved value.
 */
final class InstallParametersTest {

    private static final String ARA_M_AID_HEX = "A00000015141434C00";
    private static final byte[] ARA_M_AID = hex(ARA_M_AID_HEX);
    private static final byte[] PRIVILEGES = hex("00");

    private static final int RECORD_SIZE = 1 + AraMApplet.MAX_REF_AR_DO_LENGTH;

    private ExposedCardSimulator simulator;
    private AID appletAid;

    @BeforeEach
    void setUp() {
        simulator = new ExposedCardSimulator();
        appletAid = AIDUtil.create(ARA_M_AID_HEX);
    }

    // --- absent parameters -------------------------------------------------

    @Test
    void anEmptyInstallArrayUsesTheDefaultCapacity() {
        assertEquals(
                AraMApplet.DEFAULT_ACTIVE_RULE_CAPACITY,
                AraMJCApplet.resolveActiveRuleCapacity(new byte[0], (short) 0, (byte) 0));

        simulator.installApplet(appletAid, AraMJCApplet.class);

        assertCapacity(AraMApplet.DEFAULT_ACTIVE_RULE_CAPACITY);
    }

    @Test
    void anEmptyApplicationSpecificBlockUsesTheDefaultCapacity() {
        installWithParameters(new byte[0]);

        assertCapacity(AraMApplet.DEFAULT_ACTIVE_RULE_CAPACITY);
    }

    @Test
    void anEmptyC9ContainerUsesTheDefaultCapacity() {
        installWithParameters(hex("C900"));

        assertCapacity(AraMApplet.DEFAULT_ACTIVE_RULE_CAPACITY);
    }

    // --- in-range parameters -----------------------------------------------

    @Test
    void anInRangeCapacityIsHonoured() {
        installWithParameters(capacityParameter(4));

        assertCapacity((short) 4);
    }

    @Test
    void aCapacityStillWrappedInItsC9ContainerIsHonoured() {
        // Some Security Domains forward the C9 TLV intact rather than only its value.
        installWithParameters(concat(hex("C903"), capacityParameter(4)));

        assertCapacity((short) 4);
    }

    @Test
    void theSmallestCapacityIsHonoured() {
        installWithParameters(capacityParameter(1));

        assertCapacity((short) 1);
    }

    @Test
    void anInstalledCapacityBoundsTheCatalogAtRuntime() {
        installWithParameters(capacityParameter(3));
        simulator.selectApplet(appletAid);
        Application application = simulator.application(appletAid);

        for (short index = (short) 0; index < (short) 3; index++) {
            personalize(application, uniqueRule(index));
        }

        ISOException rejected =
                assertThrows(
                        ISOException.class,
                        () -> personalize(application, uniqueRule((short) 3)));
        assertEquals(0x6A84, rejected.getReason() & 0xFFFF);
    }

    @Test
    void anInstalledCapacityLargerThanTheDefaultAcceptsMoreRulesThanTheDefault() {
        installWithParameters(capacityParameter(20));
        simulator.selectApplet(appletAid);
        Application application = simulator.application(appletAid);

        for (short index = (short) 0; index < (short) 20; index++) {
            personalize(application, uniqueRule(index));
        }

        ISOException rejected =
                assertThrows(
                        ISOException.class,
                        () -> personalize(application, uniqueRule((short) 20)));
        assertEquals(0x6A84, rejected.getReason() & 0xFFFF);
    }

    // --- over-maximum parameters -------------------------------------------

    @Test
    void theCompiledMaximumIsAcceptedExactly() {
        installWithParameters(capacityParameter(AraMApplet.MAX_ACTIVE_RULE_CAPACITY));

        assertCapacity(AraMApplet.MAX_ACTIVE_RULE_CAPACITY);
    }

    @Test
    void aCapacityAboveTheCompiledMaximumIsClampedRatherThanRejected() {
        installWithParameters(capacityParameter(AraMApplet.MAX_ACTIVE_RULE_CAPACITY + 1));

        assertCapacity(AraMApplet.MAX_ACTIVE_RULE_CAPACITY);
    }

    @Test
    void theLargestEncodableCapacityIsClampedToTheCompiledMaximum() {
        installWithParameters(capacityParameter(0xFF));

        assertCapacity(AraMApplet.MAX_ACTIVE_RULE_CAPACITY);
    }

    // --- malformed parameters ----------------------------------------------

    @Test
    void aZeroCapacityIsRejected() {
        assertParametersRejected(capacityParameter(0));
    }

    @Test
    void anUnknownParameterTagIsRejected() {
        assertParametersRejected(hex("810104"));
    }

    @Test
    void aCapacityValueOfTheWrongWidthIsRejected() {
        assertParametersRejected(hex("80020004"));
        assertParametersRejected(hex("8000"));
    }

    @Test
    void aTruncatedCapacityTlvIsRejected() {
        assertParametersRejected(hex("80"));
        assertParametersRejected(hex("8001"));
    }

    @Test
    void bytesTrailingTheCapacityTlvAreRejected() {
        assertParametersRejected(hex("8001040000"));
    }

    @Test
    void aC9ContainerLongerThanTheParameterBlockIsRejected() {
        assertParametersRejected(hex("C90A800104"));
    }

    @Test
    void aParameterBlockLongerThanTheInstallArrayIsRejected() {
        byte[] installData = installArray(capacityParameter(4));
        installData[installData.length - 4] = (byte) 0x40;

        assertInstallDataRejected(installData);
    }

    @Test
    void aTruncatedInstanceAidFieldIsRejected() {
        byte[] installData = installArray(capacityParameter(4));
        installData[0] = (byte) 0x7F;

        assertInstallDataRejected(installData);
    }

    @Test
    void anInstallArrayWithoutAParameterLengthByteIsRejected() {
        byte[] truncated =
                concat(
                        concat(lengthValue(ARA_M_AID), lengthValue(PRIVILEGES)),
                        new byte[0]);

        assertInstallDataRejected(truncated);
    }

    // --- allocation invariant ----------------------------------------------

    @Test
    void everyBufferIsSizedFromTheInstalledCapacityAndNeverGrows() {
        installWithParameters(capacityParameter(5));
        simulator.selectApplet(appletAid);
        Application application = simulator.application(appletAid);

        byte[] arenaAtInstall = field("recordArena");
        byte[] bitmapAtInstall = field("activeBitmap");
        assertEquals(6 * RECORD_SIZE, arenaAtInstall.length);
        assertEquals(1, bitmapAtInstall.length);

        for (short index = (short) 0; index < (short) 5; index++) {
            personalize(application, uniqueRule(index));
        }

        // Same array objects, same lengths: the catalog is allocated once at install.
        assertSame(arenaAtInstall, field("recordArena"));
        assertSame(bitmapAtInstall, field("activeBitmap"));
        assertEquals(6 * RECORD_SIZE, field("recordArena").length);
        assertEquals(1, field("activeBitmap").length);
    }

    @Test
    void theBitmapGrowsOneByteWhenTheRecordCountCrossesAByteBoundary() {
        installWithParameters(capacityParameter(7));

        // R + 1 == 8 records still fits one bitmap byte.
        assertEquals(1, field("activeBitmap").length);
        assertEquals(8 * RECORD_SIZE, field("recordArena").length);

        setUp();
        installWithParameters(capacityParameter(8));

        assertEquals(2, field("activeBitmap").length);
        assertEquals(9 * RECORD_SIZE, field("recordArena").length);
    }

    // --- helpers -----------------------------------------------------------

    private void assertCapacity(short expectedCapacity) {
        short recordCount = (short) (expectedCapacity + 1);
        assertEquals(expectedCapacity, logic().activeRuleCapacity());
        assertEquals(recordCount * RECORD_SIZE, field("recordArena").length);
        assertEquals((recordCount + 7) / 8, field("activeBitmap").length);
        assertEquals((recordCount + 7) / 8, field("nextBitmap").length);
    }

    /** Both the parser and a real jCardSim installation must reject the block. */
    private void assertParametersRejected(byte[] applicationSpecificParameters) {
        assertInstallDataRejected(installArray(applicationSpecificParameters));
    }

    private void assertInstallDataRejected(byte[] installData) {
        ISOException parsed =
                assertThrows(
                        ISOException.class,
                        () ->
                                AraMJCApplet.resolveActiveRuleCapacity(
                                        installData, (short) 0, (byte) installData.length));
        assertEquals(0x6A80, parsed.getReason() & 0xFFFF);

        // The installation itself must fail and leave nothing registered. jCardSim's
        // Simulator.createApplet converts any install-time throw into a SystemException,
        // so the 6A80 reason is only observable at the parser boundary asserted above.
        assertThrows(
                SystemException.class,
                () ->
                        simulator.installApplet(
                                appletAid,
                                AraMJCApplet.class,
                                installData,
                                (short) 0,
                                (byte) installData.length));
        assertFalse(simulator.isInstalled(appletAid), "no instance may survive a failed install");
    }

    private void installWithParameters(byte[] applicationSpecificParameters) {
        byte[] installData = installArray(applicationSpecificParameters);
        simulator.installApplet(
                appletAid,
                AraMJCApplet.class,
                installData,
                (short) 0,
                (byte) installData.length);
    }

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
        return new byte[] {
            AraMJCApplet.TAG_ACTIVE_RULE_CAPACITY, (byte) 0x01, (byte) capacity
        };
    }

    private static void personalize(Application application, byte[] refArDo) {
        byte[] commandDo = tlv((byte) 0xF0, refArDo);
        application.processData(commandDo, (short) 0, (short) commandDo.length);
    }

    private static byte[] uniqueRule(short index) {
        byte[] aid =
                new byte[] {
                    (byte) 0xF0,
                    (byte) 0x00,
                    (byte) 0x00,
                    (byte) 0x00,
                    (byte) 0xCC,
                    (byte) index
                };
        byte[] refDo = tlv((byte) 0xE1, concat(tlv((byte) 0x4F, aid), hex("C100")));
        return tlv((byte) 0xE2, concat(refDo, tlv((byte) 0xE3, hex("D00101"))));
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
        for (int index = 0; index < result.length; index++) {
            result[index] =
                    (byte) Integer.parseInt(value.substring(index * 2, index * 2 + 2), 16);
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

        boolean isInstalled(AID aid) {
            return runtime.lookupApplet(aid) != null;
        }
    }
}
