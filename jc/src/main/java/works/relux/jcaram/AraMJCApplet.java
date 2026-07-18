package works.relux.jcaram;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import org.globalplatform.Application;

/** Java Card APDU adapter for the minimal ARA-M implementation. */
public final class AraMJCApplet extends Applet implements Application {

    private static final byte INS_GET_DATA = (byte) 0xCA;
    private static final byte INS_STORE_DATA = (byte) 0xE2;

    private static final byte P1_GET_ALL = (byte) 0xFF;
    private static final byte P2_GET_ALL = (byte) 0x40;
    private static final byte P1_GET_REFRESH_TAG = (byte) 0xDF;
    private static final byte P2_GET_REFRESH_TAG = (byte) 0x20;

    private static final byte P1_STORE_LAST_BER_TLV_BLOCK = (byte) 0x90;
    private static final byte P2_STORE_FIRST_BLOCK = (byte) 0x00;

    private final AraMApplet logic;

    private AraMJCApplet() {
        logic = new AraMApplet();
        register();
    }

    public static void install(byte[] installData, short offset, byte length) {
        new AraMJCApplet();
    }

    @Override
    public void process(APDU apdu) {
        if (selectingApplet()) {
            return;
        }

        byte[] buffer = apdu.getBuffer();
        byte cla = buffer[ISO7816.OFFSET_CLA];
        if (!isSupportedClass(cla)) {
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        }

        byte instruction = buffer[ISO7816.OFFSET_INS];
        if (instruction == INS_GET_DATA) {
            processGetData(apdu, buffer);
            return;
        }
        if (instruction == INS_STORE_DATA) {
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }
        ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
    }

    /** Receives authenticated STORE DATA from the Security Domain personalization flow. */
    @Override
    public void processData(byte[] data, short offset, short length) {
        storePersonalizationData(logic, data);
    }

    static void storePersonalizationData(AraMApplet logic, byte[] apduBuffer) {
        if (apduBuffer[ISO7816.OFFSET_P1] != P1_STORE_LAST_BER_TLV_BLOCK
                || apduBuffer[ISO7816.OFFSET_P2] != P2_STORE_FIRST_BLOCK) {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }
        byte encodedLength = apduBuffer[ISO7816.OFFSET_LC];
        if (encodedLength < (byte) 0) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        short dataLength = (short) encodedLength;
        logic.store(apduBuffer, ISO7816.OFFSET_CDATA, dataLength);
    }

    private void processGetData(APDU apdu, byte[] buffer) {
        byte p1 = buffer[ISO7816.OFFSET_P1];
        byte p2 = buffer[ISO7816.OFFSET_P2];
        short responseLength;

        if (p1 == P1_GET_ALL && p2 == P2_GET_ALL) {
            responseLength = logic.writeAllRules(buffer, (short) 0);
        } else if (p1 == P1_GET_REFRESH_TAG && p2 == P2_GET_REFRESH_TAG) {
            responseLength = logic.writeRefreshTag(buffer, (short) 0);
        } else {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
            return;
        }

        apdu.setOutgoingAndSend((short) 0, responseLength);
    }

    private static boolean isSupportedClass(byte cla) {
        byte category = (byte) (cla & (byte) 0xF0);
        return category == (byte) 0x80
                || category == (byte) 0xC0
                || category == (byte) 0xE0;
    }
}
