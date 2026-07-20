package works.relux.jcaram;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import org.globalplatform.Application;

/** Java Card APDU adapter for the bounded ARA-M implementation. */
public final class AraMJCApplet extends Applet implements Application {

    private static final byte INS_GET_DATA = (byte) 0xCA;
    private static final byte INS_STORE_DATA = (byte) 0xE2;

    private static final byte P1_GET_ALL = (byte) 0xFF;
    private static final byte P2_GET_ALL = (byte) 0x40;
    private static final byte P2_GET_NEXT = (byte) 0x60;
    private static final byte P1_GET_REFRESH_TAG = (byte) 0xDF;
    private static final byte P2_GET_REFRESH_TAG = (byte) 0x20;

    private static final short MAX_RESPONSE_LENGTH = (short) 256;

    private static final short MAX_STORE_DATA_FIELD_LENGTH = (short) 0x7F;

    /**
     * Application-specific parameters tag. Some Security Domains forward the {@code C9}
     * TLV intact instead of only its value, so both spellings are accepted.
     */
    private static final byte TAG_APPLICATION_SPECIFIC_PARAMETERS = (byte) 0xC9;

    /** Proprietary capacity parameter: {@code 80 01 R}, R the active-rule capacity. */
    static final byte TAG_ACTIVE_RULE_CAPACITY = (byte) 0x80;

    private final AraMApplet logic;

    private AraMJCApplet(short activeRuleCapacity) {
        logic = new AraMApplet(activeRuleCapacity);
        register();
    }

    /**
     * Creates the instance with the capacity requested by the installation parameters.
     *
     * <p>Allocation happens once, inside the constructor: a malformed parameter block
     * throws before anything is allocated and the installation fails, and an oversized
     * request is clamped to the compiled maximum rather than honoured.
     */
    public static void install(byte[] installData, short offset, byte length) {
        new AraMJCApplet(resolveActiveRuleCapacity(installData, offset, length));
    }

    /**
     * Reads the active-rule capacity R out of the JCRE installation parameter array.
     *
     * <p>The array is the standard three LV fields — instance AID, privileges,
     * application-specific parameters. The application-specific block is either empty, or
     * the proprietary TLV {@code 80 01 R}, optionally still wrapped in its {@code C9}
     * container. An absent block yields {@link AraMApplet#DEFAULT_ACTIVE_RULE_CAPACITY}, a
     * request above {@link AraMApplet#MAX_ACTIVE_RULE_CAPACITY} is clamped to that maximum,
     * and anything that does not parse throws {@code 6A80} so the installation fails
     * loudly instead of silently falling back to a capacity nobody asked for.
     */
    static short resolveActiveRuleCapacity(byte[] installData, short offset, byte length) {
        short remaining = (short) (length & (short) 0x00FF);
        if (remaining == (short) 0) {
            return AraMApplet.DEFAULT_ACTIVE_RULE_CAPACITY;
        }
        if (installData == null || offset < (short) 0) {
            malformed();
        }
        short end = (short) (offset + remaining);
        if (end < offset || end > (short) installData.length) {
            malformed();
        }

        short cursor = skipLengthValue(installData, offset, end);
        cursor = skipLengthValue(installData, cursor, end);

        if (cursor >= end) {
            malformed();
        }
        short parametersLength = (short) (installData[cursor++] & (short) 0x00FF);
        short parametersEnd = (short) (cursor + parametersLength);
        // Trailing bytes after the application-specific block are tolerated: JCRE
        // implementations differ on what, if anything, they append to the array.
        if (parametersEnd < cursor || parametersEnd > end) {
            malformed();
        }
        return parseCapacityParameters(installData, cursor, parametersEnd);
    }

    private static short parseCapacityParameters(byte[] data, short offset, short end) {
        short cursor = offset;
        short blockEnd = end;
        if (cursor < blockEnd && data[cursor] == TAG_APPLICATION_SPECIFIC_PARAMETERS) {
            cursor++;
            if (cursor >= blockEnd) {
                malformed();
            }
            short containerLength = (short) (data[cursor++] & (short) 0x00FF);
            blockEnd = (short) (cursor + containerLength);
            // The C9 container must consume the whole application-specific block.
            // Bytes trailing the container inside the block are rejected exactly
            // like trailing bytes after the bare capacity TLV: 6A80, no silent drop.
            if (blockEnd < cursor || blockEnd != end) {
                malformed();
            }
        }
        if (cursor == blockEnd) {
            return AraMApplet.DEFAULT_ACTIVE_RULE_CAPACITY;
        }

        if (data[cursor] != TAG_ACTIVE_RULE_CAPACITY) {
            malformed();
        }
        cursor++;
        if (cursor >= blockEnd) {
            malformed();
        }
        short valueLength = (short) (data[cursor++] & (short) 0x00FF);
        if (valueLength != (short) 1 || (short) (cursor + (short) 1) != blockEnd) {
            malformed();
        }

        short requested = (short) (data[cursor] & (short) 0x00FF);
        if (requested < (short) 1) {
            malformed();
        }
        if (requested > AraMApplet.MAX_ACTIVE_RULE_CAPACITY) {
            return AraMApplet.MAX_ACTIVE_RULE_CAPACITY;
        }
        return requested;
    }

    private static short skipLengthValue(byte[] data, short cursor, short end) {
        if (cursor >= end) {
            malformed();
        }
        short fieldLength = (short) (data[cursor++] & (short) 0x00FF);
        short fieldEnd = (short) (cursor + fieldLength);
        if (fieldEnd < cursor || fieldEnd > end) {
            malformed();
        }
        return fieldEnd;
    }

    private static void malformed() {
        ISOException.throwIt(ISO7816.SW_WRONG_DATA);
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

    @Override
    public void deselect() {
        logic.clearReadSession();
    }

    /**
     * Receives authenticated STORE DATA from the Security Domain personalization flow.
     *
     * <p>The Security Domain forwards only the STORE DATA command data field: {@code data}
     * may be the underlying APDU buffer, with {@code offset} at the first data byte and
     * {@code length} equal to Lc. Physically confirmed on CARD#5, whose SD passes
     * {@code offset == ISO7816.OFFSET_CDATA}. The APDU header (CLA/INS/P1/P2/Lc) is
     * consumed by the SD and is never visible here, so block-chaining P1 cannot be
     * checked; a fragment of a chained command fails command-DO parsing without mutation.
     */
    @Override
    public void processData(byte[] data, short offset, short length) {
        storePersonalizationData(logic, data, offset, length);
    }

    static void storePersonalizationData(
            AraMApplet logic, byte[] data, short offset, short length) {
        if (offset < (short) 0
                || length < (short) 1
                || (short) (offset + length) < offset
                || (short) (offset + length) > (short) data.length) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        if (length > MAX_STORE_DATA_FIELD_LENGTH) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        logic.store(data, offset, length);
    }

    private void processGetData(APDU apdu, byte[] buffer) {
        byte p1 = buffer[ISO7816.OFFSET_P1];
        byte p2 = buffer[ISO7816.OFFSET_P2];
        if (!isSupportedGetDataObject(p1, p2)) {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }

        short maximumLength = apdu.setOutgoingNoChaining();
        if (maximumLength > MAX_RESPONSE_LENGTH) {
            maximumLength = MAX_RESPONSE_LENGTH;
        }
        if (maximumLength > (short) buffer.length) {
            maximumLength = (short) buffer.length;
        }

        byte logicalChannel = logicalChannel(buffer[ISO7816.OFFSET_CLA]);
        short responseLength;

        if (p1 == P1_GET_ALL && p2 == P2_GET_ALL) {
            responseLength =
                    logic.writeAllRules(
                            buffer, (short) 0, maximumLength, logicalChannel);
        } else if (p1 == P1_GET_ALL && p2 == P2_GET_NEXT) {
            responseLength =
                    logic.writeNextRules(
                            buffer, (short) 0, maximumLength, logicalChannel);
        } else if (p1 == P1_GET_REFRESH_TAG && p2 == P2_GET_REFRESH_TAG) {
            responseLength = logic.writeRefreshTag(buffer, (short) 0);
        } else {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
            return;
        }

        apdu.setOutgoingLength(responseLength);
        apdu.sendBytes((short) 0, responseLength);
    }

    private static boolean isSupportedGetDataObject(byte p1, byte p2) {
        return (p1 == P1_GET_ALL && (p2 == P2_GET_ALL || p2 == P2_GET_NEXT))
                || (p1 == P1_GET_REFRESH_TAG && p2 == P2_GET_REFRESH_TAG);
    }

    private static byte logicalChannel(byte cla) {
        if ((cla & (byte) 0x40) == (byte) 0) {
            return (byte) (cla & (byte) 0x03);
        }
        return (byte) ((cla & (byte) 0x0F) + (byte) 4);
    }

    private static boolean isSupportedClass(byte cla) {
        byte category = (byte) (cla & (byte) 0xF0);
        return category == (byte) 0x80
                || category == (byte) 0xC0
                || category == (byte) 0xE0;
    }
}
