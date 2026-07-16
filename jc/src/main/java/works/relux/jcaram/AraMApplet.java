package works.relux.jcaram;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.RandomData;

/**
 * Single-rule ARA-M storage and BER-TLV codec.
 *
 * <p>The validated REF-AR-DO is stored verbatim. This keeps the phase-1 empty
 * DeviceAppID rule and future SHA-1/SHA-256 DeviceAppID rules on the same
 * persistent representation.
 */
final class AraMApplet {

    static final short MAX_REF_AR_DO_LENGTH = (short) 96;

    private static final short REFRESH_TAG_LENGTH = (short) 8;

    private static final byte TAG_COMMAND_STORE_REF_AR_DO = (byte) 0xF0;
    private static final byte TAG_REF_AR_DO = (byte) 0xE2;
    private static final byte TAG_REF_DO = (byte) 0xE1;
    private static final byte TAG_AID_REF_DO = (byte) 0x4F;
    private static final byte TAG_DEVICE_APP_ID_REF_DO = (byte) 0xC1;
    private static final byte TAG_AR_DO = (byte) 0xE3;
    private static final byte TAG_APDU_AR_DO = (byte) 0xD0;

    private final byte[] rule;
    private short ruleLength;
    private final byte[] refreshTag;
    private final byte[] nextRefreshTag;
    private final RandomData random;

    AraMApplet() {
        rule = new byte[MAX_REF_AR_DO_LENGTH];
        ruleLength = (short) 0;
        refreshTag = new byte[REFRESH_TAG_LENGTH];
        nextRefreshTag =
                JCSystem.makeTransientByteArray(
                        REFRESH_TAG_LENGTH, JCSystem.CLEAR_ON_DESELECT);
        random = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
        random.generateData(refreshTag, (short) 0, REFRESH_TAG_LENGTH);
    }

    short writeAllRules(byte[] output, short offset) {
        short cursor = offset;
        output[cursor++] = (byte) 0xFF;
        output[cursor++] = (byte) 0x40;
        output[cursor++] = (byte) ruleLength;

        if (ruleLength > (short) 0) {
            Util.arrayCopyNonAtomic(
                    rule, (short) 0, output, cursor, ruleLength);
            cursor += ruleLength;
        }
        return (short) (cursor - offset);
    }

    short writeRefreshTag(byte[] output, short offset) {
        short cursor = offset;
        output[cursor++] = (byte) 0xDF;
        output[cursor++] = (byte) 0x20;
        output[cursor++] = (byte) REFRESH_TAG_LENGTH;
        Util.arrayCopyNonAtomic(
                refreshTag,
                (short) 0,
                output,
                cursor,
                REFRESH_TAG_LENGTH);
        cursor += REFRESH_TAG_LENGTH;
        return (short) (cursor - offset);
    }

    void store(byte[] input, short offset, short length) {
        short commandEnd = checkedEnd(offset, length, (short) input.length);
        short cursor = offset;

        cursor = requireTag(input, cursor, commandEnd, TAG_COMMAND_STORE_REF_AR_DO);
        short commandValueLength = readLength(input, cursor, commandEnd);
        cursor++;
        short commandValueEnd = checkedEnd(cursor, commandValueLength, commandEnd);
        if (commandValueEnd != commandEnd) {
            malformed();
        }

        short refArDoOffset = cursor;
        cursor = requireTag(input, cursor, commandValueEnd, TAG_REF_AR_DO);
        short refArDoValueLength = readLength(input, cursor, commandValueEnd);
        cursor++;
        short refArDoValueOffset = cursor;
        short refArDoEnd = checkedEnd(cursor, refArDoValueLength, commandValueEnd);
        if (refArDoEnd != commandValueEnd) {
            malformed();
        }

        short refArDoLength = (short) (refArDoEnd - refArDoOffset);
        if (refArDoLength > MAX_REF_AR_DO_LENGTH) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }

        validateRefArDo(input, refArDoValueOffset, refArDoEnd);
        prepareNextRefreshTag();

        JCSystem.beginTransaction();
        Util.arrayCopy(
                input,
                refArDoOffset,
                rule,
                (short) 0,
                refArDoLength);
        ruleLength = refArDoLength;
        Util.arrayCopy(
                nextRefreshTag,
                (short) 0,
                refreshTag,
                (short) 0,
                REFRESH_TAG_LENGTH);
        JCSystem.commitTransaction();
    }

    private static void validateRefArDo(byte[] input, short offset, short end) {
        short cursor = offset;

        cursor = requireTag(input, cursor, end, TAG_REF_DO);
        short refDoLength = readLength(input, cursor, end);
        cursor++;
        short refDoEnd = checkedEnd(cursor, refDoLength, end);

        cursor = requireTag(input, cursor, refDoEnd, TAG_AID_REF_DO);
        short aidLength = readLength(input, cursor, refDoEnd);
        cursor++;
        if (aidLength != (short) 0
                && (aidLength < (short) 5 || aidLength > (short) 16)) {
            malformed();
        }
        cursor = checkedEnd(cursor, aidLength, refDoEnd);

        cursor = requireTag(input, cursor, refDoEnd, TAG_DEVICE_APP_ID_REF_DO);
        short deviceAppIdLength = readLength(input, cursor, refDoEnd);
        cursor++;
        if (deviceAppIdLength != (short) 0
                && deviceAppIdLength != (short) 20
                && deviceAppIdLength != (short) 32) {
            malformed();
        }
        cursor = checkedEnd(cursor, deviceAppIdLength, refDoEnd);
        if (cursor != refDoEnd) {
            malformed();
        }

        cursor = refDoEnd;
        cursor = requireTag(input, cursor, end, TAG_AR_DO);
        short arDoLength = readLength(input, cursor, end);
        cursor++;
        short arDoEnd = checkedEnd(cursor, arDoLength, end);

        cursor = requireTag(input, cursor, arDoEnd, TAG_APDU_AR_DO);
        short apduArLength = readLength(input, cursor, arDoEnd);
        cursor++;
        if (apduArLength == (short) 1) {
            if (cursor >= arDoEnd) {
                malformed();
            }
            byte genericRule = input[cursor];
            if (genericRule != (byte) 0x00 && genericRule != (byte) 0x01) {
                malformed();
            }
        } else if (apduArLength == (short) 0
                || (short) (apduArLength % (short) 8) != (short) 0) {
            malformed();
        }
        cursor = checkedEnd(cursor, apduArLength, arDoEnd);

        if (cursor != arDoEnd || arDoEnd != end) {
            malformed();
        }
    }

    private void prepareNextRefreshTag() {
        random.generateData(
                nextRefreshTag, (short) 0, REFRESH_TAG_LENGTH);
        if (Util.arrayCompare(
                        nextRefreshTag,
                        (short) 0,
                        refreshTag,
                        (short) 0,
                        REFRESH_TAG_LENGTH)
                == (byte) 0) {
            short last = (short) (REFRESH_TAG_LENGTH - (short) 1);
            nextRefreshTag[last] ^= (byte) 0x01;
        }
    }

    private static short requireTag(byte[] input, short cursor, short end, byte expected) {
        if (cursor >= end || input[cursor] != expected) {
            malformed();
        }
        return (short) (cursor + (short) 1);
    }

    private static short readLength(byte[] input, short cursor, short end) {
        if (cursor >= end) {
            malformed();
        }
        byte encoded = input[cursor];
        if ((encoded & (byte) 0x80) != (byte) 0) {
            malformed();
        }
        return (short) (encoded & (byte) 0x7F);
    }

    private static short checkedEnd(short offset, short length, short limit) {
        if (length < (short) 0 || offset < (short) 0 || offset > limit) {
            malformed();
        }
        short end = (short) (offset + length);
        if (end < offset || end > limit) {
            malformed();
        }
        return end;
    }

    private static void malformed() {
        ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    }
}
