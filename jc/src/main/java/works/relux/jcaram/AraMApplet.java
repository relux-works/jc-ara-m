package works.relux.jcaram;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.RandomData;

/** Bounded multi-rule ARA-M catalog and authenticated mutation engine. */
final class AraMApplet {

    /** Installed active-rule capacity R from the accepted capacity profile. */
    static final short ACTIVE_RULE_CAPACITY = (short) 16;

    static final short MAX_REF_AR_DO_LENGTH = (short) 96;

    private static final short RECORD_LENGTH_BYTES = (short) 1;
    private static final short RECORD_SIZE =
            (short) (RECORD_LENGTH_BYTES + MAX_REF_AR_DO_LENGTH);
    private static final short RECORD_COUNT = (short) (ACTIVE_RULE_CAPACITY + (short) 1);
    private static final short ARENA_LENGTH = (short) (RECORD_COUNT * RECORD_SIZE);
    private static final short ACTIVE_BITMAP_LENGTH =
            (short) ((RECORD_COUNT + (short) 7) / (short) 8);
    private static final short REFRESH_TAG_LENGTH = (short) 8;
    private static final short PUBLICATION_COMMIT_BYTES =
            (short) (ACTIVE_BITMAP_LENGTH + REFRESH_TAG_LENGTH + (short) 2);
    private static final short JOINED_F0_COMMIT_BYTES =
            (short) (RECORD_SIZE + PUBLICATION_COMMIT_BYTES);

    private static final byte SCHEMA_VERSION = (byte) 1;

    private static final byte TAG_COMMAND_STORE_REF_AR_DO = (byte) 0xF0;
    private static final byte TAG_COMMAND_DELETE = (byte) 0xF1;
    private static final byte TAG_REF_AR_DO = (byte) 0xE2;
    private static final byte TAG_REF_DO = (byte) 0xE1;
    private static final byte TAG_AID_REF_DO = (byte) 0x4F;
    private static final byte TAG_DEVICE_APP_ID_REF_DO = (byte) 0xC1;
    private static final byte TAG_AR_DO = (byte) 0xE3;
    private static final byte TAG_APDU_AR_DO = (byte) 0xD0;
    private static final byte TAG_PERM_AR_DO = (byte) 0xDB;

    private static final short PERM_AR_DO_LENGTH = (short) 8;

    private static final short SW_DATA_OBJECT_NOT_SUPPORTED = (short) 0x6981;
    private static final short SW_REFERENCE_DATA_INVALID = (short) 0x6984;
    private static final short SW_NO_CURRENT_READ_SESSION = (short) 0x6985;
    private static final short SW_MEMORY_FAILURE = (short) 0x6581;
    private static final short SW_REFERENCE_DATA_NOT_FOUND = (short) 0x6A88;

    private static final short READ_SESSION_ACTIVE = (short) 0;
    private static final short READ_SESSION_CHANNEL = (short) 1;
    private static final short READ_SESSION_NEXT_OFFSET = (short) 2;
    private static final short READ_SESSION_TOTAL_LENGTH = (short) 4;
    private static final short READ_SESSION_REVISION = (short) 6;
    private static final short READ_SESSION_LENGTH = (short) 8;

    private final byte[] recordArena;
    private final byte[] activeBitmap;
    private final byte[] refreshTag;
    private short catalogRevision;
    private byte schemaVersion;

    private final byte[] nextBitmap;
    private final byte[] nextRefreshTag;
    private final byte[] candidateRecord;
    private final byte[] readSession;
    private final RandomData random;

    AraMApplet() {
        recordArena = new byte[ARENA_LENGTH];
        activeBitmap = new byte[ACTIVE_BITMAP_LENGTH];
        refreshTag = new byte[REFRESH_TAG_LENGTH];
        catalogRevision = (short) 0;
        schemaVersion = SCHEMA_VERSION;

        nextBitmap =
                JCSystem.makeTransientByteArray(
                        ACTIVE_BITMAP_LENGTH, JCSystem.CLEAR_ON_RESET);
        nextRefreshTag =
                JCSystem.makeTransientByteArray(
                        REFRESH_TAG_LENGTH, JCSystem.CLEAR_ON_RESET);
        candidateRecord =
                JCSystem.makeTransientByteArray(RECORD_SIZE, JCSystem.CLEAR_ON_RESET);
        readSession =
                JCSystem.makeTransientByteArray(READ_SESSION_LENGTH, JCSystem.CLEAR_ON_RESET);
        random = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
        random.generateData(refreshTag, (short) 0, REFRESH_TAG_LENGTH);
    }

    short writeAllRules(
            byte[] output, short offset, short maximumLength, byte logicalChannel) {
        if (isReadSessionActive()) {
            if (readSession[READ_SESSION_CHANNEL] != logicalChannel) {
                ISOException.throwIt(SW_REFERENCE_DATA_INVALID);
            }
            clearReadSession();
        }

        short valueLength = catalogValueLength();
        short headerLength = (short) ((short) 2 + berLengthSize(valueLength));
        short availableLength = availableOutputLength(output, offset, maximumLength);
        if (availableLength < headerLength) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }

        short cursor = offset;
        output[cursor++] = (byte) 0xFF;
        output[cursor++] = (byte) 0x40;
        cursor = (short) (cursor + writeBerLength(output, cursor, valueLength));

        short copied =
                writeCatalogSlice(
                        output,
                        cursor,
                        (short) 0,
                        (short) (availableLength - headerLength));
        short nextOffset = copied;
        if (nextOffset < valueLength) {
            startReadSession(logicalChannel, nextOffset, valueLength);
        } else {
            clearReadSession();
        }
        return (short) (headerLength + copied);
    }

    short writeNextRules(
            byte[] output, short offset, short maximumLength, byte logicalChannel) {
        if (!isReadSessionActive()) {
            ISOException.throwIt(SW_NO_CURRENT_READ_SESSION);
        }
        if (readSession[READ_SESSION_CHANNEL] != logicalChannel) {
            ISOException.throwIt(SW_REFERENCE_DATA_INVALID);
        }
        if (readSessionShort(READ_SESSION_REVISION) != catalogRevision) {
            clearReadSession();
            ISOException.throwIt(SW_REFERENCE_DATA_INVALID);
        }

        short nextOffset = readSessionShort(READ_SESSION_NEXT_OFFSET);
        short totalLength = readSessionShort(READ_SESSION_TOTAL_LENGTH);
        if (nextOffset < (short) 0 || nextOffset >= totalLength) {
            clearReadSession();
            ISOException.throwIt(SW_NO_CURRENT_READ_SESSION);
        }

        short availableLength = availableOutputLength(output, offset, maximumLength);
        if (availableLength == (short) 0) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        short remaining = (short) (totalLength - nextOffset);
        short chunkLength = availableLength < remaining ? availableLength : remaining;
        short copied = writeCatalogSlice(output, offset, nextOffset, chunkLength);
        if (copied != chunkLength) {
            clearReadSession();
            malformed();
        }

        nextOffset = (short) (nextOffset + copied);
        if (nextOffset == totalLength) {
            clearReadSession();
        } else {
            setReadSessionShort(READ_SESSION_NEXT_OFFSET, nextOffset);
        }
        return copied;
    }

    void clearReadSession() {
        Util.arrayFillNonAtomic(readSession, (short) 0, READ_SESSION_LENGTH, (byte) 0);
    }

    short writeRefreshTag(byte[] output, short offset) {
        checkedEnd(
                offset,
                (short) (REFRESH_TAG_LENGTH + (short) 3),
                (short) output.length);
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
        cursor = (short) (cursor + REFRESH_TAG_LENGTH);
        return (short) (cursor - offset);
    }

    void store(byte[] input, short offset, short length) {
        short commandEnd = checkedEnd(offset, length, (short) input.length);
        if (offset >= commandEnd) {
            malformed();
        }

        byte commandTag = input[offset];
        if (commandTag == TAG_COMMAND_STORE_REF_AR_DO) {
            upsert(input, offset, commandEnd);
            return;
        }
        if (commandTag == TAG_COMMAND_DELETE) {
            delete(input, offset, commandEnd);
            return;
        }
        ISOException.throwIt(SW_DATA_OBJECT_NOT_SUPPORTED);
    }

    private void upsert(byte[] input, short offset, short commandEnd) {
        short cursor = requireTag(input, offset, commandEnd, TAG_COMMAND_STORE_REF_AR_DO);
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

        short refDoOffset = refArDoValueOffset;
        short refDoEnd = validateRefDo(input, refDoOffset, refArDoEnd);
        validateArDo(input, refDoEnd, refArDoEnd);
        short refDoLength = (short) (refDoEnd - refDoOffset);

        short oldRecord = findExactRefDo(input, refDoOffset, refDoLength);
        if (oldRecord >= (short) 0
                && recordEquals(oldRecord, input, refArDoOffset, refArDoLength)) {
            return;
        }

        short activeCount = countActiveRecords();
        if (oldRecord < (short) 0 && activeCount >= ACTIVE_RULE_CAPACITY) {
            ISOException.throwIt(ISO7816.SW_FILE_FULL);
        }

        short candidateIndex = findInactiveRecord();
        if (candidateIndex < (short) 0) {
            malformed();
        }

        Util.arrayCopyNonAtomic(
                activeBitmap,
                (short) 0,
                nextBitmap,
                (short) 0,
                ACTIVE_BITMAP_LENGTH);
        if (oldRecord >= (short) 0) {
            setActive(nextBitmap, oldRecord, false);
        }
        setActive(nextBitmap, candidateIndex, true);
        prepareNextRefreshTag();
        short nextRevision = (short) (catalogRevision + (short) 1);

        boolean ownsTransaction = JCSystem.getTransactionDepth() == (byte) 0;
        if (ownsTransaction) {
            stageInactiveRecordNonAtomic(
                    candidateIndex, input, refArDoOffset, refArDoLength);
            ensureCommitCapacity(PUBLICATION_COMMIT_BYTES);
            publishMetadata(nextRevision, true);
            return;
        }

        prepareCandidateRecord(input, refArDoOffset, refArDoLength);
        ensureCommitCapacity(JOINED_F0_COMMIT_BYTES);
        try {
            Util.arrayCopy(
                    candidateRecord,
                    (short) 0,
                    recordArena,
                    recordOffset(candidateIndex),
                    RECORD_SIZE);
            publishMetadata(nextRevision, false);
        } catch (RuntimeException failure) {
            ISOException.throwIt(SW_MEMORY_FAILURE);
        }
    }

    private void delete(byte[] input, short offset, short commandEnd) {
        short cursor = requireTag(input, offset, commandEnd, TAG_COMMAND_DELETE);
        short commandValueLength = readLength(input, cursor, commandEnd);
        cursor++;
        short commandValueEnd = checkedEnd(cursor, commandValueLength, commandEnd);
        if (commandValueEnd != commandEnd) {
            malformed();
        }

        Util.arrayCopyNonAtomic(
                activeBitmap,
                (short) 0,
                nextBitmap,
                (short) 0,
                ACTIVE_BITMAP_LENGTH);

        short deletedCount;
        if (cursor == commandValueEnd) {
            deletedCount = clearAllActiveRecords();
            if (deletedCount == (short) 0) {
                return;
            }
        } else if (input[cursor] == TAG_AID_REF_DO) {
            deletedCount = clearRecordsByAid(input, cursor, commandValueEnd);
            if (deletedCount == (short) 0) {
                ISOException.throwIt(SW_REFERENCE_DATA_NOT_FOUND);
            }
        } else if (input[cursor] == TAG_REF_DO) {
            short refDoOffset = cursor;
            short refDoEnd = validateRefDo(input, refDoOffset, commandValueEnd);
            if (refDoEnd != commandValueEnd) {
                malformed();
            }
            deletedCount =
                    clearRecordByExactRefDo(
                            input,
                            refDoOffset,
                            (short) (refDoEnd - refDoOffset));
            if (deletedCount == (short) 0) {
                ISOException.throwIt(SW_REFERENCE_DATA_NOT_FOUND);
            }
        } else if (input[cursor] == TAG_REF_AR_DO) {
            ISOException.throwIt(SW_DATA_OBJECT_NOT_SUPPORTED);
            return;
        } else {
            malformed();
            return;
        }

        prepareNextRefreshTag();
        short nextRevision = (short) (catalogRevision + (short) 1);
        ensureCommitCapacity(PUBLICATION_COMMIT_BYTES);
        publishMetadata(nextRevision, JCSystem.getTransactionDepth() == (byte) 0);
    }

    private short clearAllActiveRecords() {
        short deletedCount = countActiveRecords();
        Util.arrayFillNonAtomic(
                nextBitmap, (short) 0, ACTIVE_BITMAP_LENGTH, (byte) 0);
        return deletedCount;
    }

    private short clearRecordsByAid(byte[] input, short aidTagOffset, short end) {
        short cursor = requireTag(input, aidTagOffset, end, TAG_AID_REF_DO);
        short aidLength = readLength(input, cursor, end);
        cursor++;
        if (aidLength < (short) 5 || aidLength > (short) 16) {
            malformed();
        }
        short aidValueOffset = cursor;
        cursor = checkedEnd(cursor, aidLength, end);
        if (cursor != end) {
            malformed();
        }

        short deletedCount = (short) 0;
        short recordIndex;
        for (recordIndex = (short) 0; recordIndex < RECORD_COUNT; recordIndex++) {
            if (isActive(activeBitmap, recordIndex)
                    && recordAidEquals(recordIndex, input, aidValueOffset, aidLength)) {
                setActive(nextBitmap, recordIndex, false);
                deletedCount++;
            }
        }
        return deletedCount;
    }

    private short clearRecordByExactRefDo(
            byte[] input, short refDoOffset, short refDoLength) {
        short recordIndex = findExactRefDo(input, refDoOffset, refDoLength);
        if (recordIndex < (short) 0) {
            return (short) 0;
        }
        setActive(nextBitmap, recordIndex, false);
        return (short) 1;
    }

    private short findExactRefDo(byte[] input, short refDoOffset, short refDoLength) {
        short match = (short) -1;
        short recordIndex;
        for (recordIndex = (short) 0; recordIndex < RECORD_COUNT; recordIndex++) {
            if (!isActive(activeBitmap, recordIndex)) {
                continue;
            }
            short payloadOffset = recordPayloadOffset(recordIndex);
            short recordLength = validatedRecordLength(recordIndex);
            short storedRefDoOffset = (short) (payloadOffset + (short) 2);
            short storedRefDoEnd =
                    validateRefDo(
                            recordArena,
                            storedRefDoOffset,
                            (short) (payloadOffset + recordLength));
            short storedRefDoLength = (short) (storedRefDoEnd - storedRefDoOffset);
            if (storedRefDoLength == refDoLength
                    && Util.arrayCompare(
                                    recordArena,
                                    storedRefDoOffset,
                                    input,
                                    refDoOffset,
                                    refDoLength)
                            == (byte) 0) {
                if (match >= (short) 0) {
                    malformed();
                }
                match = recordIndex;
            }
        }
        return match;
    }

    private boolean recordAidEquals(
            short recordIndex, byte[] input, short aidValueOffset, short aidLength) {
        short payloadOffset = recordPayloadOffset(recordIndex);
        short recordLength = validatedRecordLength(recordIndex);
        short recordEnd = (short) (payloadOffset + recordLength);
        short refDoOffset = (short) (payloadOffset + (short) 2);
        short refDoEnd = validateRefDo(recordArena, refDoOffset, recordEnd);

        short cursor = requireTag(recordArena, refDoOffset, refDoEnd, TAG_REF_DO);
        readLength(recordArena, cursor, refDoEnd);
        cursor++;
        cursor = requireTag(recordArena, cursor, refDoEnd, TAG_AID_REF_DO);
        short storedAidLength = readLength(recordArena, cursor, refDoEnd);
        cursor++;
        return storedAidLength == aidLength
                && Util.arrayCompare(
                                recordArena,
                                cursor,
                                input,
                                aidValueOffset,
                                aidLength)
                        == (byte) 0;
    }

    private boolean recordEquals(
            short recordIndex, byte[] input, short offset, short length) {
        if (validatedRecordLength(recordIndex) != length) {
            return false;
        }
        return Util.arrayCompare(
                        recordArena,
                        recordPayloadOffset(recordIndex),
                        input,
                        offset,
                        length)
                == (byte) 0;
    }

    private short catalogValueLength() {
        short valueLength = (short) 0;
        short activeCount = (short) 0;
        short recordIndex;
        for (recordIndex = (short) 0; recordIndex < RECORD_COUNT; recordIndex++) {
            if (isActive(activeBitmap, recordIndex)) {
                activeCount++;
                valueLength =
                        (short) (valueLength + validatedRecordLength(recordIndex));
                if (valueLength < (short) 0) {
                    malformed();
                }
            }
        }
        if (activeCount > ACTIVE_RULE_CAPACITY) {
            malformed();
        }
        return valueLength;
    }

    private short writeCatalogSlice(
            byte[] output, short outputOffset, short logicalOffset, short maximumLength) {
        checkedEnd(outputOffset, maximumLength, (short) output.length);
        if (logicalOffset < (short) 0) {
            malformed();
        }

        short logicalCursor = (short) 0;
        short outputCursor = outputOffset;
        short remaining = maximumLength;
        short recordIndex;
        for (recordIndex = (short) 0;
                recordIndex < RECORD_COUNT && remaining > (short) 0;
                recordIndex++) {
            if (!isActive(activeBitmap, recordIndex)) {
                continue;
            }

            short recordLength = validatedRecordLength(recordIndex);
            short recordEnd = (short) (logicalCursor + recordLength);
            if (logicalOffset < recordEnd) {
                short recordRelativeOffset = (short) 0;
                if (logicalOffset > logicalCursor) {
                    recordRelativeOffset = (short) (logicalOffset - logicalCursor);
                }
                short availableInRecord = (short) (recordLength - recordRelativeOffset);
                short copyLength =
                        availableInRecord < remaining ? availableInRecord : remaining;
                Util.arrayCopyNonAtomic(
                        recordArena,
                        (short) (recordPayloadOffset(recordIndex) + recordRelativeOffset),
                        output,
                        outputCursor,
                        copyLength);
                outputCursor = (short) (outputCursor + copyLength);
                remaining = (short) (remaining - copyLength);
                logicalOffset = (short) (logicalOffset + copyLength);
            }
            logicalCursor = recordEnd;
        }
        return (short) (outputCursor - outputOffset);
    }

    private void startReadSession(byte channel, short nextOffset, short totalLength) {
        readSession[READ_SESSION_CHANNEL] = channel;
        setReadSessionShort(READ_SESSION_NEXT_OFFSET, nextOffset);
        setReadSessionShort(READ_SESSION_TOTAL_LENGTH, totalLength);
        setReadSessionShort(READ_SESSION_REVISION, catalogRevision);
        readSession[READ_SESSION_ACTIVE] = (byte) 1;
    }

    private boolean isReadSessionActive() {
        return readSession[READ_SESSION_ACTIVE] != (byte) 0;
    }

    private short readSessionShort(short offset) {
        return Util.getShort(readSession, offset);
    }

    private void setReadSessionShort(short offset, short value) {
        Util.setShort(readSession, offset, value);
    }

    private static short availableOutputLength(
            byte[] output, short offset, short maximumLength) {
        if (maximumLength < (short) 0
                || offset < (short) 0
                || offset > (short) output.length) {
            malformed();
        }
        short available = (short) ((short) output.length - offset);
        return maximumLength < available ? maximumLength : available;
    }

    private static short berLengthSize(short valueLength) {
        if (valueLength < (short) 0) {
            malformed();
        }
        if (valueLength <= (short) 0x7F) {
            return (short) 1;
        }
        if (valueLength <= (short) 0xFF) {
            return (short) 2;
        }
        return (short) 3;
    }

    private static short writeBerLength(byte[] output, short offset, short valueLength) {
        short encodedLength = berLengthSize(valueLength);
        checkedEnd(offset, encodedLength, (short) output.length);
        if (encodedLength == (short) 1) {
            output[offset] = (byte) valueLength;
            return encodedLength;
        }
        if (encodedLength == (short) 2) {
            output[offset] = (byte) 0x81;
            output[(short) (offset + (short) 1)] = (byte) valueLength;
            return encodedLength;
        }
        output[offset] = (byte) 0x82;
        output[(short) (offset + (short) 1)] = (byte) (valueLength >> (short) 8);
        output[(short) (offset + (short) 2)] = (byte) valueLength;
        return encodedLength;
    }

    private short validatedRecordLength(short recordIndex) {
        short base = recordOffset(recordIndex);
        short recordLength = (short) (recordArena[base] & (short) 0x00FF);
        if (recordLength < (short) 4 || recordLength > MAX_REF_AR_DO_LENGTH) {
            malformed();
        }

        short payloadOffset = (short) (base + RECORD_LENGTH_BYTES);
        short recordEnd = (short) (payloadOffset + recordLength);
        short cursor = requireTag(recordArena, payloadOffset, recordEnd, TAG_REF_AR_DO);
        short valueLength = readLength(recordArena, cursor, recordEnd);
        cursor++;
        if (checkedEnd(cursor, valueLength, recordEnd) != recordEnd) {
            malformed();
        }
        short refDoEnd = validateRefDo(recordArena, cursor, recordEnd);
        validateArDo(recordArena, refDoEnd, recordEnd);
        return recordLength;
    }

    private short countActiveRecords() {
        short activeCount = (short) 0;
        short recordIndex;
        for (recordIndex = (short) 0; recordIndex < RECORD_COUNT; recordIndex++) {
            if (isActive(activeBitmap, recordIndex)) {
                activeCount++;
            }
        }
        if (activeCount > ACTIVE_RULE_CAPACITY) {
            malformed();
        }
        return activeCount;
    }

    private short findInactiveRecord() {
        short start = (short) (catalogRevision % RECORD_COUNT);
        if (start < (short) 0) {
            start = (short) -start;
        }
        short scanned;
        for (scanned = (short) 0; scanned < RECORD_COUNT; scanned++) {
            short recordIndex = (short) (start + scanned);
            if (recordIndex >= RECORD_COUNT) {
                recordIndex = (short) (recordIndex - RECORD_COUNT);
            }
            if (!isActive(activeBitmap, recordIndex)) {
                return recordIndex;
            }
        }
        return (short) -1;
    }

    private void stageInactiveRecordNonAtomic(
            short recordIndex, byte[] input, short offset, short length) {
        short base = recordOffset(recordIndex);
        try {
            recordArena[base] = (byte) 0;
            Util.arrayCopyNonAtomic(
                    input,
                    offset,
                    recordArena,
                    (short) (base + RECORD_LENGTH_BYTES),
                    length);
            recordArena[base] = (byte) length;
        } catch (RuntimeException failure) {
            ISOException.throwIt(SW_MEMORY_FAILURE);
        }
    }

    private void prepareCandidateRecord(byte[] input, short offset, short length) {
        Util.arrayFillNonAtomic(candidateRecord, (short) 0, RECORD_SIZE, (byte) 0);
        Util.arrayCopyNonAtomic(
                input,
                offset,
                candidateRecord,
                RECORD_LENGTH_BYTES,
                length);
        candidateRecord[0] = (byte) length;
    }

    private void prepareNextRefreshTag() {
        try {
            random.generateData(nextRefreshTag, (short) 0, REFRESH_TAG_LENGTH);
        } catch (RuntimeException failure) {
            ISOException.throwIt(SW_MEMORY_FAILURE);
        }
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

    private void ensureCommitCapacity(short required) {
        if (JCSystem.getUnusedCommitCapacity() < required) {
            ISOException.throwIt(SW_MEMORY_FAILURE);
        }
    }

    private void publishMetadata(short nextRevision, boolean ownsTransaction) {
        try {
            if (ownsTransaction) {
                JCSystem.beginTransaction();
            }
            Util.arrayCopy(
                    nextBitmap,
                    (short) 0,
                    activeBitmap,
                    (short) 0,
                    ACTIVE_BITMAP_LENGTH);
            Util.arrayCopy(
                    nextRefreshTag,
                    (short) 0,
                    refreshTag,
                    (short) 0,
                    REFRESH_TAG_LENGTH);
            catalogRevision = nextRevision;
            if (ownsTransaction) {
                JCSystem.commitTransaction();
            }
        } catch (RuntimeException failure) {
            if (ownsTransaction && JCSystem.getTransactionDepth() != (byte) 0) {
                try {
                    JCSystem.abortTransaction();
                } catch (RuntimeException abortFailure) {
                    // The original publication failure remains the externally visible error.
                }
            }
            ISOException.throwIt(SW_MEMORY_FAILURE);
        }
    }

    private static short validateRefDo(byte[] input, short offset, short end) {
        short cursor = requireTag(input, offset, end, TAG_REF_DO);
        short refDoLength = readLength(input, cursor, end);
        cursor++;
        short refDoEnd = checkedEnd(cursor, refDoLength, end);

        cursor = requireTag(input, cursor, refDoEnd, TAG_AID_REF_DO);
        short aidLength = readLength(input, cursor, refDoEnd);
        cursor++;
        if (aidLength < (short) 5 || aidLength > (short) 16) {
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
        return refDoEnd;
    }

    private static void validateArDo(byte[] input, short offset, short end) {
        short cursor = requireTag(input, offset, end, TAG_AR_DO);
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

        if (cursor != arDoEnd) {
            // SEAC member order: the optional PERM-AR-DO follows the APDU-AR-DO.
            cursor = requireTag(input, cursor, arDoEnd, TAG_PERM_AR_DO);
            short permArLength = readLength(input, cursor, arDoEnd);
            cursor++;
            if (permArLength != PERM_AR_DO_LENGTH) {
                malformed();
            }
            cursor = checkedEnd(cursor, permArLength, arDoEnd);
        }

        if (cursor != arDoEnd || arDoEnd != end) {
            malformed();
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

    private static short recordOffset(short recordIndex) {
        return (short) (recordIndex * RECORD_SIZE);
    }

    private static short recordPayloadOffset(short recordIndex) {
        return (short) (recordOffset(recordIndex) + RECORD_LENGTH_BYTES);
    }

    private static boolean isActive(byte[] bitmap, short recordIndex) {
        short byteIndex = (short) (recordIndex >> (short) 3);
        byte mask = (byte) ((short) 1 << (short) (recordIndex & (short) 7));
        return (bitmap[byteIndex] & mask) != (byte) 0;
    }

    private static void setActive(byte[] bitmap, short recordIndex, boolean active) {
        short byteIndex = (short) (recordIndex >> (short) 3);
        byte mask = (byte) ((short) 1 << (short) (recordIndex & (short) 7));
        if (active) {
            bitmap[byteIndex] = (byte) (bitmap[byteIndex] | mask);
        } else {
            bitmap[byteIndex] = (byte) (bitmap[byteIndex] & (byte) ~mask);
        }
    }

    private static void malformed() {
        ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    }
}
