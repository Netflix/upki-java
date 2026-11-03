/*
 * Copyr *
 * Published lookup vectors are adapted from cpu/go-upki/crlite/crlite_test.go.
 * Copyright 2026 The Go Authors.
 * BSD-3-Clause; see the accompanying go-upki-LICENSE.
 */

package com.netflix.security.upki.test;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.channels.FileChannel;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Base64;
import java.util.Random;

import com.netflix.security.upki.clubcard.Clubcard;
import com.netflix.security.upki.clubcard.Clubcard.Key;
import com.netflix.security.upki.clubcard.Clubcard.Status;
import com.netflix.security.upki.clubcard.ClubcardReader;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

class ClubcardTest {
    private static final byte[] ID = new byte[32];
    private static final byte[] SERIAL = {0, (byte) 128};
    private static final Key KEY = new Key(ID, SERIAL);

    @TempDir
    Path directory;

    @Test
    void coveragePrecedesEnrollmentAndIncludesEndpoints() throws Exception {
        Clubcard card = read(
                filter(
                        false,
                        0,
                        0,
                        0,
                        0,
                        0,
                        new long[0],
                        new long[0],
                        new byte[0][]));
        assertEquals(Status.NOT_REVOKED, card.check(KEY, ID, 100));
        assertEquals(Status.NOT_REVOKED, card.check(KEY, ID, 200));
        assertEquals(Status.NOT_COVERED, card.check(KEY, ID, 99));
        assertEquals(Status.NOT_COVERED, card.check(KEY, ID, 201));
        byte[] other = ID.clone();
        other[31] = 1;
        assertEquals(Status.NOT_COVERED, card.check(KEY, other, 150));
        assertEquals(Status.NOT_ENROLLED, card.check(new Key(other, SERIAL), ID, 150));
    }

    @Test
    void zeroModulusAndInversionEncodeEmptyAndFullSets() throws Exception {
        for (boolean inverted : new boolean[] {false, true}) {
            Clubcard card = read(
                    filter(
                            inverted,
                            0,
                            0,
                            0,
                            0,
                            0,
                            new long[0],
                            new long[0],
                            new byte[0][]));
            assertEquals(inverted ? Status.REVOKED : Status.NOT_REVOKED, card.check(KEY, ID, 150));
        }
    }

    @Test
    void exceptionSerialsAreByteExactAndRespectInversion() throws Exception {
        for (boolean inverted : new boolean[] {false, true}) {
            Clubcard card = read(
                    filter(
                            inverted,
                            1,
                            0,
                            0,
                            0,
                            0,
                            new long[0],
                            new long[0],
                            new byte[][] {SERIAL}));
            assertEquals(inverted ? Status.REVOKED : Status.NOT_REVOKED, card.check(KEY, ID, 150));
            assertEquals(inverted ? Status.NOT_REVOKED : Status.REVOKED,
                    card.check(new Key(ID, new byte[] {(byte) 128}), ID, 150));
        }
    }

    @Test
    void approximateAndExactWindowsMatchIndependentBitwiseOracle() throws Exception {
        Random random = new Random(42);
        long[] column = new long[7];
        for (int i = 0; i < column.length; i++) {
            column[i] = random.nextLong();
        }
        long[] coefficients = coefficients(SERIAL);
        for (int row = 0; row < 450; row++) {
            for (boolean approximate : new boolean[] {false, true}) {
                Clubcard card = read(
                        filter(
                                false,
                                1,
                                approximate ? 1 : 0,
                                approximate ? row : 0,
                                approximate ? 0 : 1,
                                approximate ? 0 : row,
                                approximate ? column : new long[0],
                                approximate ? new long[0] : column,
                                new byte[0][]));
                assertEquals(parity(column, row, coefficients) == 0 ? Status.REVOKED : Status.NOT_REVOKED, card.check(KEY, ID, 150),
                        "row=" + row + ", approximate=" + approximate);
            }
        }
    }

    @Test
    void unsignedRemainderAndLargeOffsetsDoNotOverflow() throws Exception {
        long[] column = {-1, 0x123456789abcdef0L, 3, 7, 9};
        Clubcard card = read(filter(false, 3, 1, 0, 0, 0,
                column, new long[0], new byte[0][]));
        for (int i = 0; i < 100; i++) {
            byte[] serial = {(byte) i};
            long[] coefficients = coefficients(serial);
            long row = Long.remainderUnsigned(coefficients[3], 3);
            assertEquals(
                    parity(column, row, coefficients) == 0 ? Status.REVOKED : Status.NOT_REVOKED,
                    card.check(new Key(ID, serial), ID, 150));
        }
        card = read(filter(false, 0xffffffffL, 1, 0xffffffffL, 0xffffffffL, 0xffffffffL,
                column, column, new byte[0][]));
        assertEquals(Status.REVOKED, card.check(KEY, ID, 150));
    }

    @Test
    void coverageUsesUnsignedTimestamps() throws Exception {
        byte[] bytes = filter(
                false,
                0,
                0,
                0,
                0,
                0,
                new long[0],
                new long[0],
                new byte[0][]);
        ByteBuffer.wrap(bytes)
                .putLong(36, Long.MAX_VALUE)
                .putLong(44, -1);
        Clubcard card = read(bytes);
        assertEquals(Status.NOT_REVOKED, card.check(KEY, ID, Long.MIN_VALUE));
        assertEquals(Status.NOT_REVOKED, card.check(KEY, ID, -1));
        assertEquals(Status.NOT_COVERED, card.check(KEY, ID, 0));
    }

    @Test
    void nioReaderOwnsBytesAndDoesNotChangeCallerPositionOrOrder() throws Exception {
        byte[] encoded = filter(
                true,
                0,
                0,
                0,
                0,
                0,
                new long[0],
                new long[0],
                new byte[0][]);
        ByteBuffer input = ByteBuffer.allocateDirect(encoded.length + 3).order(ByteOrder.LITTLE_ENDIAN);
        input.position(3);
        input.put(encoded)
             .flip()
             .position(3);
        ByteBuffer view = input.asReadOnlyBuffer().order(ByteOrder.LITTLE_ENDIAN);
        Clubcard card = ClubcardReader.read(view);
        assertEquals(3, view.position());
        assertEquals(ByteOrder.LITTLE_ENDIAN, view.order());
        input.put(3, (byte) 0);
        assertEquals(Status.REVOKED, card.check(KEY, ID, 150));
        Path path = directory.resolve("test.filter");
        Files.write(path, encoded);
        assertEquals(Status.REVOKED, ClubcardReader.read(path).check(KEY, ID, 150));
    }

    @Test
    void keysOwnTheirIssuerAndSerialBytes() throws Exception {
        byte[] issuer = ID.clone();
        byte[] serial = SERIAL.clone();
        Key key = new Key(issuer, serial);
        issuer[0] = 1;
        serial[0] = 1;
        Clubcard card = read(
                filter(
                        false,
                        1,
                        0,
                        0,
                        0,
                        0,
                        new long[0],
                        new long[0],
                        new byte[][] {SERIAL}));
        assertEquals(Status.NOT_REVOKED, card.check(key, ID, 150));
    }

    @Test
    void rejectsEveryTruncatedPrefixAndTrailingBytes() throws Exception {
        byte[] valid = filter(
                false,
                1,
                1,
                0,
                1,
                0,
                new long[] {1, 2},
                new long[] {3},
                new byte[][] {SERIAL});
        for (int n = 0; n < valid.length; n++) {
            byte[] bytes = Arrays.copyOf(valid, n);
            assertThrows(IOException.class, () -> read(bytes), "length=" + n);
        }
        assertThrows(IOException.class, () -> read(Arrays.copyOf(valid, valid.length + 1)));
    }

    @Test
    void rejectsInvalidVersionReservedFlagInversionRankAndCounts() throws Exception {
        byte[] valid = filter(
                false,
                0,
                0,
                0,
                0,
                0,
                new long[0],
                new long[0],
                new byte[0][]);
        for (int[] mutation : new int[][] {{0, 3}, {1, 1}, {105, 2},
                {92, 1}}) {
            byte[] bytes = valid.clone();
            bytes[mutation[0]] = (byte) mutation[1];
            assertThrows(IOException.class, () -> read(bytes));
        }
        for (int offset : new int[] {52, 109}) {
            byte[] bytes = valid.clone();
            ByteBuffer.wrap(bytes).putInt(offset, -1);
            assertThrows(IOException.class, () -> read(bytes));
        }
    }

    @Test
    void rejectsDuplicateCoverageAndUnsortedOrDuplicateIssuers() throws Exception {
        byte[] valid = filter(
                false,
                0,
                0,
                0,
                0,
                0,
                new long[0],
                new long[0],
                new byte[0][]);
        byte[] coverage = insert(valid, 52, Arrays.copyOfRange(valid, 4, 52));
        ByteBuffer.wrap(coverage).putShort(2, (short) 2);
        assertThrows(IOException.class, () -> read(coverage));

        byte[] blocks = insert(valid, 108, Arrays.copyOfRange(valid, 56, 108));
        ByteBuffer.wrap(blocks).putInt(52, 2);
        assertThrows(IOException.class, () -> read(blocks));
        blocks[56] = (byte) 255;
        assertThrows(IOException.class, () -> read(blocks));
        blocks[56] = 0;
        blocks[108] = (byte) 255;
        assertEquals(Status.NOT_REVOKED, read(blocks).check(KEY, ID, 150));
    }

    @Test
    void checksEveryApproximateColumn() throws Exception {
        byte[] bytes = filter(
                false,
                1,
                1,
                0,
                0,
                0,
                new long[] {0},
                new long[0],
                new byte[0][]);
        ByteBuffer second = ByteBuffer.allocate(12)
                .putInt(1)
                .putLong(1);
        bytes = insert(bytes, 121, second.array());
        bytes[92] = 2;
        bytes[108] = 2;
        assertEquals(Status.NOT_REVOKED, read(bytes).check(KEY, ID, 150));
    }

    @Test
    void boundsCoverageAndExceptionCountsAndRejectsEmptyExceptionSerials() throws Exception {
        byte[] valid = filter(
                false,
                1,
                0,
                0,
                0,
                0,
                new long[0],
                new long[0],
                new byte[][] {SERIAL});
        for (int offset : new int[] {2, 106}) {
            byte[] bytes = valid.clone();
            ByteBuffer.wrap(bytes).putShort(offset, (short) -1);
            assertThrows(IOException.class, () -> read(bytes));
        }
        valid[108] = 0;
        assertThrows(IOException.class, () -> read(valid));
    }

    @Test
    void rejectsFilesTooLargeForByteBufferBeforeAllocating() throws Exception {
        Path path = directory.resolve("oversized.filter");
        try (FileChannel channel = FileChannel.open(path, StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE)) {
            channel.write(ByteBuffer.wrap(new byte[] {0}), Integer.MAX_VALUE);
        }
        assertThrows(IOException.class, () -> ClubcardReader.read(path));
    }

    @Test
    void mutatedInputsDoNotEscapeAsUncheckedParserFailures() throws Exception {
        byte[] valid = filter(
                false,
                1,
                1,
                0,
                1,
                0,
                new long[] {1, 2},
                new long[] {3},
                new byte[][] {SERIAL});
        Random random = new Random(73);
        for (int i = 0; i < 1000; i++) {
            byte[] bytes = valid.clone();
            bytes[random.nextInt(bytes.length)] ^= (byte) (1 << random.nextInt(8));
            try {
                read(bytes).check(KEY, ID, 150);
            } catch (IOException malformed) {
                // Invalid wire encodings are the expected parser error channel.
            }
        }
    }

    @Test
    void validatesLookupKeyAndLogIdentifierLengths() throws Exception {
        assertThrows(IllegalArgumentException.class, () -> new Key(new byte[31], SERIAL));
        assertThrows(IllegalArgumentException.class, () -> new Key(ID, new byte[0]));
        Clubcard card = read(
                filter(
                        false,
                        0,
                        0,
                        0,
                        0,
                        0,
                        new long[0],
                        new long[0],
                        new byte[0][]));
        assertThrows(IllegalArgumentException.class, () -> card.check(KEY, new byte[33], 150));
    }

    @Test
    void emptyFilterHasNoCoverage() throws Exception {
        ByteBuffer bytes = ByteBuffer.allocate(13);
        bytes.put((byte) 4)
             .put((byte) 0)
             .putShort((short) 0)
             .putInt(0)
             .put((byte) 0)
             .putInt(0)
             .flip();
        assertEquals(Status.NOT_COVERED, ClubcardReader.read(bytes).check(KEY, ID, 150));
    }

    @Test
    void reversedCoverageCoversNothing() throws Exception {
        byte[] bytes = filter(
                true,
                0,
                0,
                0,
                0,
                0,
                new long[0],
                new long[0],
                new byte[0][]);
        ByteBuffer.wrap(bytes)
                .putLong(36, 200)
                .putLong(44, 100);
        Clubcard card = read(bytes);
        for (long timestamp : new long[] {0, 100, 150, 200, -1}) {
            assertEquals(Status.NOT_COVERED, card.check(KEY, ID, timestamp));
        }
    }

    @Test
    void emptyColumnsAreImplicitlyZero() throws Exception {
        Clubcard card = read(
                filter(
                        false,
                        1,
                        1,
                        0,
                        1,
                        0,
                        new long[0],
                        new long[0],
                        new byte[0][]));
        assertEquals(Status.REVOKED, card.check(KEY, ID, 150));
    }

    @Test
    void matchesPublishedUpkiVectors() throws Exception {
        String fixture = System.getenv("UPKI_TEST_FILTER");
        assumeTrue(fixture != null, "Set UPKI_TEST_FILTER to 20260624-1-default.filter.delta");
        Clubcard card = ClubcardReader.read(Paths.get(fixture));
        assertEquals(
                Status.NOT_REVOKED,
                card.check(new Key(decode("LsOdqDFw3goo/G8jjeEPxe+JSJ7aFp1RF5Ih4/2ZvFY="), decode("Dkb521uxnu6ORfLc3CYMyg==")),
                        decode("1219ENGn9XfCx+lf1wC/+YLJM1pl4dCzAXMXwMjFaXc="), 1781427700550L));
        assertEquals(
                Status.REVOKED,
                card.check(new Key(decode("OdSlmQD9NWJh4EbcOHBxkhygPwNSwA9Q91eounfbcoE="), decode("APpDYjsNxwPIEFP8ZGvsOiA=")),
                        decode("1219ENGn9XfCx+lf1wC/+YLJM1pl4dCzAXMXwMjFaXc="), 1782115694514L));
    }

    private static byte[] insert(byte[] original, int offset, byte[] addition) {
        return ByteBuffer.allocate(original.length + addition.length)
                .put(original, 0, offset)
                .put(addition)
                .put(original, offset, original.length - offset)
                .array();
    }

    private static byte[] decode(String value) {
        return Base64.getDecoder().decode(value);
    }

    private static Clubcard read(byte[] bytes) throws IOException {
        return ClubcardReader.read(ByteBuffer.wrap(bytes));
    }

    private static long[] coefficients(byte[] serial) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        digest.update(ID);
        ByteBuffer hash = ByteBuffer.wrap(digest.digest(serial)).order(ByteOrder.LITTLE_ENDIAN);
        long[] words = {hash.getLong(), hash.getLong(), hash.getLong(),
                hash.getLong()};
        words[0] |= 1;
        return words;
    }

    private static int parity(long[] column, long row, long[] coefficients) {
        int parity = 0;
        for (int bit = 0; bit < 256; bit++) {
            long source = row + bit;
            if (source / 64 < column.length) {
                parity ^= (int) (((column[(int) (source / 64)] >>> (source % 64)) & (coefficients[bit / 64] >>> (bit % 64))) & 1);
            }
        }
        return parity;
    }

    private static byte[] filter(
            boolean inverted,
            long m,
            int rank,
            long offset,
            long exactM,
            long exactOffset,
            long[] approximate,
            long[] exact,
            byte[][] exceptions) {
        ByteBuffer bytes = ByteBuffer.allocate(16384);
        bytes.put((byte) 4)
             .put((byte) 0)
             .putShort((short) 1)
             .put(ID)
             .putLong(100)
             .putLong(200);
        bytes.putInt(1)
             .put(ID)
             .putInt((int) m)
             .put((byte) rank)
             .putInt((int) offset)
             .putInt((int) exactM)
             .putInt((int) exactOffset)
             .put((byte) (inverted ? 1 : 0))
             .putShort((short) exceptions.length);
        for (byte[] serial : exceptions) {
            bytes.put((byte) serial.length).put(serial);
        }
        bytes.put((byte) (rank == 0 ? 0 : 1));
        if (rank != 0) {
            column(bytes, approximate);
        }
        column(bytes, exact);
        return Arrays.copyOf(bytes.array(), bytes.position());
    }

    private static void column(ByteBuffer bytes, long[] column) {
        bytes.putInt(column.length);
        for (long word : column) {
            bytes.putLong(word);
        }
    }
}
