/*
 * Copyright 2026 Netflix, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License. You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License
 * is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
 * or implied. See the License for the specific language governing permissions and limitations under
 * the License.
 */

package com.netflix.security.upki.test;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.Arrays;
import java.util.Collections;

import com.netflix.security.upki.cache.RevocationIndex;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class RevocationIndexTest {
    @TempDir
    Path directory;

    @Test
    void findsEveryCoveringFilterIncludingOverlappingIntervals() throws Exception {
        write(
                index(new String[] {"a.filter", "b.delta"},
                        log(1, entry(0, 10, 20), entry(1, 15, 30))));
        try (RevocationIndex index = RevocationIndex.open(directory)) {
            assertEquals(Arrays.asList("a.filter", "b.delta"), index.lookup(id(1), 15));
            assertEquals(Collections.singletonList("a.filter"), index.lookup(id(1), 10));
            assertEquals(Arrays.asList("a.filter", "b.delta"), index.lookup(id(1), 20));
            assertEquals(Collections.singletonList("b.delta"), index.lookup(id(1), 30));
            assertEquals(Collections.emptyList(), index.lookup(id(1), 9));
            assertEquals(Collections.emptyList(), index.lookup(id(1), 31));
        }
    }

    @Test
    void deduplicatesFilterNames() throws Exception {
        write(index(new String[] {"a.filter"},
                log(1, entry(0, 0, 20), entry(0, 10, 30))));
        try (RevocationIndex index = RevocationIndex.open(directory)) {
            assertEquals(Collections.singletonList("a.filter"), index.lookup(id(1), 15));
        }
    }

    @Test
    void binarySearchUsesUnsignedLogIdentifiers() throws Exception {
        write(
                index(new String[] {"a"}, log(0, entry(0, 0, 10)), log(127),
                        log(128), log(255, entry(0, 0, 10))));
        try (RevocationIndex index = RevocationIndex.open(directory)) {
            assertEquals(Collections.singletonList("a"), index.lookup(id(0), 0));
            assertEquals(Collections.singletonList("a"), index.lookup(id(255), 10));
            assertEquals(Collections.emptyList(), index.lookup(id(129), 5));
        }
    }

    @Test
    void comparesTimestampsAsUnsignedIntegers() throws Exception {
        write(index(new String[] {"a"}, log(1, entry(0, Long.MAX_VALUE, -1))));
        try (RevocationIndex index = RevocationIndex.open(directory)) {
            assertEquals(Collections.singletonList("a"), index.lookup(id(1), Long.MIN_VALUE));
            assertEquals(Collections.singletonList("a"), index.lookup(id(1), -1));
            assertEquals(Collections.emptyList(), index.lookup(id(1), 0));
        }
    }

    @Test
    void acceptsEmptyIndexAndFullLengthFilename() throws Exception {
        write(index(new String[0]));
        try (RevocationIndex index = RevocationIndex.open(directory)) {
            assertEquals(Collections.emptyList(), index.lookup(id(0), 0));
        }
        String name = "01234567890123456789012345678901";
        write(index(new String[] {name}, log(1, entry(0, 0, 0))));
        try (RevocationIndex index = RevocationIndex.open(directory)) {
            assertEquals(Collections.singletonList(name), index.lookup(id(1), 0));
        }
    }

    @Test
    void rejectsBadMagicAndEveryTruncatedHeaderOrTable() throws Exception {
        byte[] valid = index(new String[] {"a"}, log(1, entry(0, 0, 1)));
        byte[] badMagic = valid.clone();
        badMagic[7] = '0';
        assertInvalid(badMagic);
        for (int length = 0; length < 88; length++) {
            assertInvalid(Arrays.copyOf(valid, length));
        }
    }

    @Test
    void rejectsHugeCountsBeforeAllocatingTables() throws Exception {
        byte[] bytes = index(new String[0]);
        ByteBuffer.wrap(bytes).putInt(10, -1);
        assertInvalid(bytes);
        bytes = index(new String[0]);
        ByteBuffer.wrap(bytes).putShort(8, (short) -1);
        assertInvalid(bytes);
    }

    @Test
    void rejectsUnsafeAndNonAsciiFilenames() throws Exception {
        for (String name : Arrays.asList("", ".", "..", "../outside", "a/b", "a\\b",
                "a:b", "a b", "a\u007f")) {
            assertInvalid(index(new String[] {name}));
        }
        byte[] bytes = index(new String[] {"a"});
        bytes[14] = (byte) 0x80;
        assertInvalid(bytes);
    }

    @Test
    void rejectsNonzeroFilenamePadding() throws Exception {
        byte[] bytes = index(new String[] {"a"});
        bytes[16] = 'b';
        assertInvalid(bytes);
    }

    @Test
    void rejectsUnsortedAndDuplicateLogIdentifiers() throws Exception {
        assertInvalid(index(new String[0], log(2), log(1)));
        assertInvalid(index(new String[0], log(1), log(1)));
    }

    @Test
    void rejectsSectionsOutsideTheFileOrOverlappingMetadata() throws Exception {
        for (long offset : new long[] {0, 87, 89, Long.MAX_VALUE, Long.MIN_VALUE, -1}) {
            byte[] bytes = index(new String[] {"a"}, log(1, entry(0, 0, 1)));
            ByteBuffer.wrap(bytes).putLong(78, offset);
            assertInvalid(bytes);
        }
    }

    @Test
    void rejectsOverlappingLogSections() throws Exception {
        for (long offset : new long[] {130, 131, 147}) {
            byte[] bytes = index(new String[] {"a"}, log(1, entry(0, 0, 1)), log(2, entry(0, 0, 1)));
            ByteBuffer.wrap(bytes).putLong(120, offset);
            assertInvalid(bytes);
        }
    }

    @Test
    void rejectsOutOfRangeFilterIndexOnLookup() throws Exception {
        write(index(new String[] {"a"}, log(1, entry(1, 0, 1))));
        try (RevocationIndex index = RevocationIndex.open(directory)) {
            assertThrows(IOException.class, () -> index.lookup(id(1), 0));
        }
    }

    @Test
    void reversedIntervalsCoverNothingAsInTheReferenceImplementation() throws Exception {
        write(index(new String[] {"a"},
                log(1, entry(0, 2, 1), entry(0, -1, 0))));
        try (RevocationIndex index = RevocationIndex.open(directory)) {
            for (long timestamp : new long[] {0, 1, 2, Long.MAX_VALUE, Long.MIN_VALUE, -1}) {
                assertEquals(Collections.emptyList(), index.lookup(id(1), timestamp));
            }
        }
    }

    @Test
    void rejectsTruncatedEntryReadAfterOpening() throws Exception {
        write(index(new String[] {"a"}, log(1, entry(0, 0, 1))));
        try (RevocationIndex index = RevocationIndex.open(directory)) {
            Files.newByteChannel(directory.resolve("index.bin"), StandardOpenOption.WRITE)
                    .truncate(88)
                    .close();
            assertThrows(IOException.class, () -> index.lookup(id(1), 0));
        }
    }

    @Test
    void requiresExactlyThirtyTwoByteLogIdentifiers() throws Exception {
        write(index(new String[0]));
        try (RevocationIndex index = RevocationIndex.open(directory)) {
            assertThrows(IllegalArgumentException.class, () -> index.lookup(new byte[31], 0));
            assertThrows(IllegalArgumentException.class, () -> index.lookup(new byte[33], 0));
        }
    }

    @Test
    void allowsNonOverlappingSectionsInAnyPhysicalOrder() throws Exception {
        byte[] bytes = index(new String[] {"a", "b"}, log(1, entry(0, 0, 1)),
                log(2, entry(1, 0, 1)));
        ByteBuffer.wrap(bytes)
                .putLong(110, 180)
                .putLong(152, 162);
        write(bytes);
        try (RevocationIndex index = RevocationIndex.open(directory)) {
            assertEquals(Collections.singletonList("b"), index.lookup(id(1), 0));
            assertEquals(Collections.singletonList("a"), index.lookup(id(2), 0));
        }
    }

    @Test
    void failsAfterCloseEvenWhenTheLogIsAbsent() throws Exception {
        write(index(new String[0]));
        RevocationIndex index = RevocationIndex.open(directory);
        index.close();
        assertThrows(IOException.class, () -> index.lookup(id(1), 0));
    }

    private void assertInvalid(byte[] bytes) throws IOException {
        write(bytes);
        assertThrows(IOException.class, () -> {
            try (RevocationIndex ignored = RevocationIndex.open(directory)) {
                throw new AssertionError("Malformed index accepted");
            }
        });
    }

    private void write(byte[] bytes) throws IOException {
        Files.write(directory.resolve("index.bin"), bytes);
    }

    private static byte[] index(String[] names, Log... logs) throws IOException {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        DataOutputStream out = new DataOutputStream(bytes);
        out.write("upkiidx1".getBytes(StandardCharsets.US_ASCII));
        out.writeShort(names.length);
        out.writeInt(logs.length);
        for (String name : names) {
            byte[] slot = new byte[32];
            byte[] encoded = name.getBytes(StandardCharsets.US_ASCII);
            System.arraycopy(encoded, 0, slot, 0, encoded.length);
            out.write(slot);
        }
        long offset = 14L + names.length * 32L + logs.length * 42L;
        for (Log log : logs) {
            out.write(log.id);
            out.writeLong(offset);
            out.writeShort(log.entries.length);
            offset += log.entries.length * 18L;
        }
        for (Log log : logs) {
            for (Entry entry : log.entries) {
                out.writeShort(entry.filter);
                out.writeLong(entry.min);
                out.writeLong(entry.max);
            }
        }
        return bytes.toByteArray();
    }

    private static byte[] id(int firstByte) {
        byte[] id = new byte[32];
        id[0] = (byte) firstByte;
        return id;
    }

    private static Log log(int id, Entry... entries) {
        return new Log(id(id), entries);
    }

    private static Entry entry(int filter, long min, long max) {
        return new Entry(filter, min, max);
    }

    private static final class Log {
        final byte[] id;
        final Entry[] entries;

        Log(byte[] id, Entry[] entries) {
            this.id = id;
            this.entries = entries;
        }
    }

    private static final class Entry {
        final int filter;
        final long min;
        final long max;

        Entry(int filter, long min, long max) {
            this.filter = filter;
            this.min = min;
            this.max = max;
        }
    }
}
