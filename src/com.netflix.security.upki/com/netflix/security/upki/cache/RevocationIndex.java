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

package com.netflix.security.upki.cache;

import java.io.Closeable;
import java.io.EOFException;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.ClosedChannelException;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map.Entry;
import java.util.Objects;
import java.util.TreeMap;

/**
 * A seek-based reader for the C2SP upkiidx1 cache index.
 *
 * <p>The opened file is retained so atomic replacement cannot mix index generations.
 * Calls use positional reads and do not share mutable buffers.
 */
public final class RevocationIndex implements Closeable {
    private static final int HEADER_SIZE = 14;
    private static final int FILENAME_SIZE = 32;
    private static final int LOG_SIZE = 42;
    private static final int ENTRY_SIZE = 18;
    private static final byte[] MAGIC = "upkiidx1".getBytes(StandardCharsets.US_ASCII);

    private final FileChannel channel;
    private final String[] filenames;
    private final long logCount;
    private final long logsOffset;

    private RevocationIndex(FileChannel channel, String[] filenames, long logCount,
                            long logsOffset) {
        this.channel = channel;
        this.filenames = filenames;
        this.logCount = logCount;
        this.logsOffset = logsOffset;
    }

    /** Opens and validates the metadata of the index in the given cache directory. */
    public static RevocationIndex open(Path directory) throws IOException {
        FileChannel channel = FileChannel.open(directory.resolve("index.bin"), StandardOpenOption.READ);
        boolean initialized = false;
        try {
            ByteBuffer header = ByteBuffer.allocate(HEADER_SIZE);
            read(channel, header, 0);
            byte[] magic = new byte[MAGIC.length];
            header.get(magic);
            if (!Arrays.equals(magic, MAGIC)) {
                throw invalid("unsupported magic");
            }
            int filenameCount = Short.toUnsignedInt(header.getShort());
            long logCount = Integer.toUnsignedLong(header.getInt());
            long logsOffset = HEADER_SIZE + (long) filenameCount * FILENAME_SIZE;
            long tablesEnd = logsOffset + logCount * LOG_SIZE;
            long fileSize = channel.size();
            if (tablesEnd > fileSize) {
                throw invalid("truncated metadata tables");
            }

            // uint16 bounds this allocation to just under 2 MiB, independently of log counts.
            ByteBuffer names = ByteBuffer.allocate(filenameCount * FILENAME_SIZE);
            read(channel, names, HEADER_SIZE);
            String[] filenames = new String[filenameCount];
            for (int i = 0; i < filenameCount; i++) {
                filenames[i] = filename(names, i * FILENAME_SIZE);
            }
            validateLogs(channel, logsOffset, logCount, tablesEnd, fileSize);
            RevocationIndex index = new RevocationIndex(channel, filenames, logCount, logsOffset);
            initialized = true;
            return index;
        } finally {
            if (!initialized) {
                channel.close();
            }
        }
    }

    /**
     * Returns distinct covering filter names in entry order.
     *
     * @param logId the raw 32-byte CT log identifier
     * @param timestamp an unsigned 64-bit SCT timestamp, represented in a Java long
     */
    public List<String> lookup(byte[] logId, long timestamp) throws IOException {
        Objects.requireNonNull(logId, "logId");
        if (logId.length != 32) {
            throw new IllegalArgumentException("A CT log identifier must contain 32 bytes");
        }
        if (!channel.isOpen()) {
            throw new ClosedChannelException();
        }

        ByteBuffer log = ByteBuffer.allocate(LOG_SIZE);
        long low = 0;
        long high = logCount;
        while (low < high) {
            long mid = low + (high - low) / 2;
            read(channel, log, logsOffset + mid * LOG_SIZE);
            int order = compare(log, logId);
            if (order < 0) {
                low = mid + 1;
            } else if (order > 0) {
                high = mid;
            } else {
                return entries(log.getLong(32), Short.toUnsignedInt(log.getShort(40)), timestamp);
            }
        }
        return new ArrayList<String>();
    }

    private List<String> entries(long offset, int count, long timestamp) throws IOException {
        ByteBuffer entries = ByteBuffer.allocate(count * ENTRY_SIZE);
        read(channel, entries, offset);
        LinkedHashSet<String> matching = new LinkedHashSet<String>();
        for (int i = 0; i < count; i++) {
            int filter = Short.toUnsignedInt(entries.getShort());
            long min = entries.getLong();
            long max = entries.getLong();
            if (filter >= filenames.length) {
                throw invalid("filter index out of range");
            }
            if (Long.compareUnsigned(min, timestamp) <= 0 && Long.compareUnsigned(timestamp, max) <= 0) {
                matching.add(filenames[filter]);
            }
        }
        return new ArrayList<String>(matching);
    }

    private static String filename(ByteBuffer names, int offset) throws IOException {
        int length = 0;
        boolean padding = false;
        for (int i = 0; i < FILENAME_SIZE; i++) {
            int ch = Byte.toUnsignedInt(names.get(offset + i));
            if (ch == 0) {
                padding = true;
            } else {
                if (padding || !filenameCharacter(ch)) {
                    throw invalid("invalid filename or padding");
                }
                length++;
            }
        }
        if (length == 0) {
            throw invalid("empty filename");
        }
        byte[] encoded = new byte[length];
        for (int i = 0; i < length; i++) {
            encoded[i] = names.get(offset + i);
        }
        String name = new String(encoded, StandardCharsets.US_ASCII);
        if (name.equals(".") || name.equals("..")) {
            throw invalid("invalid filename");
        }
        return name;
    }

    private static boolean filenameCharacter(int ch) {
        return ch >= 'A' && ch <= 'Z'
                || ch >= 'a' && ch <= 'z'
                || ch >= '0' && ch <= '9'
                || ch == '-'
                || ch == '.'
                || ch == '_';
    }

    private static void validateLogs(FileChannel channel, long offset, long count,
            long tablesEnd, long fileSize)
            throws IOException {
        ByteBuffer log = ByteBuffer.allocate(LOG_SIZE);
        byte[] previous = null;
        TreeMap<Long, Long> sections = new TreeMap<Long, Long>();
        for (long i = 0; i < count; i++) {
            read(channel, log, offset + i * LOG_SIZE);
            if (previous != null && compare(log, previous) <= 0) {
                throw invalid("log identifiers are not strictly sorted");
            }
            if (previous == null) {
                previous = new byte[32];
            }
            log.get(previous);
            long start = log.getLong();
            int entries = Short.toUnsignedInt(log.getShort());
            long size = (long) entries * ENTRY_SIZE;
            if (start < tablesEnd || start > fileSize || size > fileSize - start) {
                throw invalid("entry section outside data region");
            }
            if (entries == 0) {
                continue;
            }
            Entry<Long, Long> before = sections.floorEntry(start);
            Entry<Long, Long> after = sections.ceilingEntry(start);
            long end = start + size;
            if (before != null && before.getValue() > start
                    || after != null && after.getKey() < end) {
                throw invalid("overlapping entry sections");
            }
            sections.put(start, end);
        }
    }

    private static int compare(ByteBuffer log, byte[] id) {
        for (int i = 0; i < 32; i++) {
            int order = Integer.compare(Byte.toUnsignedInt(log.get(i)), Byte.toUnsignedInt(id[i]));
            if (order != 0) {
                return order;
            }
        }
        return 0;
    }

    private static void read(FileChannel channel, ByteBuffer buffer, long offset) throws IOException {
        buffer.clear();
        while (buffer.hasRemaining()) {
            int count = channel.read(buffer, offset + buffer.position());
            if (count < 0) {
                throw new EOFException("Truncated UPKI index");
            }
            if (count == 0) {
                throw new IOException("No progress reading UPKI index");
            }
        }
        buffer.flip();
    }

    private static IOException invalid(String reason) {
        return new IOException("Invalid UPKI index: " + reason);
    }

    @Override
    public void close() throws IOException {
        channel.close();
    }
}
