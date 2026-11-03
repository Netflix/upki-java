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

package com.netflix.security.upki.clubcard;

import java.io.EOFException;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.channels.FileChannel;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

import com.netflix.security.upki.clubcard.Clubcard.Block;
import com.netflix.security.upki.clubcard.Clubcard.Coverage;

/**
 * Strict, bounded V4 parsing with read-only NIO slices for the filter columns.
 */
public final class ClubcardReader {
    private final ByteBuffer bytes;

    private ClubcardReader(ByteBuffer bytes) {
        this.bytes = bytes;
    }

    public static Clubcard read(Path path) throws IOException {
        try (FileChannel channel = FileChannel.open(path, StandardOpenOption.READ)) {
            long size = channel.size();
            if (size > Integer.MAX_VALUE) {
                throw invalid("file exceeds the supported ByteBuffer size");
            }
            ByteBuffer bytes = ByteBuffer.allocate((int) size);
            while (bytes.hasRemaining()) {
                int count = channel.read(bytes);
                if (count < 0) {
                    throw new EOFException("Truncated UPKI clubcard");
                }
                if (count == 0) {
                    throw new IOException("No progress reading UPKI clubcard");
                }
            }
            bytes.flip();
            return new ClubcardReader(bytes).parse();
        }
    }

    /**
     * Snapshots the caller's remaining bytes without changing its position,
     * limit, or order.
     */
    public static Clubcard read(ByteBuffer source) throws IOException {
        Objects.requireNonNull(source, "source");
        ByteBuffer bytes = ByteBuffer.allocate(source.remaining());
        bytes.put(source.duplicate());
        bytes.flip();
        return new ClubcardReader(bytes).parse();
    }

    private Clubcard parse() throws IOException {
        if (u8() != 4 || u8() != 0) {
            throw invalid("expected V4 with a zero reserved byte");
        }
        int coverageCount = u16();
        require((long) coverageCount * 48);
        Map<ByteBuffer, Coverage> coverage = new HashMap<ByteBuffer, Coverage>();
        for (int i = 0; i < coverageCount; i++) {
            ByteBuffer id = take(32);
            Coverage interval = new Coverage(u64(), u64());
            if (coverage.put(id, interval) != null) {
                throw invalid("duplicate coverage log identifier");
            }
        }

        int blockCount = count(52);
        Block[] blocks = new Block[blockCount];
        ByteBuffer previous = null;
        for (int i = 0; i < blockCount; i++) {
            ByteBuffer issuer = take(32);
            if (previous != null && compare(previous, issuer) >= 0) {
                throw invalid("issuer identifiers are not strictly sorted");
            }
            previous = issuer;
            long m = u32();
            int rank = u8();
            long offset = u32();
            long exactM = u32();
            long exactOffset = u32();
            int inverted = u8();
            if (inverted > 1) {
                throw invalid("invalid inversion flag");
            }
            int exceptionCount = u16();
            require((long) exceptionCount * 2);
            ByteBuffer[] exceptions = new ByteBuffer[exceptionCount];
            for (int j = 0; j < exceptionCount; j++) {
                int length = u8();
                if (length == 0) {
                    throw invalid("empty exception serial");
                }
                exceptions[j] = take(length);
            }
            blocks[i] = new Block(issuer, m, rank, offset, exactM, exactOffset,
                    inverted != 0, exceptions);
        }

        int columnCount = u8();
        require((long) columnCount * 4 + 4);
        ByteBuffer[] columns = new ByteBuffer[columnCount];
        for (int i = 0; i < columnCount; i++) {
            columns[i] = column();
        }
        ByteBuffer exact = column();
        if (bytes.hasRemaining()) {
            throw invalid("trailing bytes");
        }
        for (Block block : blocks) {
            if (block.rank > columnCount) {
                throw invalid("issuer rank exceeds approximate column count");
            }
        }
        return new Clubcard(coverage, blocks, columns, exact);
    }

    private ByteBuffer column() throws IOException {
        int words = count(8);
        return take(words * 8);
    }

    private int count(int elementSize) throws IOException {
        long count = u32();
        require(count * elementSize);
        return (int) count;
    }

    private int u8() throws IOException {
        require(1);
        return Byte.toUnsignedInt(bytes.get());
    }

    private int u16() throws IOException {
        require(2);
        return Short.toUnsignedInt(bytes.getShort());
    }

    private long u32() throws IOException {
        require(4);
        return Integer.toUnsignedLong(bytes.getInt());
    }

    private long u64() throws IOException {
        require(8);
        return bytes.getLong();
    }

    private ByteBuffer take(int length) throws IOException {
        require(length);
        ByteBuffer view = bytes.slice();
        view.limit(length);
        bytes.position(bytes.position() + length);
        return view.asReadOnlyBuffer().order(ByteOrder.BIG_ENDIAN);
    }

    private void require(long length) throws IOException {
        if (length < 0 || length > bytes.remaining()) {
            throw new EOFException("Truncated UPKI clubcard at byte " + bytes.position());
        }
    }

    private static int compare(ByteBuffer left, ByteBuffer right) {
        for (int i = 0; i < 32; i++) {
            int order = Integer.compare(Byte.toUnsignedInt(left.get(i)), Byte.toUnsignedInt(right.get(i)));
            if (order != 0) {
                return order;
            }
        }
        return 0;
    }

    private static IOException invalid(String reason) {
        return new IOException("Invalid UPKI clubcard: " + reason);
    }
}
