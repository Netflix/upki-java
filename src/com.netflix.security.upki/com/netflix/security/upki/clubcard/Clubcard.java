/*
 * Copyr *
 * The membership query is adapted from cpu/go-upki/internal/clubcard.go.
 * Copyright 2026 The Go Authors.
 * BSD-3-Clause; see the accompanying go-upki-LICENSE.
 */

package com.netflix.security.upki.clubcard;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Map;
import java.util.Objects;

/**
 * Immutable query-side V4 clubcard, independent of certificate validation and
 * storage.
 */
public final class Clubcard {
    private final Map<ByteBuffer, Coverage> coverage;
    private final Block[] blocks;
    private final ByteBuffer[] approximate;
    private final ByteBuffer exact;

    Clubcard(Map<ByteBuffer, Coverage> coverage, Block[] blocks, ByteBuffer[] approximate,
             ByteBuffer exact) {
        this.coverage = coverage;
        this.blocks = blocks;
        this.approximate = approximate;
        this.exact = exact;
    }

    public enum Status {
        REVOKED,
        NOT_REVOKED,
        NOT_ENROLLED,
        NOT_COVERED
    }

    /**
     * Issuer hash and exact DER serial contents, with a reusable SHA-256 lookup
     * key.
     */
    public static final class Key {
        private final byte[] issuer;
        private final byte[] serial;
        private final long[] coefficients;

        public Key(byte[] issuer, byte[] serial) {
            Objects.requireNonNull(issuer, "issuer");
            Objects.requireNonNull(serial, "serial");
            if (issuer.length != 32 || serial.length == 0) {
                throw new IllegalArgumentException("Expected a 32-byte issuer hash and nonempty serial");
            }
            this.issuer = issuer.clone();
            this.serial = serial.clone();
            MessageDigest digest;
            try {
                digest = MessageDigest.getInstance("SHA-256");
            } catch (NoSuchAlgorithmException error) {
                throw new IllegalStateException("Required SHA-256 implementation is unavailable", error);
            }
            digest.update(this.issuer);
            ByteBuffer hash = ByteBuffer.wrap(digest.digest(this.serial)).order(ByteOrder.LITTLE_ENDIAN);
            coefficients = new long[] {hash.getLong(), hash.getLong(), hash.getLong(),
                    hash.getLong()};
            // Ribbon equations are aligned by forcing their first coefficient to one.
            coefficients[0] |= 1;
        }
    }

    /** Checks one SCT's coverage before evaluating issuer/serial membership. */
    public Status check(Key key, byte[] logId, long timestamp) {
        Objects.requireNonNull(key, "key");
        Objects.requireNonNull(logId, "logId");
        if (logId.length != 32) {
            throw new IllegalArgumentException("A CT log identifier must contain 32 bytes");
        }
        Coverage interval = coverage.get(ByteBuffer.wrap(logId));
        if (interval == null || Long.compareUnsigned(timestamp, interval.min) < 0 || Long.compareUnsigned(timestamp, interval.max) > 0) {
            return Status.NOT_COVERED;
        }
        int low = 0;
        int high = blocks.length;
        while (low < high) {
            int mid = low + (high - low) / 2;
            Block block = blocks[mid];
            int order = compare(block.issuer, key.issuer);
            if (order < 0) {
                low = mid + 1;
            } else if (order > 0) {
                high = mid;
            } else {
                return contains(block, key) ? Status.REVOKED : Status.NOT_REVOKED;
            }
        }
        return Status.NOT_ENROLLED;
    }

    private boolean contains(Block block, Key key) {
        if (block.m == 0) {
            return block.inverted;
        }
        long t = key.coefficients[3];
        long row = block.offset + Long.remainderUnsigned(t, block.m);
        for (int i = 0; i < block.rank; i++) {
            if (!zeroParity(approximate[i], row, key.coefficients)) {
                return block.inverted;
            }
        }
        if (block.exactM != 0) {
            row = block.exactOffset + Long.remainderUnsigned(t, block.exactM);
            if (!zeroParity(exact, row, key.coefficients)) {
                return block.inverted;
            }
        }
        ByteBuffer serial = ByteBuffer.wrap(key.serial);
        for (ByteBuffer exception : block.exceptions) {
            if (exception.equals(serial)) {
                return block.inverted;
            }
        }
        return !block.inverted;
    }

    private static boolean zeroParity(ByteBuffer column, long row, long[] coefficients) {
        long first = row / 64;
        int shift = (int) (row % 64);
        long product = 0;
        for (int i = 0; i < 4; i++) {
            long bits = word(column, first + i) >>> shift;
            if (shift != 0) {
                bits |= word(column, first + i + 1) << (64 - shift);
            }
            product ^= bits & coefficients[i];
        }
        return (Long.bitCount(product) & 1) == 0;
    }

    private static long word(ByteBuffer column, long word) {
        return word < column.limit() / 8 ? column.getLong((int) (word * 8)) : 0;
    }

    static int compare(ByteBuffer left, byte[] right) {
        for (int i = 0; i < 32; i++) {
            int order = Integer.compare(Byte.toUnsignedInt(left.get(i)), Byte.toUnsignedInt(right[i]));
            if (order != 0) {
                return order;
            }
        }
        return 0;
    }

    static final class Coverage {
        final long min;
        final long max;

        Coverage(long min, long max) {
            this.min = min;
            this.max = max;
        }
    }

    static final class Block {
        final ByteBuffer issuer;
        final long m;
        final int rank;
        final long offset;
        final long exactM;
        final long exactOffset;
        final boolean inverted;
        final ByteBuffer[] exceptions;

        Block(
                ByteBuffer issuer,
                long m,
                int rank,
                long offset,
                long exactM,
                long exactOffset,
                boolean inverted,
                ByteBuffer[] exceptions) {
            this.issuer = issuer;
            this.m = m;
            this.rank = rank;
            this.offset = offset;
            this.exactM = exactM;
            this.exactOffset = exactOffset;
            this.inverted = inverted;
            this.exceptions = exceptions;
        }
    }
}
