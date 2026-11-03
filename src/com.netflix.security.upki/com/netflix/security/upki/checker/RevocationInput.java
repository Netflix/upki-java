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

package com.netflix.security.upki.checker;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;

import com.netflix.security.upki.clubcard.Clubcard.Key;

/**
 * Owned lookup bytes from a leaf and its authenticated issuer, not proof of
 * trust.
 */
public final class RevocationInput {
    private final byte[] issuerSpkiHash;
    private final byte[] serial;
    private final Key key;
    private final List<Timestamp> timestamps;

    public RevocationInput(byte[] issuerSpkiHash, byte[] serial, List<Timestamp> timestamps) {
        this.issuerSpkiHash = Objects.requireNonNull(issuerSpkiHash, "issuerSpkiHash").clone();
        this.serial = Objects.requireNonNull(serial, "serial").clone();
        key = new Key(this.issuerSpkiHash, this.serial);
        Objects.requireNonNull(timestamps, "timestamps");
        List<Timestamp> owned = new ArrayList<Timestamp>(timestamps.size());
        for (Timestamp timestamp : timestamps) {
            owned.add(Objects.requireNonNull(timestamp, "timestamp"));
        }
        this.timestamps = Collections.unmodifiableList(owned);
    }

    public byte[] issuerSpkiHash() {
        return issuerSpkiHash.clone();
    }

    public byte[] serial() {
        return serial.clone();
    }

    public Key key() {
        return key;
    }

    public List<Timestamp> timestamps() {
        return timestamps;
    }

    /** An embedded SCT's log identifier and unsigned millisecond timestamp. */
    public static final class Timestamp {
        final byte[] logId;
        final long timestamp;

        public Timestamp(byte[] logId, long timestamp) {
            Objects.requireNonNull(logId, "logId");
            if (logId.length != 32) {
                throw new IllegalArgumentException("A CT log identifier must contain 32 bytes");
            }
            this.logId = logId.clone();
            this.timestamp = timestamp;
        }

        public byte[] logId() {
            return logId.clone();
        }

        public long timestamp() {
            return timestamp;
        }
    }
}
