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

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

/** Single-issuer synthetic cache, not an updater or a general format writer. */
final class CacheFixture {
    private CacheFixture() {}

    static void write(Path directory, byte[] issuerSpkiHash, boolean revoked) throws IOException {
        byte[] log = new byte[32];
        log[0] = 1;
        ByteBuffer filter = ByteBuffer.allocate(113);
        filter.put((byte) 4)
              .put((byte) 0)
              .putShort((short) 1)
              .put(log)
              .putLong(100)
              .putLong(200);
        filter.putInt(1)
              .put(issuerSpkiHash)
              .putInt(0)
              .put((byte) 0)
              .putInt(0)
              .putInt(0)
              .putInt(0)
              .put((byte) (revoked ? 1 : 0))
              .putShort((short) 0)
              .put((byte) 0)
              .putInt(0);
        Files.write(directory.resolve("test.filter"), filter.array());

        int metadata = 14 + 32 + 42;
        ByteBuffer index = ByteBuffer.allocate(metadata + 18);
        index.put("upkiidx1".getBytes(StandardCharsets.US_ASCII))
             .putShort((short) 1)
             .putInt(1);
        index.put("test.filter".getBytes(StandardCharsets.US_ASCII)).position(14 + 32);
        index.put(log)
             .putLong(metadata)
             .putShort((short) 1);
        index.putShort((short) 0)
             .putLong(100)
             .putLong(200);
        Files.write(directory.resolve("index.bin"), index.array());
    }
}
