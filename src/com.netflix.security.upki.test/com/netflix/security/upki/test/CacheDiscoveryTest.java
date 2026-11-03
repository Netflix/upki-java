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
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.FileTime;
import java.util.Arrays;
import java.util.Collections;
import java.util.Optional;

import com.netflix.security.upki.cache.CacheDiscovery;
import com.netflix.security.upki.cache.CacheDiscovery.Selection;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;

class CacheDiscoveryTest {
    @TempDir
    Path directory;

    @Test
    void skipsMissingAndEmptyDirectories() throws Exception {
        Path missing = directory.resolve("missing");
        Path empty = Files.createDirectory(directory.resolve("empty"));
        Path system = cache("system");
        try (Selection selected = CacheDiscovery.open(Arrays.asList(missing, empty, system)).orElseThrow()) {
            assertEquals(system, selected.directory());
        }
    }

    @Test
    void prefersFirstPublishedIndexWithoutComparingFreshness() throws Exception {
        Path user = cache("user");
        Path system = cache("system");
        Files.setLastModifiedTime(user.resolve("index.bin"), FileTime.fromMillis(0));
        try (Selection selected = CacheDiscovery.open(Arrays.asList(user, system)).orElseThrow()) {
            assertEquals(user, selected.directory());
        }
    }

    @Test
    void returnsNoCacheWhenNoIndexIsPublished() throws Exception {
        assertFalse(CacheDiscovery.open(Collections.emptyList())
                .isPresent());
        assertFalse(CacheDiscovery.open(Collections.singletonList(directory))
                .isPresent());
    }

    @Test
    void doesNotFallBackAfterMalformedIndex() throws Exception {
        Path user = cache("user");
        Path system = cache("system");
        Files.write(user.resolve("index.bin"), new byte[14]);
        assertThrows(IOException.class, () -> CacheDiscovery.open(Arrays.asList(user, system)));
    }

    @Test
    void doesNotTreatOtherIoErrorsAsAnAbsentIndex() throws Exception {
        Path user = Files.createDirectory(directory.resolve("user"));
        Files.createDirectory(user.resolve("index.bin"));
        Path system = cache("system");
        assertThrows(IOException.class, () -> CacheDiscovery.open(Arrays.asList(user, system)));
    }

    @Test
    void discoversNewPublicationAndDoesNotRetainPriorSelection() throws Exception {
        Path user = Files.createDirectory(directory.resolve("user"));
        Path system = cache("system");
        try (Selection selected = CacheDiscovery.open(Arrays.asList(user, system)).orElseThrow()) {
            assertEquals(system, selected.directory());
        }
        Files.write(user.resolve("index.bin"), emptyIndex());
        try (Selection selected = CacheDiscovery.open(Arrays.asList(user, system)).orElseThrow()) {
            assertEquals(user, selected.directory());
        }
        Files.delete(user.resolve("index.bin"));
        Files.delete(system.resolve("index.bin"));
        assertEquals(Optional.empty(), CacheDiscovery.open(Arrays.asList(user, system)));
    }

    @Test
    void selectionOwnsItsOpenedIndex() throws Exception {
        Path cache = cache("cache");
        Selection selected = CacheDiscovery.open(Collections.singletonList(cache)).orElseThrow();
        selected.close();
        assertThrows(IOException.class,
                () -> selected.index().lookup(new byte[32], 0));
        selected.close();
    }

    @Test
    void retainsOpenedGenerationAcrossAtomicReplacement() throws Exception {
        Path cache = cache("cache");
        Files.write(cache.resolve("index.bin"), singleFilterIndex("old.filter"));
        Path replacement = directory.resolve("replacement");
        Files.write(replacement, singleFilterIndex("new.filter"));
        try (Selection selected = CacheDiscovery.open(Collections.singletonList(cache)).orElseThrow()) {
            Files.move(replacement, cache.resolve("index.bin"), StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
            assertEquals(Collections.singletonList("old.filter"),
                    selected.index().lookup(new byte[32], 0));
            try (Selection current = CacheDiscovery.open(Collections.singletonList(cache)).orElseThrow()) {
                assertEquals(Collections.singletonList("new.filter"),
                        current.index().lookup(new byte[32], 0));
            }
        }
    }

    private static byte[] singleFilterIndex(String name) {
        ByteBuffer bytes = ByteBuffer.allocate(106);
        bytes.put("upkiidx1".getBytes(StandardCharsets.US_ASCII));
        bytes.putShort((short) 1).putInt(1);
        bytes.put(name.getBytes(StandardCharsets.US_ASCII));
        bytes.position(78);
        bytes.putLong(88).putShort((short) 1);
        bytes.putShort((short) 0)
             .putLong(0)
             .putLong(0);
        return bytes.array();
    }

    private Path cache(String name) throws IOException {
        Path cache = Files.createDirectory(directory.resolve(name));
        Files.write(cache.resolve("index.bin"), emptyIndex());
        return cache;
    }

    private static byte[] emptyIndex() {
        return ByteBuffer.allocate(14)
                .put("upkiidx1".getBytes(StandardCharsets.US_ASCII))
                .array();
    }
}
