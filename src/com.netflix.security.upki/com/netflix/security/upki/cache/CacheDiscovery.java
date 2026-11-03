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
import java.io.IOException;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.util.List;
import java.util.Optional;

/** Selects a published cache from an ordered list of candidate directories. */
public final class CacheDiscovery {
    private CacheDiscovery() {}

    /**
     * Opens the first available index without falling back on access or format
     * errors. Candidate order is authoritative; cache contents and modification
     * times are not merged.
     */
    public static Optional<Selection> open(List<Path> directories) throws IOException {
        for (Path directory : directories) {
            RevocationIndex index;
            try {
                index = RevocationIndex.open(directory);
            } catch (NoSuchFileException missing) {
                continue;
            }
            return Optional.of(new Selection(directory, index));
        }
        return Optional.empty();
    }

    /** The selected directory and the index generation opened during discovery. */
    public static final class Selection implements Closeable {
        private final Path directory;
        private final RevocationIndex index;

        private Selection(Path directory, RevocationIndex index) {
            this.directory = directory;
            this.index = index;
        }

        public Path directory() {
            return directory;
        }

        public RevocationIndex index() {
            return index;
        }

        @Override
        public void close() throws IOException {
            index.close();
        }
    }
}
