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

package com.netflix.security.upki;

import java.nio.file.Path;
import java.util.Objects;
import java.util.Optional;

/**
 * Immutable cache selection and revocation policy. No security configuration
 * properties are read. The builder requires explicit choices; defaults() supplies
 * the provisional best-effort profile.
 */
public final class UpkiConfiguration {
    private final Path directory;
    private final boolean enabled;
    private final Handling missingIndex;
    private final CacheFailure cacheFailure;
    private final Handling missingScts;
    private final Handling coverage;
    private final Handling unsupportedVerification;

    private UpkiConfiguration(Builder builder) {
        if (!builder.cacheConfigured) {
            throw new IllegalStateException("Choose automatic discovery or a cache directory");
        }
        enabled = required(builder.enabled, "enabled");
        missingIndex = required(builder.missingIndex, "missingIndex");
        cacheFailure = required(builder.cacheFailure, "cacheFailure");
        missingScts = required(builder.missingScts, "missingScts");
        coverage = required(builder.coverage, "coverage");
        unsupportedVerification = required(builder.unsupportedVerification, "unsupportedVerification");
        directory = builder.directory == null ? null : builder.directory.toAbsolutePath();
    }

    private static <T> T required(T value, String name) {
        if (value == null) {
            throw new IllegalStateException("Missing explicit configuration: " + name);
        }
        return value;
    }

    /**
     * Fixed best-effort profile, independent of security/system properties.
     * Warnings are observable through diagnostics, not automatically logged.
     */
    public static UpkiConfiguration defaults() {
        return builder()
                .enabled(true)
                .automaticDiscovery()
                .missingIndex(Handling.WARN)
                .cacheFailure(CacheFailure.FAIL_OPEN)
                .missingScts(Handling.IGNORE)
                .coverage(Handling.IGNORE)
                .unsupportedVerification(Handling.WARN)
                .build();
    }

    public static Builder builder() {
        return new Builder();
    }

    /** Empty selects platform user/system discovery, not an empty candidate list. */
    public Optional<Path> cacheDirectory() {
        return Optional.ofNullable(directory);
    }

    public boolean enabled() {
        return enabled;
    }

    public Handling missingIndex() {
        return missingIndex;
    }

    public CacheFailure cacheFailure() {
        return cacheFailure;
    }

    public Handling missingScts() {
        return missingScts;
    }

    public Handling coverage() {
        return coverage;
    }

    public Handling unsupportedVerification() {
        return unsupportedVerification;
    }

    /**
     * Value equality does not probe paths or collapse symbolic-link/parent
     * traversal.
     */
    @Override
    public boolean equals(Object other) {
        if (this == other) {
            return true;
        }
        if (!(other instanceof UpkiConfiguration)) {
            return false;
        }
        UpkiConfiguration that = (UpkiConfiguration) other;
        return enabled == that.enabled
                && Objects.equals(directory, that.directory)
                && missingIndex == that.missingIndex
                && cacheFailure == that.cacheFailure
                && missingScts == that.missingScts
                && coverage == that.coverage
                && unsupportedVerification == that.unsupportedVerification;
    }

    @Override
    public int hashCode() {
        return Objects.hash(directory, enabled, missingIndex, cacheFailure, missingScts, coverage,
                unsupportedVerification);
    }

    /** Warning is diagnostic severity, not automatic logging. */
    public enum Handling {
        IGNORE,
        WARN,
        FAIL
    }

    public enum CacheFailure {
        FAIL_OPEN,
        FAIL_CLOSED
    }

    /** Reusable builder; completed configurations do not retain it. */
    public static final class Builder {
        private boolean cacheConfigured;
        private Path directory;
        private Boolean enabled;
        private Handling missingIndex;
        private CacheFailure cacheFailure;
        private Handling missingScts;
        private Handling coverage;
        private Handling unsupportedVerification;

        private Builder() {}

        /**
         * Resolve platform candidates when a checker is constructed, without
         * probing them.
         */
        public Builder automaticDiscovery() {
            cacheConfigured = true;
            directory = null;
            return this;
        }

        /**
         * Select only this revocation directory, containing index.bin and
         * filters. Build captures an absolute path without normalizing away
         * symbolic-link/parent traversal.
         */
        public Builder cacheDirectory(Path directory) {
            this.directory = Objects.requireNonNull(directory, "directory");
            cacheConfigured = true;
            return this;
        }

        public Builder enabled(boolean enabled) {
            this.enabled = enabled;
            return this;
        }

        public Builder missingIndex(Handling handling) {
            missingIndex = Objects.requireNonNull(handling, "handling");
            return this;
        }

        public Builder cacheFailure(CacheFailure mode) {
            cacheFailure = Objects.requireNonNull(mode, "mode");
            return this;
        }

        public Builder missingScts(Handling handling) {
            missingScts = Objects.requireNonNull(handling, "handling");
            return this;
        }

        public Builder coverage(Handling handling) {
            coverage = Objects.requireNonNull(handling, "handling");
            return this;
        }

        public Builder unsupportedVerification(Handling handling) {
            unsupportedVerification = Objects.requireNonNull(handling, "handling");
            return this;
        }

        public UpkiConfiguration build() {
            return new UpkiConfiguration(this);
        }
    }
}
