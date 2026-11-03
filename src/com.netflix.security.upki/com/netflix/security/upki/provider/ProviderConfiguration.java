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

package com.netflix.security.upki.provider;

import java.nio.file.InvalidPathException;
import java.nio.file.Paths;
import java.security.Security;
import java.util.Locale;
import java.util.Objects;
import java.util.function.Function;

import com.netflix.security.upki.UpkiConfiguration;
import com.netflix.security.upki.UpkiConfiguration.Builder;
import com.netflix.security.upki.UpkiConfiguration.CacheFailure;
import com.netflix.security.upki.UpkiConfiguration.Handling;

/**
 * Bootstrap-only security-property snapshot; never used on the verification
 * path.
 */
public final class ProviderConfiguration {
    private static final String PREFIX = "com.netflix.security.upki.";

    private ProviderConfiguration() {}

    public static UpkiConfiguration load() {
        return read(Security::getProperty);
    }

    public static UpkiConfiguration read(Function<String, String> properties) {
        Objects.requireNonNull(properties, "properties");
        UpkiConfiguration defaults = UpkiConfiguration.defaults();
        Builder builder = UpkiConfiguration.builder()
                .enabled(enabled(properties.apply(PREFIX + "enabled"), defaults.enabled()))
                .missingIndex(choice(properties, "missingIndex", Handling.class, defaults.missingIndex()))
                .cacheFailure(choice(properties, "cacheFailure", CacheFailure.class, defaults.cacheFailure()))
                .missingScts(choice(properties, "missingScts", Handling.class, defaults.missingScts()))
                .coverage(choice(properties, "coverage", Handling.class, defaults.coverage()))
                .unsupportedVerification(choice(properties, "unsupportedVerification", Handling.class, defaults.unsupportedVerification()));
        String directory = properties.apply(PREFIX + "cacheDirectory");
        if (directory == null) {
            builder.automaticDiscovery();
        } else {
            if (directory.trim().isEmpty()) {
                throw invalid("cacheDirectory", directory);
            }
            try {
                builder.cacheDirectory(Paths.get(directory));
            } catch (InvalidPathException failure) {
                throw new IllegalArgumentException("Invalid security property " + PREFIX + "cacheDirectory", failure);
            }
        }
        return builder.build();
    }

    private static boolean enabled(String value, boolean fallback) {
        if (value == null) {
            return fallback;
        }
        if ("true".equalsIgnoreCase(value.trim())) {
            return true;
        }
        if ("false".equalsIgnoreCase(value.trim())) {
            return false;
        }
        throw invalid("enabled", value);
    }

    private static <E extends Enum<E>> E choice(Function<String, String> properties, String setting,
            Class<E> type, E fallback) {
        String value = properties.apply(PREFIX + setting);
        if (value == null) {
            return fallback;
        }
        try {
            return Enum.valueOf(type, value.trim().toUpperCase(Locale.ROOT));
        } catch (IllegalArgumentException failure) {
            throw invalid(setting, value);
        }
    }

    private static IllegalArgumentException invalid(String setting, String value) {
        return new IllegalArgumentException("Invalid security property " + PREFIX + setting + ": " + value);
    }
}
