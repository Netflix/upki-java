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

import java.nio.file.Paths;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

import com.netflix.security.upki.UpkiConfiguration;
import com.netflix.security.upki.UpkiConfiguration.CacheFailure;
import com.netflix.security.upki.UpkiConfiguration.Handling;
import com.netflix.security.upki.provider.ProviderConfiguration;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ProviderConfigurationTest {
    private static final String PREFIX = "com.netflix.security.upki.";

    @Test
    void fixedDefaultsAreBestEffortAndDoNotReadProperties() {
        UpkiConfiguration defaults = UpkiConfiguration.defaults();
        assertTrue(defaults.enabled());
        assertFalse(defaults.cacheDirectory().isPresent());
        assertEquals(Handling.WARN, defaults.missingIndex());
        assertEquals(CacheFailure.FAIL_OPEN, defaults.cacheFailure());
        assertEquals(Handling.IGNORE, defaults.missingScts());
        assertEquals(Handling.IGNORE, defaults.coverage());
        assertEquals(Handling.WARN, defaults.unsupportedVerification());
        assertEquals(defaults, ProviderConfiguration.read(key -> null));
    }

    @Test
    void readsEachSettingOnceAndCapturesAllChoicesWithoutNormalizingPaths() {
        Map<String, String> properties = new HashMap<>();
        properties.put(PREFIX + "enabled", " FALSE ");
        properties.put(PREFIX + "cacheDirectory", "child/../cache ");
        properties.put(PREFIX + "missingIndex", " fail ");
        properties.put(PREFIX + "cacheFailure", "fail_closed");
        properties.put(PREFIX + "missingScts", "WARN");
        properties.put(PREFIX + "coverage", "Fail");
        properties.put(PREFIX + "unsupportedVerification", "ignore");
        AtomicInteger reads = new AtomicInteger();
        UpkiConfiguration result = ProviderConfiguration.read(key -> {
            reads.incrementAndGet();
            return properties.get(key);
        });
        assertEquals(7, reads.get());
        properties.clear();
        assertFalse(result.enabled());
        assertEquals(Paths.get("child/../cache ").toAbsolutePath(),
                result.cacheDirectory().get());
        assertEquals(Handling.FAIL, result.missingIndex());
        assertEquals(CacheFailure.FAIL_CLOSED, result.cacheFailure());
        assertEquals(Handling.WARN, result.missingScts());
        assertEquals(Handling.FAIL, result.coverage());
        assertEquals(Handling.IGNORE, result.unsupportedVerification());
    }

    @Test
    void allPolicyValuesAreAcceptedWithoutVocabularyTranslation() {
        for (String setting : new String[] {"missingIndex", "missingScts", "coverage", "unsupportedVerification"}) {
            for (Handling value : Handling.values()) {
                assertNotNull(ProviderConfiguration.read(key -> key.equals(PREFIX + setting) ? value.name() : null));
            }
        }
        for (CacheFailure value : CacheFailure.values()) {
            assertEquals(value, ProviderConfiguration.read(key -> key.equals(PREFIX + "cacheFailure") ? value.name() : null)
                    .cacheFailure());
        }
    }

    @Test
    void invalidSettingsFailEvenWhenCheckingIsDisabled() {
        for (String setting : new String[] {"enabled", "missingIndex", "cacheFailure", "missingScts", "coverage", "unsupportedVerification",
                "cacheDirectory"}) {
            for (String invalid : new String[] {"", " ", setting.equals("cacheDirectory") ? "\0" : "typo"}) {
                Map<String, String> properties = new HashMap<>();
                properties.put(PREFIX + "enabled", "false");
                properties.put(PREFIX + setting, invalid);
                IllegalArgumentException failure = assertThrows(IllegalArgumentException.class, () -> ProviderConfiguration.read(properties::get));
                assertTrue(failure.getMessage().contains(PREFIX + setting),
                        failure.getMessage());
            }
        }
        for (String invalid : new String[] {"yes", "1", "off"}) {
            assertThrows(IllegalArgumentException.class,
                    () -> ProviderConfiguration.read(key -> key.equals(PREFIX + "enabled") ? invalid : null));
        }
    }

    @Test
    void explicitBuilderStillRequiresEveryChoice() {
        assertThrows(IllegalStateException.class,
                () -> UpkiConfiguration.builder().build());
        assertThrows(NullPointerException.class, () -> ProviderConfiguration.read(null));
    }
}
