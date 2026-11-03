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

import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import com.netflix.security.upki.cache.CachePaths;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

class CachePathsTest {
    private final Path home = Paths.get("/home/client");

    @Test
    void unixUsesXdgBeforeSystem() {
        Map<String, String> environment = new HashMap<>();
        environment.put("XDG_CACHE_HOME", "/custom/cache");
        assertEquals(Arrays.asList(Paths.get("/custom/cache/upki/revocation"), Paths.get("/var/cache/upki/revocation")),
                CachePaths.directories("Linux", environment, home));
    }

    @Test
    void unixFallsBackForUnsetEmptyAndRelativeXdg() {
        for (String value : Arrays.asList("", "relative/cache")) {
            assertEquals(Arrays.asList(home.resolve(".cache/upki/revocation"), Paths.get("/var/cache/upki/revocation")),
                    CachePaths.directories("FreeBSD", Collections.singletonMap("XDG_CACHE_HOME", value), home));
        }
        assertEquals(Arrays.asList(home.resolve(".cache/upki/revocation"), Paths.get("/var/cache/upki/revocation")),
                CachePaths.directories("Linux", Collections.emptyMap(), home));
    }

    @Test
    void macUsesBundleIdentifierAndIgnoresXdg() {
        for (String os : Arrays.asList("Mac OS X", "Darwin")) {
            assertEquals(Arrays.asList(home.resolve("Library/Caches/dev.rustls.upki/revocation"), Paths.get("/Library/Caches/dev.rustls.upki/revocation")),
                    CachePaths.directories(os, Collections.singletonMap("XDG_CACHE_HOME", "/ignored"), home));
        }
    }

    @Test
    void windowsUsesLocalAppDataBeforeProgramData() {
        Map<String, String> environment = new HashMap<>();
        environment.put("LOCALAPPDATA", "/local");
        environment.put("ProgramData", "/program");
        assertEquals(Arrays.asList(Paths.get("/local/rustls/upki/cache/revocation"), Paths.get("/program/rustls/upki/cache/revocation")),
                CachePaths.directories("Windows 11", environment, home));
    }

    @Test
    void missingHomeOrLocalAppDataDoesNotHideSystemCache() {
        assertEquals(Collections.singletonList(Paths.get("/var/cache/upki/revocation")), CachePaths.directories("Linux", Collections.emptyMap(), null));
        assertEquals(
                Collections.singletonList(Paths.get("/Library/Caches/dev.rustls.upki/revocation")),
                CachePaths.directories("Mac OS X", Collections.emptyMap(), null));
        assertEquals(
                Collections.singletonList(Paths.get("C:\\ProgramData", "rustls", "upki", "cache", "revocation")),
                CachePaths.directories("Windows 11", Collections.emptyMap(), null));
    }

    @Test
    void unixCanUseXdgWithoutHome() {
        assertEquals(Arrays.asList(Paths.get("/custom/upki/revocation"), Paths.get("/var/cache/upki/revocation")),
                CachePaths.directories("Linux", Collections.singletonMap("XDG_CACHE_HOME", "/custom"), null));
    }
}
