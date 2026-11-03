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

import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/** Platform cache locations, in user-before-system discovery order. */
public final class CachePaths {
    private CachePaths() {}

    public static List<Path> defaults() {
        String home = System.getProperty("user.home");
        return directories(System.getProperty("os.name"), System.getenv(),
                home == null || home.isEmpty()
                        ? null
                        : Paths.get(home));
    }

    /**
     * A null home omits home-relative candidates without disabling system
     * discovery.
     */
    public static List<Path> directories(String osName, Map<String, String> environment, Path home) {
        Objects.requireNonNull(osName, "osName");
        Objects.requireNonNull(environment, "environment");
        List<Path> candidates = new ArrayList<Path>();
        if (osName.startsWith("Windows")) {
            String local = environment.get("LOCALAPPDATA");
            if (local != null && !local.isEmpty()) {
                candidates.add(Paths.get(local, "rustls", "upki", "cache", "revocation"));
            }
            String system = environment.get("ProgramData");
            candidates.add(Paths.get(system == null || system.isEmpty()
                    ? "C:\\ProgramData"
                    : system,
                    "rustls", "upki", "cache", "revocation"));
        } else if (osName.equals("Darwin") || osName.startsWith("Mac")) {
            if (home != null) {
                candidates.add(home.resolve("Library/Caches/dev.rustls.upki/revocation"));
            }
            candidates.add(Paths.get("/Library/Caches/dev.rustls.upki/revocation"));
        } else {
            String xdg = environment.get("XDG_CACHE_HOME");
            Path cache = xdg == null || xdg.isEmpty()
                    ? null
                    : Paths.get(xdg);
            if (cache != null && cache.isAbsolute()) {
                candidates.add(cache.resolve("upki/revocation"));
            } else if (home != null) {
                candidates.add(home.resolve(".cache/upki/revocation"));
            }
            candidates.add(Paths.get("/var/cache/upki/revocation"));
        }
        return Collections.unmodifiableList(candidates);
    }
}
