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

import java.util.Objects;

/**
 * Internal explicit policy; public names, property mappings and defaults are
 * not fixed.
 */
public final class CheckPolicy {
    private final boolean enabled;
    private final Handling missingIndex;
    private final CacheFailure cacheFailure;
    private final Handling missingScts;
    private final Handling coverage;
    private final Handling unavailableIssuer;

    public CheckPolicy(boolean enabled, Handling missingIndex, CacheFailure cacheFailure,
                       Handling missingScts, Handling coverage, Handling unavailableIssuer) {
        this.enabled = enabled;
        this.missingIndex = Objects.requireNonNull(missingIndex, "missingIndex");
        this.cacheFailure = Objects.requireNonNull(cacheFailure, "cacheFailure");
        this.missingScts = Objects.requireNonNull(missingScts, "missingScts");
        this.coverage = Objects.requireNonNull(coverage, "coverage");
        this.unavailableIssuer = Objects.requireNonNull(unavailableIssuer, "unavailableIssuer");
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

    public Handling unavailableIssuer() {
        return unavailableIssuer;
    }

    public enum Handling {
        IGNORE,
        WARN,
        FAIL
    }

    public enum CacheFailure {
        FAIL_OPEN,
        FAIL_CLOSED
    }
}
