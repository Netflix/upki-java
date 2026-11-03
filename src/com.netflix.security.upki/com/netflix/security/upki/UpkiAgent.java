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

import com.netflix.security.provider.UpkiProvider;

/**
 * Startup installation only; no bytecode transformation or dynamic attachment.
 */
public final class UpkiAgent {
    private UpkiAgent() {}

    /**
     * Agent arguments are unsupported; configure through runtime security
     * properties.
     */
    public static void premain(String arguments) {
        if (arguments != null && !arguments.isEmpty()) {
            throw new IllegalArgumentException("UPKI agent arguments are unsupported; use security properties");
        }
        UpkiProvider.install();
    }
}
