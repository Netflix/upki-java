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

import java.security.ProviderException;

/**
 * Internal bound on synchronous SPI re-entry, without changing provider
 * eligibility.
 */
public final class InvocationGuard implements AutoCloseable {
    private static final int MAX_DEPTH = 32;
    private static final ThreadLocal<InvocationGuard> CURRENT = new ThreadLocal<InvocationGuard>();
    private final InvocationGuard previous;
    private final int depth;

    private InvocationGuard(InvocationGuard previous) {
        this.previous = previous;
        depth = previous == null ? 1 : previous.depth + 1;
    }

    public static InvocationGuard enter() {
        InvocationGuard previous = CURRENT.get();
        if (previous != null && previous.depth >= MAX_DEPTH) {
            throw new ProviderException("Provider delegation nesting limit exceeded");
        }
        InvocationGuard current = new InvocationGuard(previous);
        CURRENT.set(current);
        return current;
    }

    @Override
    public void close() {
        if (CURRENT.get() != this) {
            throw new IllegalStateException("Invocation guards must close on their thread in LIFO order");
        }
        if (previous == null) {
            CURRENT.remove();
        } else {
            CURRENT.set(previous);
        }
    }
}
