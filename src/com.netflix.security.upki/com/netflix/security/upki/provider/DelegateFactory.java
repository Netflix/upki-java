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

import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.Provider.Service;
import java.security.Security;
import java.util.Objects;

/** Internal, synchronous construction routing; not a supported provider API. */
public final class DelegateFactory {
    private static final ThreadLocal<Frame> CURRENT = new ThreadLocal<Frame>();

    private DelegateFactory() {}

    /**
     * The factory must use provider-specific lookup, without its own provider
     * fallback.
     */
    public static <T> T create(Provider owner, String type, String algorithm,
            Factory<T> factory)
            throws NoSuchAlgorithmException {
        Objects.requireNonNull(owner, "owner");
        Objects.requireNonNull(type, "type");
        Objects.requireNonNull(algorithm, "algorithm");
        Objects.requireNonNull(factory, "factory");
        Frame previous = CURRENT.get();
        for (Provider provider : Security.getProviders()) {
            if (provider == owner) {
                continue;
            }
            Service service = provider.getService(type, algorithm);
            if (service == null || active(previous, service)) {
                continue;
            }
            CURRENT.set(new Frame(service, previous));
            try {
                // Let a wrapper re-enter us, but do not select that same service again.
                return Objects.requireNonNull(factory.create(provider), "delegate");
            } finally {
                if (previous == null) {
                    CURRENT.remove();
                } else {
                    CURRENT.set(previous);
                }
            }
        }
        throw new NoSuchAlgorithmException("No available delegate for " + type + "." + algorithm);
    }

    private static boolean active(Frame frame, Service service) {
        for (; frame != null; frame = frame.previous) {
            if (frame.service.getProvider() == service.getProvider() && frame.service.getType().equalsIgnoreCase(service.getType()) && frame.service.getAlgorithm().equalsIgnoreCase(service.getAlgorithm())) {
                return true;
            }
        }
        return false;
    }

    private static final class Frame {
        final Service service;
        final Frame previous;

        Frame(Service service, Frame previous) {
            this.service = service;
            this.previous = previous;
        }
    }

    @FunctionalInterface
    public interface Factory<T> {
        T create(Provider provider) throws NoSuchAlgorithmException;
    }
}
