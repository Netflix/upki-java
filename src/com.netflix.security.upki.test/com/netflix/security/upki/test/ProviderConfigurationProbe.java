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

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.Provider;
import java.security.ProviderException;
import java.security.Security;
import javax.net.ssl.TrustManagerFactory;

import com.netflix.security.provider.UpkiProvider;
import com.netflix.security.upki.RevocationDiagnostics.CacheState;
import com.netflix.security.upki.RevocationResult.Finding;
import com.netflix.security.upki.UpkiAgent;
import com.netflix.security.upki.UpkiConfiguration;
import com.netflix.security.upki.UpkiConfiguration.CacheFailure;
import com.netflix.security.upki.UpkiConfiguration.Handling;

import static com.netflix.security.upki.test.UpkiProviderProbe.require;

/** Java 8-compatible bootstrap consumer; no internal production APIs. */
public final class ProviderConfigurationProbe {
    private static final String PREFIX = "com.netflix.security.upki.";

    public static void main(String[] args) throws Exception {
        require(args.length >= 1, "choose a bootstrap scenario");
        String mode = args[0];
        if (mode.equals("defaults")) {
            defaults();
        } else if (mode.equals("properties")) {
            properties();
        } else if (mode.equals("file-ignored") || mode.equals("file-agent-ignored")) {
            require(!"true".equalsIgnoreCase(Security.getProperty("security.overridePropertiesFile")), "overlay unexpectedly permitted");
            Provider selected = Security.getProvider(UpkiProvider.NAME);
            if (mode.equals("file-ignored")) {
                require(selected == null, "disabled overlay installed provider");
            } else {
                require(selected instanceof UpkiProvider, "agent not installed");
                require(((UpkiProvider) selected).configuration()
                        .equals(UpkiConfiguration.defaults()),
                        "agent bypassed disabled overlay");
            }
        } else if (mode.equals("static-invalid")) {
            Security.setProperty(PREFIX + "enabled", "typo");
            register();
            require(Security.getProvider(UpkiProvider.NAME) == null, "JCA did not skip invalid provider");
            require(!TrustManagerFactory.getInstance("PKIX")
                    .getProvider()
                    .getName()
                    .equals(UpkiProvider.NAME),
                    "invalid provider selected");
            try {
                UpkiProvider.install();
                throw new AssertionError("invalid configuration installed");
            } catch (IllegalArgumentException expected) {
                require(expected.getMessage().contains(PREFIX + "enabled"), "wrong configuration error");
            }
        } else if (mode.equals("agent-invalid")) {
            throw new AssertionError("MAIN ENTERED after invalid agent configuration");
        } else {
            if (mode.equals("static")) {
                Security.setProperty(PREFIX + "cacheDirectory", args[1]);
                register();
            }
            require(mode.equals("static")
                    || mode.equals("file")
                    || mode.equals("file-agent")
                    || mode.equals("agent")
                    || mode.equals("agent-static"),
                    "unknown mode");
            Provider selected = Security.getProvider(UpkiProvider.NAME);
            require(selected instanceof UpkiProvider, "provider not loaded");
            UpkiProvider provider = (UpkiProvider) selected;
            require(Security.getProviders()[0] == provider, "provider not first");
            require(
                    provider.configuration()
                            .cacheDirectory()
                            .get()
                            .equals(Paths.get(args[1]).toAbsolutePath()),
                    "cache property not captured");
            require(provider.diagnostics().assessments() == 0, "bootstrap checked certificates");
            require(provider.diagnostics().cacheState() == CacheState.NOT_CHECKED, "bootstrap probed cache");
            require(UpkiProvider.install() == provider, "installation did not reuse static/agent provider");
            tls(provider);
        }
        System.out.println("PASS bootstrap " + mode + " java=" + System.getProperty("java.version"));
    }

    private static void defaults() {
        System.setProperty(PREFIX + "enabled", "false");
        System.setProperty(PREFIX + "missingIndex", "FAIL");
        UpkiConfiguration defaults = UpkiConfiguration.defaults();
        require(defaults.enabled() && defaults.missingIndex() == Handling.WARN, "system property affected fixed defaults");
        UpkiProvider unregistered = new UpkiProvider();
        require(unregistered.configuration().equals(defaults), "system properties affected no-argument configuration");
        require(Security.getProvider(UpkiProvider.NAME) == null, "constructor installed provider");
        UpkiProvider installed = UpkiProvider.install();
        require(installed.configuration().equals(defaults), "no-argument installation changed defaults");
        require(UpkiProvider.install() == installed, "no-argument installation not idempotent");
        UpkiAgent.premain(null);
        require(Security.getProvider(UpkiProvider.NAME) == installed, "agent did not reuse equivalent installation");
        try {
            UpkiAgent.premain("enabled=false");
            throw new AssertionError("agent arguments accepted");
        } catch (IllegalArgumentException expected) {
            require(Security.getProvider(UpkiProvider.NAME) == installed, "invalid arguments changed registration");
        }
    }

    private static void properties() throws Exception {
        try (ProviderTlsFixture fixture = new ProviderTlsFixture()) {
            Security.setProperty(PREFIX + "cacheDirectory", fixture.cache.toString());
            Security.setProperty(PREFIX + "enabled", "true");
            Security.setProperty(PREFIX + "missingIndex", "FAIL");
            Security.setProperty(PREFIX + "cacheFailure", "FAIL_CLOSED");
            Security.setProperty(PREFIX + "missingScts", "WARN");
            Security.setProperty(PREFIX + "coverage", "FAIL");
            Security.setProperty(PREFIX + "unsupportedVerification", "FAIL");
            Files.write(fixture.cache.resolve("index.bin"), new byte[0]);
            UpkiProvider unregistered = new UpkiProvider();
            require(unregistered.diagnostics().cacheState() == CacheState.NOT_CHECKED, "constructor opened corrupt cache");
            UpkiProvider provider = UpkiProvider.install();
            UpkiConfiguration captured = provider.configuration();
            require(captured.equals(unregistered.configuration()), "bootstrap snapshots differ");
            require(captured.missingIndex() == Handling.FAIL
                    && captured.cacheFailure() == CacheFailure.FAIL_CLOSED
                    && captured.missingScts() == Handling.WARN
                    && captured.coverage() == Handling.FAIL
                    && captured.unsupportedVerification() == Handling.FAIL,
                    "policy properties lost");
            fixture.cache(false);
            fixture.request(false, false);
            fixture.cache(true);
            fixture.request(false, true);
            Files.write(fixture.cache.resolve("index.bin"), new byte[0]);
            Security.setProperty(PREFIX + "enabled", "false");
            Security.setProperty(PREFIX + "cacheFailure", "FAIL_OPEN");
            fixture.request(false, true);
            require(provider.configuration() == captured && captured.enabled(), "live property changes mutated provider");
            require(provider.diagnostics()
                            .lastFinding()
                            .get()
                    == Finding.FAILED,
                    "closed failure not recorded");
            try {
                UpkiProvider.install();
                throw new AssertionError("changed security properties silently reconfigured provider");
            } catch (ProviderException expected) {
                require(Security.getProvider(UpkiProvider.NAME) == provider, "conflict replaced provider");
            }
            require(UpkiProvider.install(captured) == provider, "explicit configuration did not reuse instance");
        }
    }

    private static void tls(UpkiProvider provider) throws Exception {
        try (ProviderTlsFixture fixture = new ProviderTlsFixture()) {
            Path cache = provider.configuration()
                                 .cacheDirectory()
                                 .get();
            byte[] issuer = MessageDigest.getInstance("SHA-256").digest(fixture.issuer.spki);
            CacheFixture.write(cache, issuer, false);
            fixture.request(false, false);
            require(provider.diagnostics()
                            .lastFinding()
                            .get()
                    == Finding.NOT_REVOKED,
                    "healthy cache not checked");
            CacheFixture.write(cache, issuer, true);
            fixture.request(false, true);
            require(provider.diagnostics()
                            .lastFinding()
                            .get()
                    == Finding.REVOKED,
                    "revocation bypassed");
            Files.write(cache.resolve("index.bin"), new byte[0]);
            fixture.request(false, provider.configuration().cacheFailure() == CacheFailure.FAIL_CLOSED);
            require(provider.diagnostics().cacheState() == CacheState.FAILED, "corruption not observable");
            long assessments = provider.diagnostics().assessments();
            fixture.request(true, true);
            require(provider.diagnostics().assessments() == assessments, "hostname rejection reached revocation");
        }
    }

    private static void register() {
        int count = 0;
        while (Security.getProperty("security.provider." + (count + 1)) != null) {
            count++;
        }
        for (int i = count; i >= 1; i--) {
            Security.setProperty("security.provider." + (i + 1), Security.getProperty("security.provider." + i));
        }
        Security.setProperty("security.provider.1", UpkiProvider.class.getName());
    }

    /**
     * An earlier test-only agent supplies runtime security configuration, not
     * installation.
     */
    public static final class SettingsAgent {
        public static void premain(String mode) {
            Security.setProperty(PREFIX + "cacheDirectory", System.getProperty("test.upki.cache"));
            if ("invalid".equals(mode)) {
                Security.setProperty(PREFIX + "enabled", "typo");
            } else if ("static".equals(mode)) {
                register();
            }
        }
    }
}
