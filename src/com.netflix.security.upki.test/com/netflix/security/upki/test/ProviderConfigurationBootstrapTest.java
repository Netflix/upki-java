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

import java.io.File;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.Security;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Properties;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.jar.Attributes.Name;
import java.util.jar.JarOutputStream;
import java.util.jar.Manifest;

import com.netflix.security.provider.UpkiProvider;
import com.netflix.security.upki.UpkiAgent;
import com.netflix.security.upki.test.ProviderConfigurationProbe.SettingsAgent;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

class ProviderConfigurationBootstrapTest {
    @TempDir
    Path directory;

    @ParameterizedTest
    @ValueSource(strings = {"defaults", "properties", "static", "static-invalid", "agent", "agent-static"})
    void productionBootstrapInFreshJvm(String scenario) throws Exception {
        String output = execute(scenario, false, false);
        assertTrue(output.contains("PASS bootstrap " + scenario), output);
    }

    @ParameterizedTest
    @ValueSource(strings = {"file", "file-agent"})
    void externalSecurityFileIsHonoredOnlyWhenTheRuntimePermitsIt(String scenario) throws Exception {
        String output = execute(scenario, false, false);
        boolean allowed = Boolean.parseBoolean(Security.getProperty("security.overridePropertiesFile"));
        assertTrue(output.contains("PASS bootstrap " + scenario + (allowed ? "" : "-ignored")), output);
    }

    @Test
    void invalidAgentConfigurationStopsBeforeMain() throws Exception {
        String output = execute("agent-invalid", true, false);
        assertTrue(output.contains("Invalid security property com.netflix.security.upki.enabled"), output);
        assertFalse(output.contains("MAIN ENTERED"), output);
    }

    @Test
    void unknownAgentArgumentsStopBeforeMain() throws Exception {
        String output = execute("agent-invalid", false, true);
        assertTrue(output.contains("UPKI agent arguments are unsupported"), output);
        assertFalse(output.contains("MAIN ENTERED"), output);
    }

    private String execute(String scenario, boolean invalid, boolean arguments) throws Exception {
        Set<String> locations = UpkiProviderTest.probeLocations();
        for (Class<?> type : ProviderConfigurationProbe.class.getNestMembers()) {
            locations.add(Paths.get(type.getProtectionDomain()
                                        .getCodeSource()
                                        .getLocation()
                                        .toURI())
                    .toString());
        }
        Path cache = Files.createDirectory(directory.resolve("cache"));
        Path java = Paths.get(System.getProperty("java.home"), "bin",
                System.getProperty("os.name").startsWith("Windows") ? "java.exe" : "java");
        List<String> command = new ArrayList<>(Arrays.asList(java.toString(), "-XX:-CreateCoredumpOnCrash", "-cp", String.join(File.pathSeparator, locations)));
        String probe = scenario;
        if (scenario.startsWith("file")) {
            Properties properties = new Properties();
            properties.setProperty("security.provider.1", UpkiProvider.class.getName());
            for (int i = 1; Security.getProperty("security.provider." + i) != null; i++) {
                properties.setProperty("security.provider." + (i + 1), Security.getProperty("security.provider." + i));
            }
            properties.setProperty("com.netflix.security.upki.cacheDirectory", cache.toString());
            properties.setProperty("com.netflix.security.upki.cacheFailure", "FAIL_CLOSED");
            Path overlay = directory.resolve("upki.security");
            try (OutputStream output = Files.newOutputStream(overlay)) {
                properties.store(output, "Test-only provider overlay");
            }
            command.add("-Djava.security.properties=" + overlay);
            if (scenario.equals("file-agent")) {
                command.add("-javaagent:" + agent("upki.jar", UpkiAgent.class.getName()));
            }
            if (!Boolean.parseBoolean(Security.getProperty("security.overridePropertiesFile"))) {
                probe += "-ignored";
            }
        } else if (scenario.startsWith("agent")) {
            // Manifest-only fixture JARs use the real entrypoints from the child classpath.
            Path settings = agent("settings.jar", SettingsAgent.class.getName());
            Path upki = agent("upki.jar", UpkiAgent.class.getName());
            command.add("-Dtest.upki.cache=" + cache);
            command.add("-javaagent:"
                    + settings
                    + "="
                    + (invalid ? "invalid" : scenario.equals("agent-static") ? "static" : "valid"));
            command.add("-javaagent:" + upki + (arguments ? "=unsupported" : ""));
        }
        command.addAll(Arrays.asList(ProviderConfigurationProbe.class.getName(), probe, cache.toString()));
        Path log = directory.resolve(scenario + ".log");
        Process process = new ProcessBuilder(command)
                .directory(directory.toFile())
                .redirectErrorStream(true)
                .redirectOutput(log.toFile())
                .start();
        if (!process.waitFor(45, TimeUnit.SECONDS)) {
            process.destroyForcibly().waitFor();
            fail("Bootstrap probe timed out: " + log);
        }
        String output = new String(Files.readAllBytes(log), StandardCharsets.UTF_8);
        if (invalid || arguments) {
            assertNotEquals(0, process.exitValue(), output);
        } else {
            assertEquals(0, process.exitValue(), output);
        }
        return output;
    }

    private Path agent(String name, String entrypoint) throws Exception {
        Manifest manifest = new Manifest();
        manifest.getMainAttributes().put(Name.MANIFEST_VERSION, "1.0");
        manifest.getMainAttributes().putValue("Premain-Class", entrypoint);
        Path jar = directory.resolve(name);
        try (JarOutputStream output = new JarOutputStream(Files.newOutputStream(jar), manifest)) {
            // Classes deliberately come from the same loader as the application/provider.
        }
        return jar;
    }
}
