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

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.jar.Attributes.Name;
import java.util.jar.JarEntry;
import java.util.jar.JarOutputStream;
import java.util.jar.Manifest;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import javax.tools.ToolProvider;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import static java.util.concurrent.TimeUnit.SECONDS;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ProviderBootstrapTest {
    private static final String PACKAGE = "com.netflix.security.upki.test.fixture";
    private static final String PROVIDER = PACKAGE + ".ProbeProvider";
    private static final String MAIN = PACKAGE + ".Main";

    @TempDir
    static Path directory;

    private static Path runtime;
    private static Path classes;
    private static Path trustStore;
    private static Path agent;
    private static Path appended;
    private static Path priority;
    private static boolean overlaysEnabled;

    @BeforeAll
    static void prepare() throws Exception {
        String configured = System.getenv("UPKI_TEST_JAVA_HOME");
        runtime = Paths.get(configured == null ? System.getProperty("java.home") : configured);
        classes = Files.createDirectory(directory.resolve("classes"));
        Path sources = Files.createDirectory(directory.resolve("sources"));
        List<String> arguments = new ArrayList<>(Arrays.asList("--release", "8", "-d", classes.toString()));

        for (String name : Arrays.asList("ProbeProvider", "Main", "ProviderAgent")) {
            Path source = sources.resolve(name + ".java");
            try (InputStream input = ProviderBootstrapTest.class.getResourceAsStream("fixture/" + name + ".java.txt")) {
                assertNotNull(input, name);
                Files.copy(input, source);
            }
            arguments.add(source.toString());
        }
        assertEquals(0, ToolProvider.getSystemJavaCompiler()
                .run(null, null, null, arguments.toArray(new String[0])));

        trustStore = directory.resolve("server.jks");
        execute(
                Arrays.asList(
                        executable(Paths.get(System.getProperty("java.home")), "keytool"),
                        "-genkeypair",
                        "-alias",
                        "localhost",
                        "-keyalg",
                        "RSA",
                        "-keysize",
                        "2048",
                        "-sigalg",
                        "SHA256withRSA",
                        "-keystore",
                        trustStore.toString(),
                        "-storetype",
                        "JKS",
                        "-storepass",
                        "changeit",
                        "-keypass",
                        "changeit",
                        "-dname",
                        "CN=localhost",
                        "-ext",
                        "SAN=dns:localhost",
                        "-validity",
                        "2",
                        "-noprompt"));

        String configuration = javaProcess(Arrays.asList(MAIN, "providers"));
        overlaysEnabled = configuration.contains("overlays.enabled=true");
        List<String> providers = configuration.lines()
                .filter(line -> line.startsWith("security.provider."))
                .collect(Collectors.toList());
        appended = directory.resolve("appended.security");
        Files.write(appended, Arrays.asList("security.provider." + (providers.size() + 1) + "=" + PROVIDER, "ssl.TrustManagerFactory.algorithm=UPKI"), StandardCharsets.UTF_8);

        List<String> ordered = new ArrayList<>();
        ordered.add("security.provider.1=" + PROVIDER);
        for (int i = 0; i < providers.size(); i++) {
            String entry = providers.get(i);
            ordered.add("security.provider." + (i + 2) + entry.substring(entry.indexOf('=')));
        }
        priority = directory.resolve("priority.security");
        Files.write(priority, ordered, StandardCharsets.UTF_8);

        Manifest manifest = new Manifest();
        manifest.getMainAttributes().put(Name.MANIFEST_VERSION, "1.0");
        manifest.getMainAttributes().putValue("Premain-Class", PACKAGE + ".ProviderAgent");
        agent = directory.resolve("probe-agent.jar");
        try (JarOutputStream jar = new JarOutputStream(Files.newOutputStream(agent), manifest);
             Stream<Path> files = Files.walk(classes)) {
            for (Path file : files.filter(Files::isRegularFile).collect(Collectors.toList())) {
                jar.putNextEntry(new JarEntry(classes.relativize(file)
                        .toString()
                        .replace('\\', '/')));
                Files.copy(file, jar);
                jar.closeEntry();
            }
        }
    }

    @Test
    void baselineDoesNotUseProbe() throws Exception {
        handshake("file", 0);
    }

    @Test
    void earlyInstallWithUniqueDefaultAlgorithmInterceptsHttps() throws Exception {
        String output = handshake("runtime", 1);
        assertTrue(output.contains("default factory=UPKI-Probe"), output);
        assertTrue(output.contains("pinned factory=SunJSSE"), output);
    }

    @Test
    void earlyPriorityInstallInterceptsPkixWithoutChangingAlgorithm() throws Exception {
        String output = handshake("runtime", 1, "-Dprobe.override=true");
        assertTrue(output.contains("default algorithm=PKIX"), output);
        assertTrue(output.contains("PKIX factory=UPKI-Probe"), output);
    }

    @Test
    void propertiesCanSelectAnAppendedProviderUnlessRuntimeDisablesOverlays() throws Exception {
        String output = handshake("file", overlaysEnabled ? 1 : 0, "-Djava.security.properties=" + appended);
        assertEquals(overlaysEnabled, output.contains("default factory=UPKI-Probe"), output);
    }

    @Test
    void propertiesCanPrioritizePkixUnlessRuntimeDisablesOverlays() throws Exception {
        String output = handshake("file", overlaysEnabled ? 1 : 0, "-Dprobe.override=true",
                "-Djava.security.properties=" + priority);
        assertEquals(overlaysEnabled, output.contains("PKIX factory=UPKI-Probe"), output);
    }

    @Test
    void lateInstallDoesNotReplaceCachedHttpsDefaults() throws Exception {
        String output = handshake("late", 0);
        assertTrue(output.contains("default factory=UPKI-Probe"), output);
    }

    @Test
    void freshContextUsesProviderInstalledAfterDefaultInitialization() throws Exception {
        List<String> arguments = handshakeArguments(1);
        arguments.addAll(Arrays.asList(MAIN, "late", "null-context"));
        javaProcess(arguments);
    }

    @Test
    void agentInstallsProviderBeforeUnmodifiedClientMain() throws Exception {
        String output = handshake("file", 1, "-Dprobe.override=true", "-javaagent:" + agent);
        assertTrue(output.contains("PKIX factory=UPKI-Probe"), output);
    }

    private static String handshake(String mode, int expected, String... options) throws Exception {
        List<String> arguments = handshakeArguments(expected);
        arguments.addAll(Arrays.asList(options));
        arguments.addAll(Arrays.asList(MAIN, mode));
        return javaProcess(arguments);
    }

    private static List<String> handshakeArguments(int expected) {
        return new ArrayList<>(Arrays.asList("-Djavax.net.ssl.trustStore=" + trustStore, "-Dprobe.expected=" + expected));
    }

    private static String javaProcess(List<String> arguments) throws Exception {
        List<String> command = new ArrayList<>(Arrays.asList(executable(runtime, "java"), "-cp", classes.toString()));
        command.addAll(arguments);
        return execute(command);
    }

    private static String executable(Path home, String command) {
        String suffix = System.getProperty("os.name").startsWith("Windows") ? ".exe" : "";
        return home.resolve("bin")
                   .resolve(command + suffix)
                   .toString();
    }

    private static String execute(List<String> command) throws Exception {
        Path log = Files.createTempFile(directory, "process-", ".log");
        Process process = new ProcessBuilder(command)
                .directory(directory.toFile())
                .redirectErrorStream(true)
                .redirectOutput(log.toFile())
                .start();
        if (!process.waitFor(30, SECONDS)) {
            process.destroyForcibly();
            process.waitFor();
            throw new IOException("Process timed out: " + command + "\n" + Files.readString(log));
        }
        String output = Files.readString(log);
        assertEquals(0, process.exitValue(), () -> command + "\n" + output);
        return output;
    }
}
