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
import java.io.OutputStream;
import java.io.UncheckedIOException;
import java.net.InetAddress;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.cert.Certificate;
import java.util.Comparator;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLHandshakeException;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;

/** NIO-backed fixtures for unchanged default HTTPS clients in a fresh JVM. */
final class ProviderTlsFixture implements AutoCloseable {
    final Path directory;
    final Path cache;
    final CertificateFixture issuer;
    final CertificateFixture leaf;
    final KeyStore roots;

    ProviderTlsFixture() throws Exception {
        directory = Files.createTempDirectory("upki-provider-");
        cache = Files.createDirectory(directory.resolve("cache"));
        issuer = new CertificateFixture(new byte[] {120}, false, true, null);
        byte[] scts = CertificateFixture.list(CertificateFixture.sct(1, 150, new byte[0], new byte[] {1}));
        leaf = new CertificateFixture(new byte[] {121}, true, true, scts, issuer.keys,
                "CN=localhost");
        roots = KeyStore.getInstance("JKS");
        roots.load(null, null);
        roots.setCertificateEntry("issuer", issuer.certificate);
        Path trust = directory.resolve("trust.jks");
        try (OutputStream output = Files.newOutputStream(trust)) {
            roots.store(output, "changeit".toCharArray());
        }
        System.setProperty("javax.net.ssl.trustStore", trust.toString());
        System.setProperty("javax.net.ssl.trustStoreType", "JKS");
        System.setProperty("javax.net.ssl.trustStorePassword", "changeit");
    }

    void cache(boolean revoked) throws Exception {
        CacheFixture.write(cache, MessageDigest.getInstance("SHA-256").digest(issuer.spki),
                revoked);
    }

    SSLHandshakeException request(boolean wrongHost, boolean expectedFailure) throws Exception {
        return request(leaf, issuer, wrongHost, expectedFailure, null);
    }

    SSLHandshakeException request(CertificateFixture serverLeaf, CertificateFixture serverIssuer, boolean wrongHost,
            boolean expectedFailure, SSLSocketFactory clientFactory)
            throws Exception {
        KeyStore identity = KeyStore.getInstance("JKS");
        identity.load(null, null);
        identity.setKeyEntry("server", serverLeaf.keys.getPrivate(), "changeit".toCharArray(),
                new Certificate[] {serverLeaf.certificate, serverIssuer.certificate});
        KeyManagerFactory keys = KeyManagerFactory.getInstance("SunX509");
        keys.init(identity, "changeit".toCharArray());
        // A new server context and port prevent resumption/keep-alive from replacing verification.
        SSLContext serverContext = SSLContext.getInstance("TLS");
        serverContext.init(keys.getKeyManagers(), new TrustManager[0], null);
        ExecutorService worker = Executors.newSingleThreadExecutor();
        try (SSLServerSocket server = (SSLServerSocket) serverContext.getServerSocketFactory().createServerSocket(0, 1, InetAddress.getByName("127.0.0.1"))) {
            server.setSoTimeout(10000);
            Future<?> serving = worker.submit(() -> {
                try (SSLSocket socket = (SSLSocket) server.accept()) {
                    socket.setSoTimeout(10000);
                    socket.startHandshake();
                    int tail = 0;
                    boolean complete = false;
                    for (int i = 0; i < 8192; i++) {
                        int next = socket.getInputStream().read();
                        if (next < 0) {
                            throw new IOException("Client ended before HTTP request headers");
                        }
                        tail = (tail << 8) | next;
                        if (tail == 0x0d0a0d0a) {
                            complete = true;
                            break;
                        }
                    }
                    if (!complete) {
                        throw new IOException("HTTP test request headers exceed fixture bound");
                    }
                    socket.getOutputStream().write(("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK").getBytes(StandardCharsets.US_ASCII));
                } catch (IOException failure) {
                    if (!expectedFailure) {
                        throw new UncheckedIOException(failure);
                    }
                }
            });
            HttpsURLConnection client = (HttpsURLConnection) new URL("https://"
                    + (wrongHost ? "127.0.0.1" : "localhost")
                    + ":"
                    + server.getLocalPort()
                    + "/")
                    .openConnection();
            client.setConnectTimeout(10000);
            client.setReadTimeout(10000);
            if (clientFactory != null) {
                client.setSSLSocketFactory(clientFactory);
            }
            SSLHandshakeException rejected = null;
            try {
                int status = client.getResponseCode();
                UpkiProviderProbe.require(!expectedFailure && status == 200, "HTTPS rejection was lost: " + status);
                try (InputStream body = client.getInputStream()) {
                    UpkiProviderProbe.require(body.read() == 'O' && body.read() == 'K' && body.read() == -1,
                            "HTTP response body");
                }
            } catch (SSLHandshakeException failure) {
                if (!expectedFailure) {
                    throw failure;
                }
                rejected = failure;
            } finally {
                client.disconnect();
            }
            serving.get(15, TimeUnit.SECONDS);
            return rejected;
        } finally {
            worker.shutdownNow();
        }
    }

    @Override
    public void close() throws Exception {
        List<Path> paths;
        try (Stream<Path> walk = Files.walk(directory)) {
            paths = walk.sorted(Comparator.reverseOrder()).collect(Collectors.toList());
        }
        for (Path path : paths) {
            Files.delete(path);
        }
    }
}
