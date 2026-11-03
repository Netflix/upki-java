/*
 * Copyr *
 * Published lookup vectors are adapted from cpu/go-upki/crlite/crlite_test.go.
 * Copyright 2026 The Go Authors.
 * BSD-3-Clause; see the accompanying go-upki-LICENSE.
 */

package com.netflix.security.upki.test;

import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.Random;

import com.netflix.security.upki.checker.CacheChecker;
import com.netflix.security.upki.checker.CacheChecker.Outcome;
import com.netflix.security.upki.checker.CacheChecker.Result;
import com.netflix.security.upki.checker.CertificateInputs;
import com.netflix.security.upki.checker.RevocationInput;
import com.netflix.security.upki.checker.RevocationInput.Timestamp;
import com.netflix.security.upki.clubcard.Clubcard;
import com.netflix.security.upki.clubcard.Clubcard.Status;
import com.netflix.security.upki.clubcard.ClubcardReader;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import static com.netflix.security.upki.test.CertificateFixture.*;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

class CertificateInputsTest {
    @TempDir
    Path directory;

    private static CertificateFixture issuer;
    private static CertificateFixture leaf;

    @BeforeAll
    static void certificates() throws Exception {
        issuer = new CertificateFixture(new byte[] {1}, false, false, null);
        leaf = new CertificateFixture(
                new byte[] {0, (byte) 128},
                true,
                true,
                list(
                        sct(0, 150, new byte[] {1, 2},
                                new byte[] {3}),
                        sct(1, Long.MIN_VALUE, new byte[0],
                                new byte[] {4, 5})));
    }

    @Test
    void extractsRawSerialExactSpkiAndEveryEmbeddedSct() throws Exception {
        RevocationInput input = CertificateInputs.read(leaf.certificate, issuer.certificate);
        assertArrayEquals(new byte[] {0, (byte) 128}, input.serial());
        assertArrayEquals(MessageDigest.getInstance("SHA-256").digest(issuer.spki),
                input.issuerSpkiHash());
        assertEquals(2, input.timestamps().size());
        assertArrayEquals(CacheCheckerTest.id(0),
                input.timestamps()
                     .get(0)
                     .logId());
        assertEquals(150,
                input.timestamps()
                     .get(0)
                     .timestamp());
        assertArrayEquals(CacheCheckerTest.id(1),
                input.timestamps()
                     .get(1)
                     .logId());
        assertEquals(Long.MIN_VALUE,
                input.timestamps()
                     .get(1)
                     .timestamp());
        assertArrayEquals(leaf.extension, leaf.certificate.getExtensionValue("1.3.6.1.4.1.11129.2.4.2"));
    }

    @Test
    void supportsAbsentVersionAndMissingSctExtension() throws Exception {
        RevocationInput input = CertificateInputs.read(issuer.certificate, leaf.certificate);
        assertArrayEquals(new byte[] {1}, input.serial());
        assertTrue(input.timestamps().isEmpty());
        assertThrows(UnsupportedOperationException.class,
                () -> input.timestamps().clear());
    }

    @Test
    void rawNioReaderPreservesCallerStateAndOwnsReturnedValues() throws Exception {
        ByteBuffer tbs = ByteBuffer.allocateDirect(leaf.tbs.length + 3).order(ByteOrder.LITTLE_ENDIAN);
        tbs.position(3)
           .put(leaf.tbs)
           .flip()
           .position(3);
        ByteBuffer view = tbs.asReadOnlyBuffer().order(ByteOrder.LITTLE_ENDIAN);
        RevocationInput input = CertificateInputs.read(view, ByteBuffer.wrap(issuer.tbs), ByteBuffer.wrap(leaf.extension));
        assertEquals(3, view.position());
        assertEquals(leaf.tbs.length + 3, view.limit());
        assertEquals(ByteOrder.LITTLE_ENDIAN, view.order());
        tbs.put(3, (byte) 0);
        byte[] serial = input.serial();
        serial[0] = 1;
        byte[] hash = input.issuerSpkiHash();
        hash[0] ^= 1;
        byte[] id = input.timestamps()
                         .get(0)
                         .logId();
        id[0] = 1;
        assertArrayEquals(new byte[] {0, (byte) 128}, input.serial());
        assertArrayEquals(MessageDigest.getInstance("SHA-256").digest(issuer.spki),
                input.issuerSpkiHash());
        assertArrayEquals(CacheCheckerTest.id(0),
                input.timestamps()
                     .get(0)
                     .logId());
    }

    @Test
    void inputOwnsTheSuppliedLookupBytesAndTimestampList() {
        byte[] hash = new byte[32];
        byte[] serial = {0, (byte) 128};
        byte[] log = new byte[32];
        List<Timestamp> timestamps = new ArrayList<>();
        timestamps.add(new Timestamp(log, -1));
        RevocationInput input = new RevocationInput(hash, serial, timestamps);
        hash[0] = serial[0] = log[0] = 1;
        timestamps.clear();
        assertArrayEquals(new byte[32], input.issuerSpkiHash());
        assertArrayEquals(new byte[] {0, (byte) 128}, input.serial());
        assertArrayEquals(new byte[32],
                input.timestamps()
                     .get(0)
                     .logId());
        assertEquals(-1,
                input.timestamps()
                     .get(0)
                     .timestamp());
        assertThrows(IllegalArgumentException.class, () -> new Timestamp(new byte[31], 0));
        assertThrows(NullPointerException.class,
                () -> new RevocationInput(new byte[32], serial, Arrays.asList((Timestamp) null)));
    }

    @Test
    void rejectsEveryTruncatedTbsOrExtensionAndTrailingOuterBytes() {
        for (int length = 0; length < leaf.tbs.length; length++) {
            byte[] prefix = Arrays.copyOf(leaf.tbs, length);
            assertThrows(CertificateException.class, () -> read(prefix, issuer.tbs, leaf.extension));
        }
        for (int length = 0; length < issuer.tbs.length; length++) {
            byte[] prefix = Arrays.copyOf(issuer.tbs, length);
            assertThrows(CertificateException.class, () -> read(leaf.tbs, prefix, leaf.extension));
        }
        for (int length = 0; length < leaf.extension.length; length++) {
            byte[] prefix = Arrays.copyOf(leaf.extension, length);
            assertThrows(CertificateException.class, () -> read(leaf.tbs, issuer.tbs, prefix));
        }
        assertThrows(CertificateException.class, () -> read(join(leaf.tbs, new byte[] {0}), issuer.tbs, leaf.extension));
        assertThrows(CertificateException.class, () -> read(leaf.tbs, join(issuer.tbs, new byte[] {0}), leaf.extension));
        assertThrows(CertificateException.class, () -> read(leaf.tbs, issuer.tbs, join(leaf.extension, new byte[] {0})));
    }

    @Test
    void rejectsNonDerLengthsVersionsAndSerials() {
        for (byte[] tbs : new byte[][] {
            {48, (byte) 128, 0, 0},
            {48, (byte) 129, 3, 2, 1,
                    1},
            {48, (byte) 130, 0, (byte) 128},
            {48, (byte) 132, (byte) 255,
                    (byte) 255, (byte) 255, (byte) 255},
            {48, (byte) 133, 1, 0, 0,
                    0, 0},
            der(48, der(2, new byte[0])),
            der(48, der(2, new byte[] {0, 1})),
            der(48, der(2, new byte[] {(byte) 255, (byte) 255})),
            der(48,
                    join(der(160, der(2, new byte[] {3})), der(2, new byte[] {1}))),
            der(
                    48,
                    join(
                            der(160,
                                    join(der(2, new byte[] {2}), new byte[] {0})),
                            der(2, new byte[] {1})))
        }) {
            assertThrows(CertificateException.class, () -> read(tbs, issuer.tbs, null));
        }
    }

    @Test
    void rejectsMalformedSctFramingAndUnsupportedVersions() {
        byte[] sct = sct(0, 150, new byte[0],
                new byte[] {1, 2});
        for (int length = 0; length < sct.length; length++) {
            byte[] truncated = list(Arrays.copyOf(sct, length));
            assertThrows(CertificateException.class, () -> extension(truncated));
        }
        assertThrows(CertificateException.class, () -> extension(list()));
        assertThrows(CertificateException.class,
                () -> extension(join(list(sct), new byte[] {0})));
        assertThrows(CertificateException.class,
                () -> extension(list(join(sct, new byte[] {0}))));
        byte[] version = sct.clone();
        version[0] = 1;
        assertThrows(CertificateException.class, () -> extension(list(version)));
        byte[] badExtensions = sct.clone();
        ByteBuffer.wrap(badExtensions).putShort(41, (short) -1);
        assertThrows(CertificateException.class, () -> extension(list(badExtensions)));
        byte[] badSignature = sct.clone();
        ByteBuffer.wrap(badSignature).putShort(45, (short) -1);
        assertThrows(CertificateException.class, () -> extension(list(badSignature)));
        byte[] wrongTag = leaf.extension.clone();
        wrongTag[0] = 48;
        assertThrows(CertificateException.class, () -> read(leaf.tbs, issuer.tbs, wrongTag));
    }

    @Test
    void supportsLongDerLengthsAndLongSctVectors() throws Exception {
        byte[] encoded = list(sct(7, -1, new byte[260], new byte[300]));
        RevocationInput input = extension(encoded);
        assertEquals(-1,
                input.timestamps()
                     .get(0)
                     .timestamp());
        assertArrayEquals(CacheCheckerTest.id(7),
                input.timestamps()
                     .get(0)
                     .logId());
    }

    @Test
    void publishedCertificateChainsProduceTheKnownClubcardResults() throws Exception {
        String location = System.getenv("UPKI_TEST_CHAINS");
        String filter = System.getenv("UPKI_TEST_FILTER");
        assumeTrue(location != null && filter != null, "Set UPKI_TEST_CHAINS and UPKI_TEST_FILTER for published chains");
        Files.copy(Paths.get(filter), directory.resolve("published"));
        ByteBuffer index = ByteBuffer.allocate(106);
        index.put("upkiidx1".getBytes(StandardCharsets.US_ASCII))
             .putShort((short) 1)
             .putInt(1);
        index.put("published".getBytes(StandardCharsets.US_ASCII)).position(46);
        index.put(decode("1219ENGn9XfCx+lf1wC/+YLJM1pl4dCzAXMXwMjFaXc="))
             .putLong(88)
             .putShort((short) 1)
             .putShort((short) 0)
             .putLong(0)
             .putLong(-1);
        Files.write(directory.resolve("index.bin"), index.array());
        CacheChecker checker = new CacheChecker(Collections.singletonList(directory));
        for (String name : new String[] {"good", "revoked"}) {
            List<X509Certificate> chain = new ArrayList<>();
            try (InputStream stream = Files.newInputStream(Paths.get(location).resolve(name + ".pem"))) {
                CertificateFactory.getInstance("X.509")
                        .generateCertificates(stream)
                        .forEach(c -> chain.add((X509Certificate) c));
            }
            RevocationInput input = CertificateInputs.read(chain.get(0), chain.get(1));
            assertArrayEquals(
                    decode(name.equals("good") ? "Dkb521uxnu6ORfLc3CYMyg==" : "APpDYjsNxwPIEFP8ZGvsOiA="),
                    input.serial());
            assertArrayEquals(
                    decode(name.equals("good") ? "LsOdqDFw3goo/G8jjeEPxe+JSJ7aFp1RF5Ih4/2ZvFY=" : "OdSlmQD9NWJh4EbcOHBxkhygPwNSwA9Q91eounfbcoE="),
                    input.issuerSpkiHash());
            Status status = Status.NOT_COVERED;
            Clubcard card = ClubcardReader.read(Paths.get(filter));
            for (Timestamp timestamp : input.timestamps()) {
                status = card.check(input.key(), timestamp.logId(), timestamp.timestamp());
                if (status != Status.NOT_COVERED) {
                    break;
                }
            }
            assertEquals(name.equals("good") ? Status.NOT_REVOKED : Status.REVOKED, status);
            assertEquals(name.equals("good") ? 3 : 2,
                    input.timestamps().size());
            assertEquals(name.equals("good") ? 1781427700550L : 1782115694514L,
                    input.timestamps()
                         .get(1)
                         .timestamp());
            Result result = checker.check(input);
            assertEquals(name.equals("good") ? Outcome.NOT_REVOKED : Outcome.REVOKED, result.outcome());
            assertTrue(result.failures().isEmpty());
        }
    }

    @Test
    void mutationsOnlyFailThroughTheCheckedDecodeChannel() throws Exception {
        Random random = new Random(71);
        for (int i = 0; i < 2000; i++) {
            byte[] encoded = leaf.extension.clone();
            encoded[random.nextInt(encoded.length)] ^= (byte) (1 << random.nextInt(8));
            try {
                read(leaf.tbs, issuer.tbs, encoded);
            } catch (CertificateException malformed) {
                // Invalid certificate/SCT framing is the expected decode error channel.
            }
        }
    }

    private static byte[] decode(String value) {
        return Base64.getDecoder().decode(value);
    }

    private static RevocationInput extension(byte[] list) throws CertificateException {
        return read(leaf.tbs, issuer.tbs, der(4, der(4, list)));
    }

    private static RevocationInput read(byte[] leafTbs, byte[] issuerTbs, byte[] extension) throws CertificateException {
        return CertificateInputs.read(ByteBuffer.wrap(leafTbs), ByteBuffer.wrap(issuerTbs),
                extension == null ? null : ByteBuffer.wrap(extension));
    }
}
