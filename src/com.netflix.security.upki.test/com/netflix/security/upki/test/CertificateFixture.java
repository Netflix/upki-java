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

import java.io.ByteArrayInputStream;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;
import javax.security.auth.x500.X500Principal;

/** Small, project-authored DER certificates, signed using public JDK APIs. */
final class CertificateFixture {
    private static final byte[] RSA_OID = {
        6,
        9,
        42,
        (byte) 134,
        72,
        (byte) 134,
        (byte) 247,
        13,
        1,
        1,
        1
    };
    private static final byte[] SIGNATURE_OID = {
        6,
        9,
        42,
        (byte) 134,
        72,
        (byte) 134,
        (byte) 247,
        13,
        1,
        1,
        11
    };
    private static final byte[] SCT_OID = {
        6,
        10,
        43,
        6,
        1,
        4,
        1,
        (byte) 214,
        121,
        2,
        4,
        2
    };

    final KeyPair keys;
    final byte[] spki;
    final byte[] tbs;
    final X509Certificate certificate;
    final byte[] extension;

    CertificateFixture(byte[] serial, boolean version, boolean rsaNull,
                       byte[] sctList)
            throws Exception {
        this(serial, version, rsaNull, sctList, null);
    }

    CertificateFixture(byte[] serial, boolean version, boolean rsaNull,
                       byte[] sctList, KeyPair signingKeys)
            throws Exception {
        this(serial, version, rsaNull, sctList, signingKeys, "CN=upki-java test issuer");
    }

    CertificateFixture(byte[] serial, boolean version, boolean rsaNull,
                       byte[] sctList, KeyPair signingKeys, String subject)
            throws Exception {
        this(serial, version, rsaNull, sctList, signingKeys, subject,
                null);
    }

    CertificateFixture(
            byte[] serial,
            boolean version,
            boolean rsaNull,
            byte[] sctList,
            KeyPair signingKeys,
            String subject,
            KeyPair subjectKeys)
            throws Exception {
        this(serial, version, rsaNull, sctList, signingKeys, subject,
                subjectKeys, "CN=upki-java test issuer", false);
    }

    private CertificateFixture(
            byte[] serial,
            boolean version,
            boolean rsaNull,
            byte[] sctList,
            KeyPair signingKeys,
            String subject,
            KeyPair subjectKeys,
            String issuer,
            boolean authority)
            throws Exception {
        if (subjectKeys == null) {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(2048);
            keys = generator.generateKeyPair();
        } else {
            keys = subjectKeys;
        }
        RSAPublicKey publicKey = (RSAPublicKey) keys.getPublic();
        byte[] rsa = der(
                48,
                join(der(2, publicKey.getModulus().toByteArray()),
                        der(2, publicKey.getPublicExponent().toByteArray())));
        spki = der(
                48,
                join(der(48, join(RSA_OID, rsaNull ? der(5, new byte[0]) : new byte[0])),
                        der(3, join(new byte[] {0}, rsa))));
        byte[] algorithm = der(48, join(SIGNATURE_OID, der(5, new byte[0])));
        byte[] name = new X500Principal(issuer).getEncoded();
        byte[] validity = der(48,
                join(der(23, "260101000000Z".getBytes(StandardCharsets.US_ASCII)), der(23, "490101000000Z".getBytes(StandardCharsets.US_ASCII))));
        extension = sctList == null ? null : der(4, der(4, sctList));
        byte[] sctExtension = sctList == null ? new byte[0] : der(48, join(SCT_OID, extension));
        byte[] constraints = authority ? der(
                48,
                join(
                        new byte[] {6, 3, 85, 29, 19},
                        der(1, new byte[] {(byte) 255}),
                        der(4, der(48, der(1, new byte[] {(byte) 255})))))
                : new byte[0];
        byte[] values = join(sctExtension, constraints);
        byte[] extensions = values.length == 0 ? new byte[0] : der(163, der(48, values));
        tbs = der(
                48,
                join(
                        version ? der(160, der(2, new byte[] {2})) : new byte[0],
                        der(2, serial),
                        algorithm,
                        name,
                        validity,
                        new X500Principal(subject).getEncoded(),
                        spki,
                        extensions));
        Signature signer = Signature.getInstance("SHA256withRSA");
        KeyPair signerKeys = signingKeys == null ? keys : signingKeys;
        signer.initSign(signerKeys.getPrivate());
        signer.update(tbs);
        byte[] encoded = der(
                48,
                join(
                        tbs,
                        algorithm,
                        der(3,
                                join(new byte[] {0}, signer.sign()))));
        certificate = (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(encoded));
        certificate.verify(signerKeys.getPublic());
    }

    static CertificateFixture authority(byte[] serial, CertificateFixture issuer, String subject) throws Exception {
        return issued(serial, issuer, subject, true);
    }

    static CertificateFixture issued(byte[] serial, CertificateFixture issuer, String subject) throws Exception {
        return issued(serial, issuer, subject, false);
    }

    private static CertificateFixture issued(byte[] serial, CertificateFixture issuer, String subject,
            boolean authority)
            throws Exception {
        return new CertificateFixture(
                serial,
                true,
                true,
                null,
                issuer.keys,
                subject,
                null,
                issuer.certificate.getSubjectX500Principal().getName(),
                authority);
    }

    static byte[] sct(int log, long timestamp, byte[] extensions,
                      byte[] signature) {
        ByteBuffer bytes = ByteBuffer.allocate(47 + extensions.length + signature.length);
        byte[] logId = new byte[32];
        logId[0] = (byte) log;
        bytes.put((byte) 0)
             .put(logId)
             .putLong(timestamp)
             .putShort((short) extensions.length)
             .put(extensions)
             .put((byte) 4)
             .put((byte) 3)
             .putShort((short) signature.length)
             .put(signature);
        return bytes.array();
    }

    static byte[] list(byte[]... scts) {
        int length = Arrays.stream(scts)
                .mapToInt(s -> 2 + s.length)
                .sum();
        ByteBuffer bytes = ByteBuffer.allocate(2 + length).putShort((short) length);
        for (byte[] sct : scts) {
            bytes.putShort((short) sct.length).put(sct);
        }
        return bytes.array();
    }

    static byte[] der(int tag, byte[] value) {
        int count = value.length < 128
                ? 0
                : value.length <= 255
                        ? 1
                        : value.length <= 65535 ? 2 : 3;
        ByteBuffer bytes = ByteBuffer.allocate(2 + count + value.length).put((byte) tag);
        if (count == 0) {
            bytes.put((byte) value.length);
        } else {
            bytes.put((byte) (128 + count));
            for (int i = count - 1; i >= 0; i--) {
                bytes.put((byte) (value.length >>> (8 * i)));
            }
        }
        return bytes.put(value).array();
    }

    static byte[] join(byte[]... parts) {
        ByteBuffer bytes = ByteBuffer.allocate(Arrays.stream(parts)
                .mapToInt(p -> p.length)
                .sum());
        for (byte[] part : parts) {
            bytes.put(part);
        }
        return bytes.array();
    }
}
