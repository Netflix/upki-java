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

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

import com.netflix.security.upki.checker.RevocationInput.Timestamp;

/**
 * Narrow lookup-input extraction, not certificate/path or CT signature validation.
 * The caller must supply an already-validated leaf and its authenticated issuer.
 */
public final class CertificateInputs {
    private static final String SCT_EXTENSION = "1.3.6.1.4.1.11129.2.4.2";
    private static final int INTEGER = 0x02;
    private static final int OCTET_STRING = 0x04;
    private static final int SEQUENCE = 0x30;
    private static final int EXPLICIT_VERSION = 0xa0;

    private CertificateInputs() {}

    public static RevocationInput read(X509Certificate leaf, X509Certificate issuer) throws CertificateException {
        Objects.requireNonNull(leaf, "leaf");
        Objects.requireNonNull(issuer, "issuer");
        byte[] extension = leaf.getExtensionValue(SCT_EXTENSION);
        return read(ByteBuffer.wrap(leaf.getTBSCertificate()), ByteBuffer.wrap(issuer.getTBSCertificate()),
                extension == null ? null : ByteBuffer.wrap(extension));
    }

    /**
     * Reads DER TBSCertificates and the JDK getExtensionValue representation.
     * Input buffer state is preserved; null extension means the extension is absent.
     */
    public static RevocationInput read(ByteBuffer leafTbs, ByteBuffer issuerTbs, ByteBuffer extension) throws CertificateException {
        ByteBuffer leaf = tbs(Objects.requireNonNull(leafTbs, "leafTbs"));
        byte[] serial = bytes(serial(leaf));

        ByteBuffer issuer = tbs(Objects.requireNonNull(issuerTbs, "issuerTbs"));
        serial(issuer);
        element(issuer, SEQUENCE); // signature AlgorithmIdentifier
        element(issuer, SEQUENCE); // issuer Name
        element(issuer, SEQUENCE); // validity
        element(issuer, SEQUENCE); // subject Name
        int start = issuer.position();
        element(issuer, SEQUENCE); // SubjectPublicKeyInfo, including its original tag and length below
        ByteBuffer spki = issuer.duplicate().order(ByteOrder.BIG_ENDIAN);
        spki.limit(issuer.position()).position(start);

        MessageDigest digest;
        try {
            digest = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException error) {
            throw new IllegalStateException("Required SHA-256 implementation is unavailable", error);
        }
        digest.update(spki);
        return new RevocationInput(digest.digest(), serial, timestamps(extension));
    }

    private static ByteBuffer tbs(ByteBuffer encoded) throws CertificateException {
        ByteBuffer outer = encoded.duplicate().order(ByteOrder.BIG_ENDIAN);
        ByteBuffer tbs = element(outer, SEQUENCE);
        end(outer);
        require(tbs, 1);
        if (Byte.toUnsignedInt(tbs.get(tbs.position())) == EXPLICIT_VERSION) {
            ByteBuffer version = element(tbs, EXPLICIT_VERSION);
            ByteBuffer value = element(version, INTEGER);
            if (value.remaining() != 1 || Byte.toUnsignedInt(value.get()) > 2) {
                throw invalid("unsupported certificate version");
            }
            end(version);
        }
        return tbs;
    }

    private static ByteBuffer serial(ByteBuffer tbs) throws CertificateException {
        ByteBuffer serial = element(tbs, INTEGER);
        require(serial, 1);
        if (serial.remaining() > 1) {
            int first = Byte.toUnsignedInt(serial.get(0));
            int next = Byte.toUnsignedInt(serial.get(1));
            if (first == 0 && next < 128
                    || first == 255 && next >= 128) {
                throw invalid("nonminimal serial INTEGER");
            }
        }
        return serial;
    }

    private static List<Timestamp> timestamps(ByteBuffer extension) throws CertificateException {
        List<Timestamp> timestamps = new ArrayList<Timestamp>();
        if (extension == null) {
            return timestamps;
        }
        // getExtensionValue adds an OCTET STRING around the extension's own OCTET STRING.
        ByteBuffer outer = extension.duplicate().order(ByteOrder.BIG_ENDIAN);
        ByteBuffer contents = element(outer, OCTET_STRING);
        end(outer);
        ByteBuffer encoded = element(contents, OCTET_STRING);
        end(contents);
        int length = u16(encoded);
        if (length == 0) {
            throw invalid("empty SCT list");
        }
        ByteBuffer list = take(encoded, length);
        end(encoded);
        while (list.hasRemaining()) {
            ByteBuffer sct = take(list, u16(list));
            require(sct, 1);
            if (sct.get() != 0) {
                throw invalid("unsupported SCT version");
            }
            byte[] logId = bytes(take(sct, 32));
            require(sct, 8);
            long timestamp = sct.getLong();
            take(sct, u16(sct)); // CtExtensions
            require(sct, 2);
            sct.get(); // HashAlgorithm
            sct.get(); // SignatureAlgorithm
            take(sct, u16(sct)); // digitally-signed signature; framing only, not verification
            end(sct);
            timestamps.add(new Timestamp(logId, timestamp));
        }
        return timestamps;
    }

    private static ByteBuffer element(ByteBuffer bytes, int tag) throws CertificateException {
        require(bytes, 2);
        if (Byte.toUnsignedInt(bytes.get()) != tag) {
            throw invalid("unexpected DER tag");
        }
        int first = Byte.toUnsignedInt(bytes.get());
        long length = first;
        if (first >= 128) {
            int count = first & 127;
            if (count == 0 || count > 4) {
                throw invalid("unsupported DER length");
            }
            require(bytes, count);
            if (bytes.get(bytes.position()) == 0) {
                throw invalid("nonminimal DER length");
            }
            length = 0;
            for (int i = 0; i < count; i++) {
                length = (length << 8) | Byte.toUnsignedInt(bytes.get());
            }
            if (length < 128) {
                throw invalid("nonminimal DER length");
            }
        }
        require(bytes, length);
        return take(bytes, (int) length);
    }

    private static int u16(ByteBuffer bytes) throws CertificateException {
        require(bytes, 2);
        return Short.toUnsignedInt(bytes.getShort());
    }

    private static ByteBuffer take(ByteBuffer bytes, int length) throws CertificateException {
        require(bytes, length);
        ByteBuffer value = bytes.slice().order(ByteOrder.BIG_ENDIAN);
        value.limit(length);
        bytes.position(bytes.position() + length);
        return value;
    }

    private static byte[] bytes(ByteBuffer value) {
        byte[] result = new byte[value.remaining()];
        value.get(result);
        return result;
    }

    private static void require(ByteBuffer bytes, long length) throws CertificateException {
        if (length < 0 || length > bytes.remaining()) {
            throw invalid("truncated DER or SCT field");
        }
    }

    private static void end(ByteBuffer bytes) throws CertificateException {
        if (bytes.hasRemaining()) {
            throw invalid("trailing DER or SCT bytes");
        }
    }

    private static CertificateException invalid(String reason) {
        return new CertificateException("Invalid UPKI certificate input: " + reason);
    }
}
