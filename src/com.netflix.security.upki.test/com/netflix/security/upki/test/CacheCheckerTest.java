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
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.AccessDeniedException;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.IntStream;

import com.netflix.security.upki.checker.CacheChecker;
import com.netflix.security.upki.checker.CacheChecker.Operation;
import com.netflix.security.upki.checker.CacheChecker.Outcome;
import com.netflix.security.upki.checker.CacheChecker.Result;
import com.netflix.security.upki.checker.RevocationInput;
import com.netflix.security.upki.checker.RevocationInput.Timestamp;
import com.netflix.security.upki.clubcard.ClubcardReader;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CacheCheckerTest {
    @TempDir
    Path directory;

    @Test
    void noSctsNeedsNoCacheAccess() throws Exception {
        Files.write(directory.resolve("index.bin"), new byte[0]);
        Result result = checker().check(input());
        assertEquals(Outcome.NO_SCTS, result.outcome());
        assertTrue(result.failures().isEmpty());
        assertFalse(result.directory().isPresent());
    }

    @Test
    void distinguishesMissingAndMalformedIndexesWithoutFallback() throws Exception {
        assertEquals(Outcome.NO_DATA,
                checker()
                        .check(input(timestamp(0)))
                        .outcome());
        Path system = Files.createDirectory(directory.resolve("system"));
        publish(system, new String[] {"revoked"}, new int[] {0},
                new int[][] {{0}});
        Files.write(system.resolve("revoked"), card(0, 0, true));
        Files.write(directory.resolve("index.bin"), new byte[0]);
        Result result = new CacheChecker(Arrays.asList(directory, system)).check(input(timestamp(0)));
        assertEquals(Outcome.FAILED, result.outcome());
        assertEquals(Operation.INDEX_OPEN,
                result.failures()
                      .get(0)
                      .operation());
        assertEquals(directory.resolve("index.bin"),
                result.failures()
                      .get(0)
                      .path());
    }

    @Test
    void queriesAllSctsAndDeduplicatesFiltersAcrossEntriesAndLogs() throws Exception {
        publish(
                directory,
                new String[] {"good", "good", "revoked"},
                new int[] {0, 1},
                new int[][] {{0, 1}, {0, 2}});
        Files.write(directory.resolve("good"), card(0, 0, false));
        Files.write(directory.resolve("revoked"), card(0, 1, true));
        Map<Path, Integer> reads = new HashMap<>();
        CacheChecker checker = new CacheChecker(Collections.singletonList(directory),
                path -> {
                    reads.merge(path, 1, Integer::sum);
                    return ClubcardReader.read(path);
                });
        Result result = checker.check(input(timestamp(0), timestamp(1)));
        assertEquals(Outcome.REVOKED, result.outcome());
        assertEquals(1, reads.get(directory.resolve("good")));
        assertEquals(1, reads.get(directory.resolve("revoked")));
    }

    @Test
    void unenrolledAndGoodFiltersDoNotMaskRevocationInEitherOrder() throws Exception {
        Files.write(directory.resolve("unenrolled"), card(1, 0, false));
        Files.write(directory.resolve("good"), card(0, 0, false));
        Files.write(directory.resolve("revoked"), card(0, 0, true));
        for (String[] names : new String[][] {{"unenrolled", "good", "revoked"}, {"revoked", "good", "unenrolled"}}) {
            publish(directory, names, new int[] {0},
                    new int[][] {{0, 1, 2}});
            assertEquals(Outcome.REVOKED,
                    checker()
                            .check(input(timestamp(0)))
                            .outcome());
        }
        publish(directory, new String[] {"unenrolled", "good"}, new int[] {0},
                new int[][] {{0, 1}});
        assertEquals(Outcome.NOT_REVOKED,
                checker()
                        .check(input(timestamp(0)))
                        .outcome());
        publish(directory, new String[] {"unenrolled"}, new int[] {0},
                new int[][] {{0}});
        assertEquals(Outcome.NOT_ENROLLED,
                checker()
                        .check(input(timestamp(0)))
                        .outcome());
    }

    @Test
    void distinguishesNoCoveringFiltersFromContradictoryCoverage() throws Exception {
        publish(directory, new String[] {"uncovered"}, new int[] {0},
                new int[][] {{0}});
        Files.write(directory.resolve("uncovered"), card(0, 1, false));
        assertEquals(Outcome.NOT_COVERED,
                checker()
                        .check(input(timestamp(2)))
                        .outcome());
        Result result = checker().check(input(timestamp(0)));
        assertEquals(Outcome.FAILED, result.outcome());
        assertEquals(Operation.INCONSISTENT_COVERAGE,
                result.failures()
                      .get(0)
                      .operation());
        Files.write(directory.resolve("good"), card(0, 0, false));
        publish(directory, new String[] {"uncovered", "good"}, new int[] {0},
                new int[][] {{0, 1}});
        assertEquals(Outcome.NOT_REVOKED,
                checker()
                        .check(input(timestamp(0)))
                        .outcome());
    }

    @Test
    void eachSelectedFilterIsQueriedWithEveryTimestamp() throws Exception {
        publish(directory, new String[] {"revoked"}, new int[] {0},
                new int[][] {{0}});
        Files.write(directory.resolve("revoked"), card(0, 1, true));
        assertEquals(Outcome.REVOKED,
                checker()
                        .check(input(timestamp(0), timestamp(1)))
                        .outcome());
    }

    @Test
    void retainsFilterFailuresWithoutMaskingRevokedOrClaimingNotRevoked() throws Exception {
        Files.write(directory.resolve("bad"), new byte[0]);
        Files.write(directory.resolve("revoked"), card(0, 0, true));
        Files.write(directory.resolve("good"), card(0, 0, false));
        publish(directory, new String[] {"bad", "revoked"}, new int[] {0},
                new int[][] {{0, 1}});
        Result revoked = checker().check(input(timestamp(0)));
        assertEquals(Outcome.REVOKED, revoked.outcome());
        assertEquals(Operation.FILTER_LOAD,
                revoked.failures()
                       .get(0)
                       .operation());
        assertInstanceOf(IOException.class,
                revoked.failures()
                       .get(0)
                       .cause());
        for (String[] names : new String[][] {{"bad", "good"}, {"good", "bad"}}) {
            publish(directory, names, new int[] {0},
                    new int[][] {{0, 1}});
            Result failed = checker().check(input(timestamp(0)));
            assertEquals(Outcome.FAILED, failed.outcome());
            assertTrue(failed.observedNotRevoked());
            assertThrows(UnsupportedOperationException.class,
                    () -> failed.failures().clear());
        }
    }

    @Test
    void missingFilterRecoveryRestartsTheEntireCheck() throws Exception {
        publish(directory, new String[] {"good", "gone"}, new int[] {0},
                new int[][] {{0, 1}});
        Files.write(directory.resolve("good"), card(0, 0, false));
        Files.write(directory.resolve("new"), card(1, 0, false));
        AtomicInteger reads = new AtomicInteger();
        CacheChecker checker = new CacheChecker(Collections.singletonList(directory),
                path -> {
                    reads.incrementAndGet();
                    if (path.getFileName()
                            .toString()
                            .equals("gone")) {
                        publish(directory, new String[] {"new"}, new int[] {0},
                                new int[][] {{0}});
                        throw new NoSuchFileException(path.toString());
                    }
                    return ClubcardReader.read(path);
                });
        Result result = checker.check(input(timestamp(0)));
        assertEquals(Outcome.NOT_ENROLLED, result.outcome());
        assertFalse(result.observedNotRevoked());
        assertTrue(result.failures().isEmpty());
        assertEquals(1, result.restarts());
        assertEquals(3, reads.get());
    }

    @Test
    void missingFilterRecoveryIsBoundedAndNeverSelectsAnotherCache() throws Exception {
        publish(directory, new String[] {"gone"}, new int[] {0},
                new int[][] {{0}});
        Path system = Files.createDirectory(directory.resolve("system"));
        publish(system, new String[] {"good"}, new int[] {0},
                new int[][] {{0}});
        Files.write(system.resolve("good"), card(0, 0, false));
        AtomicInteger reads = new AtomicInteger();
        CacheChecker checker = new CacheChecker(Arrays.asList(directory, system),
                path -> {
                    reads.incrementAndGet();
                    return ClubcardReader.read(path);
                });
        Result result = checker.check(input(timestamp(0)));
        assertEquals(Outcome.FAILED, result.outcome());
        assertEquals(2, result.restarts());
        assertEquals(3, reads.get());
        assertEquals(directory, result.directory().get());
        assertInstanceOf(NoSuchFileException.class,
                result.failures()
                      .get(0)
                      .cause());
    }

    @Test
    void indexDisappearingOnRecoveryIsMissingDataNotRediscovery() throws Exception {
        publish(directory, new String[] {"gone"}, new int[] {0},
                new int[][] {{0}});
        Path system = Files.createDirectory(directory.resolve("system"));
        publish(system, new String[] {"good"}, new int[] {0},
                new int[][] {{0}});
        Files.write(system.resolve("good"), card(0, 0, false));
        CacheChecker checker = new CacheChecker(Arrays.asList(directory, system),
                path -> {
                    Files.delete(directory.resolve("index.bin"));
                    throw new NoSuchFileException(path.toString());
                });
        Result result = checker.check(input(timestamp(0)));
        assertEquals(Outcome.NO_DATA, result.outcome());
        assertEquals(directory, result.directory().get());
        assertEquals(1, result.restarts());
    }

    @Test
    void otherFilterErrorsDoNotTriggerRestarts() throws Exception {
        publish(directory, new String[] {"denied"}, new int[] {0},
                new int[][] {{0}});
        AtomicInteger reads = new AtomicInteger();
        CacheChecker checker = new CacheChecker(Collections.singletonList(directory),
                path -> {
                    reads.incrementAndGet();
                    throw new AccessDeniedException(path.toString());
                });
        Result result = checker.check(input(timestamp(0)));
        assertEquals(Outcome.FAILED, result.outcome());
        assertEquals(0, result.restarts());
        assertEquals(1, reads.get());
    }

    @Test
    void lookupFailureDoesNotMaskAnotherLogsRevokedFilter() throws Exception {
        publish(directory, new String[] {"revoked"}, new int[] {0, 1},
                new int[][] {{1}, {0}});
        Files.write(directory.resolve("revoked"), card(0, 1, true));
        Result result = checker().check(input(timestamp(0), timestamp(1)));
        assertEquals(Outcome.REVOKED, result.outcome());
        assertEquals(Operation.INDEX_LOOKUP,
                result.failures()
                      .get(0)
                      .operation());
    }

    @Test
    void unexpectedFailuresAreNotConvertedToCacheErrors() throws Exception {
        publish(directory, new String[] {"bug"}, new int[] {0},
                new int[][] {{0}});
        CacheChecker checker = new CacheChecker(Collections.singletonList(directory), path -> {
            throw new IllegalStateException("test implementation failure");
        });
        assertThrows(IllegalStateException.class, () -> checker.check(input(timestamp(0))));
    }

    @Test
    void everyCheckDiscoversTheCurrentIndexAndConcurrentChecksShareNoState() throws Exception {
        CacheChecker checker = checker();
        assertEquals(Outcome.NO_DATA, checker.check(input(timestamp(0))).outcome());
        Files.write(directory.resolve("good"), card(0, 0, false));
        publish(directory, new String[] {"good"}, new int[] {0},
                new int[][] {{0}});
        IntStream.range(0, 100)
                .parallel()
                .forEach(i -> assertEquals(Outcome.NOT_REVOKED, checker.check(input(timestamp(0))).outcome()));
        Files.write(directory.resolve("revoked"), card(0, 0, true));
        publish(directory, new String[] {"revoked"}, new int[] {0},
                new int[][] {{0}});
        assertEquals(Outcome.REVOKED, checker.check(input(timestamp(0))).outcome());
    }

    @Test
    void missingFilterDoesNotTriggerRestartAfterAnotherFilterConfirmsRevocation() throws Exception {
        publish(directory, new String[] {"gone", "revoked"}, new int[] {0},
                new int[][] {{0, 1}});
        Files.write(directory.resolve("revoked"), card(0, 0, true));
        Result result = checker().check(input(timestamp(0)));
        assertEquals(Outcome.REVOKED, result.outcome());
        assertEquals(0, result.restarts());
        assertInstanceOf(NoSuchFileException.class,
                result.failures()
                      .get(0)
                      .cause());
    }

    @Test
    void corruptReplacementIndexIsARecordedFailure() throws Exception {
        publish(directory, new String[] {"gone"}, new int[] {0},
                new int[][] {{0}});
        CacheChecker checker = new CacheChecker(Collections.singletonList(directory),
                path -> {
                    Files.write(directory.resolve("index.bin"), new byte[0]);
                    throw new NoSuchFileException(path.toString());
                });
        Result result = checker.check(input(timestamp(0)));
        assertEquals(Outcome.FAILED, result.outcome());
        assertEquals(1, result.restarts());
        assertEquals(Operation.INDEX_OPEN,
                result.failures()
                      .get(0)
                      .operation());
    }

    @Test
    void missingUserIndexAllowsInitialSystemSelection() throws Exception {
        Path user = directory.resolve("missing");
        Files.write(directory.resolve("good"), card(0, 0, false));
        publish(directory, new String[] {"good"}, new int[] {0},
                new int[][] {{0}});
        Result result = new CacheChecker(Arrays.asList(user, directory)).check(input(timestamp(0)));
        assertEquals(Outcome.NOT_REVOKED, result.outcome());
        assertEquals(directory, result.directory().get());
    }

    private CacheChecker checker() {
        return new CacheChecker(Collections.singletonList(directory));
    }

    static RevocationInput input(Timestamp... timestamps) {
        return new RevocationInput(id(0), new byte[] {0, (byte) 128},
                Arrays.asList(timestamps));
    }

    static Timestamp timestamp(int log) {
        return new Timestamp(id(log), 150);
    }

    static byte[] id(int first) {
        byte[] bytes = new byte[32];
        bytes[0] = (byte) first;
        return bytes;
    }

    static byte[] card(int issuer, int log, boolean revoked) {
        ByteBuffer bytes = ByteBuffer.allocate(113);
        bytes.put((byte) 4)
             .put((byte) 0)
             .putShort((short) 1)
             .put(id(log))
             .putLong(100)
             .putLong(200);
        bytes.putInt(1)
             .put(id(issuer))
             .putInt(0)
             .put((byte) 0)
             .putInt(0)
             .putInt(0)
             .putInt(0)
             .put((byte) (revoked ? 1 : 0))
             .putShort((short) 0)
             .put((byte) 0)
             .putInt(0);
        return bytes.array();
    }

    static void publish(Path directory, String[] names, int[] logs,
                        int[][] filters)
            throws IOException {
        int entries = Arrays.stream(filters)
                .mapToInt(a -> a.length)
                .sum();
        int metadata = 14 + names.length * 32 + logs.length * 42;
        ByteBuffer bytes = ByteBuffer.allocate(metadata + entries * 18);
        bytes.put("upkiidx1".getBytes(StandardCharsets.US_ASCII))
             .putShort((short) names.length)
             .putInt(logs.length);
        for (String name : names) {
            int start = bytes.position();
            bytes.put(name.getBytes(StandardCharsets.US_ASCII)).position(start + 32);
        }
        long offset = metadata;
        for (int i = 0; i < logs.length; i++) {
            bytes.put(id(logs[i]))
                 .putLong(offset)
                 .putShort((short) filters[i].length);
            offset += filters[i].length * 18L;
        }
        for (int[] section : filters) {
            for (int filter : section) {
                bytes.putShort((short) filter)
                     .putLong(100)
                     .putLong(200);
            }
        }
        Path temporary = Files.createTempFile(directory, "index-", ".tmp");
        Files.write(temporary, bytes.array());
        Files.move(temporary, directory.resolve("index.bin"), StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
    }
}
