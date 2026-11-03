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

import java.io.IOException;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

import com.netflix.security.upki.cache.CacheDiscovery;
import com.netflix.security.upki.cache.CacheDiscovery.Selection;
import com.netflix.security.upki.checker.RevocationInput.Timestamp;
import com.netflix.security.upki.clubcard.Clubcard;
import com.netflix.security.upki.clubcard.Clubcard.Status;
import com.netflix.security.upki.clubcard.ClubcardReader;

/**
 * Internal per-check cache orchestration; it makes no connection acceptance
 * decisions.
 */
public final class CacheChecker {
    private static final int MAX_RESTARTS = 2;

    private final List<Path> directories;
    private final FilterReader filters;

    public CacheChecker(List<Path> directories) {
        this(directories, ClubcardReader::read);
    }

    /**
     * The loader seam permits deterministic update-race and I/O fault tests.
     * Injected loaders must support concurrent use if checks are concurrent.
     */
    public CacheChecker(List<Path> directories, FilterReader filters) {
        Objects.requireNonNull(directories, "directories");
        List<Path> owned = new ArrayList<Path>(directories.size());
        for (Path directory : directories) {
            owned.add(Objects.requireNonNull(directory, "directory"));
        }
        this.directories = Collections.unmodifiableList(owned);
        this.filters = Objects.requireNonNull(filters, "filters");
    }

    public Result check(RevocationInput input) {
        Objects.requireNonNull(input, "input");
        if (input.timestamps().isEmpty()) {
            return new Result(Outcome.NO_SCTS, null, new Pass(), 0);
        }

        Path selected = null;
        int candidate = 0;
        for (int restarts = 0; ; ) {
            Path directory;
            if (selected == null) {
                if (candidate == directories.size()) {
                    return new Result(Outcome.NO_DATA, null, new Pass(), restarts);
                }
                directory = directories.get(candidate++);
            } else {
                directory = selected;
            }

            Optional<Selection> opened;
            try {
                opened = CacheDiscovery.open(Collections.singletonList(directory));
            } catch (IOException error) {
                Pass failed = new Pass();
                failed.failures.add(new Failure(Operation.INDEX_OPEN, directory.resolve("index.bin"), error));
                return new Result(Outcome.FAILED, directory, failed, restarts);
            }
            if (!opened.isPresent()) {
                if (selected != null) {
                    return new Result(Outcome.NO_DATA, selected, new Pass(), restarts);
                }
                continue;
            }
            selected = directory;
            Pass pass = new Pass();
            try (Selection selection = opened.get()) {
                query(selection, input, pass);
            } catch (IOException closeError) {
                // query records expected read/decode failures itself; only close can throw here.
                pass.failures.add(new Failure(Operation.INDEX_CLOSE, directory.resolve("index.bin"), closeError));
            }

            if (pass.revoked) {
                return new Result(Outcome.REVOKED, selected, pass, restarts);
            }
            if (pass.missingFilter && restarts < MAX_RESTARTS) {
                // Discard all observations from this superseded index, not just the failed filter.
                restarts++;
                continue;
            }
            Outcome outcome = !pass.failures.isEmpty()
                    ? Outcome.FAILED
                    : pass.notRevoked ? Outcome.NOT_REVOKED : pass.notEnrolled ? Outcome.NOT_ENROLLED : Outcome.NOT_COVERED;
            return new Result(outcome, selected, pass, restarts);
        }
    }

    private void query(Selection selection, RevocationInput input, Pass pass) {
        Set<String> filenames = new LinkedHashSet<String>();
        for (Timestamp timestamp : input.timestamps()) {
            try {
                filenames.addAll(selection.index().lookup(timestamp.logId, timestamp.timestamp));
            } catch (IOException error) {
                pass.failures.add(new Failure(Operation.INDEX_LOOKUP, selection.directory().resolve("index.bin"),
                        error));
            }
        }

        int uncovered = 0;
        for (String filename : filenames) {
            Path path = selection.directory().resolve(filename);
            Clubcard filter;
            try {
                filter = Objects.requireNonNull(filters.read(path), "filter");
            } catch (IOException error) {
                pass.failures.add(new Failure(Operation.FILTER_LOAD, path, error));
                pass.missingFilter |= error instanceof NoSuchFileException;
                continue;
            }

            Status status = Status.NOT_COVERED;
            for (Timestamp timestamp : input.timestamps()) {
                status = filter.check(input.key(), timestamp.logId, timestamp.timestamp);
                if (status != Status.NOT_COVERED) {
                    break;
                }
            }
            switch (status) {
                case REVOKED:
                    pass.revoked = true;
                    return;
                case NOT_REVOKED:
                    pass.notRevoked = true;
                    break;
                case NOT_ENROLLED:
                    pass.notEnrolled = true;
                    break;
                case NOT_COVERED:
                    uncovered++;
                    break;
                default:
                    throw new AssertionError(status);
            }
        }
        if (!filenames.isEmpty() && uncovered == filenames.size()) {
            pass.failures.add(new Failure(Operation.INCONSISTENT_COVERAGE, selection.directory().resolve("index.bin"),
                    new IOException("No index-selected filter covers the supplied SCTs")));
        }
    }

    @FunctionalInterface
    public interface FilterReader {
        Clubcard read(Path path) throws IOException;
    }

    public enum Outcome {
        REVOKED,
        NOT_REVOKED,
        NOT_ENROLLED,
        NOT_COVERED,
        NO_SCTS,
        NO_DATA,
        FAILED
    }

    public enum Operation {
        INDEX_OPEN,
        INDEX_LOOKUP,
        INDEX_CLOSE,
        FILTER_LOAD,
        INCONSISTENT_COVERAGE
    }

    public static final class Failure {
        private final Operation operation;
        private final Path path;
        private final IOException cause;

        private Failure(Operation operation, Path path, IOException cause) {
            this.operation = operation;
            this.path = path;
            this.cause = cause;
        }

        public Operation operation() {
            return operation;
        }

        public Path path() {
            return path;
        }

        public IOException cause() {
            return cause;
        }
    }

    /**
     * A complete result or retained partial evidence, independent of acceptance
     * policy.
     */
    public static final class Result {
        private final Outcome outcome;
        private final Path directory;
        private final List<Failure> failures;
        private final boolean observedNotRevoked;
        private final int restarts;
        private final boolean retryExhausted;

        private Result(Outcome outcome, Path directory, Pass pass,
                       int restarts) {
            this.outcome = outcome;
            this.directory = directory;
            failures = Collections.unmodifiableList(new ArrayList<Failure>(pass.failures));
            observedNotRevoked = pass.notRevoked;
            this.restarts = restarts;
            retryExhausted = outcome == Outcome.FAILED && pass.missingFilter && restarts >= MAX_RESTARTS;
        }

        public Outcome outcome() {
            return outcome;
        }

        public Optional<Path> directory() {
            return Optional.ofNullable(directory);
        }

        public List<Failure> failures() {
            return failures;
        }

        public boolean observedNotRevoked() {
            return observedNotRevoked;
        }

        public int restarts() {
            return restarts;
        }

        public boolean retryExhausted() {
            return retryExhausted;
        }
    }

    private static final class Pass {
        final List<Failure> failures = new ArrayList<Failure>();
        boolean revoked;
        boolean notRevoked;
        boolean notEnrolled;
        boolean missingFilter;
    }
}
