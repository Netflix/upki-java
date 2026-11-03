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

package com.netflix.security.upki;

import java.io.IOException;
import java.nio.file.Path;
import java.util.List;
import java.util.Optional;

/**
 * Revocation evidence independent of connection acceptance. Library results own
 * unmodifiable failure lists; exception causes retain their original identity.
 * A not-revoked finding does not establish certificate trust, validity, or data
 * freshness.
 */
public interface RevocationResult {
    Finding finding();

    Optional<Path> directory();

    List<Failure> failures();

    /**
     * May be true in a failed check; partial evidence is not a conclusive
     * not-revoked finding.
     */
    boolean observedNotRevoked();

    int restarts();

    boolean retryExhausted();

    /**
     * Shared finding vocabulary for standalone results and provider diagnostics.
     * Issuer/evidence findings are integration outcomes, not standalone path validation.
     * INPUT_FAILURE is diagnosed before the original certificate exception is rethrown.
     */
    enum Finding {
        REVOKED,
        NOT_REVOKED,
        NOT_ENROLLED,
        NOT_COVERED,
        NO_SCTS,
        NO_DATA,
        FAILED,
        DISABLED,
        ISSUER_UNAVAILABLE,
        ISSUER_AMBIGUOUS,
        EVIDENCE_TRUNCATED,
        INPUT_FAILURE
    }

    enum Operation {
        INDEX_OPEN,
        INDEX_LOOKUP,
        INDEX_CLOSE,
        FILTER_LOAD,
        INCONSISTENT_COVERAGE
    }

    /**
     * Retained operational failure from the final cache pass, not a policy
     * decision.
     */
    interface Failure {
        Operation operation();

        Path path();

        IOException cause();
    }
}
