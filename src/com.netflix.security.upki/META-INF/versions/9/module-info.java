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
/**
 * Offline UPKI revocation data support.
 *
 * @release 8
 */
module com.netflix.security.upki {
    provides java.security.Provider with
            com.netflix.security.provider.UpkiProvider;

    exports com.netflix.security.upki;
    exports com.netflix.security.provider;
    exports com.netflix.security.upki.provider to
            com.netflix.security.upki.test;
    exports com.netflix.security.upki.checker to
            com.netflix.security.upki.test;
    exports com.netflix.security.upki.clubcard to
            com.netflix.security.upki.test;
    exports com.netflix.security.upki.cache to
            com.netflix.security.upki.test;
}
