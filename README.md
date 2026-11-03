# upki-java

![Java 8+](https://img.shields.io/badge/Java-8%2B-blue)

`upki-java` adds offline server-certificate revocation checking to Java TLS clients. It uses the local revocation cache maintained by [UPKI](https://github.com/rustls/upki), without making CRL or OCSP requests of its own. Once installed, PKIX JSSE clients use it without changing their TLS configuration.

> [!IMPORTANT]
> This library is in preview and has no published release yet. API names, configuration properties, and defaults may change. Please report bugs and feature requests in this repository's [issue tracker](https://github.com/Netflix/upki-java/issues).
>
> By default, revocation checking is best-effort: missing or unusable data does not block a connection, but confirmed revocation does. Review the [failure policy](#failure-policy) before deployment.

## Quick start

[Build the JAR from source](#development), then choose an installation method. The examples below use `build/release/com.netflix.security.upki.jar`. Adding the JAR to your dependencies alone does not enable the provider.

### Enable an existing application

Add the agent to the application's Java command:

```sh
java -javaagent:build/release/com.netflix.security.upki.jar -jar application.jar
```

The agent installs the provider before application main. It does not transform classes and takes no agent arguments. Place it before other agents that initialize TLS.

### Install from code

Put the JAR on the application's classpath or module path, then install the provider during startup:

```java
import com.netflix.security.provider.UpkiProvider;

UpkiProvider provider = UpkiProvider.install();
```

Install before creating trust managers, SSL contexts, HTTP clients, or connection pools. Installation puts UPKI first in the provider list without removing existing providers. Repeated installation reuses an equivalent first-priority instance; conflicting configuration fails rather than silently replacing it.

### Register in the runtime

For a managed runtime, register the provider first in `java.security`:

```properties
security.provider.1=com.netflix.security.provider.UpkiProvider
```

Shift every existing provider entry down one position, preserving its order; do not simply overwrite provider 1. The JAR must be visible on the application's classpath or resolved module path. The JDK security file is under `jre/lib/security` on Java 8 and `conf/security` on Java 9+.

JCA can skip a missing or invalid statically registered provider. Use the agent or an uncaught early `install()` call when installation failure must stop application startup.

## Configuration

The agent, no-argument installer, and security-file registration use **Java security properties**, not `-Dcom.netflix.security.upki.*` system properties. Configure them in the runtime's `java.security` file, or in an additional security properties file.

For example, an `upki.security` file can select a cache and reject missing or broken cache data:

```properties
com.netflix.security.upki.cacheDirectory=/var/cache/upki/revocation
com.netflix.security.upki.missingIndex=FAIL
com.netflix.security.upki.cacheFailure=FAIL_CLOSED
```

Load that configuration alongside the agent:

```sh
java -Djava.security.properties=/path/to/upki.security \
    -javaagent:build/release/com.netflix.security.upki.jar \
    -jar application.jar
```

Additional security files take effect only when the runtime permits them through `security.overridePropertiesFile`. Use the single-equals form above, not `==`, which replaces the runtime's security configuration.

Every property has the prefix `com.netflix.security.upki.`:

| Property suffix | Default | Controls |
| --- | --- | --- |
| `enabled` | `true` | Whether to perform UPKI checks |
| `cacheDirectory` | Automatic discovery | Directory containing `index.bin` and its filters |
| `missingIndex` | `WARN` | No cache index is available |
| `cacheFailure` | `FAIL_OPEN` | Cache data is unreadable, corrupt, or inconsistent |
| `missingScts` | `IGNORE` | The certificate has no embedded SCTs |
| `coverage` | `IGNORE` | Revocation data does not cover the certificate |
| `unsupportedVerification` | `WARN` | The delegate's authenticated issuer cannot be recovered reliably |

Automatic discovery prefers the platform's user cache, then its system cache when the user index is absent. An explicit directory selects only that cache. An unreadable or corrupt index does not silently fall back to another cache; `cacheFailure` decides what happens instead.

Configuration is captured once per provider, not reread during TLS checks. Changing properties does not reconfigure an installed instance. For property-independent configuration, use `UpkiConfiguration` with `UpkiProvider.install(configuration)`; its builder requires every policy choice explicitly, while `UpkiConfiguration.defaults()` supplies the fixed best-effort profile.

### Failure policy

The three-way settings accept `IGNORE`, `WARN`, or `FAIL`: allow the condition, allow it with a diagnostic warning, or reject it. `WARN` does **not** log automatically. Cache failures independently choose `FAIL_OPEN` or `FAIL_CLOSED`; an allowed cache failure remains an observable error, not a successful revocation check.

Confirmed revocation always rejects while checking is enabled. Fail-open never overrides a failure from ordinary certificate or hostname verification. Disabling UPKI checks does not disable that normal verification either.

Installation does not probe the cache. A required-index policy takes effect when verification reaches a cache lookup, not at application startup.

## Diagnostics and direct checks

Keep the provider returned by `install()` and poll `provider.diagnostics()` from your own metrics, logging, or health integration. Each call returns an immutable snapshot of findings, policy decisions, cache failures, and degradation/recovery information. Reading a snapshot does no I/O, starts no background work, and does not reset counters.

Snapshots describe observed checks, not every TLS handshake or a proactive readiness check. An application rejection before UPKI runs, or a resumed TLS session, may produce no revocation assessment.

For custom verification paths, use the standalone checker without installing a provider:

```java
import com.netflix.security.upki.RevocationChecker;
import com.netflix.security.upki.RevocationResult;
import com.netflix.security.upki.UpkiConfiguration;

RevocationChecker checker = new RevocationChecker(UpkiConfiguration.defaults());
RevocationResult result = checker.check(leaf, authenticatedIssuer);
```

Authenticate the certificate and its issuer before calling `check`; the checker does not establish trust or build a certificate path. It reports evidence, including revocation and cache failures, rather than enforcing a TLS acceptance decision or throwing merely because a certificate is revoked. The caller must act on that result.

## Compatibility

The provider targets ordinary, same-thread, unpinned JDK PKIX verification. Tests exercise unchanged `HttpsURLConnection` clients; other client/provider combinations need their own validation.

- Custom trust managers, provider-pinned validators, native TLS implementations, and objects created before installation can bypass this integration.
- Registration affects JVM-wide PKIX builder and validator selection, not just TLS. It does not promise transparent interception of every verifier.
- TLS session resumption may skip certificate verification. A trust-manager provider cannot guarantee a fresh revocation check for every resumed connection.
- For module-path deployments, resolve module `com.netflix.security.upki`, through an application `requires` directive or `--add-modules com.netflix.security.upki`.

## Development

Use [Ja](https://github.com/Netflix/ja) 0.26.16 or later and a development JDK 25+. That is the build-tool requirement, not the library's minimum Java version. There is no separate Maven or Gradle build.

```sh
ja compile
ja test --all
ja -p com.netflix.security.upki assemble --module-version 0.0.0-local build/release
```

The assembly destination must not already exist. The output includes the production binary, sources, and Javadoc JARs; JUnit and the test module are not runtime dependencies.

To run the bootstrap and authenticated-path compatibility probes on another JDK:

```sh
UPKI_TEST_JAVA_HOME=/path/to/jdk8 ja test --all
```

Keep `--all` when changing that runtime so cached successes do not replace the compatibility checks. The JUnit runner itself stays on the development JDK. CI exercises compatibility probes and assembled-agent launches on Java 8, 11, 17, 21, and 25 on Linux; it does not establish native Windows or macOS filesystem behavior. Normal tests use generated certificates and synthetic revocation data; optional external-data tests skip when their fixtures are absent.

## License

[Apache License 2.0](LICENSE). Adapted Go UPKI code and test vectors retain their BSD-3-Clause attribution in [NOTICE](NOTICE) and the [included license](src/com.netflix.security.upki/legal/go-upki-LICENSE).
