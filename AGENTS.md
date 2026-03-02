# OSGi Encryption - Project Documentation

## Project Overview

**Repository:** BlackBeltTechnology/osgi-encryption
**License:** Apache License 2.0
**Java Version:** 11 (source/target), build requires Java 21
**Build System:** Maven 3.9.4+ with Apache Felix Bundle Plugin for OSGi packaging

1. Wraps [Jasypt](http://www.jasypt.org) encryption library as OSGi Declarative Services (DS 1.3) components, providing encrypt/decrypt/digest operations as registered OSGi services
2. Supports multiple concurrent encryptor instances identified by aliases, with configurable algorithms, password sources (direct, environment variable, system property, file), and automatic password file watching
3. Integrates with OSGi ConfigAdmin to transparently decrypt `ENC(value)` and `ENC(value, alias)` wrapped configuration values
4. Provides JMX MBeans for monitoring encryption operation counts, error counts, and processing times
5. Includes Apache Karaf shell commands (`jasypt:encrypt`, `jasypt:decrypt`, `jasypt:digest`, `jasypt:info`) and a Karaf feature descriptor for one-command installation

## Directory Structure

```
osgi-encryption/
├── pom.xml                              # Reactor POM (version: ${revision} = 1.1.0-SNAPSHOT)
├── README.md                            # Quick start guide
├── CONTRIBUTING.md                      # Development and submission guidelines
├── LICENSE.txt                          # Apache 2.0 license
├── mvnw / mvnw.cmd                     # Maven wrapper scripts
├── logback-test.xml                     # Shared test logging configuration
├── .github/
│   ├── workflows/                       # GitHub Actions CI/CD pipelines
│   └── CIFLOW.md                        # Branching and CI documentation
├── osgi-encryption-services/            # Core encryption DS components
├── osgi-encryption-metrics/             # JMX statistics provider
├── osgi-encryption-karaf-commands/      # Karaf shell commands
├── osgi-encryption-karaf-features/      # Karaf feature XML descriptor
├── osgi-encryption-test/                # Sample DS components for testing
└── osgi-encryption-itest/               # Pax Exam integration tests
```

## Core Modules

### Encryption Services Layer

| Module | Type | Purpose |
|--------|------|---------|
| `osgi-encryption-services/` | OSGi Bundle | Core encryption/decryption/digest service implementations. Defines `Encryptor`, `Digester`, and `ConfigDecryptor` interfaces with Jasypt-backed DS components. Handles password file watching and BouncyCastle provider registration. |

### Monitoring & Operations

| Module | Type | Purpose |
|--------|------|---------|
| `osgi-encryption-metrics/` | OSGi Bundle | JMX MBean provider that dynamically tracks `OperationStats` services and exposes them as `StatsMBean` instances under `hu.blackbelt.encryption:type={type},name={alias}`. |
| `osgi-encryption-karaf-commands/` | OSGi Bundle | Karaf shell commands under `jasypt:` scope — `encrypt`, `decrypt`, `digest`, `info`. Includes tab completers for algorithms and output types. |

### Deployment & Testing

| Module | Type | Purpose |
|--------|------|---------|
| `osgi-encryption-karaf-features/` | Feature descriptor | Karaf feature XML that installs SCR + Jasypt dependencies and the three runtime bundles. |
| `osgi-encryption-test/` | OSGi Bundle | Sample `ConfigTest` DS component demonstrating encrypted configuration usage. |
| `osgi-encryption-itest/` | Test module | Pax Exam integration tests that boot a Karaf container with the encryption feature installed. |

## Technology Stack

### Core Technologies
- **Jasypt 1.9.2** — PBE encryption, message digesting, with configurable algorithms
- **OSGi Core 6.0.0 / Compendium 6.0.0** — Service registry, Declarative Services 1.3, ConfigAdmin
- **Apache Karaf 4.4.7** — Runtime container, feature deployment, shell commands
- **Apache Felix Maven Bundle Plugin 5.1.2** — OSGi bundle packaging
- **Lombok 1.18.34** — Boilerplate reduction via annotation processing

### Build & Quality
- **Maven 3.9.4+** with `flatten-maven-plugin` for CI-friendly `${revision}` version resolution
- **JUnit Jupiter 5.6.2** for unit tests, **Pax Exam 4.13.5** for OSGi integration tests
- **Mockito 3.0.0** and **Hamcrest 2.1** for test assertions
- **JaCoCo 0.8.12** for code coverage, **SonarQube** for quality analysis
- **SLF4J 2.0.16 / Logback 1.5.12** for logging

## Build Commands

```sh
# Full build (compile, test, package, install to local repo)
mvn clean install

# Run tests only
mvn clean test

# Run a single test class
mvn -pl osgi-encryption-services -Dtest=ClassName test

# Run integration tests (boots Karaf container)
mvn -pl osgi-encryption-itest verify

# Build with coverage report
mvn clean install jacoco:report

# Skip all modules (parent POM only)
mvn clean install -DskipModules=true
```

The Maven wrapper (`./mvnw`) is included for environments without a system Maven installation.

### Maven Profiles

| Profile | Purpose |
|---------|---------|
| `modules` | Active by default — includes all submodules in the reactor build |
| `sign-artifacts` | Signs artifacts with GPG (for release deployments) |
| `release-judong` | Deploys to JUDO Nexus repository (nexus.judo.technology) |
| `release-central` | Deploys to Maven Central via Sonatype OSSRH |
| `release-p2-judong` | Uploads P2 repository to JUDO Nexus |
| `generate-github-asciidoc-diagrams` | Generates PNG diagrams from AsciiDoc sources |
| `update-source-code-license` | Updates Apache 2.0 license headers on all source files |

## Key Configuration Files

| File | Purpose |
|------|---------|
| `pom.xml` | Reactor POM: version properties, dependency management, plugin configuration, profiles |
| `logback-test.xml` | Shared Logback configuration for all module test runs |
| `.mvn/extensions.xml` | Maven extensions (flatten plugin) |
| `osgi-encryption-karaf-features/src/main/feature/feature.xml` | Karaf feature descriptor defining runtime bundle set |
| `.github/workflows/build.yml` | Main CI pipeline: build, test, deploy, tag, release |
| `.github/workflows/release.yml` | Manual release workflow: creates version PRs on master and develop |

## Development Environment

**Required:**
- Java 21 JDK (Zulu distribution recommended, as used in CI)
- Maven 3.9.4+ (or use `./mvnw`)
- IDE with Lombok plugin support

**Recommended:**
- Apache Karaf 4.4.7 for local testing of feature installation
- JConsole or VisualVM for JMX metrics inspection

## Git Workflow

- **Main Branch:** `develop`
- **Release Branch:** `master` (latest stable release)
- **Versioning:** `${revision}` property, currently `1.1.0-SNAPSHOT`
- **Branch naming:** `feature/JNG-xxxx_description`, `bugfix/JNG-xxxx_description`, `release/x.y.z`
- **Rule:** Every commit must reference a JIRA ticket in `JNG-xxxx` format

## Important Notes

1. **OSGi DS configuration is required** — `StringEncryptor` and `StringDigester` use `ConfigurationPolicy.REQUIRE`, meaning they will not activate without a matching OSGi configuration.
2. **Multiple encryptor instances** are supported — each identified by an `encryptor.alias` service property. `OsgiConfigDecryptor` looks up encryptors by alias when processing `ENC(value, alias)` patterns.
3. **Password file watching** — When a password is loaded from a file, `FileWatcher` monitors changes and triggers configuration reload via ConfigAdmin, causing the encryptor to reinitialize with the new password.
4. **PAX-JDBC compatibility** — `StringEncryptor` also registers as `org.jasypt.encryption.StringEncryptor`, which PAX-JDBC can use to decrypt JDBC connection passwords transparently.
5. **BouncyCastle registration** — The `Activator` class dynamically registers the BouncyCastle security provider when the bundle starts, making additional PBE algorithms available.
6. **Integration tests take time** — Pax Exam boots a full Karaf container; the Surefire timeout is 30 minutes.
7. **Karaf commands use `jasypt:` scope** — Commands are `jasypt:encrypt`, `jasypt:decrypt`, `jasypt:digest`, `jasypt:info`.

## Related Documentation

- [CONTRIBUTING.md](CONTRIBUTING.md) — Development environment setup, code conventions, PR submission
- [.github/CIFLOW.md](.github/CIFLOW.md) — Branching strategy, version numbering, CI/CD pipeline details
- [README.md](README.md) — Quick start and Karaf installation instructions
