# karaf-commands Specification

## Purpose
Provides Apache Karaf shell commands under the `jasypt:` scope for interactive encryption, decryption, digest computation, and algorithm discovery from the Karaf console.

## Architecture
Four Karaf `@Command` classes (`Encrypt`, `Decrypt`, `Digest`, `Info`) extend Karaf's `AbstractAction`. Each accepts arguments and options via Karaf annotations. Three completer classes (`PBEAlgorithmCompleter`, `DigestAlgorithmCompleter`, `OutputTypeCompleter`) provide tab-completion for algorithm names and output types. Commands directly instantiate Jasypt utilities rather than going through the OSGi service registry.

## Requirements

### Requirement: Encrypt command
The `jasypt:encrypt` command SHALL encrypt a plaintext string using a specified PBE algorithm and password source.

#### Scenario: Encrypt with direct password
- **GIVEN** a Karaf shell session
- **WHEN** `jasypt:encrypt "hello" --algorithm PBEWithMD5AndDES --password secret` is executed
- **THEN** the encrypted string is printed to the console

#### Scenario: Encrypt with password from environment variable
- **GIVEN** environment variable `ENC_PASS` is set
- **WHEN** `jasypt:encrypt "hello" --algorithm PBEWithMD5AndDES --password-env ENC_PASS` is executed
- **THEN** the encrypted string using the env variable password is printed

### Requirement: Decrypt command
The `jasypt:decrypt` command SHALL decrypt an encrypted string using the same algorithm and password used for encryption.

#### Scenario: Decrypt a previously encrypted value
- **GIVEN** an encrypted value produced by `jasypt:encrypt`
- **WHEN** `jasypt:decrypt "encryptedValue" --algorithm PBEWithMD5AndDES --password secret` is executed
- **THEN** the original plaintext is printed

### Requirement: Digest command
The `jasypt:digest` command SHALL compute a message digest or validate data against an existing digest.

#### Scenario: Compute a digest
- **GIVEN** a Karaf shell session
- **WHEN** `jasypt:digest "password" --algorithm SHA-256` is executed
- **THEN** the computed digest string is printed

#### Scenario: Validate a digest
- **GIVEN** a previously computed digest value
- **WHEN** `jasypt:digest "password" --algorithm SHA-256 --digest previousValue` is executed
- **THEN** the validation result (`true` or `false`) is printed

### Requirement: Info command
The `jasypt:info` command SHALL list all available PBE and digest algorithms from the Jasypt registry.

#### Scenario: List algorithms
- **WHEN** `jasypt:info` is executed
- **THEN** all registered PBE encryption algorithms and digest algorithms are printed

### Requirement: Tab completion
Commands SHALL provide tab-completion for algorithm names and output types.

#### Scenario: Tab-complete PBE algorithm
- **GIVEN** a user types `jasypt:encrypt "text" --algorithm PBE`
- **WHEN** tab is pressed
- **THEN** available PBE algorithms matching the prefix are suggested
