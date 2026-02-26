# encryption-services Specification

## Purpose
Provides core encryption, decryption, and digest services as OSGi Declarative Services components backed by Jasypt, with support for multiple named instances, flexible password sources, password file watching, and transparent OSGi configuration decryption.

## Architecture
The module defines three service interfaces (`Encryptor`, `Digester`, `ConfigDecryptor`) and a metrics interface (`OperationStats`). Implementations are DS components requiring OSGi ConfigAdmin configuration. `StringEncryptor` wraps Jasypt's `StandardPBEStringEncryptor`, `StringDigester` wraps `StandardStringDigestUtil`. `OsgiConfigDecryptor` looks up `Encryptor` services by alias to decrypt `ENC()` wrapped config values. An `Activator` registers the BouncyCastle security provider at bundle start. `FileWatcher` monitors password files and triggers configuration reload via ConfigAdmin.

## Requirements

### Requirement: String encryption and decryption
The `StringEncryptor` component SHALL encrypt and decrypt strings using a configured PBE algorithm via Jasypt.

#### Scenario: Encrypt a plaintext string
- **GIVEN** a `StringEncryptor` is activated with algorithm `PBEWithMD5AndDES` and a password
- **WHEN** `encrypt("hello")` is called
- **THEN** an encrypted Base64 or hexadecimal string is returned

#### Scenario: Decrypt an encrypted string
- **GIVEN** a `StringEncryptor` is activated with the same algorithm and password used for encryption
- **WHEN** `decrypt(encryptedValue)` is called
- **THEN** the original plaintext `"hello"` is returned

### Requirement: Encryptor alias identification
Each `StringEncryptor` instance SHALL be identifiable by a unique alias via the `encryptor.alias` service property.

#### Scenario: Multiple encryptors with different aliases
- **GIVEN** two `StringEncryptor` components configured with aliases `"primary"` and `"secondary"`
- **WHEN** the OSGi service registry is queried with filter `(encryptor.alias=primary)`
- **THEN** only the `"primary"` encryptor is returned

### Requirement: Multiple password sources
The `StringEncryptor` SHALL support loading passwords from direct configuration, environment variables, JVM system properties, or a file path.

#### Scenario: Password from environment variable
- **GIVEN** an environment variable `ENCRYPT_PASS` is set to `"secret"`
- **WHEN** `StringEncryptor` is configured with `encryption_passwordEnvName=ENCRYPT_PASS`
- **THEN** the encryptor uses `"secret"` as the encryption password

#### Scenario: Password from file
- **GIVEN** a file `/etc/encryption/password.txt` contains `"fileSecret"`
- **WHEN** `StringEncryptor` is configured with `encryption_passwordFile=/etc/encryption/password.txt`
- **THEN** the encryptor uses `"fileSecret"` as the encryption password

### Requirement: Password file watching
When `encryptor_enablePasswordFileWatcher` is `true`, the component SHALL monitor the password file for changes and reinitialize the encryptor when the file is modified.

#### Scenario: Password file updated at runtime
- **GIVEN** a `StringEncryptor` is active with a password file and file watching enabled
- **WHEN** the password file content changes
- **THEN** the `FileWatcher` detects the change, updates the ConfigAdmin configuration, and the encryptor reinitializes with the new password

### Requirement: Configuration value decryption
`OsgiConfigDecryptor` SHALL decrypt OSGi configuration values wrapped in `ENC()` notation.

#### Scenario: Decrypt a configuration value without alias
- **GIVEN** an `Encryptor` is registered as the default encryptor
- **WHEN** `ConfigDecryptor.decrypt("ENC(abc123)")` is called
- **THEN** the encrypted value `"abc123"` is decrypted using the default encryptor

#### Scenario: Decrypt a configuration value with alias
- **GIVEN** an `Encryptor` with alias `"db"` is registered
- **WHEN** `ConfigDecryptor.decrypt("ENC(abc123, db)")` is called
- **THEN** the encrypted value `"abc123"` is decrypted using the encryptor with alias `"db"`

#### Scenario: Non-encrypted value passthrough
- **WHEN** `ConfigDecryptor.decrypt("plaintext")` is called
- **THEN** the original `"plaintext"` value is returned unchanged

### Requirement: Message digesting
`StringDigester` SHALL compute message digests and validate data against existing digests.

#### Scenario: Compute a digest
- **GIVEN** a `StringDigester` configured with algorithm `SHA-256`
- **WHEN** `digest("password")` is called
- **THEN** a salted digest string is returned

#### Scenario: Validate a digest
- **GIVEN** a digest was previously computed for `"password"`
- **WHEN** `matches("password", previousDigest)` is called
- **THEN** `true` is returned

### Requirement: Operation metrics tracking
Each `StringEncryptor` SHALL register two `OperationStats` services (one for encryption, one for decryption) and each `StringDigester` SHALL register two `OperationStats` services (one for digest, one for validation).

#### Scenario: Metrics updated after encryption
- **GIVEN** a `StringEncryptor` is active
- **WHEN** `encrypt("data")` is called successfully
- **THEN** the encryption `OperationStats` request counter is incremented and processing time is recorded

#### Scenario: Error counter incremented on failure
- **GIVEN** a `StringEncryptor` is active but misconfigured
- **WHEN** an encryption operation throws an exception
- **THEN** the encryption `OperationStats` error counter is incremented

### Requirement: PAX-JDBC compatibility
`StringEncryptor` SHALL also register as `org.jasypt.encryption.StringEncryptor` so that PAX-JDBC can use it for transparent JDBC connection password decryption.

#### Scenario: PAX-JDBC looks up Jasypt encryptor
- **GIVEN** a `StringEncryptor` is active
- **WHEN** PAX-JDBC queries for `org.jasypt.encryption.StringEncryptor`
- **THEN** the registered service is found and can decrypt database passwords

### Requirement: BouncyCastle provider registration
The bundle `Activator` SHALL register the BouncyCastle security provider when the bundle starts and unregister it when the bundle stops.

#### Scenario: Additional algorithms available
- **GIVEN** the osgi-encryption-services bundle is started
- **WHEN** a `StringEncryptor` is configured with a BouncyCastle-specific algorithm
- **THEN** the algorithm is available because the provider was registered by the `Activator`
