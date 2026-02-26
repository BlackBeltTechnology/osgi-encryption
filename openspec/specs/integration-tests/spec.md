# integration-tests Specification

## Purpose
Validates that the encryption services, metrics, and Karaf commands work correctly when deployed inside a real Apache Karaf OSGi container, using the Pax Exam test framework.

## Architecture
`EncryptionITest` uses Pax Exam's `@RunWith(PaxExam.class)` to launch a Karaf container, install the `osgi-encryption` feature, and run tests inside the container. `KarafFeatureProvider` configures the base Karaf distribution and feature repository. Tests inject OSGi services via `@Inject` and verify service availability and behavior.

## Requirements

### Requirement: Feature deployment in Karaf
The integration tests SHALL verify that the `osgi-encryption` feature can be installed and all bundles start correctly in a Karaf container.

#### Scenario: Feature bundles are active
- **GIVEN** a Pax Exam Karaf container is started
- **WHEN** the `osgi-encryption` feature is installed
- **THEN** all encryption bundles reach the `ACTIVE` state

### Requirement: Service availability
The integration tests SHALL verify that `Encryptor`, `Digester`, and `ConfigDecryptor` services are available in the OSGi service registry after feature installation.

#### Scenario: Encryption service is registered
- **GIVEN** the `osgi-encryption` feature is installed and a StringEncryptor configuration exists
- **WHEN** the service registry is queried for `Encryptor`
- **THEN** at least one `Encryptor` service is found

### Requirement: End-to-end encryption
The integration tests SHALL verify that encrypt/decrypt round-trips produce the original plaintext.

#### Scenario: Round-trip encryption
- **GIVEN** an `Encryptor` service is available
- **WHEN** a string is encrypted and then decrypted
- **THEN** the decrypted result matches the original string
