# encryption-metrics Specification

## Purpose
Provides JMX monitoring for encryption operations by dynamically tracking `OperationStats` OSGi services and exposing them as JMX MBeans with request counts, error counts, and processing times.

## Architecture
`JmxOperationStatsProvider` is a DS component that uses a dynamic `@Reference` with `MULTIPLE` cardinality to track all `OperationStats` services. For each tracked service, it wraps it in a `Stats` object implementing `StatsMBean` and registers it with the JMX `MBeanServer`. The MBean ObjectName follows the pattern `{jmx_package}:type={type},name={alias}`.

## Requirements

### Requirement: Dynamic MBean registration
`JmxOperationStatsProvider` SHALL register a JMX MBean for each `OperationStats` service that appears in the OSGi service registry.

#### Scenario: Encryptor activates and MBeans appear
- **GIVEN** `JmxOperationStatsProvider` is active
- **WHEN** a `StringEncryptor` with alias `"default"` activates (registering encryption and decryption `OperationStats`)
- **THEN** two MBeans are registered: `hu.blackbelt.encryption:type=ENCRYPTION,name=default` and `hu.blackbelt.encryption:type=DECRYPTION,name=default`

### Requirement: Dynamic MBean unregistration
`JmxOperationStatsProvider` SHALL unregister MBeans when the corresponding `OperationStats` service is removed.

#### Scenario: Encryptor deactivates and MBeans disappear
- **GIVEN** MBeans are registered for an encryptor with alias `"default"`
- **WHEN** the encryptor component is deactivated
- **THEN** the corresponding MBeans are unregistered from the MBeanServer

### Requirement: MBean exposes operation statistics
Each `StatsMBean` SHALL expose `totalProcessingTime`, `requestCounter`, and `errorCounter` as read-only JMX attributes.

#### Scenario: Query encryption metrics via JMX
- **GIVEN** an encryption MBean is registered and 10 encrypt operations have been performed
- **WHEN** a JMX client reads the `RequestCounter` attribute
- **THEN** the value `10` is returned

### Requirement: Configurable JMX domain
The JMX domain name SHALL be configurable via the `jmx_package` configuration property, defaulting to `"hu.blackbelt.encryption"`.

#### Scenario: Custom JMX domain
- **GIVEN** `JmxOperationStatsProvider` is configured with `jmx_package=com.example.crypto`
- **WHEN** an `OperationStats` for encryption with alias `"main"` is registered
- **THEN** the MBean ObjectName is `com.example.crypto:type=ENCRYPTION,name=main`
