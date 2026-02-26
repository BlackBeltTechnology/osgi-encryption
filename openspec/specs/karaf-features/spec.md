# karaf-features Specification

## Purpose
Defines an Apache Karaf feature descriptor that bundles the encryption services, metrics, and Karaf commands for one-command installation into a Karaf container.

## Architecture
A single `feature.xml` defines the `osgi-encryption` feature. It declares dependencies on the `scr` (Service Component Runtime) and `jasypt-encryption` features, then lists the three runtime bundles: services, metrics, and commands.

## Requirements

### Requirement: Feature installation
The `osgi-encryption` Karaf feature SHALL install all required encryption bundles and their dependencies.

#### Scenario: Install encryption feature
- **GIVEN** a running Apache Karaf instance with the feature repository added
- **WHEN** `feature:install osgi-encryption` is executed
- **THEN** the `osgi-encryption-services`, `osgi-encryption-metrics`, and `osgi-encryption-karaf-commands` bundles are installed and active

### Requirement: Dependency resolution
The feature SHALL declare dependencies on `scr` and `jasypt-encryption` features.

#### Scenario: SCR dependency satisfied
- **GIVEN** the `osgi-encryption` feature is being installed
- **WHEN** the `scr` feature is not yet installed
- **THEN** Karaf automatically installs `scr` before installing the encryption bundles

### Requirement: Feature repository registration
The feature repository SHALL be registrable via Maven coordinates.

#### Scenario: Add feature repository
- **WHEN** `feature:repo-add mvn:hu.blackbelt/osgi-encryption-karaf-features/{version}/xml/features` is executed
- **THEN** the `osgi-encryption` feature appears in `feature:list`
