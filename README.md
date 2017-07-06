![Build Status](https://travis-ci.org/BlackBeltTechnology/osgi-encryption.svg?branch=develop)

# OSGi encryption

Wrapper OSGi components for [Jasypt](http://www.jasypt.org).

## Modules

* osgi-encryption-services: OSGi Declarative Service 1.3 components supporting configuration in standard way
* osgi-encryption-metrics: JMX statistics povider for encryption services
* osgi-encryption-karaf-commands: Apache Karaf console commands
* osgi-encryption-karaf-feature: Apache Karaf feature definition
* osgi-encryption-test: sample module showing how to use encrypted configuration values

## How to build

Use the following command to build and sign (including JavaDoc and source JARs) modules.

~~~~
mvn clean install -Pbuild-extras -Psign
~~~~

Add `deploy` argument to upload artifacts to Sonatype OSS Repository.

## How to use

### Apache Karaf

Install as Apache Karaf feature (Apache Felix SCR and Jasypt encryption dependencies are installed too).

~~~~
feature:repo-add mvn:hu.blackbelt/osgi-encryption-karaf-feature/1.0.2/xml/karaf4-features
feature:install osgi-encryption
~~~~
