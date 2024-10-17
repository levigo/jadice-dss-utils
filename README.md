# jadice dss utils

The following module provides classes that support integrators in the use of dss (Digital Signature Service, https://github.com/esig/dss).
DSS can be used to work with signatures, certificates & key/trust stores.

Jadice uses dss to validate signed documents. The following jadice module can be integrated for this purpose:
```
<dependency>
    <groupId>com.levigo.jadice.documentplatform.core</groupId>
    <artifactId>signature-dss</artifactId>
</dependency>
```

## How to use

Either add this module to your `pom.xml` or simply clone the project, adjust it for your needs and build via Apache Maven. Execute `mvn install` in the project's root folder (where the `pom.xml` is placed). This should result in a JAR file that will be placed in `target` folder under project's root folder. Include this JAR in your application's classpath and you will be able to use the included font resources.
