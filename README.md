# JSignify

JSignify is a very basic Java library that supports verifying (OpenBSD) [Signify](https://www.openbsd.org/papers/bsdcan-signify.html) signatures.
JSignify uses Google's [Tink](https://github.com/google/tink) for the verification of the Ed25519 signatures.

## Sample

Verifying the signature of a message (using Base64 strings instead of files).

```java
String publicKey = "RWRm/JNSNUb77CmSMXBAA5Owr4XzPbRO/PKDXXLIUfOgFDd/F8hT8p5t";
String signature = "RWRm/JNSNUb77AmgjFuNCA6+3wwVotARqp2BqrG+ZoqFaK2PB8pW/Acpo660s+DmF1pxJOTB8uXp6b1S1N+sZLZwx8G6tnxSIg0=";
byte[] message = "testmessage\n".getBytes(UTF_8);

try {
  SignifyVerifier verifier = new SignifyVerifier(publicKey);
  verifier.verify(signature, message);
} catch (VerificationFailedException e) {
  // Handle signature verification failed...
} catch (Exception e) {
  // Handle other exceptions...
}
```

## Supported use cases
* verifying a Signify signature of a message against a public key (file based)
* verifying a Signify signature of a message against a public key (with Base64 signatures and public keys)

## Not (yet) supported use cases
* signing of messages
* creating key pairs
* verifying a GZIP embedded Signify signature against a public key
* verifying a SHA-256 checksum list and the corresponding files

## Building
To build JSignify locally you need at least a Java 8 JDK (e.g. OpenJDK). For development [IntelliJ IDEA Community Edition](https://www.jetbrains.com/idea/download/) can be used.

Build with:

    ./gradlew clean build

## License
Licensed under [Apache License Version 2.0](LICENSE)

## Dependencies
* [Tink](https://github.com/google/tink)
* [Guava](https://github.com/google/guava)

## Contributors
* [p-](https://github.com/p-)