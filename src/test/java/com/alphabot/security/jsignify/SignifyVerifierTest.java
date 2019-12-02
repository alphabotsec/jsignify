/*
 * Copyright (C) 2020 The JSignify Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License
 * is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
 * or implied. See the License for the specific language governing permissions and limitations under
 * the License.
 */

package com.alphabot.security.jsignify;

import com.alphabot.security.jsignify.exception.VerificationFailedException;
import org.junit.jupiter.api.Test;

import java.net.URISyntaxException;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.nio.file.Paths;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class SignifyVerifierTest {

  @Test
  void verifySignedMessage() throws Exception {
    String publicKey = "RWRm/JNSNUb77CmSMXBAA5Owr4XzPbRO/PKDXXLIUfOgFDd/F8hT8p5t";
    String signature = "RWRm/JNSNUb77AmgjFuNCA6+3wwVotARqp2BqrG+ZoqFaK2PB8pW/Acpo660s+DmF1pxJOTB8uXp6b1S1N+sZLZwx8G6tnxSIg0=";
    byte[] message = "testmessage\n".getBytes(UTF_8);

    SignifyVerifier verifier = new SignifyVerifier(publicKey);
    verifier.verify(signature, message);
  }

  @Test
  void failIfSignatureDoesNotMatchMessage() {
    String publicKey = "RWRm/JNSNUb77CmSMXBAA5Owr4XzPbRO/PKDXXLIUfOgFDd/F8hT8p5t";
    String signature = "RWRm/JNSNUb77AmgjFuNCA6+3wwVotARqp2BqrG+ZoqFaK2PB8pW/Acpo660s+DmF1pxJOTB8uXp6b1S1N+sZLZwx8G6tnxSIg0=";
    byte[] message = "not-signed".getBytes(UTF_8);

    SignifyVerifier verify = new SignifyVerifier(publicKey);
    assertThatThrownBy(() -> verify.verify(signature, message))
        .isExactlyInstanceOf(VerificationFailedException.class)
        .hasMessage("signature verification failed");
  }

  @Test
  void failIfWrongPublicKeyNumberIsUsed() {
    String publicKey = "RWSvK/c+cFe24BIalifKnqoqdvLlXfeZ9MIj3MINndNeKgyYw5PpcWGn";
    String signature = "RWRm/JNSNUb77AmgjFuNCA6+3wwVotARqp2BqrG+ZoqFaK2PB8pW/Acpo660s+DmF1pxJOTB8uXp6b1S1N+sZLZwx8G6tnxSIg0=";

    SignifyVerifier verifier = new SignifyVerifier(publicKey);
    assertThatThrownBy(() -> verifier.verify(signature, new byte[0]))
        .isExactlyInstanceOf(VerificationFailedException.class)
        .hasMessage("verification failed: checked against wrong key");
  }

  @Test
  void failIfInvalidPublicKeyIsUsed() {
    String publicKey = "RWSvK/";

    assertThatThrownBy(() -> new SignifyVerifier(publicKey))
        .isExactlyInstanceOf(IllegalArgumentException.class)
        .hasMessage("Decoded public key total length must be 42, but was 4.");
  }

  @Test
  void failIfNotExistingPublicKeyFileIsUsed() {
    Path notExistingPublicKeyFile = Paths.get("notexistinpublickeyfile.txt");

    assertThatThrownBy(() -> new SignifyVerifier(notExistingPublicKeyFile))
        .isExactlyInstanceOf(NoSuchFileException.class)
        .hasMessage("notexistinpublickeyfile.txt");
  }

  // TODO split up tests for files and else

  @Test
  void verifySignedMessageUsingFiles() throws Exception {
    Path publicKeyFile = getPathFromResource("publickey.pub");
    Path signatureFile = getPathFromResource("signature.sig");
    Path messageFile = getPathFromResource("testmessage.txt");

    SignifyVerifier verifier = new SignifyVerifier(publicKeyFile);
    verifier.verifyFile(signatureFile, messageFile);
  }

  @Test
  void failIfSignatureDoesNotMatchMessageUsingFiles() throws Exception {
    Path publicKeyFile = getPathFromResource("publickey.pub");
    Path signatureFile = getPathFromResource("signature.sig");
    Path notSignedMessageFile = getPathFromResource("notsignedmessage.txt");

    SignifyVerifier verifier = new SignifyVerifier(publicKeyFile);
    assertThatThrownBy(() -> verifier.verifyFile(signatureFile, notSignedMessageFile))
        .isExactlyInstanceOf(VerificationFailedException.class)
        .hasMessage("signature verification failed");
  }

  @Test
  void failIfMessageFileIsNotFound() throws Exception {
    Path publicKeyFile = getPathFromResource("publickey.pub");
    Path signatureFile = getPathFromResource("signature.sig");
    Path notExistingMessageFile = Paths.get("notexistingmessagefile.txt");

    SignifyVerifier verifier = new SignifyVerifier(publicKeyFile);
    assertThatThrownBy(() -> verifier.verifyFile(signatureFile, notExistingMessageFile))
        .isExactlyInstanceOf(NoSuchFileException.class)
        .hasMessage("notexistingmessagefile.txt");
  }

  private Path getPathFromResource(String resourceName) throws URISyntaxException {
    return Paths.get(getClass().getResource(resourceName).toURI());
  }
}
