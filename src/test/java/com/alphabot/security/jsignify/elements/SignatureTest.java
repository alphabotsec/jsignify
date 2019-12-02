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

package com.alphabot.security.jsignify.elements;

import org.junit.jupiter.api.Test;

import java.net.URISyntaxException;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.nio.file.Paths;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class SignatureTest {

  @Test
  void createSignatureFromBase64String() {
    Signature signature = Signature.fromBase64String("RWRm/JNSNUb77AmgjFuNCA6+3wwVotARqp2BqrG+ZoqFaK2PB8pW/Acpo660s+DmF1pxJOTB8uXp6b1S1N+sZLZwx8G6tnxSIg0=");
    assertThat(signature.getAlgorithm().getRaw()).containsExactly('E', 'd');
    assertThat(signature.getKeyNumber().getRaw()).containsExactly(102, -4, -109, 82, 53, 70, -5, -20);
  }

  @Test
  void failIfWrongLength() {
    assertThatThrownBy(() -> Signature.fromBase64String("RWRm/JNSNUb77AmgjFuNCA"))
        .isExactlyInstanceOf(IllegalArgumentException.class)
        .hasMessage("Decoded signature total length should be 74, but was 16.");
  }

  @Test
  void failIfInvalidBase64() {
    assertThatThrownBy(() -> Signature.fromBase64String("sugus$"))
        .isExactlyInstanceOf(IllegalArgumentException.class)
        .hasMessage("Illegal base64 character 24");
  }

  @Test
  void failIfNull() {
    assertThatThrownBy(() -> Signature.fromBase64String(null))
        .isExactlyInstanceOf(NullPointerException.class)
        .hasMessage("base64Signature");
  }

  @Test
  void createSignatureFromFile() throws Exception {
    Path signatureFile = getPathFromResource("../signature.sig");
    Signature signature = Signature.fromFile(signatureFile);
    assertThat(signature.getAlgorithm().getRaw()).containsExactly('E', 'd');
    assertThat(signature.getKeyNumber().getRaw()).containsExactly(102, -4, -109, 82, 53, 70, -5, -20);
  }

  @Test
  void failIfNotExistingFile() {
    assertThatThrownBy(() -> Signature.fromFile(Paths.get("not-existing.txt")))
        .isExactlyInstanceOf(NoSuchFileException.class)
        .hasMessage("not-existing.txt");
  }

  private Path getPathFromResource(String resourceName) throws URISyntaxException {
    return Paths.get(getClass().getResource(resourceName).toURI());
  }
}
