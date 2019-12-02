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

class PublicKeyTest {

  @Test
  void createPublicKeyFromBase64String() {
    PublicKey publicKey = PublicKey.fromBase64String("RWRm/JNSNUb77CmSMXBAA5Owr4XzPbRO/PKDXXLIUfOgFDd/F8hT8p5t");
    assertThat(publicKey.getAlgorithm().getRaw()).containsExactly('E', 'd');
    assertThat(publicKey.getKeyNumber().getRaw()).containsExactly(102, -4, -109, 82, 53, 70, -5, -20);
  }

  @Test
  void failIfWrongLengthBase64() {
    assertThatThrownBy(() -> PublicKey.fromBase64String("RWRm/JNSNUb77CmSMXBAA5"))
        .isExactlyInstanceOf(IllegalArgumentException.class)
        .hasMessage("Decoded public key total length must be 42, but was 16.");
  }

  @Test
  void failIfInvalidBase64() {
    assertThatThrownBy(() -> PublicKey.fromBase64String("sugus$"))
        .isExactlyInstanceOf(IllegalArgumentException.class)
        .hasMessage("Illegal base64 character 24");
  }

  @Test
  void failIfNullBase64() {
    assertThatThrownBy(() -> PublicKey.fromBase64String(null))
        .isExactlyInstanceOf(NullPointerException.class)
        .hasMessage("base64PublicKey");
  }

  @Test
  void createPublicKeyFromFile() throws Exception {
    Path publicKeyFile = getPathFromResource("../publickey.pub");
    PublicKey publicKey = PublicKey.fromFile(publicKeyFile);
    assertThat(publicKey.getAlgorithm().getRaw()).containsExactly('E', 'd');
    assertThat(publicKey.getKeyNumber().getRaw()).containsExactly(102, -4, -109, 82, 53, 70, -5, -20);
  }

  @Test
  void failIfNotExistingFile() {
    assertThatThrownBy(() -> PublicKey.fromFile(Paths.get("not-existing.txt")))
        .isExactlyInstanceOf(NoSuchFileException.class)
        .hasMessage("not-existing.txt");
  }

  private Path getPathFromResource(String resourceName) throws URISyntaxException {
    return Paths.get(getClass().getResource(resourceName).toURI());
  }
}
