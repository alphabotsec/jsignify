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

package com.alphabot.security.jsignify.common;

import org.junit.jupiter.api.Test;

import java.net.URISyntaxException;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.nio.file.Paths;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class FileUtilTest {

  @Test
  void readAllBytes() throws Exception {
    Path messageFile = getPathFromResource("../testmessage.txt");
    byte[] fileContent = FileUtil.readAllBytes(messageFile);
    assertThat(fileContent).isEqualTo("testmessage\n".getBytes(UTF_8));
  }

  @Test
  void failIfNotExistingMessageFile() {
    assertThatThrownBy(() -> FileUtil.readBase64File(Paths.get("not-existing-msg.txt")))
        .isExactlyInstanceOf(NoSuchFileException.class)
        .hasMessage("not-existing-msg.txt");
  }

  @Test
  void readBase64File() throws Exception {
    Path signatureFile = getPathFromResource("../publickey.pub");
    String base64 = FileUtil.readBase64File(signatureFile);
    assertThat(base64).isEqualTo("RWRm/JNSNUb77CmSMXBAA5Owr4XzPbRO/PKDXXLIUfOgFDd/F8hT8p5t");
  }

  @Test
  void failIfNotExistingBase64File() {
    assertThatThrownBy(() -> FileUtil.readBase64File(Paths.get("not-existing.txt")))
        .isExactlyInstanceOf(NoSuchFileException.class)
        .hasMessage("not-existing.txt");
  }

  @Test
  void failIfBase64FileStartsWithWrongComment() throws Exception {
    Path wrongComment = getPathFromResource("wrongcomment.txt");
    assertThatThrownBy(() -> FileUtil.readBase64File(wrongComment))
        .isExactlyInstanceOf(IllegalArgumentException.class)
        .hasMessageStartingWith("invalid comment in ");
  }

  private Path getPathFromResource(String resourceName) throws URISyntaxException {
    return Paths.get(getClass().getResource(resourceName).toURI());
  }
}