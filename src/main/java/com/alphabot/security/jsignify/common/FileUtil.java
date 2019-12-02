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

import com.alphabot.security.jsignify.exception.VerificationFailedException;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

public final class FileUtil {
  private static final String COMMENT_HEADER = "untrusted comment: ";

  public static byte[] readAllBytes(Path file) throws IOException {
    return Files.readAllBytes(file);
  }

  public static String readBase64File(Path file) throws IOException {
    List<String> lines = Files.readAllLines(file, StandardCharsets.UTF_8);

    if (lines.size() < 2 || !lines.get(0).startsWith(COMMENT_HEADER)) {
      throw new IllegalArgumentException("invalid comment in " + file.toAbsolutePath().toString()
          + "; must start with '" + COMMENT_HEADER + "'");
    }
    return lines.get(1).trim();
  }
}
