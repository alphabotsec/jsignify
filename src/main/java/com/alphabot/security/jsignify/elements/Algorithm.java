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

import com.google.common.base.Preconditions;
import com.google.crypto.tink.subtle.ImmutableByteArray;

import java.util.Arrays;

import static java.nio.charset.StandardCharsets.ISO_8859_1;

/*
 * A Signify key algorithm (used internally)
 * The only currently supported algorithm is 'Ed'.
 */
public final class Algorithm {
  static final int KEY_ALGORITHM_LEN = 2;
  private static final byte[] KEY_ALGORITHM = "Ed".getBytes(ISO_8859_1);
  private final ImmutableByteArray algorithm;

  public Algorithm(byte[] algorithm) {
    Preconditions.checkNotNull(algorithm, "algorithm must not be null");
    Preconditions.checkArgument(Arrays.equals(algorithm, KEY_ALGORITHM), "Algorithm must equal 'Ed'");
    this.algorithm = ImmutableByteArray.of(algorithm);
  }

  public byte[] getRaw() {
    return algorithm.getBytes();
  }
}
