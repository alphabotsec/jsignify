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

/*
 * A Signify key number (used internally).
 */
public final class KeyNumber {
  static final int KEY_NUMBER_LEN = 8;
  private final ImmutableByteArray keyNumber;

  public KeyNumber(byte[] keyNumber) {
    Preconditions.checkNotNull(keyNumber, "keyNumber must not be null");
    Preconditions.checkArgument(
        keyNumber.length == KEY_NUMBER_LEN,
        "Key number length must be %s, but was %s.", KEY_NUMBER_LEN, keyNumber.length);
    this.keyNumber = ImmutableByteArray.of(keyNumber);
  }

  public byte[] getRaw() {
    return keyNumber.getBytes();
  }

  public boolean isNotEqualTo(KeyNumber otherKeyNumber) {
    return !Arrays.equals(keyNumber.getBytes(), otherKeyNumber.keyNumber.getBytes());
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }
    KeyNumber otherKeyNumber = (KeyNumber) o;
    return Arrays.equals(keyNumber.getBytes(), otherKeyNumber.keyNumber.getBytes());
  }

  @Override
  public int hashCode() {
    return Arrays.hashCode(keyNumber.getBytes());
  }
}
