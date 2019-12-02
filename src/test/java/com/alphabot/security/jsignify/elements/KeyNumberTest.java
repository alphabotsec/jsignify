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

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class KeyNumberTest {

  @Test
  void keyNumberTooShort() {
    assertThatThrownBy(() -> new KeyNumber(new byte[]{0x11, 0x22, 0x22, 0x44}))
        .isExactlyInstanceOf(IllegalArgumentException.class)
        .hasMessage("Key number length must be 8, but was 4.");
  }

  @Test
  void keyNumberTooLong() {
    assertThatThrownBy(() -> new KeyNumber(new byte[]{0x11, 0x22, 0x22, 0x44, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e}))
        .isExactlyInstanceOf(IllegalArgumentException.class)
        .hasMessage("Key number length must be 8, but was 9.");
  }

  @Test
  void getRaw() {
    KeyNumber actual = new KeyNumber(new byte[]{0x11, 0x22, 0x22, 0x44, 0x0a, 0x0b, 0x0c, 0x0d});
    assertThat(actual.getRaw()).isEqualTo(new byte[]{0x11, 0x22, 0x22, 0x44, 0x0a, 0x0b, 0x0c, 0x0d});
  }



  @Test
  void isNotEqualTo() {
    KeyNumber k1 = new KeyNumber(new byte[]{0x11, 0x22, 0x22, 0x44, 0x0a, 0x0b, 0x0c, 0x0d});
    KeyNumber k2 = new KeyNumber(new byte[]{0x11, 0x22, 0x22, 0x44, 0x0a, 0x0b, 0x0c, 0x0d});

    assertThat(k1.isNotEqualTo(k2)).isFalse();
    assertThat(k2.isNotEqualTo(k1)).isFalse();
  }

  @Test
  void isEqualTo() {
    KeyNumber k1 = new KeyNumber(new byte[]{0x07, 0x14, 0x21, 0x42, 0x0a, 0x0b, 0x0c, 0x0d});
    KeyNumber k2 = new KeyNumber(new byte[]{0x11, 0x22, 0x22, 0x44, 0x0a, 0x0b, 0x0c, 0x0d});

    assertThat(k1.isNotEqualTo(k2)).isTrue();
    assertThat(k2.isNotEqualTo(k1)).isTrue();
  }

  @Test
  void equal() {
    KeyNumber k1 = new KeyNumber(new byte[]{0x11, 0x22, 0x22, 0x44, 0x0a, 0x0b, 0x0c, 0x0d});
    KeyNumber k2 = new KeyNumber(new byte[]{0x11, 0x22, 0x22, 0x44, 0x0a, 0x0b, 0x0c, 0x0d});

    assertThat(k1.equals(k2)).isTrue();
    assertThat(k2.equals(k1)).isTrue();
  }

  @Test
  void notEqual() {
    KeyNumber k1 = new KeyNumber(new byte[]{0x07, 0x14, 0x21, 0x42, 0x0a, 0x0b, 0x0c, 0x0d});
    KeyNumber k2 = new KeyNumber(new byte[]{0x11, 0x22, 0x22, 0x44, 0x0a, 0x0b, 0x0c, 0x0d});

    assertThat(k1.equals(k2)).isFalse();
    assertThat(k2.equals(k1)).isFalse();
  }

  @Test
  void sameHashCode() {
    KeyNumber k1 = new KeyNumber(new byte[]{0x01, 0x02, 0x03, 0x04, 0x0a, 0x0b, 0x0c, 0x0d});
    KeyNumber k2 = new KeyNumber(new byte[]{0x01, 0x02, 0x03, 0x04, 0x0a, 0x0b, 0x0c, 0x0d});

    assertThat(k1.hashCode()).isEqualTo(k2.hashCode());
  }
}