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

import static org.assertj.core.api.Assertions.assertThatThrownBy;

class AlgorithmTest {

  @Test
  void correctAlgorithm() {
    new Algorithm(new byte[]{'E', 'd'});
  }

  @Test
  void wrongAlgorithm() {
    assertThatThrownBy(() -> new Algorithm(new byte[]{'E', 'x'}))
        .isExactlyInstanceOf(IllegalArgumentException.class)
        .hasMessage("Algorithm must equal 'Ed'");
  }
}