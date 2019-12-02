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

import com.alphabot.security.jsignify.common.FileUtil;
import com.alphabot.security.jsignify.exception.VerificationFailedException;
import com.google.common.base.Preconditions;
import com.google.crypto.tink.subtle.ImmutableByteArray;

import java.io.IOException;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.Base64;

import static com.alphabot.security.jsignify.elements.Algorithm.KEY_ALGORITHM_LEN;
import static com.alphabot.security.jsignify.elements.KeyNumber.KEY_NUMBER_LEN;
import static com.google.crypto.tink.subtle.Ed25519Verify.PUBLIC_KEY_LEN;

/*
 * A Signify public key. (used internally)
 * Consisting of an algorithm (currently always 'Ed'), a key number and the actual Ed25519 public key.
 */
public final class PublicKey {
  private static final int DECODED_PUBLIC_KEY_LEN = KEY_ALGORITHM_LEN + KEY_NUMBER_LEN + PUBLIC_KEY_LEN;

  private final Algorithm algorithm;
  private final KeyNumber keyNumber;
  private final ImmutableByteArray publicKey;

  private PublicKey(byte[] algorithm, byte[] keyNumber, byte[] publicKey) {
    this.algorithm = new Algorithm(algorithm);
    this.keyNumber = new KeyNumber(keyNumber);
    this.publicKey = ImmutableByteArray.of(publicKey);
  }

  public static PublicKey fromBase64String(String base64PublicKey) {
    Preconditions.checkNotNull(base64PublicKey, "base64PublicKey");
    byte[] decoded = Base64.getDecoder().decode(base64PublicKey);
    Preconditions.checkArgument(
        decoded.length == DECODED_PUBLIC_KEY_LEN,
        "Decoded public key total length must be %s, but was %s.", DECODED_PUBLIC_KEY_LEN, decoded.length);

    byte[] algorithm = Arrays.copyOfRange(decoded, 0, KEY_ALGORITHM_LEN);
    byte[] keyNumber = Arrays.copyOfRange(decoded, KEY_ALGORITHM_LEN, 2 + KEY_NUMBER_LEN);
    byte[] publicKey = Arrays.copyOfRange(decoded, 10, 10 + PUBLIC_KEY_LEN);
    return new PublicKey(algorithm, keyNumber, publicKey);
  }

  public static PublicKey fromFile(Path publicKeyFile) throws IOException {
    Preconditions.checkNotNull(publicKeyFile, "publicKeyFile");
    String base64 = FileUtil.readBase64File(publicKeyFile);
    return PublicKey.fromBase64String(base64);
  }

  public Algorithm getAlgorithm() {
    return algorithm;
  }

  public KeyNumber getKeyNumber() {
    return keyNumber;
  }

  public byte[] getPublicKey() {
    return publicKey.getBytes();
  }
}
