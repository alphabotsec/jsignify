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
import static com.google.crypto.tink.subtle.Ed25519Verify.SIGNATURE_LEN;

/*
 * A Signify signature. (used internally)
 * Consisting of an algorithm (currently always 'Ed'), a key number and the actual Ed25519 signature.
 */
public final class Signature {
  private static final int DECODED_SIGNATURE_LEN = KEY_ALGORITHM_LEN + KEY_NUMBER_LEN + SIGNATURE_LEN;

  private final Algorithm algorithm;
  private final KeyNumber keyNumber;
  private final ImmutableByteArray signature;

  private Signature(byte[] algorithm, byte[] keyNumber, byte[] signature) {
    this.algorithm = new Algorithm(algorithm);
    this.keyNumber = new KeyNumber(keyNumber);
    this.signature = ImmutableByteArray.of(signature);
  }

  public static Signature fromBase64String(String base64Signature) {
    Preconditions.checkNotNull(base64Signature, "base64Signature");
    byte[] decoded = Base64.getDecoder().decode(base64Signature);
    Preconditions.checkArgument(
        decoded.length == DECODED_SIGNATURE_LEN,
        "Decoded signature total length should be %s, but was %s.", DECODED_SIGNATURE_LEN, decoded.length);

    byte[] algorithm = Arrays.copyOfRange(decoded, 0, KEY_ALGORITHM_LEN);
    byte[] keyNumber = Arrays.copyOfRange(decoded, KEY_ALGORITHM_LEN, 2 + KEY_NUMBER_LEN);
    byte[] signature = Arrays.copyOfRange(decoded, 10, 10 + SIGNATURE_LEN);
    return new Signature(algorithm, keyNumber, signature);
  }

  public static Signature fromFile(Path signatureFile) throws VerificationFailedException, IOException {
    Preconditions.checkNotNull(signatureFile, "signatureFile");
    String base64 = FileUtil.readBase64File(signatureFile);
    return Signature.fromBase64String(base64);
  }

  public Algorithm getAlgorithm() {
    return algorithm;
  }

  public KeyNumber getKeyNumber() {
    return keyNumber;
  }

  public byte[] getSignature() {
    return signature.getBytes();
  }
}
