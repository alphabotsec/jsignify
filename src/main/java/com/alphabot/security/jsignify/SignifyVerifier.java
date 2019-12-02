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

package com.alphabot.security.jsignify;

import com.alphabot.security.jsignify.common.FileUtil;
import com.alphabot.security.jsignify.elements.PublicKey;
import com.alphabot.security.jsignify.elements.Signature;
import com.alphabot.security.jsignify.exception.VerificationFailedException;
import com.google.crypto.tink.annotations.Alpha;
import com.google.crypto.tink.subtle.Ed25519Verify;

import java.io.IOException;
import java.nio.file.Path;
import java.security.GeneralSecurityException;

/**
 * SignifyVerifier can be used to verify (OpenBSD) Signify signatures.
 */
@Alpha
public final class SignifyVerifier {
  private final PublicKey publicKey;

  /**
   * Create a new SignifyVerifier with a public key from file.
   * @param publicKeyFile a path pointing to the public key file
   * @throws IOException in case an I/O error occurs (e.g. public key file not found)
   * @throws IllegalArgumentException in case an argument is in the wrong format
   */
  public SignifyVerifier(Path publicKeyFile) throws IOException {
    publicKey = PublicKey.fromFile(publicKeyFile);
  }

  /**
   * Create a new SignifyVerifier with a public key from a Base64 string.
   * @param base64PublicKey public key Base64 encoded (typically starting with RW...)
   * @throws IllegalArgumentException in case an argument is in the wrong format
   */
  public SignifyVerifier(String base64PublicKey) {
    publicKey = PublicKey.fromBase64String(base64PublicKey);
  }

  /**
   * Verify a message file with its corresponding signature file.
   * @param signatureFile a path pointing to the signature file
   * @param messageFile a path pointing to the message file to verify
   * @throws VerificationFailedException in case the verification of the message fails (e.g. not signed by this public key)
   * @throws IOException in case an I/O error occurs (e.g. message file not found)
   * @throws IllegalArgumentException in case an argument is in the wrong format
   */
  public void verifyFile(Path signatureFile, Path messageFile) throws VerificationFailedException, IOException {
    Signature signature = Signature.fromFile(signatureFile);
    byte[] message = FileUtil.readAllBytes(messageFile);

    verifyMessage(signature, message);
  }

  /**
   * Verify a message with its corresponding signature in Base64 format.
   * @param base64Signature signature Base64 encoded (typically starting with RW...)
   * @param message message to verify
   * @throws VerificationFailedException in case the verification of the message fails (e.g. not signed by this public key)
   * @throws IllegalArgumentException in case an argument is in the wrong format
   */
  public void verify(String base64Signature, byte[] message) throws VerificationFailedException {
    Signature signature = Signature.fromBase64String(base64Signature);

    verifyMessage(signature, message);
  }

  private void verifyMessage(Signature signature, byte[] message) throws VerificationFailedException {
    if (publicKey.getKeyNumber().isNotEqualTo(signature.getKeyNumber())) {
      throw new VerificationFailedException("verification failed: checked against wrong key");
    }

    Ed25519Verify verifier = new Ed25519Verify(publicKey.getPublicKey());
    try {
      verifier.verify(signature.getSignature(), message);
    } catch (GeneralSecurityException e) {
      throw new VerificationFailedException("signature verification failed", e);
    }
  }
}
