/*
 * Copyright (c) 2016, Regents of the University of California
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * IOTAUTH_COPYRIGHT_VERSION_1
 */

package org.iot.auth.db;

import org.json.simple.JSONObject;

/**
 * A class for symmetric key cryptography specifications
 * @author Hokeun Kim
 */
public class SymmetricKeyCryptoSpec {
    private enum key {
        cipher,
        hash
    }

    public SymmetricKeyCryptoSpec(String cipherAlgo, int cipherKeySize, String hashAlgo) {
        this.cipherAlgo = cipherAlgo;
        this.cipherKeySize = cipherKeySize;

        this.hashAlgo = hashAlgo;
    }

    public static SymmetricKeyCryptoSpec fromJSONObject(JSONObject jsonObject) {
        CryptoAlgoKeySize cipherAlgoKeySize = fromJSCryptoAlgo((String)jsonObject.get(key.cipher.toString()));
        CryptoAlgoKeySize hashAlgoKeySize = fromJSCryptoAlgo((String)jsonObject.get(key.hash.toString()));

        return new SymmetricKeyCryptoSpec(cipherAlgoKeySize.getCryptoAlgo(), cipherAlgoKeySize.getKeySize(),
                hashAlgoKeySize.getCryptoAlgo());
    }

    public static SymmetricKeyCryptoSpec fromJSSpec(String cipherAlgo, String hashAlgo) {
        CryptoAlgoKeySize retCipher = fromJSCryptoAlgo(cipherAlgo);
        CryptoAlgoKeySize retHash = fromJSCryptoAlgo(hashAlgo);

        return new SymmetricKeyCryptoSpec(retCipher.getCryptoAlgo(), retCipher.getKeySize(), retHash.getCryptoAlgo());
    }

    public String getCipherAlgo() {
        return cipherAlgo;
    }
    public int getCipherKeySize() {
        return cipherKeySize;
    }
    public String getHashAlgo() {
        return hashAlgo;
    }

    public JSONObject toJSONObject() {
        JSONObject object = new JSONObject();
        object.put(key.cipher, toJSCryptoAlgo(cipherAlgo, cipherKeySize));
        object.put(key.hash, toJSCryptoAlgo(hashAlgo, -1));
        return object;
    }

    public String toString() {
            return "CipherAlgorithm: " + cipherAlgo + "\tCipherKeySize: " + cipherKeySize + "\tHashAlgorithm: " + hashAlgo;
    }

    private String cipherAlgo;
    private int cipherKeySize;
    private String hashAlgo;

    public static String toJSCryptoAlgo(String cryptoAlgo, int keySize) {
        if (cryptoAlgo.equals("AES/CBC/PKCS5Padding")) {
            if (keySize == 16) {
                return new String("AES-128-CBC");
            }
            else if (keySize == 24) {
                return new String("AES-192-CBC");
            }
            else if (keySize == 32) {
                return new String("AES-256-CBC");
            }
            // 128 bits -> 16 bytes
        }
        else if (cryptoAlgo.equals("SHA-256")) {
            return new String("SHA256");
        }
        throw new IllegalArgumentException("No such crypto algorithm: " + cryptoAlgo + ", keySize:" + keySize);
    }

    public static class CryptoAlgoKeySize {
        public CryptoAlgoKeySize(String cipherAlgo, int keySize) {
            this.cipherAlgo = cipherAlgo;
            this.keySize = keySize;
        }
        public CryptoAlgoKeySize(String cipherAlgo) {
            this.cipherAlgo = cipherAlgo;
            this.keySize = -1;
        }
        public String getCryptoAlgo() {
            return cipherAlgo;
        }
        public int getKeySize() {
            return keySize;
        }
        private String cipherAlgo;
        private int keySize;
    }

    public static CryptoAlgoKeySize fromJSCryptoAlgo(String jsCryptoAlgo) {
        if (jsCryptoAlgo.equals("AES-128-CBC")) {
            // 128 bits -> 16 bytes
            return new CryptoAlgoKeySize("AES/CBC/PKCS5Padding", 16);
        }
        else if (jsCryptoAlgo.equals("AES-192-CBC")) {
            // 128 bits -> 16 bytes
            return new CryptoAlgoKeySize("AES/CBC/PKCS5Padding", 24);
        }
        else if (jsCryptoAlgo.equals("AES-256-CBC")) {
            // 128 bits -> 16 bytes
            return new CryptoAlgoKeySize("AES/CBC/PKCS5Padding", 32);
        }
        else if (jsCryptoAlgo.equals("SHA256")) {
            return new CryptoAlgoKeySize("SHA-256");
        }
        throw new IllegalArgumentException("No such JS crypto algorithm: " + jsCryptoAlgo);
    }
}
