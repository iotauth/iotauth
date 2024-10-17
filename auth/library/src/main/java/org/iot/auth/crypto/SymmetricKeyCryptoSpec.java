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

package org.iot.auth.crypto;

import org.json.simple.JSONObject;

/**
 * A class for symmetric key cryptography specifications
 * @author Hokeun Kim
 */
public class SymmetricKeyCryptoSpec extends CryptoSpec {

    private enum key {
        cipher,
        mac
    }

    public SymmetricKeyCryptoSpec(String cipherAlgorithm, int cipherKeySize, String macAlgorithm) {
        this.cipherAlgorithm = cipherAlgorithm;
        this.cipherKeySize = cipherKeySize;

        this.macAlgorithm = macAlgorithm;
        this.macKeySize = getMacAlgoKeySize(macAlgorithm);
    }

    /**
     * Constructor for symmetric crypto spec that uses MAC only.
     * @param macAlgorithm The name of MAC algorithm
     */
    public SymmetricKeyCryptoSpec(String macAlgorithm) {
        this("", 0, macAlgorithm);
    }

    public SymmetricKeyCryptoSpec makeMacOnly() {
        return new SymmetricKeyCryptoSpec(macAlgorithm);
    }

    public static SymmetricKeyCryptoSpec fromJSONObject(JSONObject jsonObject) {
        CryptoAlgoKeySize cipherAlgoKeySize = fromJSCryptoAlgo((String)jsonObject.get(key.cipher.toString()));
        CryptoAlgoKeySize hashAlgoKeySize = fromJSCryptoAlgo((String)jsonObject.get(key.mac.toString()));

        return new SymmetricKeyCryptoSpec(cipherAlgoKeySize.getCryptoAlgo(), cipherAlgoKeySize.getKeySize(),
                hashAlgoKeySize.getCryptoAlgo());
    }

    public static SymmetricKeyCryptoSpec fromSpecString(String cryptoSpecString) {
        String[] stringArray = cryptoSpecString.split(":");
        String cipherAlgo = stringArray[0];
        String hashAlgo = stringArray[1];
        CryptoAlgoKeySize retCipher = fromJSCryptoAlgo(cipherAlgo);
        CryptoAlgoKeySize retHash = fromJSCryptoAlgo(hashAlgo);

        return new SymmetricKeyCryptoSpec(retCipher.getCryptoAlgo(), retCipher.getKeySize(), retHash.getCryptoAlgo());
    }

    public String toSpecString() {
        return toJavaScriptSpecString(cipherAlgorithm, cipherKeySize) + ":" + toJavaScriptSpecString(macAlgorithm, -1);
    }
    public String getCipherAlgorithm() {
        return cipherAlgorithm;
    }
    public int getCipherKeySize() {
        return cipherKeySize;
    }
    public String getMacAlgorithm() {
        return macAlgorithm;
    }
    public int getMacKeySize() {
        return macKeySize;
    }

    @SuppressWarnings("unchecked")
    public JSONObject toJSONObject() {
        JSONObject object = new JSONObject();
        object.put(key.cipher, toJavaScriptSpecString(cipherAlgorithm, cipherKeySize));
        object.put(key.mac, toJavaScriptSpecString(macAlgorithm, -1));
        return object;
    }

    public String toString() {
            return "Cipher: " + cipherAlgorithm + "\tCipherKeySize: " + cipherKeySize + "\tMAC Algorithm: " + macAlgorithm;
    }

    private String cipherAlgorithm;
    private int cipherKeySize;
    private String macAlgorithm;
    private int macKeySize;

    private static String toJavaScriptSpecString(String cryptoAlgo, int keySize) {
        if (cryptoAlgo.equals("")) {
            return new String("");
        }
        else if (cryptoAlgo.equals("AES/CBC/PKCS5Padding")) {
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
        else if (cryptoAlgo.equals("AES/CTR/NoPadding")) {
            if (keySize == 16) {
                return new String("AES-128-CTR");
            }
        }
        else if (cryptoAlgo.equals("HmacSHA256")) {
            return new String("SHA256");
        }
        throw new IllegalArgumentException("No such crypto algorithm: " + cryptoAlgo + ", keySize:" + keySize);
    }

    private static int getMacAlgoKeySize(String macAlgo) {
        if (macAlgo.equals("HmacSHA256")) {
            return 32;
        }
        else {
            throw new IllegalArgumentException("No such MAC algorithm: " + macAlgo);
        }
    }


    private static class CryptoAlgoKeySize {
        public CryptoAlgoKeySize(String cipherAlgo, int keySize) {
            this.cipherAlgo = cipherAlgo;
            this.keySize = keySize;
        }
        public CryptoAlgoKeySize(String cipherAlgo) {
            this.cipherAlgo = cipherAlgo;
            this.keySize = -1;
        }
        public CryptoAlgoKeySize() {
            this.cipherAlgo = "";
            this.keySize = 0;
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

    private static CryptoAlgoKeySize fromJSCryptoAlgo(String jsCryptoAlgo) {
        if (jsCryptoAlgo.equals("")) {
            return new CryptoAlgoKeySize();
        }
        else if (jsCryptoAlgo.equals("AES-128-CBC")) {
            // 128 bits -> 16 bytes
            return new CryptoAlgoKeySize("AES/CBC/PKCS5Padding", 16);
        }
        else if (jsCryptoAlgo.equals("AES-192-CBC")) {
            // 192 bits -> 24 bytes
            return new CryptoAlgoKeySize("AES/CBC/PKCS5Padding", 24);
        }
        else if (jsCryptoAlgo.equals("AES-256-CBC")) {
            // 256 bits -> 32 bytes
            return new CryptoAlgoKeySize("AES/CBC/PKCS5Padding", 32);
        }
        else if (jsCryptoAlgo.equals("AES-128-CTR")) {
            return new CryptoAlgoKeySize("AES/CTR/NoPadding", 16);
        }
        else if (jsCryptoAlgo.equals("AES-128-GCM")) {
            return new CryptoAlgoKeySize("AES/GCM/PKCS5Padding", 16);
        }
        else if (jsCryptoAlgo.equals("SHA256")) {
            return new CryptoAlgoKeySize("HmacSHA256");
        }
        throw new IllegalArgumentException("No such JS crypto algorithm: " + jsCryptoAlgo);
    }
}
