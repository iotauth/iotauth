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

import org.iot.auth.exception.InvalidMacException;
import org.iot.auth.exception.InvalidSymmetricKeyOperationException;
import org.iot.auth.exception.MessageIntegrityException;
import org.iot.auth.exception.UseOfExpiredKeyException;
import org.iot.auth.io.Buffer;
import org.iot.auth.util.ExceptionToString;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Date;

/**
 * This class specifies symmetric keys, including encryption key and MAC key.
 * Also specifies cryptography specs to be used for symmetric keys.
 * If cipherKeyVal is null, then it uses MAC only.
 * @author Hokeun Kim
 */
public class SymmetricKey {
    private Buffer cipherKeyVal = null;
    private Buffer macKeyVal = null;
    private Date expirationTime;
    private SymmetricKeyCryptoSpec cryptoSpec;
    private Cipher cipher = null;
    private Mac mac = null;
    private SecretKey cipherKey = null;
    protected static final Logger logger = LoggerFactory.getLogger(SymmetricKey.class);
    /**
     * Constructor with given key value
     * @param cryptoSpec Given cryptography specification for the symmetric key.
     * @param expirationTime Expiration time of the symmetric key.
     * @param serializedKeyVal Serialized key value which includes encryption and/or MAC keys.
     */
    public SymmetricKey(SymmetricKeyCryptoSpec cryptoSpec, long expirationTime, Buffer serializedKeyVal) {
        this.cryptoSpec = cryptoSpec;
        this.expirationTime = new Date(expirationTime);

        int curIndex = 0;
        int cipherKeySize = serializedKeyVal.getByte(curIndex);
        curIndex += 1;
        if (cryptoSpec.getCipherKeySize() != cipherKeySize) {
            throw new RuntimeException("Wrong cipher key size!");
        }
        if (cipherKeySize > 0) {
            this.cipherKeyVal = serializedKeyVal.slice(curIndex, curIndex + cipherKeySize);
            curIndex += cipherKeySize;
        }

        int macKeySize = serializedKeyVal.getByte(curIndex);
        curIndex += 1;
        if (cryptoSpec.getMacKeySize() != macKeySize) {
            throw new RuntimeException("Wrong MAC key size!");
        }
        if (macKeySize > 0) {
            this.macKeyVal = serializedKeyVal.slice(curIndex, curIndex + macKeySize);
            curIndex += macKeySize;
        }
        if (curIndex != serializedKeyVal.length()) {
            throw new RuntimeException("Wrong key size!");
        }
    }

    /**
     * For creating with new key value
     * @param cryptoSpec Given cryptography specification for the symmetric key.
     * @param expirationTime Expiration time of the symmetric key.
     */
    public SymmetricKey(SymmetricKeyCryptoSpec cryptoSpec, long expirationTime) {
        this(cryptoSpec, expirationTime,
                getSerializedKeyVal(generateCipherKeyValue(cryptoSpec), generateMacKeyValue(cryptoSpec)));
    }

    public boolean isMacOnly() {
        return cipherKeyVal == null;
    }

    public SymmetricKey makeMacOnly() {
        return new SymmetricKey(cryptoSpec.makeMacOnly(), getRawExpirationTime(),
                getSerializedKeyVal(null, macKeyVal));
    }

    public static Buffer getSerializedKeyVal(Buffer rawCipherKeyVal, Buffer rawMacKeyVal) {
        int curIndex = 0;
        int rawCipherKeyLen = 0;
        int rawMacKeyLen = 0;
        if (rawCipherKeyVal != null) {
            rawCipherKeyLen = rawCipherKeyVal.length();
        }
        if (rawMacKeyVal != null) {
            rawMacKeyLen = rawMacKeyVal.length();
        }
        Buffer buffer = new Buffer(2 + rawCipherKeyLen + rawMacKeyLen);
        buffer.putByte((byte)rawCipherKeyLen, curIndex);
        curIndex += 1;
        if (rawCipherKeyLen > 0) {
            buffer.putBytes(rawCipherKeyVal.getRawBytes(), curIndex);
            curIndex += rawCipherKeyVal.length();
        }
        buffer.putByte((byte)rawMacKeyLen, curIndex);
        curIndex += 1;
        if (rawMacKeyLen > 0) {
            buffer.putBytes(rawMacKeyVal.getRawBytes(), curIndex);
            curIndex += rawMacKeyVal.length();
        }
        return buffer;
    }
    public Buffer getSerializedKeyVal() {
        return getSerializedKeyVal(cipherKeyVal, macKeyVal);
    }
    public Buffer getCipherKeyVal() {
        return cipherKeyVal;
    }
    public Buffer getMacKeyVal() {
        return macKeyVal;
    }

    private static Buffer generateCipherKeyValue(SymmetricKeyCryptoSpec cryptoSpec) {
        String[] cipherAlgoTokens = cryptoSpec.getCipherAlgorithm().split("/");
        KeyGenerator keyGenerator;
        try {
            // TODO: support more cryptos
            keyGenerator = KeyGenerator.getInstance(cipherAlgoTokens[0]);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Failed to generate a cipher key! \n" + e.getMessage());
        }
        keyGenerator.init(8 * cryptoSpec.getCipherKeySize());
        SecretKey key = keyGenerator.generateKey();
        return new Buffer(key.getEncoded());
    }

    private static Buffer generateMacKeyValue(SymmetricKeyCryptoSpec cryptoSpec) {
        KeyGenerator keyGenerator;
        try {
            keyGenerator = KeyGenerator.getInstance(cryptoSpec.getMacAlgorithm());
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Failed to generate a MAC key! \n" + e.getMessage());
        }
        keyGenerator.init(8 * cryptoSpec.getMacKeySize());
        SecretKey key = keyGenerator.generateKey();
        return new Buffer(key.getEncoded());
    }

    private void initializeMac() {
        try {
            mac = Mac.getInstance(cryptoSpec.getMacAlgorithm());
        } catch (NoSuchAlgorithmException e) {
            logger.error("Exception {}", ExceptionToString.convertExceptionToStackTrace(e));
            throw new RuntimeException("Exception occurred while initializing MAC object!");
        }
        SecretKey macKey = new SecretKeySpec(macKeyVal.getRawBytes(), mac.getAlgorithm());
        try {
            mac.init(macKey);
        } catch (InvalidKeyException e) {
            logger.error("Exception {}", ExceptionToString.convertExceptionToStackTrace(e));
            throw new RuntimeException("Exception occurred while initializing MAC object!");
        }
    }

    private void initializeCipherMac() {
        try {
            cipher = Cipher.getInstance(cryptoSpec.getCipherAlgorithm());
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            logger.error("Exception {}", ExceptionToString.convertExceptionToStackTrace(e));
            throw new RuntimeException("Exception occurred while initializing cipher!");
        }
        String[] cipherAlgoTokens = cipher.getAlgorithm().split("/");
        cipherKey = new SecretKeySpec(cipherKeyVal.getRawBytes(), cipherAlgoTokens[0]);
        initializeMac();
    }

    public Buffer authenticateAttachMac(Buffer input) throws UseOfExpiredKeyException {
        if (isExpired()) {
            throw new UseOfExpiredKeyException("Trying to use an expired key!");
        }
        if (mac == null) {
            initializeMac();
        }
        Buffer buffer = new Buffer(input);
        Buffer tag = new Buffer(mac.doFinal(input.getRawBytes()));
        buffer.concat(tag);
        return buffer;
    }

    public Buffer verifyMacExtractData(Buffer input) throws UseOfExpiredKeyException, InvalidMacException {
        if (isExpired()) {
            throw new UseOfExpiredKeyException("Trying to use an expired key!");
        }
        if (mac == null) {
            initializeMac();
        }
        Buffer data = input.slice(0, input.length() - mac.getMacLength());
        Buffer receivedTag = input.slice(input.length() - mac.getMacLength());
        Buffer computedTag = new Buffer(mac.doFinal(data.getRawBytes()));
        if (!receivedTag.equals(computedTag)) {
            throw new InvalidMacException("MAC of session key request is NOT correct!");
        }
        return data;
    }

    public Buffer encryptAuthenticate(Buffer input) throws UseOfExpiredKeyException, InvalidSymmetricKeyOperationException {
        if (isMacOnly()) {
            throw new InvalidSymmetricKeyOperationException("Encryption is invalid for MAC only session key!");
        }
        if (isExpired()) {
            throw new UseOfExpiredKeyException("Trying to use an expired key!");
        }
        if (cipher == null || mac == null) {
            initializeCipherMac();
        }
        try {
            cipher.init(Cipher.ENCRYPT_MODE, cipherKey);

            ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
            // write initialization vector first
            byte[] initVector = cipher.getIV();
            if (initVector != null) {
                byteArrayOutputStream.write(initVector);
            }
            byteArrayOutputStream.write(cipher.doFinal(input.getRawBytes()));
            Buffer buffer = new Buffer(byteArrayOutputStream.toByteArray());

            Buffer tag = new Buffer(mac.doFinal(buffer.getRawBytes()));
            buffer.concat(tag);
            return buffer;
        }
        catch (InvalidKeyException | IOException | BadPaddingException
                | IllegalBlockSizeException e) {
            logger.error("Exception {}", ExceptionToString.convertExceptionToStackTrace(e));
            throw new RuntimeException("Exception occurred while performing encryptAuthenticate!");
        }
    }

    public Buffer decryptVerify(Buffer input) throws InvalidMacException, MessageIntegrityException,
            UseOfExpiredKeyException, InvalidSymmetricKeyOperationException {
        if (isMacOnly()) {
            throw new InvalidSymmetricKeyOperationException("Decryption is invalid for MAC only session key!");
        }
        if (isExpired()) {
            throw new UseOfExpiredKeyException("Trying to use an expired key!");
        }
        if (cipher == null || mac == null) {
            initializeCipherMac();
        }
        Buffer encrypted = input.slice(0, input.length() - mac.getMacLength());
        Buffer receivedTag = input.slice(input.length() - mac.getMacLength());
        Buffer computedTag = new Buffer(mac.doFinal(encrypted.getRawBytes()));
        if (!receivedTag.equals(computedTag)) {
            throw new InvalidMacException("MAC of session key request is NOT correct!");
        }

        int blockSize = cipher.getBlockSize();
        byte[] initVector = encrypted.slice(0, blockSize).getRawBytes();
        IvParameterSpec ivSpec = new IvParameterSpec(initVector);
        try {
            cipher.init(Cipher.DECRYPT_MODE, cipherKey, ivSpec);
        } catch (InvalidKeyException | InvalidAlgorithmParameterException e) {
            logger.error("InvalidKeyException | InvalidAlgorithmParameterException {}",
                    ExceptionToString.convertExceptionToStackTrace(e));
            throw new RuntimeException("Exception occurred while performing decryptVerify!");
        }

        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        int ivSize = 0;
        if (cipher.getIV() != null) {
            ivSize = cipher.getIV().length;
        }

        try {
            byteArrayOutputStream.write(cipher.doFinal(encrypted.getRawBytes(), ivSize, encrypted.length() - ivSize));
        } catch (IOException e) {
            logger.error("IOException {}", ExceptionToString.convertExceptionToStackTrace(e));
            throw new RuntimeException("Exception occurred while performing decryptVerify!");
        } catch (IllegalBlockSizeException | BadPaddingException e) {
            logger.error("IllegalBlockSizeException | BadPaddingException {}",
                    ExceptionToString.convertExceptionToStackTrace(e));
            throw new MessageIntegrityException("Integrity error occurred during decryptVerify!");
        }
        return new Buffer(byteArrayOutputStream.toByteArray());
    }

    public SymmetricKeyCryptoSpec getCryptoSpec() {
        return cryptoSpec;
    }
    public Date getExpirationTime() {
        return expirationTime;
    }
    public long getRawExpirationTime() {
        return expirationTime.getTime();
    }

    public boolean isExpired() {
        Date now = new Date();
        return expirationTime.before(now);
    }
}
