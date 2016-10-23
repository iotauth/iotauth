package org.iot.auth.crypto;

import org.iot.auth.exception.InvalidMacException;
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
 * Also specifies cryptography specs to be used for symmetric keys
 */
public class SymmetricKey {
    /**
     * With given key value
     * @param cryptoSpec
     * @param expirationTime
     * @param serializedKeyVal
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
        this.cipherKeyVal = serializedKeyVal.slice(curIndex, curIndex + cipherKeySize);
        curIndex += cipherKeySize;

        int macKeySize = serializedKeyVal.getByte(curIndex);
        curIndex += 1;
        if (cryptoSpec.getMacKeySize() != macKeySize) {
            throw new RuntimeException("Wrong MAC key size!");
        }
        this.macKeyVal = serializedKeyVal.slice(curIndex, curIndex + macKeySize);
        curIndex += macKeySize;
        if (curIndex != serializedKeyVal.length()) {
            throw new RuntimeException("Wrong key size!");
        }
    }

    /**
     * For creating new key value
     * @param cryptoSpec
     * @param expirationTime
     */
    public SymmetricKey(SymmetricKeyCryptoSpec cryptoSpec, long expirationTime) {
        this(cryptoSpec, expirationTime,
                getSerializedKeyVal(generateCipherKeyValue(cryptoSpec), generateMacKeyValue(cryptoSpec)));
    }

    public static Buffer getSerializedKeyVal(Buffer rawCipherKeyVal, Buffer rawMacKeyVal) {
        int curIndex = 0;
        Buffer buffer = new Buffer(2 + rawCipherKeyVal.length() + rawMacKeyVal.length());
        buffer.putByte((byte)rawCipherKeyVal.length(), curIndex);
        curIndex += 1;
        buffer.putBytes(rawCipherKeyVal.getRawBytes(), curIndex);
        curIndex += rawCipherKeyVal.length();
        buffer.putByte((byte)rawMacKeyVal.length(), curIndex);
        curIndex += 1;
        buffer.putBytes(rawMacKeyVal.getRawBytes(), curIndex);
        return buffer;
    }
    public Buffer getSerializedKeyVal() {
        return getSerializedKeyVal(cipherKeyVal, macKeyVal);
    }
    public Buffer getCipherKeyVal() {
        return cipherKeyVal;
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

    private void initializeCipherMac() {
        try {
            cipher = Cipher.getInstance(cryptoSpec.getCipherAlgorithm());
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            logger.error("Exception {}", ExceptionToString.convertExceptionToStackTrace(e));
            throw new RuntimeException("Exception occurred while initializing cipher!");
        }
        String[] cipherAlgoTokens = cipher.getAlgorithm().split("/");
        cipherKey = new SecretKeySpec(cipherKeyVal.getRawBytes(), cipherAlgoTokens[0]);
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

    public Buffer encryptAuthenticate(Buffer input) throws UseOfExpiredKeyException {
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
            UseOfExpiredKeyException {
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

    private Buffer cipherKeyVal;
    private Buffer macKeyVal;
    private Date expirationTime;
    private SymmetricKeyCryptoSpec cryptoSpec;
    private Cipher cipher = null;
    private Mac mac = null;
    private SecretKey cipherKey = null;
    protected static final Logger logger = LoggerFactory.getLogger(SymmetricKey.class);
}
