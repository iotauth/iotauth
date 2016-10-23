package org.iot.auth.crypto;

import org.iot.auth.exception.InvalidMacException;
import org.iot.auth.exception.MessageIntegrityException;
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
import java.security.MessageDigest;
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
        if (cryptoSpec.getCipherKeySize() != serializedKeyVal.length()) {
            throw new RuntimeException("Wrong key size!");
        }
        this.cryptoSpec = cryptoSpec;
        this.expirationTime = new Date(expirationTime);
        this.keyVal = new Buffer(serializedKeyVal);
    }

    /**
     * For creating new key value
     * @param cryptoSpec
     * @param expirationTime
     */
    public SymmetricKey(SymmetricKeyCryptoSpec cryptoSpec, long expirationTime) {
        this(cryptoSpec, expirationTime, generateCipherKeyValue(cryptoSpec));
    }

    public Date getExpirationTime() {
        return expirationTime;
    }
    public Buffer getSerializedKeyVal() {
        return keyVal;
    }
    public Buffer getCipherKeyVal() {
        return keyVal;
    }

    private static Buffer generateCipherKeyValue(SymmetricKeyCryptoSpec cryptoSpec) {
        String[] cipherAlgoTokens = cryptoSpec.getCipherAlgo().split("/");
        KeyGenerator keyGenerator;
        try {
            // TODO: support more cryptos
            keyGenerator = KeyGenerator.getInstance(cipherAlgoTokens[0]);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Failed to generate key! \n" + e.getMessage());
        }
        keyGenerator.init(8 * cryptoSpec.getCipherKeySize());
        SecretKey key = keyGenerator.generateKey();
        return new Buffer(key.getEncoded());
    }

    private void initializeCipher() {
        try {
            cipher = Cipher.getInstance(cryptoSpec.getCipherAlgo());
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            logger.error("Exception {}", ExceptionToString.convertExceptionToStackTrace(e));
            throw new RuntimeException("Exception occurred while initializing cipher!");
        }
        String[] cipherAlgoTokens = cipher.getAlgorithm().split("/");
        cipherKey = new SecretKeySpec(keyVal.getRawBytes(), cipherAlgoTokens[0]);
    }

    public Buffer encryptAuthenticate(Buffer input) {
        if (cipher == null) {
            initializeCipher();
        }
        try {
            MessageDigest messageDigest = MessageDigest.getInstance(cryptoSpec.getHashAlgo());
            Buffer buffer = new Buffer(input);
            buffer.concat(new Buffer(messageDigest.digest(input.getRawBytes())));

            cipher.init(Cipher.ENCRYPT_MODE, cipherKey);

            ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
            // write initialization vector first
            byte[] initVector = cipher.getIV();
            if (initVector != null) {
                byteArrayOutputStream.write(initVector);
            }
            byteArrayOutputStream.write(cipher.doFinal(buffer.getRawBytes()));
            return new Buffer(byteArrayOutputStream.toByteArray());
        }
        catch (NoSuchAlgorithmException | InvalidKeyException | IOException | BadPaddingException
                | IllegalBlockSizeException e) {
            logger.error("Exception {}", ExceptionToString.convertExceptionToStackTrace(e));
            throw new RuntimeException("Exception occurred while performing encryptAuthenticate!");
        }
    }

    public Buffer decryptVerify(Buffer input) throws InvalidMacException, MessageIntegrityException {
        if (cipher == null) {
            initializeCipher();
        }

        int blockSize = cipher.getBlockSize();
        byte[] initVector = input.slice(0, blockSize).getRawBytes();
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
            byteArrayOutputStream.write(cipher.doFinal(input.getRawBytes(), ivSize, input.length() - ivSize));
        } catch (IOException e) {
            logger.error("IOException {}", ExceptionToString.convertExceptionToStackTrace(e));
            throw new RuntimeException("Exception occurred while performing decryptVerify!");
        } catch (IllegalBlockSizeException | BadPaddingException e) {
            logger.error("IllegalBlockSizeException | BadPaddingException {}",
                    ExceptionToString.convertExceptionToStackTrace(e));
            throw new MessageIntegrityException("Integrity error occurred during decryptVerify!");
        }
        Buffer buffer = new Buffer(byteArrayOutputStream.toByteArray());

        MessageDigest messageDigest = null;
        try {
            messageDigest = MessageDigest.getInstance(cryptoSpec.getHashAlgo());
        } catch (NoSuchAlgorithmException e) {
            logger.error("NoSuchAlgorithmException {}", ExceptionToString.convertExceptionToStackTrace(e));
            throw new RuntimeException("Exception occurred while performing decryptVerify!");
        }
        int macLength = messageDigest.getDigestLength();
        Buffer decPayload = buffer.slice(0, buffer.length() - macLength);
        Buffer receivedMAC = buffer.slice(buffer.length() - macLength);
        Buffer computedMAC = new Buffer(messageDigest.digest(decPayload.getRawBytes()));

        if (!receivedMAC.equals(computedMAC)) {
            throw new InvalidMacException("MAC of session key request is NOT correct!");
        }
        return decPayload;
    }

    private Buffer keyVal;
    protected Date expirationTime;
    protected SymmetricKeyCryptoSpec cryptoSpec;
    private Cipher cipher = null;
    private SecretKeySpec cipherKey = null;
    protected static final Logger logger = LoggerFactory.getLogger(SymmetricKey.class);
}
