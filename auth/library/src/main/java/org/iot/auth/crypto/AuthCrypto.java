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

import com.google.common.net.InetAddresses;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x500.style.IETFUtils;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v1CertificateBuilder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.iot.auth.io.Buffer;
import org.iot.auth.io.FileIOHelper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.*;

import java.math.BigInteger;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Calendar;
import java.util.Date;
import java.util.Enumeration;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * A class for performing cryptography operations for Auth.
 * @author Hokeun Kim
 */
public class AuthCrypto {
    private static final Logger logger = LoggerFactory.getLogger(AuthCrypto.class);

    /**
     * Constructor for AuthCrypto object, where Auth's credentials and default cryptography algorithms are initialized.
     * @param entityKeyStorePath Path to the key store file, that includes Auth's asymmetric key pair for communicating
     *                           with registered entities.
     * @param entityKeyStorePassword Password to the Auth's key store for entities.
     * @throws IOException If file IO fails.
     * @throws KeyStoreException If key store loading fails.
     * @throws CertificateException If a certificate related problem occurs.
     * @throws NoSuchAlgorithmException If the algorithm specified in the key store is invalid.
     * @throws UnrecoverableEntryException If a key entry in the key store is invalid.
     * @throws IllegalArgumentException If conditions for the key store are wrong.
     */
    public AuthCrypto(String entityKeyStorePath, String entityKeyStorePassword) throws IOException, KeyStoreException,
            CertificateException, NoSuchAlgorithmException, UnrecoverableEntryException, IllegalArgumentException
    {
        KeyStore authKeyStoreForEntities = loadKeyStore(entityKeyStorePath, entityKeyStorePassword);

        if (authKeyStoreForEntities.size() != 1) {
            throw new IllegalArgumentException("Auth key store must contain one key entry.");
        }
        Enumeration<String> aliases = authKeyStoreForEntities.aliases();

        KeyStore.ProtectionParameter protParam =
                new KeyStore.PasswordProtection(entityKeyStorePassword.toCharArray());
        while (aliases.hasMoreElements()) {
            String alias = aliases.nextElement();
            KeyStore.PrivateKeyEntry pkEntry = (KeyStore.PrivateKeyEntry) authKeyStoreForEntities.getEntry(alias, protParam);
            logger.debug("Alias: {}, ", alias);
            logger.debug("Cert: {}, ", pkEntry.getCertificate());
            logger.debug("Key: {}", pkEntry.getPrivateKey());
            this.authCertificateForEntities = convert(pkEntry.getCertificate());
            this.authPrivateKeyForEntities = pkEntry.getPrivateKey();
        }
        this.authSignAlgorithm = "SHA256withRSA";
        this.authPublicCipherAlgorithm = "RSA/ECB/PKCS1PADDING";
    }

    /**
     * Check if a signature is valid for the given data and public key.
     * @param data Data used to generate signature.
     * @param signature A digital signature to be verified.
     * @param publicKey A public key to be used for signature verification.
     * @return Whether the signature is verified.
     * @throws NoSuchAlgorithmException If the algorithm specified in the key store is invalid.
     * @throws InvalidKeyException If the key is not valid.
     * @throws SignatureException If the signature is not valid.
     */
    public boolean verifySignedData(Buffer data, Buffer signature, PublicKey publicKey)
            throws NoSuchAlgorithmException, InvalidKeyException, SignatureException
    {
        Signature verifier;
        verifier = Signature.getInstance(authSignAlgorithm);
        verifier.initVerify(publicKey);
        verifier.update(data.getRawBytes());
        return verifier.verify(signature.getRawBytes());
    }

    public Buffer signWithPrivateKey(Buffer input)
            throws IllegalArgumentException {
        try {
            Signature signer = Signature.getInstance(authSignAlgorithm);
            signer.initSign(authPrivateKeyForEntities); // cf) initVerify
            signer.update(input.getRawBytes());
            return new Buffer(signer.sign());
        }
        catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
            throw new IllegalArgumentException("Problem signing with private key\n" + e.getMessage());
        }
    }

    public Buffer authPrivateDecrypt(Buffer input)
            throws IllegalArgumentException {
        return performAsymmetricCrypto(Cipher.DECRYPT_MODE, input, authPrivateKeyForEntities, authPublicCipherAlgorithm);
    }

    public static Buffer privateDecrypt(Buffer input, PrivateKey privateKey, String publicCipherAlgorithm)
            throws IllegalArgumentException {
        return performAsymmetricCrypto(Cipher.DECRYPT_MODE, input, privateKey, publicCipherAlgorithm);
    }

    public Buffer authPublicEncrypt(Buffer input, PublicKey publicKey)
            throws IllegalArgumentException {
        return performAsymmetricCrypto(Cipher.ENCRYPT_MODE, input, publicKey, authPublicCipherAlgorithm);
    }

    public static Buffer publicEncrypt(Buffer input, PublicKey publicKey, String publicCipherAlgorithm)
            throws IllegalArgumentException{
        return performAsymmetricCrypto(Cipher.ENCRYPT_MODE, input, publicKey, publicCipherAlgorithm);
    }

    /**
     * Load a key store from the specified file path, using the given password.
     * @param filePath Path of the key store file.
     * @param password Password for the key store.
     * @return Key store object loaded from the key store file.
     * @throws IOException When file IO fails.
     * @throws KeyStoreException When loading key store fails.
     * @throws CertificateException When there is an error in certificate.
     * @throws NoSuchAlgorithmException When the algorithm is not supported.
     */
    public static KeyStore loadKeyStore(String filePath, String password) throws IOException, KeyStoreException,
            CertificateException, NoSuchAlgorithmException {
        File keyStoreFile = new File(filePath);

        FileInputStream keyStoreFIS = new FileInputStream(keyStoreFile);

        // check if it's pfx
        KeyStore keyStore;

        if (keyStoreFile.getName().endsWith(".pfx")) {
            keyStore = KeyStore.getInstance("pkcs12");
        }
        else {
            keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
        }

        keyStore.load(keyStoreFIS, password.toCharArray());
        return keyStore;
    }

    public static X509Certificate loadCertificateFromBytes(byte[] bytes) {
        try {
            CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
            InputStream in = new ByteArrayInputStream(bytes);
            return (X509Certificate)certFactory.generateCertificate(in);
        } catch (CertificateException e) {
            throw new IllegalArgumentException("Problem loading certificate from bytes" + "\n" + e.getMessage());
        }
    }

    /**
     * Load an X.509 certificate from file.
     * @param filePath Path to the certificate file.
     * @return Loaded X.509 certificate.
     */
    public static X509Certificate loadCertificateFromFile(String filePath) {
        try {
            CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
            FileInputStream inStream = new FileInputStream(filePath);
            return (X509Certificate) certFactory.generateCertificate(inStream);
        } catch (CertificateException | FileNotFoundException e) {
            throw new IllegalArgumentException("Problem loading certificate " + filePath + "\n" + e.getMessage());
        }
    }

    public static PublicKey loadPublicKeyFromBytes(byte[] bytes)  {
        X509EncodedKeySpec spec = new X509EncodedKeySpec(bytes);
        try {
            KeyFactory kf = KeyFactory.getInstance("RSA");
            return kf.generatePublic(spec);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new IllegalArgumentException("Problem loading public key from bytes" + "\n" + e.getMessage());
        }
    }

    public static PublicKey loadPublicKeyFromFile(String filePath) {
        if (filePath.endsWith(".pem")) {
            return loadCertificateFromFile(filePath).getPublicKey();
        }
        else if (filePath.endsWith(".der")) {
            try {
                byte[] keyBytes = FileIOHelper.readFully(filePath);
                return loadPublicKeyFromBytes(keyBytes);
            }
            catch (IOException e) {
                throw new IllegalArgumentException("Problem loading public key " + filePath + "\n" + e.getMessage());
            }
        }
        else {
            throw new RuntimeException("Unrecognized file format for public key :" + filePath);
        }
    }
    // Converts to java.security
    public static X509Certificate convert(Certificate cert) {
        try {
            byte[] encoded = cert.getEncoded();
            ByteArrayInputStream bis = new ByteArrayInputStream(encoded);
            java.security.cert.CertificateFactory cf
                    = java.security.cert.CertificateFactory.getInstance("X.509");
            return (java.security.cert.X509Certificate)cf.generateCertificate(bis);
        } catch (java.security.cert.CertificateEncodingException e) {
        } catch (java.security.cert.CertificateException e) {
        }
        return null;
    }
    public static Buffer getRandomBytes(int size) {
        SecureRandom random = new SecureRandom();
        byte seed[] = random.generateSeed(size);
        byte[] randomBytes = new byte[size];
        random.setSeed(seed);
        random.nextBytes(randomBytes);
        return new Buffer(randomBytes);
    }

    public X509Certificate issueCertificate(X509Certificate certificate,
                                            int issuerAuthID, int subjectAuthID, String subjectAuthCN) throws CertIOException {
        try {
            Principal issuerPrincipal = authCertificateForEntities.getSubjectDN();
            String strIssuerDN = issuerPrincipal.getName();
            String issuerOU = "Auth" + issuerAuthID;
            String subjectOU = "Auth" + subjectAuthID;

            X500Name issuerDNFromCertificate = new X500Name(strIssuerDN);
            RDN rdnIssuerCN = issuerDNFromCertificate.getRDNs(BCStyle.CN)[0];
            String strIssuerCN = IETFUtils.valueToString(rdnIssuerCN.getFirst().getValue());
            //authCertificateForEntities.getSubjectDN()
            X500Name issuerDN = new X500Name("C=US, ST=CA, L=Berkeley, O=EECS, OU=" + issuerOU + ", CN=" + strIssuerCN);
            X500Name subjectDN = new X500Name("C=US, ST=CA, L=Berkeley, O=EECS, OU=" + subjectOU + ", CN=" + subjectAuthCN);
            BigInteger serialNumber = BigInteger.valueOf(System.currentTimeMillis());
            // 100 seconds before now
            Date validityStartDate = new Date(System.currentTimeMillis() - 100 * 1000);
            Calendar calendar = Calendar.getInstance();
            // 24 hours after now
            calendar.add(Calendar.HOUR, 24);
            //calendar.add(Calendar.YEAR, 24);
            Date validityEndDate = new Date(calendar.getTime().getTime());
            SubjectPublicKeyInfo subPubKeyInfo = SubjectPublicKeyInfo.getInstance(certificate.getPublicKey().getEncoded());

            X509v3CertificateBuilder builder = new X509v3CertificateBuilder(issuerDN, serialNumber, validityStartDate,
                    validityEndDate, subjectDN, subPubKeyInfo);
            if (InetAddresses.isInetAddress(subjectAuthCN)) {
                builder.addExtension(Extension.subjectAlternativeName,false,
                        new GeneralNames(new GeneralName(GeneralName.iPAddress, subjectAuthCN)));
            }
            //X509v1CertificateBuilder builder = new X509v1CertificateBuilder(issuerDN, serialNumber, validityStartDate,
            //        validityEndDate, subjectDN, subPubKeyInfo);
            JcaContentSignerBuilder signerBuilder = new JcaContentSignerBuilder(authSignAlgorithm);


            X509CertificateHolder holder = builder.build(signerBuilder.build(authPrivateKeyForEntities));

            return new JcaX509CertificateConverter().getCertificate(holder);

        } catch (CertificateException e) {
            throw new IllegalArgumentException("Problem dealing with a certificate in issuing" + "\n" + e.getMessage());
        } catch (OperatorCreationException e) {
            throw new IllegalArgumentException("Problem dealing with a certificate in issuing" + "\n" + e.getMessage());
        }
    }

//    public static Buffer generateSymmetricKey(int size) {
//        KeyGenerator keyGenerator;
//        try {
//            // TODO: support more cryptos
//            keyGenerator = KeyGenerator.getInstance("AES");
//        } catch (NoSuchAlgorithmException e) {
//            throw new RuntimeException("Failed to generate key! \n" + e.getMessage());
//        }
//        // bytes to bits
//        keyGenerator.init(size * 8);
//        SecretKey key = keyGenerator.generateKey();
//        return new Buffer(key.getEncoded());
//    }

//    public static Buffer symmetricEncryptAuthenticate(Buffer input, Buffer key, SymmetricKeyCryptoSpec cryptoSpec) {
//        Buffer buffer = new Buffer(input);
//        buffer.concat(AuthCrypto.mac(buffer, cryptoSpec.getMacAlgorithm()));
//        return AuthCrypto.symmetricEncrypt(buffer, key, cryptoSpec.getCipherAlgorithm());
//    }

//    private static Buffer symmetricEncrypt(Buffer input, Buffer key, String cipherAlgorithm) {
//        Cipher cipher = getCipher(Cipher.ENCRYPT_MODE, cipherAlgorithm, key, null);
//
//        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
//        try {
//            // write initialization vector first
//            byte[] initVector = cipher.getIV();
//            if (initVector != null) {
//                byteArrayOutputStream.write(initVector);
//            }
//            byteArrayOutputStream.write(cipher.doFinal(input.getRawBytes()));
//        } catch (IllegalBlockSizeException | BadPaddingException | IOException e) {
//            throw new RuntimeException("Problem processing " + input.toHexString() + "\n" + e.getMessage());
//        }
//
//        return new Buffer(byteArrayOutputStream.toByteArray());
//    }

//    public static Buffer symmetricDecryptAuthenticate(Buffer cipherText, Buffer key, SymmetricKeyCryptoSpec cryptoSpec) {
//        Buffer decPayloadAndMAC = AuthCrypto.symmetricDecrypt(cipherText, key, cryptoSpec.getCipherAlgorithm());
//
//        // Check MAC (message authentication code) value within dec payload
//        int hashLength = AuthCrypto.getHashLength(cryptoSpec.getMacAlgorithm());
//        Buffer decPayload = decPayloadAndMAC.slice(0, decPayloadAndMAC.length() - hashLength);
//        Buffer receivedMAC = decPayloadAndMAC.slice(decPayloadAndMAC.length() - hashLength);
//        Buffer computedMAC = AuthCrypto.mac(decPayload, cryptoSpec.getMacAlgorithm());
//
//        if (!receivedMAC.equals(computedMAC)) {
//            throw new RuntimeException("MAC of session key request is NOT correct!");
//        }
//        else {
//            logger.debug("MAC is correct!");
//        }
//        return decPayload;
//    }

//    private static Buffer symmetricDecrypt(Buffer cipherText, Buffer key, String cipherAlgorithm) {
//        Cipher cipher = getCipher(Cipher.DECRYPT_MODE, cipherAlgorithm, key, cipherText);
//
//        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
//
//        int ivSize = 0;
//        if (cipher.getIV() != null) {
//            ivSize = cipher.getIV().length;
//        }
//        try {
//            byteArrayOutputStream.write(cipher.doFinal(cipherText.getRawBytes(), ivSize, cipherText.length() - ivSize));
//        } catch (IllegalBlockSizeException | BadPaddingException | IOException e) {
//            throw new RuntimeException("Problem processing " + cipherText.toHexString() + "\n" + e.getMessage());
//        }
//        return new Buffer(byteArrayOutputStream.toByteArray());
//    }

//    public static int getHashLength(String hashAlgorithm) throws RuntimeException {
//        try {
//            MessageDigest messageDigest = MessageDigest.getInstance(hashAlgorithm);
//            return messageDigest.getDigestLength();
//        } catch (NoSuchAlgorithmException e) {
//            throw new RuntimeException("Failed to initialize messageDigest.\n" + e.getMessage());
//        }
//    }

//    public static Buffer mac(Buffer input, String hashAlgorithm) throws RuntimeException {
//        try {
//            MessageDigest messageDigest = MessageDigest.getInstance(hashAlgorithm);
//            return new Buffer(messageDigest.digest(input.getRawBytes()));
//        } catch (NoSuchAlgorithmException e) {
//            throw new RuntimeException("Failed to initialize messageDigest.\n" + e.getMessage());
//        }
//    }

    private PrivateKey loadPrivateKey(String filePath) {
        if (!filePath.endsWith(".der")) {
            throw new IllegalArgumentException("Private key should be in DER format. " + filePath);
        }
        PKCS8EncodedKeySpec keySpec = null;
        try {
            keySpec = new PKCS8EncodedKeySpec(readBinaryFile(filePath));
        } catch (IOException e) {
            e.printStackTrace();
        }
        KeyFactory keyFactory;
        try {
            keyFactory = KeyFactory.getInstance("RSA");
            return keyFactory.generatePrivate(keySpec);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new IllegalArgumentException("Problem loading private key " + filePath + "\n" + e.getMessage());
        }
    }

    /**
     * Helper method for loading binary data from a file.
     * @param filePath Path to the file to be loaded
     * @return Byte array, the binary data of the file
     * @throws IOException If file IO fails.
     */
    public static byte[] readBinaryFile(String filePath) throws IOException {
        File file = new File(filePath);
        DataInputStream dataInStream = new DataInputStream(new FileInputStream(filePath));
        byte[] bytes = new byte[(int) file.length()];
        dataInStream.readFully(bytes);
        return bytes;
    }

    private static Buffer performAsymmetricCrypto(int operationMode, Buffer input, Key key, String cipherAlgorithm)
            throws IllegalArgumentException {
        Cipher cipher;
        try {
            cipher = Cipher.getInstance(cipherAlgorithm);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            throw new IllegalArgumentException("Problem getting instance " + input + "\n" + e.getMessage());
        }

        try {
            cipher.init(operationMode, key);
        } catch (InvalidKeyException e) {
            throw new IllegalArgumentException("Problem with key " + input + "\n" + e.getMessage());
        }

        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();

        try {
            byteArrayOutputStream.write(cipher.doFinal(input.getRawBytes()));
        } catch (IllegalBlockSizeException | BadPaddingException | IOException e) {
            throw new IllegalArgumentException("Problem processing crypto " + input + "\n" + e.getMessage());
        }
        return new Buffer(byteArrayOutputStream.toByteArray());
    }

    /**
     * Initialize and get a cipher object for the given symmetric cryptography, mode, key, and optionally, IV
     * (initialization vector)
     * @param operationMode Encrypt or decrypt (Cipher.ENCRYPT_MODE or Cipher.DECRYPT_MODE)
     * @param cipherAlgo Specified cipher algorithm.
     * @param cipherKey Cryptographic key to be used for the cipher.
     * @param cipherText To extract IV (initialization vector) from the cipher text. Only used when the mode is decrypt,
     *                   and cipher uses IV , otherwise set to null.
     * @return Initialized cipher object
     * @throws IllegalArgumentException If invalid cipher algorithm or IV (prefix of cipherText) is given.
     */
    private static Cipher getCipher(int operationMode, String cipherAlgo, Buffer cipherKey, Buffer cipherText)
            throws IllegalArgumentException {
        String[] tokens = cipherAlgo.split("-");
        if (tokens.length < 1) {
            throw new IllegalArgumentException("Invalid cipher algorithm: " + cipherAlgo);
        }

        Cipher cipher;
        try {
            cipher = Cipher.getInstance(cipherAlgo);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            throw new IllegalArgumentException("Invalid cipher algorithm: " + cipherAlgo + "\n" + e.getMessage());
        }

        String[] cipherAlgoTokens = cipher.getAlgorithm().split("/");
        SecretKeySpec secretKeySpec = new SecretKeySpec(cipherKey.getRawBytes(), cipherAlgoTokens[0]);
        logger.debug("cipher.getAlgorithm(): {}", cipher.getAlgorithm());

        IvParameterSpec ivSpec = null;
        if (operationMode == Cipher.DECRYPT_MODE) {
            int blockSize = cipher.getBlockSize();
            byte[] initVector = cipherText.slice(0, blockSize).getRawBytes();
            ivSpec = new IvParameterSpec(initVector);
        }

        try {
            if (ivSpec != null) {
                cipher.init(operationMode, secretKeySpec, ivSpec);
            } else {
                cipher.init(operationMode, secretKeySpec);
            }
        } catch (InvalidKeyException | InvalidAlgorithmParameterException e) {
            throw new IllegalArgumentException("Invalid cipher algorithm: " + cipherAlgo + "\n" + e.getMessage());
        }

        return cipher;
    }

    private X509Certificate authCertificateForEntities;
    private PrivateKey authPrivateKeyForEntities;
    private String authSignAlgorithm;
    private String authPublicCipherAlgorithm;
}
