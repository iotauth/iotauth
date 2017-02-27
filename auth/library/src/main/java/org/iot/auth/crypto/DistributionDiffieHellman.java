package org.iot.auth.crypto;

import org.bouncycastle.asn1.*;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.ECPointUtil;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.jce.spec.ECNamedCurveSpec;
import org.iot.auth.io.Buffer;
import org.iot.auth.io.VariableLengthInt;
import sun.security.ec.ECPublicKeyImpl;

import javax.crypto.KeyAgreement;
import java.io.IOException;
import java.security.*;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.util.Date;

/**
 * Helper class to use an ephemeral Diffie-Hellman key exchange for distribution key
 * @author Hokeun Kim
 */
public class DistributionDiffieHellman {
    /**
     * Constructs an object for distribution key exchange
     * @param distributionCryptoSpec Crypto spec for distribution key to be derived.
     * @param keyFactoryAlgorithm Algorithm to be used for constructors of KeyFactory and KeyPairGenerator,
     *                            Allowed algorithms: DiffieHellman (DH), DSA, RSA, EC
     * @param keyAgreementAlgorithm Algorithm to be used for constructor of KeyAgreement,
     *                              Allowed algorithms: DiffieHellman, ECDH, ECMQV
     * @param keySize The key size; an algorithm-specific metric, such as modulus length, specified in number of bits.
     * @param relativeValidityPeriod The relative validity period for the distribution key to be derived.
     */
    public DistributionDiffieHellman(SymmetricKeyCryptoSpec distributionCryptoSpec, String keyFactoryAlgorithm,
                                     String keyAgreementAlgorithm, int keySize, long relativeValidityPeriod)
            throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException {
        this.distributionCryptoSpec = distributionCryptoSpec;
        this.keyAgreementAlgorithm = keyAgreementAlgorithm;
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(keyFactoryAlgorithm);
        kpg.initialize(keySize);
        this.keyPair = kpg.generateKeyPair();
        this.expirationTime = new Date(new Date().getTime() + relativeValidityPeriod);
    }

    public Buffer getSerializedBuffer() throws InvalidKeyException, IOException {
        Buffer buf = new Buffer(DistributionKey.DIST_KEY_EXPIRATION_TIME_SIZE);
        int curIndex = 0;
        buf.putNumber(getRawExpirationTime(), curIndex, DistributionKey.DIST_KEY_EXPIRATION_TIME_SIZE);
        curIndex += DistributionKey.DIST_KEY_EXPIRATION_TIME_SIZE;
        PublicKey authPublicParameter = keyPair.getPublic();
        String authPublicParameterFormat = authPublicParameter.getFormat();
        if (authPublicParameterFormat.equals("X.509")) {
            ECPublicKeyImpl ecPublicKey = (ECPublicKeyImpl) authPublicParameter;
            byte[] shit = ecPublicKey.getEncodedInternal();
            ASN1InputStream ans1InputStream = new ASN1InputStream(authPublicParameter.getEncoded());
            ASN1Primitive primitive = ans1InputStream.readObject();
            ans1InputStream.close();
            ASN1Sequence sequence = ASN1Sequence.getInstance(primitive);
            DERBitString bitString = DERBitString.getInstance(sequence.getObjectAt(1));
            byte[] authPublicParameterBytes = bitString.getOctets();

            VariableLengthInt publicParameterLength = new VariableLengthInt(authPublicParameterBytes.length);
            Buffer publicParameterBuffer = new Buffer(publicParameterLength.getRawBytes());
            publicParameterBuffer.concat(new Buffer(authPublicParameterBytes));
            buf.concat(publicParameterBuffer);
            return buf;
        }
        else {
            throw new RuntimeException("Unrecognized format for Diffie-Hellman parameter!");
        }
    }

    private PublicKey getPublicKeyFromBytes(byte[] pubKey) throws NoSuchAlgorithmException, InvalidKeySpecException {
        ECNamedCurveParameterSpec spec = ECNamedCurveTable.getParameterSpec("secp384r1");
        KeyFactory keyFactory = KeyFactory.getInstance("ECDH", new BouncyCastleProvider());

        ECNamedCurveSpec params = new ECNamedCurveSpec("secp384r1", spec.getCurve(), spec.getG(), spec.getN());
        ECPoint point =  ECPointUtil.decodePoint(params.getCurve(), pubKey);
        ECPublicKeySpec pubKeySpec = new ECPublicKeySpec(point, params);
        ECPublicKey ecPublicKey = (ECPublicKey) keyFactory.generatePublic(pubKeySpec);
        return ecPublicKey;
    }

    public DistributionKey deriveDistributionKey(Buffer entityPublicParameterBuffer)
            throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException {
        PublicKey entityPublicParameter = getPublicKeyFromBytes(entityPublicParameterBuffer.getRawBytes());
        KeyAgreement keyAgreement = KeyAgreement.getInstance(keyAgreementAlgorithm);

        keyAgreement.init(keyPair.getPrivate());
        keyAgreement.doPhase(entityPublicParameter, true);
        Buffer sharedSecret = new Buffer(keyAgreement.generateSecret());
        Buffer cipherKeyVal = sharedSecret.slice(0, distributionCryptoSpec.getCipherKeySize());
        Buffer macKeyVal = sharedSecret.slice(distributionCryptoSpec.getCipherKeySize(),
                distributionCryptoSpec.getCipherKeySize() + distributionCryptoSpec.getMacKeySize());
        Buffer serializedKeyVal = SymmetricKey.getSerializedKeyVal(cipherKeyVal, macKeyVal);
        return new DistributionKey(distributionCryptoSpec, getRawExpirationTime(), serializedKeyVal);
    }

    // TODO: Common with symmetric key can be tied together with a common parent class?
    public long getRawExpirationTime() {
        return expirationTime.getTime();
    }
    private Date expirationTime;
    private KeyPair keyPair;
    private String keyAgreementAlgorithm;
    private SymmetricKeyCryptoSpec distributionCryptoSpec;
}
