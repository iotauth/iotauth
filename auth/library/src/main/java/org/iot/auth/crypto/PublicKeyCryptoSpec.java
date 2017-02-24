package org.iot.auth.crypto;


/**
 * A class for public key cryptography specifications
 * @author Hokeun Kim
 */
public class PublicKeyCryptoSpec extends CryptoSpec {
    private String signAlgorithm = "SHA256withRSA";
    private String publicCipherAlgorithm = "RSA/ECB/PKCS1PADDING";
    private String diffieHellman = "EC";
}
