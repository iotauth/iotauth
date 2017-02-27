package org.iot.auth.crypto;


/**
 * A class for public key cryptography specifications
 * @author Hokeun Kim
 */
public class PublicKeyCryptoSpec extends CryptoSpec {
    private String signAlgorithm;
    //private String publicCipherAlgorithm = "RSA/ECB/PKCS1PADDING";
    //private int keySize = 256; // 2048 bits
    private String diffieHellman;

    public String getSignAlgorithm() {
        return signAlgorithm;
    }
    public String getDiffieHellman() {
        return diffieHellman;
    }
    //private int diffieHellmanKeySize = 48;  // 384 bits

    public PublicKeyCryptoSpec(String signAlgorithm, String diffieHellman) {
        this.signAlgorithm = signAlgorithm;
        this.diffieHellman = diffieHellman;
    }

    public static PublicKeyCryptoSpec fromSpecString(String cryptoSpecString) {
        String[] stringArray = cryptoSpecString.split(":");
        String jsSignAlgorithm = stringArray[0];

        String signAlgorithm = null;
        if (jsSignAlgorithm.toUpperCase().equals("RSA-SHA256")) {
            signAlgorithm = "SHA256withRSA";
        }
        String diffieHellman = null;
        if (stringArray.length > 1) {
            String jsDiffieHellman = stringArray[1];
            if (jsDiffieHellman.toUpperCase().contains("DH")) {
                diffieHellman = "DH";
            }
        }

        return new PublicKeyCryptoSpec(signAlgorithm, diffieHellman);
    }

    public String toSpecString() {
        String ret = signAlgorithm;
        if (diffieHellman != null) {
            ret += ":DH-secp384r1";
        }
        return ret;
    }
}
