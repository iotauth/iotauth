package org.iot.auth.crypto;

import org.iot.auth.io.Buffer;
import org.iot.auth.io.VariableLengthInt;

/**
 * Migration token to be used for entities not using public keys
 * @author Hokeun Kim
 */
public class MigrationToken {
    public MigrationToken(DistributionKey currentDistributionMacKey, Buffer encryptedNewDistributionKey) {
        this.currentDistributionMacKey = currentDistributionMacKey;
        this.encryptedNewDistributionKey = encryptedNewDistributionKey;
    }
    public MigrationToken(SymmetricKeyCryptoSpec cryptoSpec, Buffer buffer) {
        int curIndex = 0;
        VariableLengthInt varLenInt = buffer.getVariableLengthInt(curIndex);
        curIndex += varLenInt.getRawBytes().length;
        this.encryptedNewDistributionKey = buffer.slice(curIndex, curIndex + varLenInt.getNum());
        curIndex += varLenInt.getNum();
        //this.currentMacKey = new SessionKey(cryptoSpec, buffer.slice(curIndex));
        // TODO: should use fromBuffer of DistributionKey?
        this.currentDistributionMacKey = DistributionKey.fromBuffer(cryptoSpec, buffer.slice(curIndex));
    }
    public Buffer serialize() {
        Buffer buffer = new VariableLengthInt(encryptedNewDistributionKey.length()).serialize();
        buffer.concat(encryptedNewDistributionKey);
        buffer.concat(currentDistributionMacKey.serialize());
        return buffer;
    }
    public DistributionKey getCurrentDistributionMacKey() {
        return currentDistributionMacKey;
    }
    public Buffer getEncryptedNewDistributionKey() {
        return encryptedNewDistributionKey;
    }
    // TODO: this must not be just symmetric key, should be distribution key?
    // TODO: it is because when serializing, experiation data and crypto spec should be included as well?
    private DistributionKey currentDistributionMacKey;
    private Buffer encryptedNewDistributionKey;
}
