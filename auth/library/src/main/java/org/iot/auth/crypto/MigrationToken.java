package org.iot.auth.crypto;

import org.iot.auth.io.Buffer;

/**
 * Migration token to be used for entities not using public keys
 * @author Hokeun Kim
 */
public class MigrationToken {
    public MigrationToken(SymmetricKey currentMacKey, Buffer encryptedNewDistributionKey) {
        this.currentMacKey = currentMacKey;
        this.encryptedNewDistributionKey = encryptedNewDistributionKey;
    }
    public Buffer serialize() {
        Buffer buffer = currentMacKey.getSerializedKeyVal();
        buffer.concat(encryptedNewDistributionKey);
        return buffer;
    }
    private SymmetricKey currentMacKey;
    private Buffer encryptedNewDistributionKey;
}
