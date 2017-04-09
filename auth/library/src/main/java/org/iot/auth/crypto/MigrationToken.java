package org.iot.auth.crypto;

import org.iot.auth.io.Buffer;

/**
 * Migration token to be used for entities not using public keys
 * @author Hokeun Kim
 */
public class MigrationToken {
    public MigrationToken(SymmetricKey oldMacKey, Buffer encryptedNewDistributionKey) {
        this.oldMacKey = oldMacKey;
        this.encryptedNewDistributionKey = encryptedNewDistributionKey;
    }
    public Buffer serialize() {
        return encryptedNewDistributionKey;
    }
    private SymmetricKey oldMacKey;
    private Buffer encryptedNewDistributionKey;
}
