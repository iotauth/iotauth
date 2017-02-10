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

package org.iot.auth.db;

import org.iot.auth.crypto.SymmetricKeyCryptoSpec;
import org.iot.auth.db.bean.RegisteredEntityTable;
import org.iot.auth.io.Buffer;
import org.iot.auth.util.DateHelper;

import java.security.PublicKey;

/**
 * A class for a registered entity instance.
 * @author Hokeun Kim
 */
public class RegisteredEntity {
    public RegisteredEntity(RegisteredEntityTable tableElement, DistributionKey distributionKey)
    {
        this.name = tableElement.getName();
        this.group = tableElement.getGroup();
        this.distProtocol = tableElement.getDistProtocol();
        this.usePermanentDistKey = tableElement.getUsePermanentDistKey();
        this.publicKey = tableElement.getPublicKey();
        this.publicKeyCryptoSpec = tableElement.getPublicKeyCryptoSpec();
        this.distKeyValidityPeriod = DateHelper.parseTimePeriod(tableElement.getDistKeyValidityPeriod());
        this.maxSessionKeysPerRequest = tableElement.getMaxSessionKeysPerRequest();
        this.distCryptoSpec = SymmetricKeyCryptoSpec.fromSpecString(tableElement.getDistCryptoSpec());
        this.active = tableElement.isActive();
        this.backupToAuthID = tableElement.getBackupToAuthID();
        this.backupFromAuthID = tableElement.getBackupFromAuthID();
        this.distributionKey = distributionKey; // Decrypted from database
    }
    public String getName() {
        return name;
    }
    public String getGroup() {
        return group;
    }
    public String getDistProtocol() {
        return distProtocol;
    }
    public PublicKey getPublicKey() {
        return publicKey;
    }
    public long getDistKeyValidityPeriod() {
        return distKeyValidityPeriod;
    }
    public DistributionKey getDistributionKey() {
        return distributionKey;
    }
    public int getMaxSessionKeysPerRequest() {
        return maxSessionKeysPerRequest;
    }
    public SymmetricKeyCryptoSpec getDistCryptoSpec() {
        return distCryptoSpec;
    }
    public String getPublicKeyCryptoSpec() {
        return publicKeyCryptoSpec;
    }

    public boolean isActive() {
        return active;
    }

    public int getBackupToAuthID() {
        return backupToAuthID;
    }

    public int getBackupFromAuthID() {
        return backupFromAuthID;
    }

    public String toString() {
        String ret = "Name: " + name + "\tGroup: " + group +
                "\tDistProtocol: " + distProtocol +
                "\tUsePermanentKey: " + usePermanentDistKey +
                "\tDistKeyValidityPeriod: " + distKeyValidityPeriod +
                "\tDistCryptoSpec: " + distCryptoSpec.toString() +
                "\tActive: " + active +
                "\tBackupToAuthID: " + backupToAuthID +
                "\tBackupFromAuthID: " + backupFromAuthID;

        ret += "\tDistKey: ";
        if (distributionKey == null) {
            ret += "NULL";
        }
        else {
            ret += distributionKey.toString();
        }
        if (!usePermanentDistKey) {
            ret += "\tPublicKeyCryptoSpec: " + publicKeyCryptoSpec;
            ret += "\tPublicKey: " + Buffer.toHexString(publicKey.getEncoded());
        }
        return ret;
    }
    public void setDistributionKey(DistributionKey distributionKey) {
        this.distributionKey = distributionKey;
    }

    private String name;
    private String group;
    private String distProtocol;
    private boolean usePermanentDistKey;
    private PublicKey publicKey;
    private String publicKeyCryptoSpec;
    private long distKeyValidityPeriod;
    private int maxSessionKeysPerRequest;
    private SymmetricKeyCryptoSpec distCryptoSpec;
    private boolean active;
    private int backupToAuthID;
    private int backupFromAuthID;
    private DistributionKey distributionKey = null;
}
