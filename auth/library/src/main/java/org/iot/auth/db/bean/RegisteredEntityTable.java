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

package org.iot.auth.db.bean;

import org.iot.auth.crypto.AuthCrypto;
import org.json.simple.JSONObject;

import java.security.PublicKey;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Arrays;

/**
 * @author Salomon Lee, Hokeun Kim
 */
public class RegisteredEntityTable {
    public static final String T_REGISTERED_ENTITY = "registered_entity";

    public enum c {
        Name,
        Group,
        DistProtocol,
        UsePermanentDistKey,
        DistKeyValidityPeriod,
        PublicKeyValue,
        PublicKeyFile,
        PublicKeyCryptoSpec,
        DistCryptoSpec,
        DistKeyExpirationTime,
        DistKeyValue,
        MaxSessionKeysPerRequest,
        Active,
        BackupToAuthID,
        BackupFromAuthID
    }
    private String name;
    private String group;
    private String distProtocol;
    private boolean usePermanentDistKey;
    private PublicKey publicKey = null;
    private String distKeyValidityPeriod;
    private String publicKeyCryptoSpec;
    private String distCryptoSpec;
    private long distKeyExpirationTime = -1;
    private byte[] distKeyVal = null;
    private int maxSessionKeysPerRequest;
    private boolean active;
    private int backupToAuthID = -1;
    private int backupFromAuthID = -1;

    public String getName() {
        return name;
    }
    public void setName(String name) {
        this.name = name;
    }

    public String getGroup() {
        return group;
    }
    public void setGroup(String group) {
        this.group = group;
    }

    public String getDistProtocol() {
        return distProtocol;
    }
    public void setDistProtocol(String distProtocol) {
        this.distProtocol = distProtocol;
    }


    public boolean getUsePermanentDistKey() {
        return usePermanentDistKey;
    }
    public void setUsePermanentDistKey(boolean usePermanentDistKey) {
        this.usePermanentDistKey = usePermanentDistKey;
    }

    public PublicKey getPublicKey() {
        return publicKey;
    }
    public void setPublicKey(PublicKey publicKey) {
        this.publicKey = publicKey;
    }

    public String getDistKeyValidityPeriod() {
        return distKeyValidityPeriod;
    }
    public void setDistKeyValidityPeriod(String distKeyValidityPeriod) {
        this.distKeyValidityPeriod = distKeyValidityPeriod;
    }

    public String getPublicKeyCryptoSpec() {
        return publicKeyCryptoSpec;
    }

    public void setPublicKeyCryptoSpec(String publicKeyCryptoSpec) {
        this.publicKeyCryptoSpec = publicKeyCryptoSpec;
    }

    public String getDistCryptoSpec() {
        return distCryptoSpec;
    }
    public void setDistCryptoSpec(String distCipherAlgo) {
        this.distCryptoSpec = distCipherAlgo;
    }

    public long getDistKeyExpirationTime() {
        return distKeyExpirationTime;
    }
    public void setDistKeyExpirationTime(long distKeyExpirationTime) {
        this.distKeyExpirationTime = distKeyExpirationTime;
    }

    public byte[] getDistKeyVal() {
        return distKeyVal;
    }
    public void setDistKeyVal(byte[] distKeyVal) {
        this.distKeyVal = Arrays.copyOf(distKeyVal, distKeyVal.length);
    }

    public int getMaxSessionKeysPerRequest() {
        return maxSessionKeysPerRequest;
    }
    public void setMaxSessionKeysPerRequest(int maxSessionKeysPerRequest) {
        this.maxSessionKeysPerRequest = maxSessionKeysPerRequest;
    }

    public boolean isActive() {
        return active;
    }

    public void setActive(boolean active) {
        this.active = active;
    }

    public int getBackupToAuthID() {
        return backupToAuthID;
    }

    public void setBackupToAuthID(int backupToAuthID) {
        this.backupToAuthID = backupToAuthID;
    }

    public int getBackupFromAuthID() {
        return backupFromAuthID;
    }

    public void setBackupFromAuthID(int backupFromAuthID) {
        this.backupFromAuthID = backupFromAuthID;
    }

    public String toString() {
        return toJSONObject().toJSONString();
    }

    @SuppressWarnings("unchecked")
    public JSONObject toJSONObject(){
        JSONObject object = new JSONObject();
        object.put(c.Name.name(), getName());
        object.put(c.Group.name(), getGroup());
        object.put(c.DistProtocol.name(), getDistProtocol());
        object.put(c.UsePermanentDistKey.name(), getUsePermanentDistKey());
        object.put(c.PublicKeyCryptoSpec.name(), getPublicKeyCryptoSpec());
        //object.put(c.PublicKeyValue.name(), getPublicKeyFile().toString());
        object.put(c.PublicKeyValue.name(), getPublicKey().getEncoded());
        object.put(c.MaxSessionKeysPerRequest.name(), getMaxSessionKeysPerRequest());
        object.put(c.Active.name(), isActive());
        object.put(c.BackupToAuthID.name(), getBackupToAuthID());
        object.put(c.BackupFromAuthID.name(), getBackupFromAuthID());
        return object;
    }

    public static RegisteredEntityTable createRecord(ResultSet resultSet) throws SQLException {
        RegisteredEntityTable entity = new RegisteredEntityTable();
        entity.setName(resultSet.getString(c.Name.name()));
        entity.setGroup(resultSet.getString(c.Group.name()));
        entity.setDistProtocol(resultSet.getString(c.DistProtocol.name()));
        entity.setUsePermanentDistKey(resultSet.getBoolean(c.UsePermanentDistKey.name()));
        entity.setPublicKeyCryptoSpec(resultSet.getString(c.PublicKeyCryptoSpec.name()));
        entity.setDistKeyValidityPeriod(resultSet.getString(c.DistKeyValidityPeriod.name()));
        if (!entity.getUsePermanentDistKey()) {
            entity.setPublicKey(AuthCrypto.loadPublicKeyFromBytes(resultSet.getBytes(c.PublicKeyValue.name())));
        }
        entity.setDistCryptoSpec(resultSet.getString(c.DistCryptoSpec.name()));
        byte[] distKeyVal = resultSet.getBytes(c.DistKeyValue.name());
        if (distKeyVal != null) {
            entity.setDistKeyVal(distKeyVal);
            entity.setDistKeyExpirationTime(resultSet.getLong(c.DistKeyExpirationTime.name()));
        }
        entity.setMaxSessionKeysPerRequest(resultSet.getInt(c.MaxSessionKeysPerRequest.name()));
        entity.setActive(resultSet.getBoolean(c.Active.name()));
        entity.setBackupToAuthID(resultSet.getInt(c.BackupToAuthID.name()));
        entity.setBackupFromAuthID(resultSet.getInt(c.BackupFromAuthID.name()));
        return entity;
    }
}
