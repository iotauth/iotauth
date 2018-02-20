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
        BackupToAuthIDs,
        BackupFromAuthID,
        MigrationToken
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
    private String backupToAuthIDs = "";
    private int backupFromAuthID = -1;
    private byte[] migrationTokenVal = null;

    public String getName() {
        return name;
    }
    public RegisteredEntityTable setName(String name) {
        this.name = name;
        return this;
    }

    public String getGroup() {
        return group;
    }
    public RegisteredEntityTable setGroup(String group) {
        this.group = group;
        return this;
    }

    public String getDistProtocol() {
        return distProtocol;
    }
    public RegisteredEntityTable setDistProtocol(String distProtocol) {
        this.distProtocol = distProtocol;
        return this;
    }


    public boolean getUsePermanentDistKey() {
        return usePermanentDistKey;
    }
    public RegisteredEntityTable setUsePermanentDistKey(boolean usePermanentDistKey) {
        this.usePermanentDistKey = usePermanentDistKey;
        return this;
    }

    public PublicKey getPublicKey() {
        return publicKey;
    }
    public RegisteredEntityTable setPublicKey(PublicKey publicKey) {
        this.publicKey = publicKey;
        return this;
    }

    public String getDistKeyValidityPeriod() {
        return distKeyValidityPeriod;
    }
    public RegisteredEntityTable setDistKeyValidityPeriod(String distKeyValidityPeriod) {
        this.distKeyValidityPeriod = distKeyValidityPeriod;
        return this;
    }

    public String getPublicKeyCryptoSpec() {
        return publicKeyCryptoSpec;
    }

    public RegisteredEntityTable setPublicKeyCryptoSpec(String publicKeyCryptoSpec) {
        this.publicKeyCryptoSpec = publicKeyCryptoSpec;
        return this;
    }

    public String getDistCryptoSpec() {
        return distCryptoSpec;
    }
    public RegisteredEntityTable setDistCryptoSpec(String distCipherAlgo) {
        this.distCryptoSpec = distCipherAlgo;
        return this;
    }

    public long getDistKeyExpirationTime() {
        return distKeyExpirationTime;
    }
    public RegisteredEntityTable setDistKeyExpirationTime(long distKeyExpirationTime) {
        this.distKeyExpirationTime = distKeyExpirationTime;
        return this;
    }

    public byte[] getDistKeyVal() {
        return distKeyVal;
    }
    public RegisteredEntityTable setDistKeyVal(byte[] distKeyVal) {
        this.distKeyVal = Arrays.copyOf(distKeyVal, distKeyVal.length);
        return this;
    }

    public int getMaxSessionKeysPerRequest() {
        return maxSessionKeysPerRequest;
    }
    public RegisteredEntityTable setMaxSessionKeysPerRequest(int maxSessionKeysPerRequest) {
        this.maxSessionKeysPerRequest = maxSessionKeysPerRequest;
        return this;
    }

    public boolean isActive() {
        return active;
    }

    public RegisteredEntityTable setActive(boolean active) {
        this.active = active;
        return this;
    }

    public String getBackupToAuthIDs() {
        return backupToAuthIDs;
    }

    public RegisteredEntityTable setBackupToAuthIDs(String backupToAuthIDs) {
        this.backupToAuthIDs = backupToAuthIDs;
        return this;
    }

    public int getBackupFromAuthID() {
        return backupFromAuthID;
    }

    public RegisteredEntityTable setBackupFromAuthID(int backupFromAuthID) {
        this.backupFromAuthID = backupFromAuthID;
        return this;
    }

    public byte[] getMigrationTokenVal() {
        return migrationTokenVal;
    }

    public RegisteredEntityTable setMigrationTokenVal(byte[] migrationTokenVal) {
        this.migrationTokenVal = migrationTokenVal;
        return this;
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
        object.put(c.BackupToAuthIDs.name(), getBackupToAuthIDs());
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
        entity.setBackupToAuthIDs(resultSet.getString(c.BackupToAuthIDs.name()));
        entity.setBackupFromAuthID(resultSet.getInt(c.BackupFromAuthID.name()));
        entity.setMigrationTokenVal(resultSet.getBytes(c.MigrationToken.name()));
        return entity;
    }
}
