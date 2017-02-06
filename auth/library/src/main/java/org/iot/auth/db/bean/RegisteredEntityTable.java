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
import org.iot.auth.util.DateHelper;
import org.json.simple.JSONObject;

import java.security.PublicKey;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Arrays;

/**
 * @author Salomon Lee
 */
public class RegisteredEntityTable {
    public static final String T_REGISTERED_ENTITY = "registered_entity";
    public enum c {
        Name,
        Group,
        DistProtocol,
        UsePermanentDistKey,
        DistKeyValidity,
        DistValidityPeriod,
        PublKeyFile,
        PublicKey,
        DistCryptoSpec,
        DistKeyExpirationTime,
        DistKeyVal,
        MaxSessionKeysPerRequest
    }
    private String name;
    private String group;
    private String distProtocol;
    private boolean usePermanentDistKey;
    private PublicKey publicKey;
    private String publicKeyFile;
    private String distValidityPeriod;
    private long distKeyValidity;
    private String distCryptoSpec;
    private long distKeyExpirationTime = -1;
    private byte[] distKeyVal = null;
    private int maxSessionKeysPerRequest;


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

    public long getDistKeyValidity() {
        return distKeyValidity;
    }
    public void setDistKeyValidity(long distKeyValidity) {
        this.distKeyValidity = distKeyValidity;
    }

    public String getPublicKeyFile() {
        return publicKeyFile;
    }
    public void setPublicKeyFile(String publicKeyFile) {
        this.publicKeyFile = publicKeyFile;
    }

    public String getDistValidityPeriod() {
        return distValidityPeriod;
    }
    public void setDistValidityPeriod(String distValidityPeriod) {
        this.distValidityPeriod = distValidityPeriod;
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
        object.put(c.DistKeyValidity.name(), getDistKeyValidity());
        object.put(c.PublKeyFile.name(), getPublicKeyFile().toString());
        object.put(c.PublicKey.name(), getPublicKey());
        object.put(c.MaxSessionKeysPerRequest.name(), getMaxSessionKeysPerRequest());
        return object;
    }

    public static RegisteredEntityTable createRecord(String authDatabaseDir, ResultSet r) throws SQLException {
        RegisteredEntityTable entity = new RegisteredEntityTable();
        entity.setName(r.getString(c.Name.name()));
        entity.setGroup(r.getString(c.Group.name()));
        entity.setDistProtocol(r.getString(c.DistProtocol.name()));
        entity.setPublicKeyFile(r.getString(c.PublKeyFile.name()));
        entity.setUsePermanentDistKey(r.getBoolean(c.UsePermanentDistKey.name()));
        if (!entity.getUsePermanentDistKey()) {
            entity.setPublicKey(AuthCrypto.loadPublicKey(authDatabaseDir + "/" + entity.getPublicKeyFile()));
        }
        entity.setDistKeyValidity(DateHelper.parseTimePeriod(r.getString(c.DistValidityPeriod.name())));
        entity.setDistCryptoSpec(r.getString(c.DistCryptoSpec.name()));
        byte[] distKeyVal = r.getBytes(c.DistKeyVal.name());
        if (distKeyVal != null) {
            entity.setDistKeyVal(distKeyVal);
            entity.setDistKeyExpirationTime(r.getLong(c.DistKeyExpirationTime.name()));
        }
        entity.setMaxSessionKeysPerRequest(r.getInt(c.MaxSessionKeysPerRequest.name()));
        return entity;
    }
}
