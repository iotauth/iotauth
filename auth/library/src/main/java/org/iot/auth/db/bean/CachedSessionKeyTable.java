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

import org.iot.auth.crypto.SessionKey;
import org.iot.auth.crypto.SymmetricKeyCryptoSpec;
import org.iot.auth.io.Buffer;
import org.json.simple.JSONObject;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Arrays;

/**
 * @author Hokeun Kim
 */
public class CachedSessionKeyTable {
    public static final String T_CACHED_SESSION_KEY = "cached_session_key";

    public enum c {
        ID,
        Owners,
        MaxNumOwners,
        Purpose,
        ExpirationTime,
        RelValidity,
        CryptoSpec,
        KeyVal
    }

    public static CachedSessionKeyTable fromSessionKey(SessionKey sessionKey) {
        CachedSessionKeyTable cachedSessionKey = new CachedSessionKeyTable();
        cachedSessionKey.setID(sessionKey.getID());
        cachedSessionKey.setOwner(String.join(SessionKey.SESSION_KEY_OWNER_NAME_DELIM, sessionKey.getOwners()));
        cachedSessionKey.setMaxNumOwners(sessionKey.getMaxNumOwners());
        cachedSessionKey.setPurpose(sessionKey.getPurpose());
        cachedSessionKey.setAbsValidity(sessionKey.getRawExpirationTime());
        cachedSessionKey.setRelValidity(sessionKey.getRelValidity());
        cachedSessionKey.setSessionCryptoSpec(sessionKey.getCryptoSpec().toSpecString());
        cachedSessionKey.setKeyVal(sessionKey.getSerializedKeyVal().getRawBytes());
        return cachedSessionKey;
    }

    public SessionKey toSessionKey() {
        SymmetricKeyCryptoSpec cryptoSpec = SymmetricKeyCryptoSpec.fromSpecString(getSessionCryptoSpec());
        SessionKey sessionKey = new SessionKey(getID(), getOwner().split(SessionKey.SESSION_KEY_OWNER_NAME_DELIM),
                getMaxNumOwners(), getPurpose(),
                getAbsValidity(), getRelValidity(),
                cryptoSpec, new Buffer(getKeyVal()));
        return sessionKey;
    }

    public long getID() {
        return id;
    }
    public void setID(long id) {
        this.id = id;
    }
    public String getOwner() {
        return owners;
    }
    public void setOwner(String owner) {
        this.owners = owner;
    }
    public int getMaxNumOwners() {
        return maxNumOwners;
    }
    public void setMaxNumOwners(int maxNumOwners) {
        this.maxNumOwners = maxNumOwners;
    }
    public String getPurpose() {
        return purpose;
    }
    public void setPurpose(String purpose) {
        this.purpose = purpose;
    }


    public long getAbsValidity() {
        return absValidity;
    }
    public void setAbsValidity(long absValidity) {
        this.absValidity = absValidity;
    }
    public long getRelValidity() {
        return relValidity;
    }
    public void setRelValidity(long relValidity) {
        this.relValidity = relValidity;
    }

    public String getSessionCryptoSpec() {
        return sessionCryptoSpec;
    }
    public void setSessionCryptoSpec(String sessionCryptoSpec) {
        this.sessionCryptoSpec = sessionCryptoSpec;
    }

    public byte[] getKeyVal() {
        return keyVal;
    }
    public void setKeyVal(byte[] keyVal) {
        this.keyVal = Arrays.copyOf(keyVal, keyVal.length);
    }

    public static CachedSessionKeyTable createRecord(ResultSet r) throws SQLException {
        CachedSessionKeyTable cachedSessionKey = new CachedSessionKeyTable();
        cachedSessionKey.setID(r.getLong(c.ID.name()));
        cachedSessionKey.setOwner(r.getString(c.Owners.name()));
        cachedSessionKey.setMaxNumOwners(r.getInt(c.MaxNumOwners.name()));
        cachedSessionKey.setPurpose(r.getString(c.Purpose.name()));
        cachedSessionKey.setAbsValidity(r.getLong(c.ExpirationTime.name()));
        cachedSessionKey.setRelValidity(r.getLong(c.RelValidity.name()));
        cachedSessionKey.setSessionCryptoSpec(r.getString(c.CryptoSpec.name()));
        cachedSessionKey.setKeyVal(r.getBytes(c.KeyVal.name()));
        return cachedSessionKey;
    }

    @SuppressWarnings("unchecked")
    public JSONObject toJSONObject() {
        JSONObject object = new JSONObject();
        object.put(c.ID.name(), getID());
        object.put(c.Owners.name(), getOwner());
        object.put(c.MaxNumOwners.name(), getMaxNumOwners());
        object.put(c.Purpose.name(), getPurpose());
        object.put(c.ExpirationTime.name(), getAbsValidity());
        object.put(c.RelValidity.name(), getRelValidity());
        object.put(c.CryptoSpec.name(), getSessionCryptoSpec());
        object.put(c.KeyVal.name(), getKeyVal());
        return object;
    }

    private long id;
    private String owners;
    private int maxNumOwners;
    private String purpose;

    private long absValidity;
    private long relValidity;

    private String sessionCryptoSpec;

    private byte[] keyVal;
}
