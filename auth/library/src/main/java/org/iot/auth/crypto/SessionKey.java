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

package org.iot.auth.crypto;

import org.iot.auth.io.Buffer;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;

/**
 * A class for an instance of a session key that is used for communication between entities.
 * <pre>
 * SessionKey Format
 * {
 *      ID: /UIntBE, SESSION_KEY_ID_SIZE Bytes/,
 *      ExpirationTime: /UIntBE, SESSION_KEY_EXPIRATION_TIME Bytes, Date() format/, // for absolute validity period
 *      relValidity: /UIntBE, SESSION_KEY_REL_VALIDITY_SIZE Bytes, integer in millisecons/, // for relative validity period
 *      val: /Buffer/
 * } </pre>
 * @author Hokeun Kim
 */

public class SessionKey extends SymmetricKey {
    private static final int SESSION_KEY_ID_SIZE = 8;
    private static final int SESSION_KEY_EXPIRATION_TIME = 6;
    private static final int SESSION_KEY_REL_VALIDITY_SIZE = 6;

    public static final String SESSION_KEY_OWNER_NAME_DELIM = ",";

    private enum key {
        ID,
        Owners,
        MaxNumOwners,
        Purpose,
        ExpirationTime,
        RelValidity,
        CryptoSpec,
        KeyVal
    }

    public SessionKey(long id, String[] owners, int maxNumOwners, String purpose,
                      long expirationTime, long relValidity,
                      SymmetricKeyCryptoSpec cryptoSpec, Buffer serializedKeyVal)
    {
        super(cryptoSpec, expirationTime, serializedKeyVal);
        this.id = id;
        this.owners = owners;
        this.maxNumOwners = maxNumOwners;
        this.purpose = purpose;
        this.relValidity = relValidity;
    }

    public SessionKey(long id, String[] owners, int maxNumOwners, String purpose,
                      long expirationTime, long relValidity,
                      SymmetricKeyCryptoSpec cryptoSpec)
    {
        super(cryptoSpec, expirationTime);
        this.id = id;
        this.owners = owners;
        this.maxNumOwners = maxNumOwners;
        this.purpose = purpose;
        this.relValidity = relValidity;
    }

    public String toString() {
        return "ID: " + id + "\tOwners: " + String.join(SESSION_KEY_OWNER_NAME_DELIM, owners) +
                "\tAbsoluteValidity: " + getExpirationTime() + "\tRelativeValidity: " + relValidity +
                "\t" + getCryptoSpec().toString() + "\tCipherKey: " + getCipherKeyVal().toHexString() +
                "\tMacKey: " + getMacKeyVal().toHexString();
    }

    public Buffer serialize() {
        Buffer buf = new Buffer(SESSION_KEY_ID_SIZE + SESSION_KEY_EXPIRATION_TIME + SESSION_KEY_REL_VALIDITY_SIZE);
        int curIndex = 0;
        buf.putNumber(id, curIndex, SESSION_KEY_ID_SIZE);
        curIndex += SESSION_KEY_ID_SIZE;
        buf.putNumber(getRawExpirationTime(), curIndex, SESSION_KEY_EXPIRATION_TIME);
        curIndex += SESSION_KEY_EXPIRATION_TIME;
        buf.putNumber(relValidity, curIndex, SESSION_KEY_REL_VALIDITY_SIZE);
        curIndex += SESSION_KEY_REL_VALIDITY_SIZE;

        buf.concat(getSerializedKeyVal());
        return buf;
    }

    @SuppressWarnings("unchecked")
    public JSONObject toJSONObject() {
        JSONObject jsonObject = new JSONObject();
        jsonObject.put(key.ID, id);
        jsonObject.put(key.Owners, String.join(SESSION_KEY_OWNER_NAME_DELIM, owners));
        jsonObject.put(key.MaxNumOwners, maxNumOwners);
        jsonObject.put(key.Purpose, purpose);
        jsonObject.put(key.ExpirationTime, getRawExpirationTime());
        jsonObject.put(key.RelValidity, relValidity);
        jsonObject.put(key.CryptoSpec, getCryptoSpec().toJSONObject());
        jsonObject.put(key.KeyVal, getSerializedKeyVal().toBase64());
        return jsonObject;
    }

    public static SessionKey fromJSONObject(JSONObject jsonObject) throws ParseException {
        SessionKey sessionKey = new SessionKey(
                Long.parseLong(jsonObject.get(key.ID.name()).toString()),
                jsonObject.get(key.Owners.name()).toString().split(SESSION_KEY_OWNER_NAME_DELIM),
                Integer.parseInt(jsonObject.get(key.MaxNumOwners.name()).toString()),
                jsonObject.get(key.Purpose.name()).toString(),
                Long.parseLong(jsonObject.get(key.ExpirationTime.name()).toString()),
                Long.parseLong(jsonObject.get(key.RelValidity.name()).toString()),
                SymmetricKeyCryptoSpec.fromJSONObject(
                        (JSONObject) new JSONParser().parse(jsonObject.get(key.CryptoSpec.name()).toString())),
                Buffer.fromBase64(jsonObject.get(key.KeyVal.name()).toString())
        );
        return sessionKey;
    }

    public long getID() {
        return id;
    }

    public String[] getOwners() {
        return owners;
    }

    public int getMaxNumOwners() {
        return maxNumOwners;
    }
    public String getPurpose() {
        return purpose;
    }

    public long getRelValidity() {
        return relValidity;
    }


    private long id;
    private String[] owners;

    private int maxNumOwners;
    private String purpose;

    private long relValidity;
}
