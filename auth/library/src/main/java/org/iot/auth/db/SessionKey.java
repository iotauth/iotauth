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

import org.iot.auth.io.Buffer;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;

import java.util.Date;

/**
 * A class for an instance of a session key that is used for communication between entities.
 * <pre>
 * SessionKey Format
 * {
 *      ID: /UIntBE, SESSION_KEY_ID_SIZE Bytes/,
 *      absValidity: /UIntBE, SESSION_KEY_ABS_VALIDITY_SIZE Bytes, Date() format/, // for absolute validity period
 *      relValidity: /UIntBE, SESSION_KEY_REL_VALIDITY_SIZE Bytes, integer in millisecons/, // for relative validity period
 *      val: /Buffer/
 * } </pre>
 * @author Hokeun Kim
 */

public class SessionKey {
    private static final int SESSION_KEY_ID_SIZE = 8;
    private static final int SESSION_KEY_ABS_VALIDITY_SIZE = 6;
    private static final int SESSION_KEY_REL_VALIDITY_SIZE = 6;

    public static final String SESSION_KEY_OWNER_NAME_DELIM = ",";

    private enum key {
        ID,
        Owners,
        AbsValidity,
        RelValidity,
        CryptoSpec,
        KeyVal
    }

    public SessionKey(long id, String[] owners,
                      long absValidity, long relValidity,
                      SymmetricKeyCryptoSpec cryptoSpec, Buffer keyVal)
    {
        if (cryptoSpec.getCipherKeySize() != keyVal.length()) {
            throw new RuntimeException("Wrong key size!");
        }
        this.id = id;
        this.owners = owners;

        // from time of generation
        this.absValidity = new Date(absValidity);
        this.relValidity = relValidity;

        this.cryptoSpec = cryptoSpec;
        this.keyVal = keyVal;
    }

    public String toString() {
        return "ID: " + id + "\tOwners: " + String.join(SESSION_KEY_OWNER_NAME_DELIM, owners) +
                "\tAbsoluteValidity: " + absValidity + "\tRelativeValidity: " + relValidity +
                "\t" + cryptoSpec.toString() + "\tKeyVal: " + keyVal.toHexString();
    }

    public Buffer serialize() {
        Buffer buf = new Buffer(SESSION_KEY_ID_SIZE + SESSION_KEY_ABS_VALIDITY_SIZE + SESSION_KEY_REL_VALIDITY_SIZE);
        int curIndex = 0;
        buf.putNumber(id, curIndex, SESSION_KEY_ID_SIZE);
        curIndex += SESSION_KEY_ID_SIZE;
        buf.putNumber(absValidity.getTime(), curIndex, SESSION_KEY_ABS_VALIDITY_SIZE);
        curIndex += SESSION_KEY_ABS_VALIDITY_SIZE;
        buf.putNumber(relValidity, curIndex, SESSION_KEY_REL_VALIDITY_SIZE);
        curIndex += SESSION_KEY_REL_VALIDITY_SIZE;

        buf.concat(keyVal);
        return buf;
    }

    public JSONObject toJSONObject() {
        JSONObject jsonObject = new JSONObject();
        jsonObject.put(key.ID, id);
        jsonObject.put(key.Owners, String.join(SESSION_KEY_OWNER_NAME_DELIM, owners));
        jsonObject.put(key.AbsValidity, absValidity.getTime());
        jsonObject.put(key.RelValidity, relValidity);
        jsonObject.put(key.CryptoSpec, cryptoSpec.toJSONObject());
        jsonObject.put(key.KeyVal, keyVal.toBase64());
        return jsonObject;
    }

    public static SessionKey fromJSONObject(JSONObject jsonObject) throws ParseException {
        SessionKey sessionKey = new SessionKey(
                Long.parseLong(jsonObject.get(key.ID.toString()).toString()),
                jsonObject.get(key.Owners.toString()).toString().split(SESSION_KEY_OWNER_NAME_DELIM),
                Long.parseLong(jsonObject.get(key.AbsValidity.toString()).toString()),
                Long.parseLong(jsonObject.get(key.RelValidity.toString()).toString()),
                SymmetricKeyCryptoSpec.fromJSONObject(
                        (JSONObject) new JSONParser().parse(jsonObject.get(key.CryptoSpec.toString()).toString())),
                Buffer.fromBase64(jsonObject.get(key.KeyVal.toString()).toString())
        );
        return sessionKey;
    }

    public long getID() {
        return id;
    }

    public String[] getOwners() {
        return owners;
    }

    public Date getAbsValidity() {
        return absValidity;
    }
    public long getRelValidity() {
        return relValidity;
    }


    public SymmetricKeyCryptoSpec getCryptoSpec() {
        return cryptoSpec;
    }

    public Buffer getKeyVal() {
        return keyVal;
    }

    private long id;
    private String[] owners;

    private Date absValidity;
    private long relValidity;

    private SymmetricKeyCryptoSpec cryptoSpec;

    private Buffer keyVal;
}
