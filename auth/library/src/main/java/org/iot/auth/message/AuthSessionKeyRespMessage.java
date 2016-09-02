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

package org.iot.auth.message;

import org.iot.auth.db.SessionKey;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;

/**
 * A class for Auth session key response message to Auth who requested session key(s) on behalf of its
 * registered entity.
 * <pre>
 * AuthSessionKeyResp Format
 * {
 *     SessionKey: [SessionKey in JSON string]
 * } </pre>
 * @author Hokeun Kim
 */
public class AuthSessionKeyRespMessage {
    private enum key {
        SessionKey
    }
    public AuthSessionKeyRespMessage(SessionKey sessionKey) {
        this.sessionKey = sessionKey;
    }
    public JSONObject toJSONObject() {
        JSONObject jsonObject = new JSONObject();
        jsonObject.put(key.SessionKey, sessionKey.toJSONObject().toJSONString());
        return jsonObject;
    }
    public SessionKey getSessionKey() {
        return sessionKey;
    }
    public static AuthSessionKeyRespMessage fromJSONObject(JSONObject jsonObject) throws ParseException {
        String sessionKeyStr = jsonObject.get(key.SessionKey.toString()).toString();

        Object obj = new JSONParser().parse(sessionKeyStr);
        SessionKey sessionKey = SessionKey.fromJSONObject(
                (JSONObject) new JSONParser().parse(sessionKeyStr));

        return new AuthSessionKeyRespMessage(sessionKey);
    }
    public String toString() {
        return "SessionKey: " + sessionKey.toString();
    }
    private SessionKey sessionKey;
}
