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

import org.eclipse.jetty.client.api.ContentResponse;
import org.json.simple.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedReader;
import java.io.IOException;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeoutException;

/**
 * A class for Auth session key request message to Auth who requested session key(s) on behalf of its
 * registered entity.
 * <pre>
 * AuthSessionKeyReq Format
 * {
 *     KeyID: [KeyID in Long],
 *     EntityName: [EntityName in String],
 *     EntityGroup: [EntityGroup in String]
 * } </pre>
 * @author Hokeun Kim
 */
public class AuthSessionKeyReqMessage extends TrustedAuthReqMessasge {
    private enum key {
        KeyID,
        EntityName,
        EntityGroup,
        CachedKeyAuthID
    }

    private long sessionKeyID;
    private String requestingEntityName;
    private String requestingEntityGroup;
    private int cachedKeyAuthID;

    private static final Logger logger = LoggerFactory.getLogger(AuthSessionKeyReqMessage.class);

    public AuthSessionKeyReqMessage(long sessionKeyID, String requestingEntityName, String requestingEntityGroup, int cachedKeyAuthID) {
        this.sessionKeyID = sessionKeyID;
        this.requestingEntityName = requestingEntityName;
        this.requestingEntityGroup = requestingEntityGroup;
        this.cachedKeyAuthID = cachedKeyAuthID;
    }

    public long getSessionKeyID() {
        return sessionKeyID;
    }
    public String getRequestingEntityName() {
        return requestingEntityName;
    }
    public String getRequestingEntityGroup() {
        return requestingEntityGroup;
    }
    public int getCachedKeyAuthID() { return cachedKeyAuthID; }
    public String toString() {
        return "KeyID: " + sessionKeyID + ", RequestingEntityName: " + requestingEntityName +
                ", ReqeustingEntityGroup: " + requestingEntityGroup + ", CachedKeyAuthID: " + cachedKeyAuthID;
    }

    @SuppressWarnings("unchecked")
    private JSONObject toJSONObject() {
        JSONObject jsonObject = new JSONObject();
        jsonObject.put(key.KeyID, sessionKeyID);
        jsonObject.put(key.EntityName, requestingEntityName);
        jsonObject.put(key.EntityGroup, requestingEntityGroup);
        jsonObject.put(key.CachedKeyAuthID, cachedKeyAuthID);
        return jsonObject;
    }
    // Because of the class name conflict of Request (client's or server's)
    public ContentResponse sendAsHttpRequest(org.eclipse.jetty.client.api.Request postRequest)
            throws TimeoutException, ExecutionException, InterruptedException
    {
        JSONObject jsonObject = this.toJSONObject();
        postRequest.param(TrustedAuthReqMessasge.TYPE, type.AUTH_SESSION_KEY_REQ.name());
        for (final Object key: jsonObject.keySet()) {
            Object value = jsonObject.get(key);
            postRequest.param(key.toString(), value.toString());
        }
        return postRequest.send();
    }

    private static AuthSessionKeyReqMessage fromJSONObject(JSONObject jsonObject) {
        Object obj = jsonObject.get(key.KeyID.name());
        Long sessionKeyIDObj = Long.parseLong(obj.toString());
        obj = jsonObject.get(key.CachedKeyAuthID.name());
        int cachedKeyAuthIDObj = Integer.parseInt(obj.toString());
        return new AuthSessionKeyReqMessage(sessionKeyIDObj,
                jsonObject.get(key.EntityName.name()).toString(),
                jsonObject.get(key.EntityGroup.name()).toString(),
                cachedKeyAuthIDObj);
    }
    public static AuthSessionKeyReqMessage fromHttpRequest(org.eclipse.jetty.server.Request baseRequest)
            throws IOException
    {
        BufferedReader br = baseRequest.getReader();
        StringBuilder sb = new StringBuilder();
        while (br.ready()) {
            sb.append(br.readLine());
        }
        String currentData = sb.toString();
        logger.info("Received contents: {} ", currentData);

        JSONObject jsonObject = convertRequestToJSONObject(baseRequest);

        logger.info("Received JSON: {}", jsonObject.toJSONString());

        return fromJSONObject(jsonObject);
    }
}
