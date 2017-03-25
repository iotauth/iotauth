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
import org.iot.auth.crypto.SessionKey;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;

import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

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
public class AuthSessionKeyRespMessage extends TrustedAuthRespMessage {
    private enum key {
        SessionKey,
        SessionKeyList
    }
    private List<SessionKey> sessionKeyList;
    public AuthSessionKeyRespMessage(List<SessionKey> sessionKeyList) {
        this.sessionKeyList = sessionKeyList;
    }

    public List<SessionKey> getSessionKeyList() {
        return sessionKeyList;
    }

    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("Session key List: \n");
        for (SessionKey sessionKey : sessionKeyList) {
            sb.append(sessionKey.toString() + "\n");
        }
        return sb.toString();
    }

    /**
     * Internal helper function to convert AuthSessionKeyResp object to JSON object.
     * @return JSONObject converted from AuthSessionKeyResp.
     */
    @SuppressWarnings("unchecked")
    private JSONObject toJSONObject() {
        JSONObject jsonObject = new JSONObject();
        JSONArray jsonArray = new JSONArray();

        for (SessionKey sessionKey : sessionKeyList) {
            JSONObject jsonArrayItem = new JSONObject();
            jsonArrayItem.put(key.SessionKey.name(), sessionKey.toJSONObject().toJSONString());
            jsonArray.add(jsonArrayItem);
        }
        jsonObject.put(key.SessionKeyList, jsonArray);

        return jsonObject;
    }

    /**
     * Send Auth session key response as HTTP response.
     * @param response HTTP response object used to send Auth session key response.
     * @throws IOException If a problem occurs while writing the response.
     */
    @Override
    public void sendAsHttpResponse(HttpServletResponse response) throws IOException {
        // Declare response encoding and types
        response.setContentType("text/html; charset=utf-8");
        // Declare response status code
        response.setStatus(HttpServletResponse.SC_OK);

        // Write back response
        //response.getOutputStream().
        response.getWriter().println(toJSONObject().toJSONString());
    }

    // To receive session key response as HTTP response
    private static AuthSessionKeyRespMessage fromJSONObject(JSONObject jsonObject) throws ParseException {
        String sessionKeyListStr = jsonObject.get(key.SessionKeyList.name()).toString();

        JSONArray objArray = (JSONArray) new JSONParser().parse(sessionKeyListStr);
        List<SessionKey> sessionKeyList = new ArrayList<>();
        for (Object obj : objArray) {
            JSONObject jsonObj =  (JSONObject)obj;
            jsonObj = (JSONObject) new JSONParser().parse((jsonObj.get(key.SessionKey.name()).toString()));
            SessionKey sessionKey = SessionKey.fromJSONObject(jsonObj);
            sessionKeyList.add(sessionKey);
        }

        return new AuthSessionKeyRespMessage(sessionKeyList);
    }

    /**
     * Receive Auth session key response as HTTP response and convert it to AuthSessionRespMessage.
     * @param contentResponse HTTP response received.
     * @return New AuthSessionRespMessage object converted from HTTP response.
     * @throws ParseException If an error occurs while parsing the HTTP response.
     */
    public static AuthSessionKeyRespMessage fromHttpResponse(ContentResponse contentResponse)
            throws ParseException
    {
        return fromJSONObject((JSONObject) new JSONParser().parse(contentResponse.getContentAsString()));
    }
}
