package org.iot.auth.message;

import org.eclipse.jetty.client.api.ContentResponse;
import org.eclipse.jetty.server.Request;
import org.json.simple.JSONObject;

import java.util.Map;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeoutException;

/**
 * Parent class of messages between trustued Auths
 *
 * @author Hokeun Kim
 */
public abstract class TrustedAuthReqMessasge {
    public static final String TYPE = "TYPE";
    public enum type {
        AUTH_SESSION_KEY_REQ,
        BACKUP_REQ,
        HEARTBEAT_REQ
    }
    @SuppressWarnings("unchecked")
    protected static JSONObject convertRequestToJSONObject(Request request) {
        JSONObject jsonObject = new JSONObject();
        Map<String,String[]> params = request.getParameterMap();
        for (Map.Entry<String,String[]> entry : params.entrySet()) {
            String v[] = entry.getValue();
            Object o = (v.length == 1) ? v[0] : v;
            jsonObject.put(entry.getKey(), o);
        }
        return jsonObject;
    }

    public abstract ContentResponse sendAsHttpRequest(org.eclipse.jetty.client.api.Request postRequest)
            throws TimeoutException, ExecutionException, InterruptedException;
}
