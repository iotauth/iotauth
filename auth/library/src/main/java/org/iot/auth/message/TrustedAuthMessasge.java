package org.iot.auth.message;

import org.eclipse.jetty.server.Request;
import org.json.simple.JSONObject;

import java.util.Map;

/**
 * Parent class of messages between trustued Auths
 *
 * @author Hokeun Kim
 */
public class TrustedAuthMessasge {

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
}
