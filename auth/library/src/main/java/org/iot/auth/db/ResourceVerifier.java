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

import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Verifies requested resources (sensors and actuators) against communication policy resource constraints.
 * 
 * Policy context JSON format:
 * {
 *   "resources": {
 *     "sensors": {
 *       "Allowed": ["LiFi", "IR", "UltraSound", "BLE"]
 *     },
 *     "actuators": {
 *       "Allowed": ["LiFi", "IR", "UltraSound", "BLE"]
 *     }
 *   }
 * }
 * 
 * Request purpose resources format:
 * {
 *   "sensors": "LiFi,IR,BLE",
 *   "actuators": "IR,BLE"
 * }
 */
public class ResourceVerifier {

    /**
     * Verifies requested resources against policy resource requirements.
     * @param policyContextJson Policy context JSON string from CommunicationPolicy.
     * @param requestResources JSONObject extracted from "resources" key in purpose JSON.
     * @return true if all requested resources are allowed by policy; false otherwise.
     */
    public static boolean verifyResources(String policyContextJson, JSONObject requestResources) {
        // If policy does not define any context requirements, allow by default
        if (policyContextJson == null || policyContextJson.isEmpty()) {
            return true;
        }
        // If request specifies no resources, allow by default
        if (requestResources == null) {
            return true;
        }

        JSONObject policyContext;
        try {
            policyContext = (JSONObject) new JSONParser().parse(policyContextJson);
        } catch (ParseException e) {
            logger.error("Failed to parse policy context JSON: {}", policyContextJson);
            return false;
        }

        // If policy context does not contain a "resources" section, verification passes
        if (!policyContext.containsKey("resources") || !(policyContext.get("resources") instanceof JSONObject)) {
            return true;
        }

        JSONObject policyResources = (JSONObject) policyContext.get("resources");

        // Validate both "sensors" and "actuators" resource requirements
        for (String resourceType : new String[]{"sensors", "actuators"}) {
            if (policyResources.containsKey(resourceType) && policyResources.get(resourceType) instanceof JSONObject) {
                JSONObject typePolicy = (JSONObject) policyResources.get(resourceType);
                if (typePolicy.containsKey("Allowed") && typePolicy.get("Allowed") instanceof JSONArray) {
                    JSONArray allowed = (JSONArray) typePolicy.get("Allowed");
                    Object providedValue = requestResources.get(resourceType);
                    if (providedValue != null) {
                        // Split comma-separated resource names and check each item against the policy allowlist
                        String[] items = providedValue.toString().split(",");
                        for (String item : items) {
                            String trimmed = item.trim();
                            if (!trimmed.isEmpty() && !allowed.contains(trimmed)) {
                                logger.error("Requested {} '{}' is not in allowed policy list {}.",
                                        resourceType, trimmed, allowed);
                                return false;
                            }
                        }
                    }
                }
            }
        }
        return true;
    }

    private static final Logger logger = LoggerFactory.getLogger(ResourceVerifier.class);
}
