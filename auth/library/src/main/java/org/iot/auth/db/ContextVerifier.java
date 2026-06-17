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
 * Verifies that the context provided in a session key request purpose satisfies
 * the context requirements stored in the communication policy.
 *
 * Policy context format (JSON string stored in the Context column):
 * {
 *   "Number of People": {"Max": 3},
 *   "Location": {"Allowed": ["Classroom", "Meeting Room"]},
 *   "Time of Day": {"Min": "09:00", "Max": "18:00"}
 * }
 *
 * Request purpose context format (JSON object inside the purpose JSON):
 * {
 *   "Number of People": 2,
 *   "Location": "Classroom",
 *   "Time of Day": "10:30"
 * }
 *
 * @author Hokeun Kim
 */
public class ContextVerifier {

    /**
     * Verifies that the context in the session key request purpose satisfies all
     * conditions in the communication policy's context requirements.
     *
     * @param policyContextJson JSON string from the Context column of the communication policy.
     * @param requestContext    JSONObject extracted from the "context" key of the purpose JSON.
     * @return true if all conditions are satisfied; false otherwise.
     */
    public static boolean verifyContext(String policyContextJson, JSONObject requestContext) {
        if (policyContextJson == null || policyContextJson.isEmpty()) {
            return true;
        }
        if (requestContext == null) {
            logger.error("Policy requires context but no context was provided in the request.");
            return false;
        }

        JSONObject policyContext;
        try {
            policyContext = (JSONObject) new JSONParser().parse(policyContextJson);
        } catch (ParseException e) {
            logger.error("Failed to parse policy context JSON: {}", policyContextJson);
            return false;
        }

        for (Object keyObj : policyContext.keySet()) {
            String conditionName = (String) keyObj;
            JSONObject requirement = (JSONObject) policyContext.get(conditionName);
            Object providedValue = requestContext.get(conditionName);

            if (providedValue == null) {
                logger.error("Context requirement '{}' not provided in request.", conditionName);
                return false;
            }

            if (requirement.containsKey("Allowed")) {
                // Location-style: value must be in the allowed list
                JSONArray allowed = (JSONArray) requirement.get("Allowed");
                if (!allowed.contains(providedValue)) {
                    logger.error("Context '{}' value '{}' is not in allowed list {}.",
                            conditionName, providedValue, allowed);
                    return false;
                }
            } else if (requirement.containsKey("Max") && requirement.containsKey("Min")) {
                // Time-of-Day-style: value must be between Min and Max (lexicographic HH:MM comparison)
                String min = (String) requirement.get("Min");
                String max = (String) requirement.get("Max");
                String value = providedValue.toString();
                if (value.compareTo(min) < 0 || value.compareTo(max) > 0) {
                    logger.error("Context '{}' value '{}' is not between '{}' and '{}'.",
                            conditionName, value, min, max);
                    return false;
                }
            } else if (requirement.containsKey("Max")) {
                // Number-of-People-style: value must be <= Max
                long maxVal = toLong(requirement.get("Max"));
                long actualVal = toLong(providedValue);
                if (actualVal > maxVal) {
                    logger.error("Context '{}' value {} exceeds maximum of {}.",
                            conditionName, actualVal, maxVal);
                    return false;
                }
            } else if (requirement.containsKey("Min")) {
                // Minimum-only numeric constraint
                long minVal = toLong(requirement.get("Min"));
                long actualVal = toLong(providedValue);
                if (actualVal < minVal) {
                    logger.error("Context '{}' value {} is below minimum of {}.",
                            conditionName, actualVal, minVal);
                    return false;
                }
            } else {
                logger.warn("Unknown context requirement type for '{}': {}", conditionName, requirement);
            }
        }
        return true;
    }

    private static long toLong(Object obj) {
        if (obj instanceof Long) return (Long) obj;
        if (obj instanceof Integer) return ((Integer) obj).longValue();
        if (obj instanceof Double) return ((Double) obj).longValue();
        return Long.parseLong(obj.toString());
    }

    private static final Logger logger = LoggerFactory.getLogger(ContextVerifier.class);
}
