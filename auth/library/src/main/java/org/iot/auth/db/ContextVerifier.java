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

import java.time.LocalTime;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;

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
                // Allowlist-style: value must be in the allowed list
                JSONArray allowed = (JSONArray) requirement.get("Allowed");
                if (!allowed.contains(providedValue)) {
                    logger.error("Context '{}' value '{}' is not in allowed list {}.",
                            conditionName, providedValue, allowed);
                    return false;
                }
            } else if (requirement.containsKey("Min") || requirement.containsKey("Max")) {
                // Range-style: value must be within the [Min, Max] bounds. The data
                // type (integer or time) is detected from the values themselves, and
                // the provided value and bounds must all share the same format.
                if (!checkRange(conditionName, requirement, providedValue)) {
                    return false;
                }
            } else {
                logger.error("Unknown context requirement type for '{}': {}", conditionName, requirement);
                return false;
            }
        }
        return true;
    }

    /**
     * Supported data formats for a range ({@code Min}/{@code Max}) requirement.
     */
    private enum ValueFormat {
        INTEGER,
        TIME
    }

    /**
     * Checks a range requirement by first verifying that the provided value and the
     * present bounds ({@code Min} and/or {@code Max}) share the same detectable
     * format, then comparing them within that format. If the formats do not match,
     * the context cannot be verified, so an error is logged and false is returned.
     *
     * @param conditionName name of the context condition (for logging).
     * @param requirement   the policy requirement object containing Min and/or Max.
     * @param providedValue the value provided in the request for this condition.
     * @return true if the value is within bounds; false on format mismatch or violation.
     */
    private static boolean checkRange(String conditionName, JSONObject requirement, Object providedValue) {
        Object minObj = requirement.get("Min");
        Object maxObj = requirement.get("Max");

        ValueFormat providedFormat = detectFormat(providedValue);
        if (providedFormat == null) {
            logger.error("Context '{}' value '{}' is not in a recognized format " +
                    "(integer or time HH:mm[:ss]).", conditionName, providedValue);
            return false;
        }
        if (minObj != null && detectFormat(minObj) != providedFormat) {
            logger.error("Context '{}': Min bound '{}' format does not match provided value '{}' format ({}).",
                    conditionName, minObj, providedValue, providedFormat);
            return false;
        }
        if (maxObj != null && detectFormat(maxObj) != providedFormat) {
            logger.error("Context '{}': Max bound '{}' format does not match provided value '{}' format ({}).",
                    conditionName, maxObj, providedValue, providedFormat);
            return false;
        }

        if (providedFormat == ValueFormat.INTEGER) {
            long value = toLong(providedValue);
            if (minObj != null && value < toLong(minObj)) {
                logger.error("Context '{}' value {} is below minimum of {}.",
                        conditionName, value, toLong(minObj));
                return false;
            }
            if (maxObj != null && value > toLong(maxObj)) {
                logger.error("Context '{}' value {} exceeds maximum of {}.",
                        conditionName, value, toLong(maxObj));
                return false;
            }
        } else { // TIME
            LocalTime value = parseTime(providedValue.toString());
            if (minObj != null && value.isBefore(parseTime(minObj.toString()))) {
                logger.error("Context '{}' value '{}' is before minimum of '{}'.",
                        conditionName, providedValue, minObj);
                return false;
            }
            if (maxObj != null && value.isAfter(parseTime(maxObj.toString()))) {
                logger.error("Context '{}' value '{}' is after maximum of '{}'.",
                        conditionName, providedValue, maxObj);
                return false;
            }
        }
        return true;
    }

    /**
     * Detects the format of a value for range comparison. A value is an INTEGER if
     * it is an integral number (or a string parseable as one), or a TIME if it is a
     * string in {@code HH:mm} or {@code HH:mm:ss} format.
     *
     * @param value the value to inspect.
     * @return the detected {@link ValueFormat}, or null if not recognized.
     */
    private static ValueFormat detectFormat(Object value) {
        if (value instanceof Long || value instanceof Integer) {
            return ValueFormat.INTEGER;
        }
        if (value instanceof Double) {
            double d = (Double) value;
            return (d == Math.floor(d) && !Double.isInfinite(d)) ? ValueFormat.INTEGER : null;
        }
        String s = value.toString();
        try {
            Long.parseLong(s);
            return ValueFormat.INTEGER;
        } catch (NumberFormatException e) {
            // Not an integer; fall through to time check.
        }
        if (parseTime(s) != null) {
            return ValueFormat.TIME;
        }
        return null;
    }

    /**
     * Parses a time string in {@code HH:mm} or {@code HH:mm:ss} format.
     *
     * @param s the string to parse.
     * @return the parsed {@link LocalTime}, or null if it is not a valid time.
     */
    private static LocalTime parseTime(String s) {
        try {
            return LocalTime.parse(s, TIME_FORMATTER);
        } catch (DateTimeParseException e) {
            return null;
        }
    }

    private static long toLong(Object obj) {
        if (obj instanceof Long) return (Long) obj;
        if (obj instanceof Integer) return ((Integer) obj).longValue();
        if (obj instanceof Double) {
            double d = (Double) obj;
            if (d != Math.floor(d)) {
                throw new IllegalArgumentException("Non-integer numeric value not allowed: " + d);
            }
            return (long) d;
        }
        return Long.parseLong(obj.toString());
    }

    private static final DateTimeFormatter TIME_FORMATTER = DateTimeFormatter.ofPattern("HH:mm[:ss]");

    private static final Logger logger = LoggerFactory.getLogger(ContextVerifier.class);
}
