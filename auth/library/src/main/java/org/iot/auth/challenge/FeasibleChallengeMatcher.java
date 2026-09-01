package org.iot.auth.challenge;

import org.iot.auth.db.CommunicationPolicy;
import org.iot.auth.db.bean.PhysicalChallengeTable;
import org.iot.auth.db.RegisteredEntity;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.*;

/**
 * FeasibleChallengeMatcher computes the verification plan for a session key request.
 *
 * For each required physical presence check, it selects the highest-priority feasible
 * verification method (catalog order = priority) by intersecting four data dimensions:
 * 1. Requesting entity's registered capabilities in Auth DB vs. dynamic runtime resources (purpose.resources).
 * 2. Target entities' registered capabilities in Auth DB.
 * 3. Required physical presence checks defined in the communication policy (PhysicalPresenceRequirements).
 * 4. Challenge method definitions and requirement constraints stored in the physical_challenge table.
 *
 * @author Dongha Kim
 */
public class FeasibleChallengeMatcher {
    private static final Logger logger = LoggerFactory.getLogger(FeasibleChallengeMatcher.class);

    /**
     * Computes the verification plan JSON object for a session key request.
     *
     * @param requestingEntity    Registered entity object for requester retrieved from Auth DB.
     * @param requestResources   Runtime resources JSON object passed in purpose.resources.
     * @param targetEntities     List of target registered entities (e.g., entities belonging to the target group).
     * @param communicationPolicy Communication policy for the requesting entity and target group.
     * @param challengeDefinitions List of physical challenge definitions retrieved from Auth DB.
     * @return JSONObject containing requester name, effective capabilities, required checks, and the
     *         selected verification method (with parameters) per check, or null per check if none is feasible.
     */
    @SuppressWarnings("unchecked")
    public static JSONObject computeFeasibleChallenges(
            RegisteredEntity requestingEntity,
            JSONObject requestResources,
            List<RegisteredEntity> targetEntities,
            CommunicationPolicy communicationPolicy,
            List<PhysicalChallengeTable> challengeDefinitions) {

        JSONObject result = new JSONObject();
        result.put("requester", requestingEntity.getName());

        // Step 1: Calculate Requester Effective Capabilities (Registered Capabilities INTERSECT Dynamic Runtime Resources)
        Set<String> registeredReqSensors = parseResourcesFromEntity(requestingEntity, "sensors");
        Set<String> registeredReqActuators = parseResourcesFromEntity(requestingEntity, "actuators");

        Set<String> runtimeReqSensors = parseResourceSet(requestResources, "sensors");
        Set<String> runtimeReqActuators = parseResourceSet(requestResources, "actuators");

        // Retain only sensors that are both registered in DB and currently active in runtime
        Set<String> effectiveReqSensors = new LinkedHashSet<>(registeredReqSensors);
        if (!runtimeReqSensors.isEmpty()) {
            effectiveReqSensors.retainAll(runtimeReqSensors);
        }

        // Retain only actuators that are both registered in DB and currently active in runtime
        Set<String> effectiveReqActuators = new LinkedHashSet<>(registeredReqActuators);
        if (!runtimeReqActuators.isEmpty()) {
            effectiveReqActuators.retainAll(runtimeReqActuators);
        }

        JSONObject reqCapObj = new JSONObject();
        reqCapObj.put("sensors", new JSONArray() {{ addAll(effectiveReqSensors); }});
        reqCapObj.put("actuators", new JSONArray() {{ addAll(effectiveReqActuators); }});

        // Step 2: Calculate Union of Target Capabilities (Sensors & Actuators across all entities in target group)
        Set<String> targetSensorsUnion = new LinkedHashSet<>();
        Set<String> targetActuatorsUnion = new LinkedHashSet<>();
        for (RegisteredEntity target : targetEntities) {
            targetSensorsUnion.addAll(parseResourcesFromEntity(target, "sensors"));
            targetActuatorsUnion.addAll(parseResourcesFromEntity(target, "actuators"));
        }

        JSONObject targetCapObj = new JSONObject();
        targetCapObj.put("sensors", new JSONArray() {{ addAll(targetSensorsUnion); }});
        targetCapObj.put("actuators", new JSONArray() {{ addAll(targetActuatorsUnion); }});

        JSONObject effCapObj = new JSONObject();
        effCapObj.put("requester", reqCapObj);
        effCapObj.put("target", targetCapObj);
        result.put("effectiveCapabilities", effCapObj);

        // Step 3: Extract Required Physical Presence Checks from Communication Policy Context
        List<String> requiredChecks = new ArrayList<>();
        if (communicationPolicy != null && communicationPolicy.getContext() != null) {
            try {
                JSONObject policyContext = (JSONObject) new JSONParser().parse(communicationPolicy.getContext());
                if (policyContext.containsKey("PhysicalPresenceRequirements")) {
                    JSONArray reqArray = (JSONArray) policyContext.get("PhysicalPresenceRequirements");
                    for (Object item : reqArray) {
                        requiredChecks.add(item.toString());
                    }
                }
            } catch (ParseException e) {
                logger.error("Failed to parse policy context: {}", e.getMessage());
            }
        }
        result.put("requiredChecks", new JSONArray() {{ addAll(requiredChecks); }});

        // Step 4: For each required check, select the highest-priority feasible method (m_i*) from the
        // catalog. Priority is given by the method's position in the catalog's "methods" array
        // (earlier entries are higher priority).
        JSONObject verificationPlan = new JSONObject();
        for (String checkID : requiredChecks) {
            JSONObject checkObj = new JSONObject();
            PhysicalChallengeTable checkDef = findChallengeDefinition(challengeDefinitions, checkID);
            JSONObject selectedMethod = null;
            if (checkDef != null) {
                checkObj.put("topology", checkDef.getTopology());
                if (checkDef.getMethods() != null) {
                    try {
                        JSONArray methodsArray = (JSONArray) new JSONParser().parse(checkDef.getMethods());
                        for (Object mObj : methodsArray) {
                            JSONObject method = (JSONObject) mObj;
                            String methodID = (String) method.get("id");
                            JSONObject reqs = (JSONObject) method.get("requirements");

                            // Check if requester and target possess all required sensors/actuators for this method
                            if (isMethodFeasible(reqs, effectiveReqSensors, effectiveReqActuators, targetSensorsUnion, targetActuatorsUnion)) {
                                selectedMethod = new JSONObject();
                                selectedMethod.put("method", methodID);
                                if (method.containsKey("parameters")) {
                                    selectedMethod.put("parameters", method.get("parameters"));
                                }
                                break;
                            }
                        }
                    } catch (ParseException e) {
                        logger.error("Failed to parse methods for check {}: {}", checkID, e.getMessage());
                    }
                }
            }
            if (selectedMethod == null) {
                logger.warn("[FeasibleChallengeMatcher] No feasible mechanism found for check {} requested by {}",
                        checkID, requestingEntity.getName());
            }
            checkObj.put("selectedMethod", selectedMethod);
            verificationPlan.put(checkID, checkObj);
        }
        result.put("verificationPlan", verificationPlan);

        logger.info("[FeasibleChallengeMatcher] Computed Verification Plan for {}: {}",
                requestingEntity.getName(), result.toJSONString());

        return result;
    }

    /**
     * Checks if a challenge method is feasible given the effective requester capabilities and target group capabilities.
     * 
     * @param requirements    Requirements JSON object for the method specifying needed requester/target sensors/actuators.
     * @param reqSensors      Effective requester sensors set.
     * @param reqActuators    Effective requester actuators set.
     * @param targetSensors   Target group sensors union set.
     * @param targetActuators Target group actuators union set.
     * @return true if all required sensors and actuators are available; false otherwise.
     */
    private static boolean isMethodFeasible(
            JSONObject requirements,
            Set<String> reqSensors,
            Set<String> reqActuators,
            Set<String> targetSensors,
            Set<String> targetActuators) {

        if (requirements == null) return true;

        // Verify requester requirements
        if (requirements.containsKey("requester")) {
            JSONObject reqObj = (JSONObject) requirements.get("requester");
            Set<String> neededSensors = parseResourceSet(reqObj, "sensors");
            if (!reqSensors.containsAll(neededSensors)) return false;

            Set<String> neededActuators = parseResourceSet(reqObj, "actuators");
            if (!reqActuators.containsAll(neededActuators)) return false;
        }

        // Verify target requirements
        if (requirements.containsKey("target")) {
            JSONObject tgtObj = (JSONObject) requirements.get("target");
            Set<String> neededSensors = parseResourceSet(tgtObj, "sensors");
            if (!targetSensors.containsAll(neededSensors)) return false;

            Set<String> neededActuators = parseResourceSet(tgtObj, "actuators");
            if (!targetActuators.containsAll(neededActuators)) return false;
        }

        return true;
    }

    /**
     * Helper method to lookup a physical challenge definition by check ID (case-insensitive).
     */
    private static PhysicalChallengeTable findChallengeDefinition(List<PhysicalChallengeTable> defs, String checkID) {
        if (defs == null) return null;
        for (PhysicalChallengeTable def : defs) {
            if (checkID.equalsIgnoreCase(def.getCheckID())) {
                return def;
            }
        }
        return null;
    }

    /**
     * Helper method to parse registered resources from a RegisteredEntity database object.
     */
    private static Set<String> parseResourcesFromEntity(RegisteredEntity entity, String key) {
        if (entity == null || entity.getResources() == null) return new LinkedHashSet<>();
        try {
            JSONObject obj = (JSONObject) new JSONParser().parse(entity.getResources());
            return parseResourceSet(obj, key);
        } catch (ParseException e) {
            logger.error("Failed to parse entity resources for {}: {}", entity.getName(), e.getMessage());
            return new LinkedHashSet<>();
        }
    }

    /**
     * Helper method to parse a comma-separated string or JSONArray of resources into a LinkedHashSet.
     */
    private static Set<String> parseResourceSet(JSONObject resources, String key) {
        Set<String> result = new LinkedHashSet<>();
        if (resources == null || !resources.containsKey(key)) {
            return result;
        }
        Object val = resources.get(key);
        if (val instanceof JSONArray) {
            for (Object item : (JSONArray) val) {
                String s = item.toString().trim();
                if (!s.isEmpty()) result.add(s);
            }
        } else if (val instanceof String) {
            for (String s : ((String) val).split(",")) {
                String t = s.trim();
                if (!t.isEmpty()) result.add(t);
            }
        }
        return result;
    }
}
