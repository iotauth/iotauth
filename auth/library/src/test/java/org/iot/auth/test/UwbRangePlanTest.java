package org.iot.auth.test;

import org.iot.auth.challenge.FeasibleChallengeMatcher;
import org.iot.auth.db.*;
import org.iot.auth.db.bean.*;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.junit.Test;
import java.util.*;
import static org.junit.Assert.*;

public class UwbRangePlanTest {
    private static final String PARAMS = "{\"max_distance_cm\":150,\"samples\":20,\"timeout_ms\":10000}";

    private JSONObject json(String s) throws Exception { return (JSONObject)new JSONParser().parse(s); }
    private RegisteredEntity entity(String name, boolean rx, boolean tx) {
        return new RegisteredEntity(new RegisteredEntityTable().setName(name)
                .setDistKeyValidityPeriod("1*hour").setDistCryptoSpec("AES-128-CBC:SHA256")
                .setResources("{\"sensors\":" + (rx ? "[\"UWB\"]" : "[]")
                        + ",\"actuators\":" + (tx ? "[\"UWB\"]" : "[]") + "}"), null);
    }
    private JSONObject plan(RegisteredEntity requester, JSONObject runtime, List<RegisteredEntity> targets,
                            String params) {
        CommunicationPolicy policy = new CommunicationPolicy(new CommunicationPolicyTable()
                .setSessionCryptoSpec("AES-128-CBC:SHA256")
                .setContext("{\"PhysicalPresenceRequirements\":[\"CO_LOCATION\"]}"));
        PhysicalChallengeTable uwb = new PhysicalChallengeTable().setCheckID("CO_LOCATION").setTopology("MUTUAL")
                // Empty catalog requirements must not bypass the mutual capability checks.
                .setMethods("[{\"id\":\"UWB\",\"requirements\":{},\"parameters\":" + params + "}]");
        return FeasibleChallengeMatcher.computeFeasibleChallenges(requester, runtime, targets, policy,
                Collections.singletonList(uwb));
    }
    private Object selected(JSONObject plan) {
        return ((JSONObject)((JSONObject)plan.get("verificationPlan")).get("CO_LOCATION")).get("selectedMethod");
    }

    @Test public void requiresUwbAtBothEndsAndExactlyOneTarget() throws Exception {
        RegisteredEntity robot = entity("robot", true, true), locker = entity("locker", true, true);
        assertNotNull(selected(plan(robot, null, Collections.singletonList(locker), PARAMS)));
        assertNull(selected(plan(entity("robot", false, true), null, Collections.singletonList(locker), PARAMS)));
        assertNull(selected(plan(entity("robot", true, false), null, Collections.singletonList(locker), PARAMS)));
        assertNull(selected(plan(robot, null, Collections.singletonList(entity("locker", true, false)), PARAMS)));
        assertNull(selected(plan(robot, null, Collections.singletonList(entity("locker", false, true)), PARAMS)));
        assertNull(selected(plan(robot, null, Arrays.asList(locker, entity("locker2", true, true)), PARAMS)));
        assertNull(selected(plan(robot, null, Collections.emptyList(), PARAMS)));
        // Runtime resources that drop the radio make the requester ineligible.
        assertNull(selected(plan(robot, json("{\"sensors\":[],\"actuators\":[\"UWB\"]}"),
                Collections.singletonList(locker), PARAMS)));
    }

    @Test public void validatesUwbParameters() throws Exception {
        FeasibleChallengeMatcher.validateUwbParameters(json(PARAMS));
        FeasibleChallengeMatcher.validateUwbParameters(
                json("{\"max_distance_cm\":1,\"samples\":1,\"timeout_ms\":1}"));
        FeasibleChallengeMatcher.validateUwbParameters(
                json("{\"max_distance_cm\":10000,\"samples\":100,\"timeout_ms\":60000}"));
        String[] invalid = {
            "{\"max_distance_cm\":150.5,\"samples\":20,\"timeout_ms\":10000}",
            "{\"max_distance_cm\":\"150\",\"samples\":20,\"timeout_ms\":10000}",
            "{\"max_distance_cm\":0,\"samples\":20,\"timeout_ms\":10000}",
            "{\"max_distance_cm\":10001,\"samples\":20,\"timeout_ms\":10000}",
            "{\"max_distance_cm\":150,\"samples\":0,\"timeout_ms\":10000}",
            "{\"max_distance_cm\":150,\"samples\":101,\"timeout_ms\":10000}",
            "{\"max_distance_cm\":150,\"samples\":20,\"timeout_ms\":0}",
            "{\"max_distance_cm\":150,\"samples\":20,\"timeout_ms\":60001}",
            "{\"samples\":20,\"timeout_ms\":10000}",
            "{\"max_distance_cm\":150,\"timeout_ms\":10000}",
            "{\"max_distance_cm\":150,\"samples\":20}"};
        for (String s : invalid) {
            try { FeasibleChallengeMatcher.validateUwbParameters(json(s)); fail(s); }
            catch (IllegalArgumentException expected) { /* no key should be issued */ }
        }
        try { FeasibleChallengeMatcher.validateUwbParameters(null); fail("null"); }
        catch (IllegalArgumentException expected) { }
    }
}
