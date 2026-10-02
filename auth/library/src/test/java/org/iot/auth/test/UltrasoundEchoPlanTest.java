package org.iot.auth.test;

import org.iot.auth.challenge.FeasibleChallengeMatcher;
import org.iot.auth.db.*;
import org.iot.auth.db.bean.*;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.junit.Test;
import java.util.*;
import static org.junit.Assert.*;

public class UltrasoundEchoPlanTest {
    private static final String PARAMS = "{\"max_response_us\":5000000,\"response_timeout_ms\":10000}";

    private JSONObject json(String s) throws Exception { return (JSONObject)new JSONParser().parse(s); }
    private RegisteredEntity entity(String name, boolean mic, boolean speaker) {
        return new RegisteredEntity(new RegisteredEntityTable().setName(name)
                .setDistKeyValidityPeriod("1*hour").setDistCryptoSpec("AES-128-CBC:SHA256")
                .setResources("{\"sensors\":" + (mic ? "[\"UltraSound\"]" : "[]")
                        + ",\"actuators\":" + (speaker ? "[\"UltraSound\"]" : "[]") + "}"), null);
    }
    private JSONObject plan(RegisteredEntity requester, JSONObject runtime, List<RegisteredEntity> targets,
                            String params) {
        CommunicationPolicy policy = new CommunicationPolicy(new CommunicationPolicyTable()
                .setSessionCryptoSpec("AES-128-CBC:SHA256")
                .setContext("{\"PhysicalPresenceRequirements\":[\"CO_LOCATION\"]}"));
        PhysicalChallengeTable echo = new PhysicalChallengeTable().setCheckID("CO_LOCATION").setTopology("MUTUAL")
                // Empty catalog requirements must not bypass the mutual capability checks.
                .setMethods("[{\"id\":\"ULTRASOUND\",\"requirements\":{},\"parameters\":" + params + "}]");
        return FeasibleChallengeMatcher.computeFeasibleChallenges(requester, runtime, targets, policy,
                Collections.singletonList(echo));
    }
    private Object selected(JSONObject plan) {
        return ((JSONObject)((JSONObject)plan.get("verificationPlan")).get("CO_LOCATION")).get("selectedMethod");
    }

    @Test public void requiresMicAndSpeakerAtBothEndsAndExactlyOneTarget() throws Exception {
        RegisteredEntity robot = entity("robot", true, true), locker = entity("locker", true, true);
        assertNotNull(selected(plan(robot, null, Collections.singletonList(locker), PARAMS)));
        assertNull(selected(plan(entity("robot", false, true), null, Collections.singletonList(locker), PARAMS)));
        assertNull(selected(plan(entity("robot", true, false), null, Collections.singletonList(locker), PARAMS)));
        assertNull(selected(plan(robot, null, Collections.singletonList(entity("locker", true, false)), PARAMS)));
        assertNull(selected(plan(robot, null, Collections.singletonList(entity("locker", false, true)), PARAMS)));
        assertNull(selected(plan(robot, null, Arrays.asList(locker, entity("locker2", true, true)), PARAMS)));
        assertNull(selected(plan(robot, null, Collections.emptyList(), PARAMS)));
        // Runtime resources that drop the microphone make the requester ineligible.
        assertNull(selected(plan(robot, json("{\"sensors\":[],\"actuators\":[\"UltraSound\"]}"),
                Collections.singletonList(locker), PARAMS)));
    }

    @Test public void planNamesBothParties() throws Exception {
        JSONObject p = plan(entity("robot", true, true), null,
                Collections.singletonList(entity("locker", true, true)), PARAMS);
        assertEquals("robot", p.get("requester"));
        JSONArray targets = (JSONArray) p.get("targets");
        assertEquals(1, targets.size());
        assertEquals("locker", targets.get(0));
    }

    @Test public void validatesEchoParameters() throws Exception {
        FeasibleChallengeMatcher.validateUltrasoundEchoParameters(json(PARAMS));
        FeasibleChallengeMatcher.validateUltrasoundEchoParameters(
                json("{\"max_response_us\":10000000,\"response_timeout_ms\":10000}"));
        String[] invalid = {
            "{\"rounds\":64,\"max_delay_us\":2000}",
            "{\"max_response_us\":5000000,\"response_timeout_ms\":10000,\"rounds\":64}",
            "{\"max_response_us\":5000000,\"response_timeout_ms\":10000,\"max_delay_us\":2000}",
            "{\"max_response_us\":5000000.5,\"response_timeout_ms\":10000}",
            "{\"max_response_us\":\"5000000\",\"response_timeout_ms\":10000}",
            "{\"max_response_us\":0,\"response_timeout_ms\":10000}",
            "{\"max_response_us\":5000000,\"response_timeout_ms\":0}",
            "{\"max_response_us\":60000001,\"response_timeout_ms\":60000}",
            "{\"max_response_us\":5000000,\"response_timeout_ms\":60001}",
            "{\"max_response_us\":5000001,\"response_timeout_ms\":5000}",
            "{\"max_response_us\":5000000}",
            "{\"response_timeout_ms\":10000}"};
        for (String s : invalid) {
            try { FeasibleChallengeMatcher.validateUltrasoundEchoParameters(json(s)); fail(s); }
            catch (IllegalArgumentException expected) { /* no key should be issued */ }
        }
        try { FeasibleChallengeMatcher.validateUltrasoundEchoParameters(null); fail("null"); }
        catch (IllegalArgumentException expected) { }
    }
}
