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

public class FreshnessPlanTest {
    private JSONObject json(String s) throws Exception { return (JSONObject)new JSONParser().parse(s); }
    private RegisteredEntity entity(String name) {
        return new RegisteredEntity(new RegisteredEntityTable().setName(name)
                .setDistKeyValidityPeriod("1*hour").setDistCryptoSpec("AES-128-CBC:SHA256")
                .setResources("{\"sensors\":[\"WiFi\"],\"actuators\":[\"WiFi\"]}"), null);
    }
    private JSONObject plan(String context, JSONObject runtime) {
        CommunicationPolicy policy = new CommunicationPolicy(new CommunicationPolicyTable()
                .setSessionCryptoSpec("AES-128-CBC:SHA256").setContext(context));
        // A catalog entry trying to set its own freshness must not override the policy's bound.
        PhysicalChallengeTable wifi = new PhysicalChallengeTable().setCheckID("CO_LOCATION").setTopology("MUTUAL")
                .setMethods("[{\"id\":\"WIFI_RSSI\",\"requirements\":{},\"freshness_ms\":600000,"
                        + "\"parameters\":{\"min_rssi_dbm\":-60,\"samples\":20,\"interval_ms\":100}}]");
        PhysicalChallengeTable human = new PhysicalChallengeTable().setCheckID("HUMAN_PRESENCE").setTopology("LOCAL")
                .setMethods("[{\"id\":\"DUMMY\",\"requirements\":{}}]");
        return FeasibleChallengeMatcher.computeFeasibleChallenges(entity("robot"), runtime,
                Collections.singletonList(entity("locker")), policy, Arrays.asList(wifi, human));
    }
    private JSONObject check(JSONObject plan, String id) {
        return (JSONObject)((JSONObject)plan.get("verificationPlan")).get(id);
    }
    private static String ctx(String checks, String bounds) {
        return "{\"PhysicalPresenceRequirements\":" + checks + ",\"PhysicalPresenceFreshnessMs\":" + bounds + "}";
    }
    private void rejected(String context) {
        try { plan(context, null); fail(context); }
        catch (IllegalArgumentException expected) { /* no key should be issued */ }
    }

    @Test public void carriesEachPolicyBoundUnchanged() throws Exception {
        JSONObject p = plan(ctx("[\"HUMAN_PRESENCE\",\"CO_LOCATION\"]",
                "{\"HUMAN_PRESENCE\":1000,\"CO_LOCATION\":10000}"), null);
        assertEquals(10000L, check(p, "CO_LOCATION").get("freshness_ms"));
        assertEquals(1000L, check(p, "HUMAN_PRESENCE").get("freshness_ms"));
        // Outside the method's parameters, which stay as the catalog gave them.
        JSONObject params = (JSONObject)((JSONObject)check(p, "CO_LOCATION").get("selectedMethod")).get("parameters");
        assertFalse(params.containsKey("freshness_ms"));
        // Both range limits are accepted.
        assertEquals(1L, check(plan(ctx("[\"CO_LOCATION\"]", "{\"CO_LOCATION\":1}"), null),
                "CO_LOCATION").get("freshness_ms"));
        assertEquals(600000L, check(plan(ctx("[\"CO_LOCATION\"]", "{\"CO_LOCATION\":600000}"), null),
                "CO_LOCATION").get("freshness_ms"));
    }

    @Test public void requesterInputCannotSetTheBound() throws Exception {
        JSONObject runtime = json("{\"sensors\":[\"WiFi\"],\"actuators\":[\"WiFi\"],\"freshness_ms\":600000,"
                + "\"PhysicalPresenceFreshnessMs\":{\"CO_LOCATION\":600000}}");
        JSONObject p = plan(ctx("[\"CO_LOCATION\"]", "{\"CO_LOCATION\":5000}"), runtime);
        assertEquals(5000L, check(p, "CO_LOCATION").get("freshness_ms"));
    }

    @Test public void rejectsMissingOrInvalidBounds() {
        String req = "[\"CO_LOCATION\"]";
        rejected("{\"PhysicalPresenceRequirements\":" + req + "}");                // no map: no default
        rejected(ctx(req, "{}"));
        rejected(ctx(req, "{\"HUMAN_PRESENCE\":1000}"));                          // other check only
        rejected(ctx(req, "{\"CO_LOCATION\":0}"));
        rejected(ctx(req, "{\"CO_LOCATION\":-1}"));
        rejected(ctx(req, "{\"CO_LOCATION\":600001}"));
        rejected(ctx(req, "{\"CO_LOCATION\":1000.5}"));
        rejected(ctx(req, "{\"CO_LOCATION\":\"1000\"}"));
        rejected(ctx(req, "{\"CO_LOCATION\":null}"));
        rejected(ctx(req, "[1000]"));
        // Every required check needs its own bound.
        rejected(ctx("[\"HUMAN_PRESENCE\",\"CO_LOCATION\"]", "{\"CO_LOCATION\":1000}"));
    }

    @Test public void rejectsMalformedContextInsteadOfDroppingChecks() {
        rejected("{\"PhysicalPresenceRequirements\":[\"CO_LOCATION\"]");          // truncated JSON
        rejected("[\"CO_LOCATION\"]");                                             // not an object
        rejected(ctx("\"CO_LOCATION\"", "{\"CO_LOCATION\":1000}"));                 // not an array
        rejected(ctx("[\"CO_LOCATION\",\"CO_LOCATION\"]", "{\"CO_LOCATION\":1000}"));
        rejected(ctx("[1]", "{\"1\":1000}"));
    }

    @Test public void conventionalPoliciesAreUnaffected() throws Exception {
        for (String context : new String[] {null, "", "{}", "{\"Location\":{\"Allowed\":[\"Lab\"]}}",
                "{\"PhysicalPresenceRequirements\":[]}"}) {
            JSONObject p = plan(context, null);
            assertTrue(context, ((JSONArray)p.get("requiredChecks")).isEmpty());
            assertTrue(context, ((JSONObject)p.get("verificationPlan")).isEmpty());
        }
    }

    @Test public void boundHelperMatchesEndpointRange() throws Exception {
        assertEquals(600000L, FeasibleChallengeMatcher.MAX_FRESHNESS_MS);
        assertEquals(7L, FeasibleChallengeMatcher.freshnessBoundMs(
                json("{\"PhysicalPresenceFreshnessMs\":{\"X\":7}}"), "X"));
        try { FeasibleChallengeMatcher.freshnessBoundMs(null, "X"); fail(); }
        catch (IllegalArgumentException expected) { }
    }
}
