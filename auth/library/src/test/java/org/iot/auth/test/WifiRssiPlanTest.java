package org.iot.auth.test;

import org.iot.auth.challenge.FeasibleChallengeMatcher;
import org.iot.auth.db.*;
import org.iot.auth.db.bean.*;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.junit.Test;
import java.util.*;
import static org.junit.Assert.*;

public class WifiRssiPlanTest {
    private static final String PARAMS = "{\"min_rssi_dbm\":-60,\"samples\":20,\"interval_ms\":100}";

    private JSONObject json(String s) throws Exception { return (JSONObject)new JSONParser().parse(s); }
    private RegisteredEntity entity(String name, boolean rx, boolean tx) {
        return new RegisteredEntity(new RegisteredEntityTable().setName(name)
                .setDistKeyValidityPeriod("1*hour").setDistCryptoSpec("AES-128-CBC:SHA256")
                .setResources("{\"sensors\":" + (rx ? "[\"WiFi\"]" : "[]")
                        + ",\"actuators\":" + (tx ? "[\"WiFi\"]" : "[]") + "}"), null);
    }
    private JSONObject plan(RegisteredEntity requester, JSONObject runtime, List<RegisteredEntity> targets,
                            String params) {
        CommunicationPolicy policy = new CommunicationPolicy(new CommunicationPolicyTable()
                .setSessionCryptoSpec("AES-128-CBC:SHA256")
                .setContext("{\"PhysicalPresenceRequirements\":[\"CO_LOCATION\"],"
                        + "\"PhysicalPresenceFreshnessMs\":{\"CO_LOCATION\":10000}}"));
        PhysicalChallengeTable wifi = new PhysicalChallengeTable().setCheckID("CO_LOCATION").setTopology("MUTUAL")
                // Empty catalog requirements must not bypass the mutual capability checks.
                .setMethods("[{\"id\":\"WIFI_RSSI\",\"requirements\":{},\"parameters\":" + params + "}]");
        return FeasibleChallengeMatcher.computeFeasibleChallenges(requester, runtime, targets, policy,
                Collections.singletonList(wifi));
    }
    private Object selected(JSONObject plan) {
        return ((JSONObject)((JSONObject)plan.get("verificationPlan")).get("CO_LOCATION")).get("selectedMethod");
    }

    @Test public void requiresWifiAtBothEndsAndExactlyOneTarget() throws Exception {
        RegisteredEntity robot = entity("robot", true, true), locker = entity("locker", true, true);
        assertNotNull(selected(plan(robot, null, Collections.singletonList(locker), PARAMS)));
        assertNull(selected(plan(entity("robot", false, true), null, Collections.singletonList(locker), PARAMS)));
        assertNull(selected(plan(entity("robot", true, false), null, Collections.singletonList(locker), PARAMS)));
        assertNull(selected(plan(robot, null, Collections.singletonList(entity("locker", true, false)), PARAMS)));
        assertNull(selected(plan(robot, null, Collections.singletonList(entity("locker", false, true)), PARAMS)));
        assertNull(selected(plan(robot, null, Arrays.asList(locker, entity("locker2", true, true)), PARAMS)));
        assertNull(selected(plan(robot, null, Collections.emptyList(), PARAMS)));
        // Runtime resources that drop the radio make the requester ineligible.
        assertNull(selected(plan(robot, json("{\"sensors\":[],\"actuators\":[\"WiFi\"]}"),
                Collections.singletonList(locker), PARAMS)));
    }

    @Test public void validatesRssiParameters() throws Exception {
        FeasibleChallengeMatcher.validateWifiRssiParameters(json(PARAMS));
        FeasibleChallengeMatcher.validateWifiRssiParameters(
                json("{\"min_rssi_dbm\":-127,\"samples\":1,\"interval_ms\":0}"));
        FeasibleChallengeMatcher.validateWifiRssiParameters(
                json("{\"min_rssi_dbm\":20,\"samples\":1000,\"interval_ms\":1000}"));
        String[] invalid = {
            "{\"min_rssi_dbm\":-60.5,\"samples\":20,\"interval_ms\":100}",
            "{\"min_rssi_dbm\":\"-60\",\"samples\":20,\"interval_ms\":100}",
            "{\"min_rssi_dbm\":-128,\"samples\":20,\"interval_ms\":100}",
            "{\"min_rssi_dbm\":21,\"samples\":20,\"interval_ms\":100}",
            "{\"min_rssi_dbm\":-60,\"samples\":0,\"interval_ms\":100}",
            "{\"min_rssi_dbm\":-60,\"samples\":1001,\"interval_ms\":100}",
            "{\"min_rssi_dbm\":-60,\"samples\":20,\"interval_ms\":-1}",
            "{\"min_rssi_dbm\":-60,\"samples\":20,\"interval_ms\":1001}",
            "{\"samples\":20,\"interval_ms\":100}",
            "{\"min_rssi_dbm\":-60,\"interval_ms\":100}",
            "{\"min_rssi_dbm\":-60,\"samples\":20}"};
        for (String s : invalid) {
            try { FeasibleChallengeMatcher.validateWifiRssiParameters(json(s)); fail(s); }
            catch (IllegalArgumentException expected) { /* no key should be issued */ }
        }
        try { FeasibleChallengeMatcher.validateWifiRssiParameters(null); fail("null"); }
        catch (IllegalArgumentException expected) { }
    }
}
