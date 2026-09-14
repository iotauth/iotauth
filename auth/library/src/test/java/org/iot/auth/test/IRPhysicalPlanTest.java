package org.iot.auth.test;

import org.iot.auth.challenge.FeasibleChallengeMatcher;
import org.iot.auth.crypto.SessionKey;
import org.iot.auth.crypto.SymmetricKeyCryptoSpec;
import org.iot.auth.db.*;
import org.iot.auth.db.bean.*;
import org.iot.auth.db.dao.SQLiteConnector;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.junit.Test;
import java.nio.file.*;
import java.util.*;
import static org.junit.Assert.*;

public class IRPhysicalPlanTest {
    private JSONObject json(String s) throws Exception { return (JSONObject)new JSONParser().parse(s); }
    private RegisteredEntity entity(String name, boolean rx, boolean tx) {
        return new RegisteredEntity(new RegisteredEntityTable().setName(name)
                .setDistKeyValidityPeriod("1*hour").setDistCryptoSpec("AES-128-CBC:SHA256")
                .setResources("{\"sensors\":" + (rx ? "[\"IR\"]" : "[]")
                        + ",\"actuators\":" + (tx ? "[\"IR\"]" : "[]") + "}"), null);
    }
    private JSONObject plan(RegisteredEntity requester, JSONObject runtime, List<RegisteredEntity> targets) {
        CommunicationPolicy policy = new CommunicationPolicy(new CommunicationPolicyTable()
                .setSessionCryptoSpec("AES-128-CBC:SHA256")
                .setContext("{\"PhysicalPresenceRequirements\":[\"CO_LOCATION\"]}"));
        PhysicalChallengeTable ir = new PhysicalChallengeTable().setCheckID("CO_LOCATION").setTopology("MUTUAL")
                // Empty catalog requirements must not bypass the mutual IR capability checks.
                .setMethods("[{\"id\":\"IR\",\"requirements\":{},\"parameters\":{\"rounds\":32,\"success_threshold\":0.8,\"max_delay_us\":1000}}]");
        return FeasibleChallengeMatcher.computeFeasibleChallenges(requester, runtime, targets, policy,
                Collections.singletonList(ir));
    }
    private Object selected(JSONObject plan) {
        return ((JSONObject)((JSONObject)plan.get("verificationPlan")).get("CO_LOCATION")).get("selectedMethod");
    }
    @Test public void requiresTransmitterAndReceiverAtEachEndpoint() throws Exception {
        RegisteredEntity a = entity("robot", true, true), b = entity("locker", true, true);
        assertNotNull(selected(plan(a, null, Collections.singletonList(b))));
        assertNull(selected(plan(entity("robot", false, true), null, Collections.singletonList(b))));
        assertNull(selected(plan(a, null, Collections.singletonList(entity("locker", true, false)))));
        assertNull(selected(plan(a, null, Arrays.asList(entity("one", true, false), entity("two", false, true)))));
        assertNull(selected(plan(a, json("{\"sensors\":[],\"actuators\":[\"IR\"]}"), Collections.singletonList(b))));
        assertNull(selected(plan(a, null, Collections.emptyList())));
    }
    @Test public void validatesAuthParameters() throws Exception {
        for (int rounds : new int[]{32,64,128}) {
            FeasibleChallengeMatcher.validateIRParameters(json("{\"rounds\":"+rounds+",\"success_threshold\":0.8,\"max_delay_us\":1000}"));
        }
        String[] invalid = {"{\"rounds\":31,\"success_threshold\":0.8,\"max_delay_us\":1000}",
            "{\"rounds\":32,\"success_threshold\":0,\"max_delay_us\":1000}",
            "{\"rounds\":32,\"success_threshold\":1.01,\"max_delay_us\":1000}",
            "{\"rounds\":32,\"success_threshold\":0.8000001,\"max_delay_us\":1000}",
            "{\"rounds\":32,\"success_threshold\":0.8,\"max_delay_us\":0}",
            "{\"rounds\":32,\"success_threshold\":\"0.8\",\"max_delay_us\":1000}",
            "{\"rounds\":32,\"max_delay_us\":1000}"};
        for (String s : invalid) {
            try { FeasibleChallengeMatcher.validateIRParameters(json(s)); fail(s); }
            catch (IllegalArgumentException expected) { /* no key should be issued */ }
        }
    }
    @Test public void originalPlanSurvivesDatabaseAndOwnerAddition() throws Exception {
        String challenge = plan(entity("robot",true,true), null,
                Collections.singletonList(entity("locker",true,true))).toJSONString();
        SymmetricKeyCryptoSpec spec = SymmetricKeyCryptoSpec.fromSpecString("AES-128-CBC:SHA256");
        spec.setChallenge(challenge);
        SessionKey key = new SessionKey(42, new String[]{"robot"}, 2, "Action:RETRIEVE_ITEM",
                System.currentTimeMillis()+60000, 60000, spec, null);
        Path file = Files.createTempFile("ir-plan-", ".db");
        SQLiteConnector db = new SQLiteConnector(file.toString(), AuthDBProtectionMethod.DEBUG);
        try {
            db.initialize((org.iot.auth.crypto.SymmetricKey)null);
            db.createTablesIfNotExists();
            db.insertRecords(CachedSessionKeyTable.fromSessionKey(key));
            db.appendSessionKeyOwner(42, "locker");
            SessionKey restored = db.selectCachedSessionKeyByID(42).toSessionKey();
            assertEquals(challenge, restored.getCryptoSpec().getChallenge());
            assertArrayEquals(key.getSerializedKeyVal().getRawBytes(), restored.getSerializedKeyVal().getRawBytes());
            assertTrue(Arrays.asList(restored.getOwners()).contains("locker"));
        } finally { db.close(); Files.deleteIfExists(file); }
        CachedSessionKeyTable legacy = CachedSessionKeyTable.fromSessionKey(key);
        legacy.setSessionCryptoSpec("AES-128-CBC:SHA256");
        assertEquals("", legacy.toSessionKey().getCryptoSpec().getChallenge());
    }
}
