package org.iot.auth.optimization;

import org.iot.auth.util.SSTGraph;
import org.iot.auth.util.SSTVar;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import com.google.common.collect.ImmutableMap;

import java.util.*;

/**
 * MigrationEngine
 *
 *Performs an optimization task to find the most desirable
 * migration plan from one topology to another.
 *
 */
public class MigrationEngine {
    public final static String DELIM = "_";
    public final static int SOLVER_GRUBI = 0;
    public final static int SOLVER_OJALGO = 1;
    public final static int DEFAULT_SOLVER = SOLVER_GRUBI;

    /**
     * Find an otpimal migration plan for the given network, with
     */
    public static MigrationPlan findMigratePlan(SSTGraph network, final double weightThings, final double weightAuth) throws IllegalAccessException {
       return findMigratePlan(network, weightThings, weightAuth, DEFAULT_SOLVER);
    }

    /**
     * Find an optimal migration plan for the given network.
     *
     * @param network The SST network, with possibly one or more things disconnected from an Auth.
     * @param weightThings The contribution of the things to the overall migration cost.
     * @param weightAuth The contribution of the auth to the overall cost.
     * @param solverType The ILP solver used.
     * @return An optimal migration plan.
     */
    public static MigrationPlan findMigratePlan(SSTGraph network, final double weightThings, final double weightAuth, int solverType) throws IllegalAccessException {

        Solver solver = null;
        switch (solverType) {
            case SOLVER_GRUBI:
                solver = new SolverGurobi();
                break;
            case SOLVER_OJALGO:
                solver = new SolverOjAlgo();
                break;
            default:
                throw new IllegalAccessException("Invalid solver type specified: " + solverType);
        }

        final Map<SSTGraph.SSTEdge, SSTVar> varmap = new HashMap<SSTGraph.SSTEdge, SSTVar>();

        // Construct a variable for possible things to Auth connection
        for (SSTGraph.SSTNode a : network.auths()){
            for (SSTGraph.SSTNode t : network.things()) {
                SSTGraph.SSTEdge costAT = network.lookupEdge(a, t, SSTGraph.EdgeType.AT_COST);
                if (costAT == null) continue;
                SSTGraph.SSTEdge costTA = network.lookupEdge(t, a, SSTGraph.EdgeType.TA_COST);
                SSTGraph.SSTEdge connected = network.lookupEdge(a, t, SSTGraph.EdgeType.AT_CONNECTED);
                SSTVar var;
                double thingCost = 0;
                double authCost = 0;

                /**
                 * Computing Things cost induced by "t"
                 */
                // for every thing that "t" needs to communicate to:
                for (SSTGraph.SSTEdge e : network.lookupEdgesFrom(t, SSTGraph.EdgeType.TT_REQ)){
                    thingCost += costTA.weight;
                }

                /**
                 * Computing Auth cost induced by "t"
                 */
                // for every thing that "t" needs to communicate to:
                for (SSTGraph.SSTEdge e : network.lookupEdgesFrom(t, SSTGraph.EdgeType.TT_REQ)){
                    authCost += costAT.weight;
                }

                double totalCost = weightAuth*authCost + weightThings*thingCost;

                if (connected != null) {
                    // thing "t" is already connected to "a" and must remain so
                    var = solver.addBinaryVar(SSTGraph.CONNECTED + "_"+ a + "_" + t, 1, 1, totalCost);
                } else {
                    // thing "t" may become connected to "a" in the new network
                    var = solver.addBinaryVar(SSTGraph.CONNECTED + "_" + a + "_" + t, 0, 1, totalCost);
                }
                varmap.put(costAT, var);
            }
        }

        // Construct a variable for possible Auth to Auth communication
        for (SSTGraph.SSTNode tx : network.things()){
            for (SSTGraph.SSTEdge e : network.lookupEdgesFrom(tx, SSTGraph.EdgeType.TT_REQ)){
                SSTGraph.SSTNode ty = e.to;
                // there exists a communication requirement from tx to ty
                Set<SSTVar> x2yVars = new HashSet<SSTVar>();
                for (SSTGraph.SSTEdge ex : network.lookupEdgesTo(tx, SSTGraph.EdgeType.AT_COST)) {
                    for (SSTGraph.SSTEdge ey : network.lookupEdgesTo(ty, SSTGraph.EdgeType.AT_COST)) {
                        SSTGraph.SSTNode ax = ex.from;
                        SSTGraph.SSTNode ay = ey.from;
                        // tx may communicate to ty through (ax, ay)
                        SSTGraph.SSTEdge aa = network.lookupEdge(ax, ay, SSTGraph.EdgeType.AA_COST);
                        if (aa == null) continue;
                        String name = "edge_" + tx + "_" + ax + "_" + ay + "_" + ty;
                        SSTVar var = solver.addBinaryVar(name, 0, 1, aa.weight*weightAuth);
                        varmap.put(e, var);
                        x2yVars.add(var);
                        name = "prod_" + tx + "_" + ax + "_" + ay + "_" + ty;
                        final SSTVar vx = varmap.get(ex);
                        final SSTVar vy = varmap.get(ey);
                        /**
                         * var itself is a product of vx & vy
                         */
                        // var <= vx (i.e., var - vx <= 0)
                        //model.addExpression(name+"_A").upper(0).set(var,1).set(vx,-1);
                        solver.addLTE(name+"_A", ImmutableMap.of(var, Double.valueOf(1), vx, Double.valueOf(-1)), 0);

                        // var <= vy
                        //model.addExpression(name+"_B").upper(0).set(var,1).set(vy,-1);
                        solver.addLTE(name+"_B", ImmutableMap.of(var, Double.valueOf(1), vy, Double.valueOf(-1)), 0);

                        // var >= vx + vy - 1
                        //model.addExpression(name+"_C").lower(-1).set(var,1).set(vx,-1).set(vy,-1);
                        solver.addGTE(name+"_C",
                                ImmutableMap.of(var, Double.valueOf(1), vx, Double.valueOf(-1), vy, Double.valueOf(-1)), -1);
                    }
                }
                if (!x2yVars.isEmpty()){
                    Map<SSTVar, Double> m = new HashMap<SSTVar, Double>();
                    for (SSTVar v : x2yVars){
                        m.put(v, Double.valueOf(1));
                    }
                    solver.addBetween("disj_" + tx + ty, m, 0, 1);
                }
            }
        }

        // Constraint that each thing can be connected to at most one Auth
        for (SSTGraph.SSTNode t : network.things()){
            Set<SSTGraph.SSTEdge> edges = network.lookupEdgesTo(t, SSTGraph.EdgeType.AT_COST);
            if (edges.isEmpty()) continue;
            Map<SSTVar, Double> m = new HashMap<SSTVar, Double>();
            for (SSTGraph.SSTEdge e : edges){
                m.put(varmap.get(e), Double.valueOf(1));
            }
            solver.addEQ("disj_" + t, m, 1);
        }

        // Constraint that each Auth is connected to no more than the number of things that it has capacity for
        for (SSTGraph.SSTNode a : network.auths()){
            Set<SSTGraph.SSTEdge> edges = network.lookupEdgesFrom(a, SSTGraph.EdgeType.AT_COST);
            if (edges.isEmpty()) continue;
            Map<SSTVar, Double> m = new HashMap<SSTVar, Double>();
            for (SSTGraph.SSTEdge e : edges){
                m.put(varmap.get(e), Double.valueOf(1));
            }
            solver.addBetween("authCap_" + a, m, 0, network.authCap(a));
        }
        //solver.write("model.lp");
        solver.minimize();
        MigrationPlan p = new MigrationPlan(network,
                solver.varsWithVal(new HashSet<SSTVar>(varmap.values()), 1),
                solver.cost());
        //solver.dispose();
        return p;
    }

    /**
     * Construct a JSON object for the given SST network n
     * including migration plan for each thing, assuming that
     * the auth to which the thing is connected may experience a failure.
     *
     * @param n SST network.
     * @param weightThings Weight for the cost of the things.
     * @param weightAuth Weight for the cost of the auths.
     * @return JSON object.
     */
    public static JSONObject mkJSON(SSTGraph n, double weightThings, double weightAuth) throws IllegalAccessException{

        JSONObject overall = new JSONObject();

        int numAuths = n.auths().size();
        List<SSTGraph.SSTNode> auths = new ArrayList<SSTGraph.SSTNode>(n.auths());
        Map<String,String> moveTo = new HashMap<String,String>();

        JSONArray authlist = new JSONArray();
        JSONArray echoServerList = new JSONArray();
        JSONArray autoClientList = new JSONArray();

        for (SSTGraph.SSTNode a : auths) {
            JSONObject o = new JSONObject();
            o.put("id", a.id);
            authlist.add(o);

            // remove the auth "a" from the original network
            // and generate the migration plan
            SSTGraph n2 = n.destroyAuth(a);
            MigrationPlan p = findMigratePlan(n2, weightThings, weightAuth);
            for (String t : p.thingsToMove()){
                moveTo.put(t, p.moveTo(t));
            }
        }

        // create "echoServerList" and "authClientList"
        for (SSTGraph.SSTNode t : n.things()) {
            String backup = "none";
            if (moveTo.containsKey(t.id))
                backup = moveTo.get(t.id);
            JSONObject o = new JSONObject();
            if (!n.isClient(t.id)) {
                o.put("name", t);
                o.put("backupTo", backup);
                echoServerList.add(o);
            } else {
                o.put("name", t);
                o.put("target", n.getServer(t.id));
                o.put("backupTo", backup);
                autoClientList.add(o);
            }
        }

        // create the "authTrusts" list
        JSONArray authTrusts = new JSONArray();
        for (int i=0; i < numAuths; i++){
            for (int j=i+1; j < numAuths; j++){
                JSONObject o = new JSONObject();
                o.put("id1", auths.get(i).id);
                o.put("id2", auths.get(j).id);
                authTrusts.add(o);
            }
        }

        // create the "assignments" list
        JSONArray assignments = new JSONArray();
        for (SSTGraph.SSTNode t : n.things()){
            JSONObject o = new JSONObject();
            o.put(t.id, n.connectedTo(t).id);
            assignments.add(o);
        }

        overall.put("authList", authlist);
        overall.put("authTrusts", authTrusts);
        overall.put("assignments", assignments);
        overall.put("echoServerList", echoServerList);
        overall.put("autoClientList", autoClientList);

        return overall;
    }

    public static void main(final String[] args) throws IllegalAccessException {

        double weightThings = 0.8;
        double weightAuth = 0.2;
        // generate the graph from the CCS paper
        //SSTGraph n = NetworkFactory.sampleNetworkFull();
        SSTGraph n = NetworkFactory.mkRandomGraph(4, 10, 5,
                1.0, 0.5, 0.5,
                5, 5);
        MigrationPlan p1 = findMigratePlan(n, weightThings, weightAuth);
        MigrationPlan p2 = findMigratePlan(n, weightThings, weightAuth, SOLVER_OJALGO);

        // construct the JSOn object for it
        //JSONObject obj = mkJSON(n, 0.8, 0.2);

        //System.out.println(obj);
    }

}
