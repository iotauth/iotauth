package org.iot.auth.optimization;

import org.apache.commons.cli.*;
import org.iot.auth.optimization.util.SSTGraph;
import org.iot.auth.optimization.util.SSTVar;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import com.google.common.collect.ImmutableMap;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

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

    private final static String DEFAULT_INPUT_FILE_PATH = "migration-solver/data/cory5th.json";
    private final static String[] DEFAULT_DESTROYED_AUTH_IDS = {"1", "3", "4"};

    /**
     * Find an optimal migration plan for the given network, with
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

                /**
                 * Computing Auth to Thing connection
                 */
                if (connected != null) {
                    // thing "t" is already connected to "a" and must remain so
                    var = solver.addBinaryVar(SSTGraph.CONNECTED + "_"+ a + "_" + t, 1, 1, totalCost);
                } else {
                    // upper range will be 1 only when migration trust exists
                    if (network.lookupEdge(a, t, SSTGraph.EdgeType.AT_MIGRATION_TRUST) != null) {
                        // thing "t" may become connected to "a" in the new network
                        var = solver.addBinaryVar(SSTGraph.CONNECTED + "_" + a + "_" + t, 0, 1, totalCost);
                    }
                    // it is always 0 when there is no migration trust
                    else {
                        var = solver.addBinaryVar(SSTGraph.CONNECTED + "_" + a + "_" + t, 0, 0, totalCost);
                    }
                }

                varmap.put(costAT, var);
            }
        }

        // Construct a variable for possible Auth to Auth communication
        for (SSTGraph.SSTNode tx : network.things()){
            for (SSTGraph.SSTEdge e : network.lookupEdgesFrom(tx, SSTGraph.EdgeType.TT_REQ)){
                SSTGraph.SSTNode ty = e.to;
                // there exists a communication requirement from tx to ty
                Set<SSTVar> x2yVars = new HashSet<>();
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

                        // add constraints about trust relationships between Auths
                        SSTGraph.SSTEdge aaTrust = network.lookupEdge(ax, ay, SSTGraph.EdgeType.AA_TRUST);
                        if (aaTrust == null || aaTrust.weight != 1.0) {
                            solver.addEQ(name + "_Trust",
                                    ImmutableMap.of(var, Double.valueOf(1)), 0);
                        }
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
                SSTVar sstVar = varmap.get(e);
                m.put(sstVar, Double.valueOf(1));
            }
            solver.addEQ("disj_" + t, m, Double.valueOf(1));
        }

        // Constraint that each Auth is connected to no more than the number of things that it has capacity for
        for (SSTGraph.SSTNode a : network.auths()){
            Set<SSTGraph.SSTEdge> edges = network.lookupEdgesFrom(a, SSTGraph.EdgeType.AT_COST);
            if (edges.isEmpty()) continue;
            Map<SSTVar, Double> m = new HashMap<SSTVar, Double>();
            for (SSTGraph.SSTEdge e : edges){
                double thingRequirement = network.getThingRequirement(e.to);
                m.put(varmap.get(e), thingRequirement);
            }
            double authCapacity = network.authCap(a);
            solver.addBetween("authCap_" + a, m, 0, authCapacity);
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

    /**
     * Construct migration plans for the Cory 5th floor scenario
     *
     * @param weightThings & weightAuth: Distribution of costs over thing vs auths
     * @return JSON object for autoClientList and echoServerList
     * @throws IllegalAccessException
     */
    public static JSONObject makeCoryFloorMigration(double weightThings, double weightAuth, String filePath, String[] destroyedAuthIDs) throws IllegalAccessException{
        JSONObject overall = new JSONObject();

        // Construct the initial Cory 5th floor plan
        SSTGraph n = NetworkFactory.coryFloorPlan(filePath);
        List<SSTGraph.SSTNode> auths = new ArrayList<SSTGraph.SSTNode>(n.auths());

        // create migration plans for respective partial graphs
        List<MigrationPlan> plans = new ArrayList<MigrationPlan>();
        SSTGraph destroyedAuth = n;
        for (String destroyedAuthID: destroyedAuthIDs) {
            logger.info("ID of Auth to be destroyed: " + destroyedAuthID);
            destroyedAuth = destroyedAuth.destroyAuth(n.getAuth(destroyedAuthID));
            plans.add(findMigratePlan(destroyedAuth, weightThings, weightAuth));
        }

        Map<String,List<String>> moveTo = new HashMap<String,List<String>>();

        JSONArray echoServerList = new JSONArray();
        JSONArray autoClientList = new JSONArray();

        // extract backup info from each plan
        plans.forEach((p) -> {
            for (String t : p.thingsToMove()){
                if (!moveTo.containsKey(t)){
                    moveTo.put(t, new ArrayList<String>());
                }
                moveTo.get(t).add(p.moveTo(t));
            }
        });

        // create "echoServerList" and "authClientList"
        for (SSTGraph.SSTNode t : n.things()) {
            List<String> backups = new ArrayList<String>();
            if (moveTo.containsKey(t.id))
                backups = moveTo.get(t.id);

            // clean up duplicates
            ListIterator<String> iter = backups.listIterator();
            HashSet<String> prevBackups = new HashSet<>();
            while(iter.hasNext()){
                String currentBackup = iter.next();
                if (prevBackups.contains(currentBackup)) {
                    iter.remove();
                }
                else {
                    prevBackups.add(currentBackup);
                }
            }

            JSONObject o = new JSONObject();
            if (!n.isClient(t.id)) {
                o.put("name", t);
                o.put("backupTo", backups);
                echoServerList.add(o);
            } else {
                o.put("name", t);
                o.put("target", n.getServer(t.id));
                o.put("backupTo", backups);
                autoClientList.add(o);
            }
        }

        overall.put("echoServerList", echoServerList);
        overall.put("autoClientList", autoClientList);

        return overall;
    }

    public static void main(final String[] args) throws IllegalAccessException {
        // parsing command line arguments
        Options options = new Options();

        Option inputFileOption = new Option("i", "input", true, "input json file path");
        inputFileOption.setRequired(false);
        options.addOption(inputFileOption);
        Option destroyedAuthsOption = new Option("d", "destroyed_auths", true, "IDs of Auths to be destroyed, comma (,) delimited");
        destroyedAuthsOption.setRequired(false);
        options.addOption(destroyedAuthsOption);

        CommandLineParser parser = new DefaultParser();
        HelpFormatter formatter = new HelpFormatter();
        CommandLine cmd;

        try {
            cmd = parser.parse(options, args);
        } catch (ParseException e) {
            System.out.println(e.getMessage());
            formatter.printHelp("utility-name", options);

            System.exit(1);
            return;
        }

        String inputJsonFile = cmd.getOptionValue("input");
        if (inputJsonFile == null) {
            inputJsonFile = DEFAULT_INPUT_FILE_PATH;
            logger.info("Input JSON file is not specified. Using default vale: {}", inputJsonFile);
        }
        else {
            logger.info("Given input JSON file: {}", inputJsonFile);
        }

        String[] destroyedAuthIDs = DEFAULT_DESTROYED_AUTH_IDS;
        String destroyedAuthIDsStr = cmd.getOptionValue("destroyed_auths");
        if (destroyedAuthIDsStr != null) {
            destroyedAuthIDs = destroyedAuthIDsStr.split(",");
        }
        logger.info("IDs of Auths to be destroyed: " + Arrays.toString(destroyedAuthIDs));

        double weightThings = 0.8;
        double weightAuth = 0.2;

        // generate the graph from the CCS paper
        // SSTGraph n = NetworkFactory.sampleNetworkFull();
        // SSTGraph n = NetworkFactory.mkRandomGraph(4, 10, 5,
        //                1.0, 0.5, 0.5,
        //                5, 5);
        // MigrationPlan p1 = findMigratePlan(n, weightThings, weightAuth);
        // MigrationPlan p2 = findMigratePlan(n, weightThings, weightAuth, SOLVER_OJALGO);

        JSONObject obj = makeCoryFloorMigration(0.8, 0.2, inputJsonFile, destroyedAuthIDs);
        System.out.println(obj);
    }

    private static final Logger logger = LoggerFactory.getLogger(MigrationEngine.class);
}
