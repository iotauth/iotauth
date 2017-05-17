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

package org.iot.auth.optimization;

import org.ojalgo.netio.BasicLogger;
import org.ojalgo.optimisation.Expression;
import org.ojalgo.optimisation.ExpressionsBasedModel;
import org.ojalgo.optimisation.Optimisation;
import org.ojalgo.optimisation.Variable;

import org.iot.auth.util.SSTGraph;

import org.json.simple.JSONArray;
import org.json.simple.JSONObject;

import java.util.Set;
import java.util.HashSet;
import java.util.Map;
import java.util.HashMap;
import java.util.List;
import java.util.ArrayList;

/**
 * Solver class
 *
 * Performs an optimization task to find the most desirable
 * migration plan from one topology to another.
 *
 * At most one instance of Solver exists at a time.
 *
 * @author Eunsuk Kang
 */
public class Solver {

    public final static String DELIM = "_";

    /**
     * Find an optimal migration plan for the given network.
     *
     * @param network The SST network, with possibly one or more things disconnected from an Auth.
     * @param weightThings The contribution of the things to the overall migration cost.
     * @param weightAuth The contribution of the auth to the overall cost.
     * @return An optimal migration plan.
     */

    public static MigrationPlan findMigratePlan(SSTGraph network, final double weightThings, final double weightAuth){

        final ExpressionsBasedModel model = new ExpressionsBasedModel();
        final Map<SSTGraph.SSTEdge, Variable> varmap = new HashMap<SSTGraph.SSTEdge, Variable>();

        // Construct a variable for possible things to Auth connection
        for (SSTGraph.SSTNode a : network.auths()){
            for (SSTGraph.SSTNode t : network.things()) {
                SSTGraph.SSTEdge costAT = network.lookupEdge(a, t, SSTGraph.EdgeType.AT_COST);
                if (costAT == null) continue;
                SSTGraph.SSTEdge costTA = network.lookupEdge(t, a, SSTGraph.EdgeType.TA_COST);
                SSTGraph.SSTEdge connected = network.lookupEdge(a, t, SSTGraph.EdgeType.AT_CONNECTED);
                Variable var;
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
                    var = Variable.make(SSTGraph.CONNECTED + "_"+ a + "_" + t).lower(1).upper(1).weight(totalCost);
                } else {
                    // thing "t" may become connected to "a" in the new network
                    var = Variable.make(SSTGraph.CONNECTED + "_" + a + "_" + t).lower(0).upper(1).weight(totalCost);
                }
                var.integer(true);
                varmap.put(costAT, var);
                model.addVariable(var);
            }
        }

        // Construct a variable for possible Auth to Auth communication
        for (SSTGraph.SSTNode tx : network.things()){
            for (SSTGraph.SSTEdge e : network.lookupEdgesFrom(tx, SSTGraph.EdgeType.TT_REQ)){
                SSTGraph.SSTNode ty = e.to;
                // there exists a communication requirement from tx to ty
                Set<Variable> x2yVars = new HashSet<Variable>();
                for (SSTGraph.SSTEdge ex : network.lookupEdgesTo(tx, SSTGraph.EdgeType.AT_COST)) {
                    for (SSTGraph.SSTEdge ey : network.lookupEdgesTo(ty, SSTGraph.EdgeType.AT_COST)) {
                        SSTGraph.SSTNode ax = ex.from;
                        SSTGraph.SSTNode ay = ey.from;
                        // tx may communicate to ty through (ax, ay)
                        SSTGraph.SSTEdge aa = network.lookupEdge(ax, ay, SSTGraph.EdgeType.AA_COST);
                        if (aa == null) continue;
                        String name = "edge_" + tx + "_" + ax + "_" + ay + "_" + ty;
                        Variable var =
                                Variable.make(name).lower(0).upper(1).weight(aa.weight*weightAuth);
                        var.integer(true);
                        varmap.put(e, var);
                        model.addVariable(var);
                        x2yVars.add(var);
                        name = "prod_" + tx + "_" + ax + "_" + ay + "_" + ty;
                        final Variable vx = varmap.get(ex);
                        final Variable vy = varmap.get(ey);
                        /**
                         * var itself is a product of vx & vy
                         */
                        // var <= vx (i.e., var - vx <= 0)
                        model.addExpression(name+"_A").upper(0).set(var,1).set(vx,-1);
                        // var <= vy
                        model.addExpression(name+"_B").upper(0).set(var,1).set(vy,-1);
                        // var >= vx + vy - 1
                        model.addExpression(name+"_C").lower(-1).set(var,1).set(vx,-1).set(vy,-1);
                    }
                }
                if (!x2yVars.isEmpty()){
                    final Expression disj = model.addExpression("disj_" + tx + ty).lower(0).upper(1);
                    for (Variable v : x2yVars){
                        disj.set(v, 1);
                    }
                }
            }
        }

        // Constraint that each thing can be connected to at most one Auth
        for (SSTGraph.SSTNode t : network.things()){
            Set<SSTGraph.SSTEdge> edges = network.lookupEdgesTo(t, SSTGraph.EdgeType.AT_COST);
            if (edges.isEmpty()) continue;
            final Expression disjConstraint = model.addExpression("disj_" + t).lower(1).upper(1);
            for (SSTGraph.SSTEdge e : edges){
                disjConstraint.set(varmap.get(e), 1);
            }
        }

        // Constraint that each Auth is connected to no more than the number of things that it has capacity for
        for (SSTGraph.SSTNode a : network.auths()){
            Set<SSTGraph.SSTEdge> edges = network.lookupEdgesFrom(a, SSTGraph.EdgeType.AT_COST);
            if (edges.isEmpty()) continue;
            final Expression capacityConstraint = model.addExpression("authCap_" + a).lower(0).upper(network.authCap(a));
            for (SSTGraph.SSTEdge e : edges){
                capacityConstraint.set(varmap.get(e), 1);
            }
        }
        Optimisation.Result result = model.minimise();

        // Print the result, and the model
        BasicLogger.debug();
        BasicLogger.debug(result);
        BasicLogger.debug();
        BasicLogger.debug(model);
        BasicLogger.debug();

        return new MigrationPlan(network,model,result);
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
    public static JSONObject mkJSON(SSTGraph n, double weightThings, double weightAuth){

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

    public static void main(final String[] args) {

        double weightThings = 0.8;
        double weightAuth = 0.2;
        // generate the graph from the CCS paper
        SSTGraph n = NetworkFactory.sampleNetworkFull();
        //SSTGraph n = NetworkFactory.mkRandomGraph(4, 8, 5, 1.0, 0.5, 0.5, 5, 5);
        // construct the JSOn object for it
        JSONObject obj = Solver.mkJSON(n, 0.8, 0.2);

        System.out.println(obj);
    }

}
