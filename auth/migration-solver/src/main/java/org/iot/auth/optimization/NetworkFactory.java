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

import org.iot.auth.util.SSTGraph;

import java.util.ArrayList;
import java.util.List;
import java.util.Random;

/**
 * Class responsible for constructing SST network graphs.
 *
 * @author Eunsuk Kang
 */
public class NetworkFactory {

    /**
     * Construct a random SST network.
     *
     * @param numAuths The number of Auths.
     * @param numThings The number of things.
     * @param authCap The max. number of things that each Auth is capable of handling.
     * @param prob_connected The probability that a thing is connected to some Auth.
     * @param prob_tt_req The probability that a thing is required to communicate to another thing.
     * @param prob_server The probability that a thing is a server.
     * @param at_cost_bound The max. cost between a thing and an Auth.
     * @param aa_cost_bound The max. cost between a pair of Auths.
     * @return A random SST network.
     */
    public static SSTGraph mkRandomGraph(final int numAuths, final int numThings, final int authCap,
                                         final double prob_connected, final double prob_tt_req,
                                         final double prob_server,
                                         final double at_cost_bound, final double aa_cost_bound){
        SSTGraph network = new SSTGraph();
        List<SSTGraph.SSTNode> auths = new ArrayList<SSTGraph.SSTNode>();
        List<SSTGraph.SSTNode> things = new ArrayList<SSTGraph.SSTNode>();

        for (int i=0; i < numAuths; i++){
            auths.add(network.addAuth("a" + i, Double.valueOf(authCap)));
        }
        for (int i=0; i < numThings; i++){
            things.add(network.addThing("t" + i));
        }

        // randomly create connections from things to Auths
        for (SSTGraph.SSTNode t : things) {
            if (randomDouble() > prob_connected) continue;
            int randomAuth = randomInt(0, numAuths);
            network.addEdge(auths.get(randomAuth), t, SSTGraph.EdgeType.AT_CONNECTED, 1);
        }

        // randomly generate costs between things & Auths
        for (SSTGraph.SSTNode t : things) {
            for (SSTGraph.SSTNode a : auths) {
                double cost = randomDouble()*at_cost_bound;
                // for now, assume the costs are symmetric
                network.addEdge(a, t, SSTGraph.EdgeType.AT_COST, cost);
                network.addEdge(t, a, SSTGraph.EdgeType.TA_COST, cost);
            }
        }

        for (int i=0; i < numAuths; i++) {
            for (int j=i+1; j < numAuths; j++) {
                SSTGraph.SSTNode a1 = auths.get(i);
                SSTGraph.SSTNode a2 = auths.get(j);
                double cost = randomDouble()*aa_cost_bound;
                // again, assuming that costs are symmetric
                network.addEdge(a1, a2, SSTGraph.EdgeType.AA_COST, cost);
                network.addEdge(a2, a1, SSTGraph.EdgeType.AA_COST, cost);
            }
        }

        for (int i=0; i < numThings; i++) {
            for (int j=i+1; j < numThings; j++) {
                if (randomDouble() > prob_tt_req) continue;
                SSTGraph.SSTNode t1 = things.get(i);
                SSTGraph.SSTNode t2 = things.get(j);
                network.addEdge(t1, t2, SSTGraph.EdgeType.TT_REQ, 1);
                network.addEdge(t2, t1, SSTGraph.EdgeType.TT_REQ, 1);
            }
        }

        // randomly designate some subset of the things to be servers
        List<SSTGraph.SSTNode> servers = new ArrayList<SSTGraph.SSTNode>();
        for (SSTGraph.SSTNode t : things) {
            if (randomDouble() > prob_server) continue;
            servers.add(t);
        }

        // randomly assign client-server relationship between things
        for (SSTGraph.SSTNode t : things){
            if (!servers.contains(t)){
                int randomServerID = randomInt(0, servers.size());
                network.addEdge(t, servers.get(randomServerID), SSTGraph.EdgeType.TT_CLIENT_SERVER, 1);
            }
        }

        return network;
    }



    /**
     * Generate a random number between min and (max - 1), inclusively
     * @return the generated random number.
     */
    private static int randomInt(int min, int max){
        Random rand = new Random();
        return rand.nextInt((max - min)) + min;
    }

    private static double randomDouble(){
        Random rand = new Random();
        return rand.nextDouble();
    }

    /**
     * Create an example network (from the CCS paper),
     * with some things ("t1" and "t2") disconnected from an Auth ("a1")
     *
     * @return the graph representing the network.
     */
    public static SSTGraph sampleNetworkPartial(){

        SSTGraph network  = new SSTGraph();

        SSTGraph.SSTNode a2 = network.addAuth("a2", Double.valueOf(3));
        SSTGraph.SSTNode a3 = network.addAuth("a3", Double.valueOf(3));

        SSTGraph.SSTNode t1 = network.addThing("t1");
        SSTGraph.SSTNode t2 = network.addThing("t2");
        SSTGraph.SSTNode t3 = network.addThing("t3");
        SSTGraph.SSTNode t4 = network.addThing("t4");
        SSTGraph.SSTNode t5 = network.addThing("t5");

        // things that are already connected to Auths
        network.addEdge(a2, t3, SSTGraph.EdgeType.AT_CONNECTED, 1);
        network.addEdge(a2, t4, SSTGraph.EdgeType.AT_CONNECTED, 1);
        network.addEdge(a3, t5, SSTGraph.EdgeType.AT_CONNECTED, 1);

        // costs from things to Auths
        network.addEdge(a2, t1, SSTGraph.EdgeType.AT_COST, 2);
        network.addEdge(a2, t2, SSTGraph.EdgeType.AT_COST, 1.5);
        network.addEdge(a2, t3, SSTGraph.EdgeType.AT_COST, 1);
        network.addEdge(a2, t4, SSTGraph.EdgeType.AT_COST, 1);
        network.addEdge(a3, t1, SSTGraph.EdgeType.AT_COST, 2.5);
        network.addEdge(a3, t2, SSTGraph.EdgeType.AT_COST, 3);
        network.addEdge(a3, t5, SSTGraph.EdgeType.AT_COST, 1);

        // costs from auths to things
        network.addEdge(t1, a2, SSTGraph.EdgeType.TA_COST, 2);
        network.addEdge(t2, a2, SSTGraph.EdgeType.TA_COST, 1.5);
        network.addEdge(t3, a2, SSTGraph.EdgeType.TA_COST, 1);
        network.addEdge(t4, a2, SSTGraph.EdgeType.TA_COST, 1);
        network.addEdge(t1, a3, SSTGraph.EdgeType.TA_COST, 2.5);
        network.addEdge(t2, a3, SSTGraph.EdgeType.TA_COST, 3);
        network.addEdge(t5, a3, SSTGraph.EdgeType.TA_COST, 1);

        // costs from auths to auths
        network.addEdge(a2, a3, SSTGraph.EdgeType.AA_COST, 3);
        network.addEdge(a3, a2, SSTGraph.EdgeType.AA_COST, 3);

        // thing to thing communication requirement
        network.addEdge(t1, t2, SSTGraph.EdgeType.TT_REQ, 1);
        network.addEdge(t2, t1, SSTGraph.EdgeType.TT_REQ, 1);
        network.addEdge(t1, t5, SSTGraph.EdgeType.TT_REQ, 1);
        network.addEdge(t5, t1, SSTGraph.EdgeType.TT_REQ, 1);
        network.addEdge(t3, t4, SSTGraph.EdgeType.TT_REQ, 1);
        network.addEdge(t4, t3, SSTGraph.EdgeType.TT_REQ, 1);

        // add client to server relationship
        network.addEdge(t2, t1, SSTGraph.EdgeType.TT_CLIENT_SERVER, 1);
        network.addEdge(t4, t3, SSTGraph.EdgeType.TT_CLIENT_SERVER, 1);
        network.addEdge(t5, t1, SSTGraph.EdgeType.TT_CLIENT_SERVER, 1);

        return network;
    }

    /**
     * Create an example network (from the CCS paper),
     * with all things connected to some Auth
     *
     * @return the graph representing the network.
     */
    public static SSTGraph sampleNetworkFull(){

        // Create variables expressing servings of each of the considered foods
        // Set lower and upper limits on the number of servings as well as the weight (cost of a
        // serving) for each variable.

        SSTGraph network  = new SSTGraph();

        SSTGraph.SSTNode a1 = network.addAuth("a1", Double.valueOf(3));
        SSTGraph.SSTNode a2 = network.addAuth("a2", Double.valueOf(3));
        SSTGraph.SSTNode a3 = network.addAuth("a3", Double.valueOf(3));

        SSTGraph.SSTNode t1 = network.addThing("t1");
        SSTGraph.SSTNode t2 = network.addThing("t2");
        SSTGraph.SSTNode t3 = network.addThing("t3");
        SSTGraph.SSTNode t4 = network.addThing("t4");
        SSTGraph.SSTNode t5 = network.addThing("t5");

        // things that are already connected to Auths
        network.addEdge(a1, t1, SSTGraph.EdgeType.AT_CONNECTED, 1);
        network.addEdge(a1, t2, SSTGraph.EdgeType.AT_CONNECTED, 1);
        network.addEdge(a2, t3, SSTGraph.EdgeType.AT_CONNECTED, 1);
        network.addEdge(a2, t4, SSTGraph.EdgeType.AT_CONNECTED, 1);
        network.addEdge(a3, t5, SSTGraph.EdgeType.AT_CONNECTED, 1);

        // costs from things to Auths
        network.addEdge(a1, t1, SSTGraph.EdgeType.AT_COST, 2);
        network.addEdge(a1, t2, SSTGraph.EdgeType.AT_COST, 1.5);
        network.addEdge(a1, t3, SSTGraph.EdgeType.AT_COST, 1);
        network.addEdge(a1, t4, SSTGraph.EdgeType.AT_COST, 1.5);
        network.addEdge(a1, t5, SSTGraph.EdgeType.AT_COST, 2.5);

        network.addEdge(a2, t1, SSTGraph.EdgeType.AT_COST, 2);
        network.addEdge(a2, t2, SSTGraph.EdgeType.AT_COST, 1.5);
        network.addEdge(a2, t3, SSTGraph.EdgeType.AT_COST, 1);
        network.addEdge(a2, t4, SSTGraph.EdgeType.AT_COST, 1);
        network.addEdge(a2, t5, SSTGraph.EdgeType.AT_COST, 2.5);

        network.addEdge(a3, t1, SSTGraph.EdgeType.AT_COST, 2.5);
        network.addEdge(a3, t2, SSTGraph.EdgeType.AT_COST, 3);
        network.addEdge(a3, t3, SSTGraph.EdgeType.AT_COST, 1.5);
        network.addEdge(a3, t4, SSTGraph.EdgeType.AT_COST, 2);
        network.addEdge(a3, t5, SSTGraph.EdgeType.AT_COST, 1);

        // costs from auths to things
        network.addEdge(t1, a1, SSTGraph.EdgeType.TA_COST, 2);
        network.addEdge(t2, a1, SSTGraph.EdgeType.TA_COST, 1.5);
        network.addEdge(t3, a1, SSTGraph.EdgeType.TA_COST, 1);
        network.addEdge(t4, a1, SSTGraph.EdgeType.TA_COST, 1.5);
        network.addEdge(t5, a1, SSTGraph.EdgeType.TA_COST, 2.5);

        network.addEdge(t1, a2, SSTGraph.EdgeType.TA_COST, 2);
        network.addEdge(t2, a2, SSTGraph.EdgeType.TA_COST, 1.5);
        network.addEdge(t3, a2, SSTGraph.EdgeType.TA_COST, 1);
        network.addEdge(t4, a2, SSTGraph.EdgeType.TA_COST, 1);
        network.addEdge(t5, a2, SSTGraph.EdgeType.TA_COST, 2.5);

        network.addEdge(t1, a3, SSTGraph.EdgeType.TA_COST, 2.5);
        network.addEdge(t2, a3, SSTGraph.EdgeType.TA_COST, 3);
        network.addEdge(t3, a3, SSTGraph.EdgeType.TA_COST, 1.5);
        network.addEdge(t4, a3, SSTGraph.EdgeType.TA_COST, 2);
        network.addEdge(t5, a3, SSTGraph.EdgeType.TA_COST, 1);

        // costs from auths to auths
        network.addEdge(a1, a2, SSTGraph.EdgeType.AA_COST, 2);
        network.addEdge(a2, a1, SSTGraph.EdgeType.AA_COST, 2);

        network.addEdge(a1, a3, SSTGraph.EdgeType.AA_COST, 1.5);
        network.addEdge(a3, a1, SSTGraph.EdgeType.AA_COST, 1.5);

        network.addEdge(a2, a3, SSTGraph.EdgeType.AA_COST, 3);
        network.addEdge(a3, a2, SSTGraph.EdgeType.AA_COST, 3);

        // thing to thing communication requirement
        network.addEdge(t1, t2, SSTGraph.EdgeType.TT_REQ, 1);
        network.addEdge(t2, t1, SSTGraph.EdgeType.TT_REQ, 1);
        network.addEdge(t1, t5, SSTGraph.EdgeType.TT_REQ, 1);
        network.addEdge(t5, t1, SSTGraph.EdgeType.TT_REQ, 1);
        network.addEdge(t3, t4, SSTGraph.EdgeType.TT_REQ, 1);
        network.addEdge(t4, t3, SSTGraph.EdgeType.TT_REQ, 1);

        // add client to server relationship
        network.addEdge(t2, t1, SSTGraph.EdgeType.TT_CLIENT_SERVER, 1);
        network.addEdge(t4, t3, SSTGraph.EdgeType.TT_CLIENT_SERVER, 1);
        network.addEdge(t5, t1, SSTGraph.EdgeType.TT_CLIENT_SERVER, 1);

        return network;
    }

}
