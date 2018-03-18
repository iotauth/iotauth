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

package org.iot.auth.optimization.util;

import java.util.*;

import com.google.common.collect.ImmutableMap;

/**
 *
 * A graph representing an SST network.
 *
 * @author Eunsuk Kang
 */
public class SSTGraph extends Graph<SSTGraph.SSTNode> {

    public final static String CONNECTED = "connected";
    private final static String AUTH_CAPACITY = "capacity";
    private final static String THING_REQUIREMENT = "requirement";
    private final static double DEFAULT_THING_REQUIREMENT = 1.0;

    private final Set<SSTNode> auths = new HashSet<SSTNode>();
    private final Set<SSTNode> things = new HashSet<SSTNode>();

    /**
     * Create an empty graph.
     */
    public SSTGraph() {}

    /**
     * Types of edges from nodes in SST.
     */
    public enum EdgeType {
        AT_CONNECTED,   // connection between a thing and an auth, binary
        AT_COST,    // comm. cost from a thing to an auth
        TA_COST,    // comm. cost from an auth to thing,
        AA_COST,    // comm. cost from an auth to an auth
        AA_TRUST,   // trust relationship between auths, binary
        TT_REQ, // comm requirement between things, binary,
        AT_MIGRATION_TRUST, // whether a thing migrate to Auth, from initial trust
        TT_CLIENT_SERVER,
        NONE
    }

    /**
     * Types of nodes in SST -- either an auth or a thing.
     */
    public enum NodeType {
        AUTH,
        THING
    }

    /**
     * Nodes in an SST network.
     */
    public class SSTNode {
        public final NodeType type;
        public final String id;
        public final Map<String,Object> attr;
        private SSTNode(String id, NodeType type, Map<String,Object> attr){
            this.id = id;
            this.type = type;
            this.attr = attr;
        }
        @Override
        public String toString(){
            //return (this.type == NodeType.AUTH ? "Auth(" : "Thing(") + this.id + ")";
            return this.id;
        }
    }

    /**
     * Add a new Auth with the given ID and capacity (i.e., # things it can handle)
     * @param id The ID of Auth
     * @param capacity Capacity of the given Auth
     * @return the new auth added.
     */
    public SSTNode addAuth(String id, Double capacity){
        SSTNode n = new SSTNode(id, NodeType.AUTH, ImmutableMap.of(AUTH_CAPACITY, capacity));
        auths.add(n);
        return n;
    }

    /**
     * Add a new thing with the given ID.
     * @param id The ID of Auth
     * @return the new thing added.
     */
    public SSTNode addThing(String id){
        SSTNode n = new SSTNode(id, NodeType.THING, new HashMap<>());
        things.add(n);
        return n;
    }

    public Set<SSTNode> auths(){
        return Collections.unmodifiableSet(auths);
    }
    public Set<SSTNode> things(){
        return Collections.unmodifiableSet(things);
    }

    /**
     * Edges in an SST network.
     */
    public class SSTEdge extends Edge {
        public final EdgeType type;
        public final double weight;
        private SSTEdge(SSTNode from, SSTNode to, EdgeType type, double weight){
            super(from,to);
            this.type = type;
            this.weight = weight;
        }
        @Override
        public String toString(){
            return "Edge(" + from + "," + to + "," + type + "," + weight + ")";
        }
        private SSTEdge(SSTNode from, SSTNode to){
            this(from, to, EdgeType.NONE, 0);
        }
    }

    public void addEdge(SSTNode from, SSTNode to, EdgeType type, double weight){
        edges.add(new SSTEdge(from,to,type,weight));
    }

    public SSTEdge lookupEdge(SSTNode from, SSTNode to, EdgeType type) {
        for (Edge edge : edges){
            SSTEdge e = (SSTEdge)edge;

            if (e.from.equals(from) && e.to.equals(to) && e.type.equals(type))
                return e;
        }
        return null;
    }

    public Set<SSTEdge> lookupEdgesTo(SSTNode to, EdgeType type){
        Set<SSTEdge> match = new HashSet<SSTEdge>();
        for (Edge edge : edges) {
            SSTEdge e = (SSTEdge)edge;
            if (e.to.equals(to) && e.type.equals(type))
                match.add(e);
        }
        return Collections.unmodifiableSet(match);
    }

    public Set<SSTEdge> lookupEdgesFrom(SSTNode to, EdgeType type){
        Set<SSTEdge> match = new HashSet<SSTEdge>();
        for (Edge edge : edges) {
            SSTEdge e = (SSTEdge)edge;
            if (e.from.equals(to) && e.type.equals(type))
                match.add(e);
        }
        return Collections.unmodifiableSet(match);
    }

    public Set<SSTEdge> edgesOfType(EdgeType type){
        Set<SSTEdge> match = new HashSet<SSTEdge>();
        for (Edge edge : edges) {
            SSTEdge e = (SSTEdge)edge;
            if (e.type.equals(type))
                match.add(e);
        }
        return Collections.unmodifiableSet(match);
    }

    /**
     * Return true if every thing in this network is connected to some Auth.
     * @return Whether all Things are connected to some Auth
     */
    public boolean allThingsConnected() {
        for (SSTNode t : things){
            if (lookupEdgesTo(t, EdgeType.AT_CONNECTED).isEmpty())
                return false;
        }
        return true;
    }

    /**
     * Return the Auth that the thing "t" is connected to.
     * @return The node (Auth) that t is connected to.
     */
    public SSTNode connectedTo(SSTNode t) {
        for (Edge e : lookupEdgesTo(t, EdgeType.AT_CONNECTED)){
            return ((SSTEdge)e).from;
        }
        return null;
    }

    /**
     * Return the max. capacity of Auths.
     * @param auth Given Auth.
     * @return Capacity in double.
     */
    public double authCap(SSTNode auth){
        return ((Double)auth.attr.get(AUTH_CAPACITY)).doubleValue();
    }

    /**
     * Set authorization requirement of Thing
     * @param thing
     * @param requirement
     */
    public void setThingRequirement(SSTNode thing, double requirement) {
        thing.attr.put(THING_REQUIREMENT, requirement);
    }

    public double getThingRequirement(SSTNode thing) {
        if (thing.attr.containsKey(THING_REQUIREMENT)) {
            return (double)thing.attr.get(THING_REQUIREMENT);
        }
        else {
            return DEFAULT_THING_REQUIREMENT;
        }
    }

    /**
     * Return the thing with the given id.
     * @param thingID The ID of the thing.
     */
    public SSTNode getThing(String thingID) {
        for (SSTNode t : things) {
            if (t.id.equals(thingID)) return t;
        }
        return null;
    }

    /**
     * Return the auth with the given id.
     * @param authID The ID of Auth
     */
    public SSTNode getAuth(String authID) {
        for (SSTNode a : auths){
            if (a.id.equals(authID)) return a;
        }
        return null;
    }

    /**
     * Return true iff the thing with "thingID" is a client.
     */
    public boolean isClient(String thingID) {
        for (Edge edge : edges){
            SSTEdge e = (SSTEdge)edge;
            if (e.type.equals(EdgeType.TT_CLIENT_SERVER) &&
                    e.from.id.equals(thingID))
                return true;
        }
        return false;
    }

    /**
     * Return the server thing that the thing with "clientID" is talking to.
     */
    public String getServer(String clientID){
        for (Edge edge : edges){
            SSTEdge e = (SSTEdge)edge;
            if (e.type.equals(EdgeType.TT_CLIENT_SERVER) &&
                    e.from.id.equals(clientID))
                return e.to.id;
        }
        return null;
    }

    /**
     *
     * Return a new network with "auth" removed from this one.
     *
     * @param auth Auth to destroy from the current network.
     * @return the new network
     */
    public SSTGraph destroyAuth(SSTNode auth) {
        SSTGraph newNetwork = new SSTGraph();
        // keep all Auths except the one being destroyed.
        for (SSTNode a : auths) {
            if (!a.equals(auth))
                newNetwork.auths.add(a);
        }
        // keep all edges except the one that involves "auth" as a node.
        newNetwork.things.addAll(things);
        for (Edge edge : edges) {
            SSTEdge e = (SSTEdge)edge;
            if (!(e.from.equals(auth) || e.to.equals(auth)))
             newNetwork.edges.add(e);
        }
        return newNetwork;
    }

}
