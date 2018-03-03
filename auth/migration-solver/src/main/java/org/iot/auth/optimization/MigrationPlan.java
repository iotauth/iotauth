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

import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import org.iot.auth.optimization.util.SSTGraph;
import org.iot.auth.optimization.util.SSTVar;

/**
 *
 * A plan for migrating things to Auths
 *
 * @author Eunsuk Kang
 */
public class MigrationPlan {
    // (t, a) is an entry in move iff thing "t" is to be moved to "a"
    private final Map<String,String> move;
    private final double totalCost;

    public MigrationPlan(SSTGraph network, Set<SSTVar> varConns, double totalCost) {
        move = new HashMap<String,String>();
        for (SSTVar v : varConns){
            String[] tokens = v.name().split(MigrationEngine.DELIM);
            String auth = tokens[1];
            String thing = tokens[2];
            move.put(thing, auth);
        }
        this.totalCost = totalCost;
    }

    public Set<String> thingsToMove() {
        return move.keySet();
    }

    public String moveTo(String thing) {
        return move.get(thing);
    }

    @Override
    public String toString(){
        String s = "";
        s += "The total communication cost of the migrated network is " + totalCost + "\n";
        for (String thing : move.keySet()){
            String auth = move.get(thing);
            s += "Migrate " + thing + " to " + auth + "\n";
        }
        return s;
    }
}
