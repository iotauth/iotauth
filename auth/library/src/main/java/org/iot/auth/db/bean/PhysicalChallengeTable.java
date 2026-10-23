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

package org.iot.auth.db.bean;

import org.json.simple.JSONObject;

import java.sql.ResultSet;
import java.sql.SQLException;

/**
 * Physical Challenge (Physical Presence Check) Table schema definition.
 * Stores topology and available challenge methods for each physical check.
 *
 * @author Dongha Kim
 */
public class PhysicalChallengeTable {
    public static final String T_PHYSICAL_CHALLENGE = "physical_challenge";

    public enum c {
        CheckID,
        Topology,
        Methods
    }

    private String checkID;
    private String topology;
    private String methods;

    public String getCheckID() {
        return checkID;
    }

    public PhysicalChallengeTable setCheckID(String checkID) {
        this.checkID = checkID;
        return this;
    }

    public String getTopology() {
        return topology;
    }

    public PhysicalChallengeTable setTopology(String topology) {
        this.topology = topology;
        return this;
    }

    public String getMethods() {
        return methods;
    }

    public PhysicalChallengeTable setMethods(String methods) {
        this.methods = methods;
        return this;
    }

    @SuppressWarnings("unchecked")
    public JSONObject toJSONObject() {
        JSONObject object = new JSONObject();
        object.put(c.CheckID.name(), getCheckID());
        object.put(c.Topology.name(), getTopology());
        object.put(c.Methods.name(), getMethods());
        return object;
    }

    public static PhysicalChallengeTable createRecord(ResultSet resultSet) throws SQLException {
        PhysicalChallengeTable table = new PhysicalChallengeTable();
        table.setCheckID(resultSet.getString(c.CheckID.name()));
        table.setTopology(resultSet.getString(c.Topology.name()));
        table.setMethods(resultSet.getString(c.Methods.name()));
        return table;
    }
}
