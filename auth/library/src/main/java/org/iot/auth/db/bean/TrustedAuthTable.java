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
 * @author Salomon Lee
 */
public class TrustedAuthTable {
    public static final String T_TRUSTED_AUTH = "trusted_auth";
    public enum c {
        ID,
        Host,
        Port,
        CertificatePath
    }

    private int id;
    private String host;
    private int port;
    private String certificatePath;

    public int getId() {
        return id;
    }

    public void setId(int id) {
        this.id = id;
    }

    public String getHost() {
        return host;
    }

    public void setHost(String host) {
        this.host = host;
    }

    public int getPort() {
        return port;
    }

    public void setPort(int port) {
        this.port = port;
    }

    public String getCertificatePath() {
        return certificatePath;
    }

    public void setCertificatePath(String certificatePath) {
        this.certificatePath = certificatePath;
    }

    public JSONObject toJSONObject() {
        JSONObject object = new JSONObject();
        object.put(c.ID.name(), getId());
        object.put(c.Host.name(), getHost());
        object.put(c.Port.name(), getPort());
        object.put(c.CertificatePath.name(), getCertificatePath());
        return object;
    }

    public String toString(){
        return toJSONObject().toString();
    }

    public static TrustedAuthTable createRecord(ResultSet resultSet) throws SQLException {
        TrustedAuthTable trustedAuth = new TrustedAuthTable();
        trustedAuth.setId(resultSet.getInt(c.ID.name()));
        trustedAuth.setHost(resultSet.getString(c.Host.name()));
        trustedAuth.setPort(resultSet.getInt(c.Port.name()));
        trustedAuth.setCertificatePath(resultSet.getString(c.CertificatePath.name()));
        return trustedAuth;
    }
}
