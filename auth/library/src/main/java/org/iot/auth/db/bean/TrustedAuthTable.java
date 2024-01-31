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

import org.iot.auth.crypto.AuthCrypto;
import org.json.simple.JSONObject;

import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.sql.ResultSet;
import java.sql.SQLException;

/**
 * @author Salomon Lee, Hokeun Kim
 */
public class TrustedAuthTable {
    public static final String T_TRUSTED_AUTH = "trusted_auth";
    public enum c {
        ID,
        Host,
        EntityHost,
        Port,
        HeartbeatPeriod,
        FailureThreshold,
        InternetCertificateValue,
        EntityCertificateValue,
        BackupCertificateValue,
        InternetCertificatePath,
        EntityCertificatePath
    }

    private int id;
    private String host;
    private String entityHost;
    private int port;
    private X509Certificate internetCertificate;
    private X509Certificate entityCertificate;
    private X509Certificate backupCertificate = null;
    private int heartbeatPeriod;
    private int failureThreshold;
    public int getId() {
        return id;
    }

    public void setId(int id) {
        this.id = id;
    }

    public String getEntityHost() {
        return entityHost;
    }

    public void setEntityHost(String entityHost) {
        this.entityHost = entityHost;
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

    public int getHeartbeatPeriod() {
        return heartbeatPeriod;
    }

    public void setHeartbeatPeriod(int heartbeatPeriod) {
        this.heartbeatPeriod = heartbeatPeriod;
    }

    public int getFailureThreshold() {
        return failureThreshold;
    }

    public void setFailureThreshold(int failureThreshold) {
        this.failureThreshold = failureThreshold;
    }

    public X509Certificate getInternetCertificate() {
        return internetCertificate;
    }

    public void setInternetCertificate(X509Certificate internetCertificate) {
        this.internetCertificate = internetCertificate;
    }

    public X509Certificate getEntityCertificate() {
        return entityCertificate;
    }

    public void setEntityCertificate(X509Certificate entityCertificate) {
        this.entityCertificate = entityCertificate;
    }

    public X509Certificate getBackupCertificate() {
        return backupCertificate;
    }

    public void setBackupCertificate(X509Certificate backupCertificate) {
        this.backupCertificate = backupCertificate;
    }

    @SuppressWarnings("unchecked")
    public JSONObject toJSONObject() throws CertificateEncodingException {
        JSONObject object = new JSONObject();
        object.put(c.ID.name(), getId());
        object.put(c.Host.name(), getHost());
        object.put(c.EntityHost.name(), getEntityHost());
        object.put(c.Port.name(), getPort());
        object.put(c.HeartbeatPeriod.name(), getHeartbeatPeriod());
        object.put(c.FailureThreshold.name(), getFailureThreshold());
        object.put(c.InternetCertificateValue.name(), getInternetCertificate().getEncoded());
        object.put(c.EntityCertificateValue.name(), getEntityCertificate().getEncoded());
        object.put(c.BackupCertificateValue.name(), getEntityCertificate().getEncoded());
        return object;
    }

    public String toString() {
        try {
            return toJSONObject().toString();
        }
        catch (CertificateEncodingException e) {
            throw new RuntimeException("Problem converting TrustedAuthTable into String: \n"
                    + e.getMessage());
        }
    }

    public static TrustedAuthTable createRecord(ResultSet resultSet)
            throws SQLException, CertificateEncodingException {
        TrustedAuthTable trustedAuth = new TrustedAuthTable();
        trustedAuth.setId(resultSet.getInt(c.ID.name()));
        trustedAuth.setHost(resultSet.getString(c.Host.name()));
        trustedAuth.setEntityHost(resultSet.getString(c.EntityHost.name()));
        trustedAuth.setPort(resultSet.getInt(c.Port.name()));
        trustedAuth.setHeartbeatPeriod(resultSet.getInt(c.HeartbeatPeriod.name()));
        trustedAuth.setFailureThreshold(resultSet.getInt(c.FailureThreshold.name()));
        trustedAuth.setInternetCertificate(
                AuthCrypto.loadCertificateFromBytes(resultSet.getBytes(c.InternetCertificateValue.name())));
        trustedAuth.setEntityCertificate(
                AuthCrypto.loadCertificateFromBytes(resultSet.getBytes(c.EntityCertificateValue.name())));
        byte[] backupCertificateBytes = resultSet.getBytes(c.BackupCertificateValue.name());
        if (backupCertificateBytes != null) {
            trustedAuth.setBackupCertificate(AuthCrypto.loadCertificateFromBytes(backupCertificateBytes));
        }
        return trustedAuth;
    }
}
