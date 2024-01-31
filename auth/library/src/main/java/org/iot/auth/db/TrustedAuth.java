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

package org.iot.auth.db;

import java.security.cert.X509Certificate;

/**
 * Class for information of a trusted Auth.
 * @author Hokeun Kim
 */
public class TrustedAuth {
    public TrustedAuth(int id, String host, String entityHost, int port, int heartbeatPeriod, int failureThreshold,
                       X509Certificate internetCertificate, X509Certificate entityCertificate,
                       X509Certificate backupCertificate) {
        this.id = id;
        this.host = host;
        this.entityHost = entityHost;
        this.port = port;
        this.heartbeatPeriod = heartbeatPeriod;
        this.failureThreshold = failureThreshold;
        this.internetCertificate = internetCertificate;
        this.entityCertificate = entityCertificate;
        this.backupCertificate = backupCertificate;
    }

    public int getID() {
        return id;
    }

    public String getHost() {
        return host;
    }

    public String getEntityHost() {
        return entityHost;
    }

    public int getPort() {
        return port;
    }

    public int getHeartbeatPeriod() {
        return heartbeatPeriod;
    }

    public int getFailureThreshold() {
        return failureThreshold;
    }

    public X509Certificate getInternetCertificate() {
        return internetCertificate;
    }

    public X509Certificate getEntityCertificate() {
        return entityCertificate;
    }

    public X509Certificate getBackupCertificate() {
        return backupCertificate;
    }

    public void setBackupCertificate(X509Certificate backupCertificate) {
        this.backupCertificate = backupCertificate;
    }

    public String toString() {
        return "ID: " + id + "\tHost: " + host + "\tEntityHost" + entityHost + "\tPort: " + port +
                "\tHeartbeatPeriod: " + heartbeatPeriod +
                "\tFailureThreshold: " + failureThreshold +
                "\tInternetCertificate: " + internetCertificate +
                "\tEntityCertificate: " + entityCertificate +
                "\tBackupCertificate: " + backupCertificate;
    }

    public String toBriefString() {
        return "ID: " + id + "\tHost: " + host + "\tEntityHost" + entityHost + "\tPort: " + port +
                "\tHeartbeatPeriod: " + heartbeatPeriod +
                "\tFailureThreshold: " + failureThreshold +
                "\tInternetCertificate: " + internetCertificate.getSubjectDN() +
                "\tEntityCertificate: " + entityCertificate.getSubjectDN() +
                "\tBackupCertificate: " + (backupCertificate == null ?
                    "NULL" : backupCertificate.getSubjectDN().toString());
    }

    private int id;
    private String host;
    private String entityHost;
    private int port;
    private int heartbeatPeriod;
    private int failureThreshold;
    private X509Certificate internetCertificate;
    private X509Certificate entityCertificate;
    private X509Certificate backupCertificate;
}
