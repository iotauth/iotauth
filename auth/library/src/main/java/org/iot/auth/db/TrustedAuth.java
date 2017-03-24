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
    public TrustedAuth(int id, String host, int port, int heartbeatPeriod, X509Certificate certificate) {
        this.id = id;
        this.host = host;
        this.port = port;
        this.heartbeatPeriod = heartbeatPeriod;
        this.certificate = certificate;
    }

    public int getID() {
        return id;
    }

    public String getHost() {
        return host;
    }

    public int getPort() {
        return port;
    }

    public int getHeartbeatPeriod() {
        return heartbeatPeriod;
    }

    public X509Certificate getCertificate() {
        return certificate;
    }

    public String toString() {
        return "ID: " + id + "\tHost: " + host + "\tPort: " + port +
                "\tCertificate: " + certificate;
    }

    public String toBriefString() {
        return "ID: " + id + "\tHost: " + host + "\tPort: " + port +
                "\tCertificate: " + certificate.getSubjectDN();
    }

    private int id;
    private String host;
    private int port;
    private int heartbeatPeriod;
    private X509Certificate certificate;
}
