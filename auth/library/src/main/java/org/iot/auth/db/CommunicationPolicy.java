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

import org.iot.auth.crypto.SymmetricKeyCryptoSpec;
import org.iot.auth.db.bean.CommunicationPolicyTable;

/**
 * A class for describing the communication policy between entities.
 * @author Hokeun Kim
 */
public class CommunicationPolicy {
    public CommunicationPolicy(CommunicationPolicyTable communicationPolicyTable)
    {
        this.reqGroup = communicationPolicyTable.getReqGroup();
        this.targetType = communicationPolicyTable.getTargetType();
        this.target = communicationPolicyTable.getTarget();
        this.maxNumSessionKeyOwners = communicationPolicyTable.getMaxNumSessionKeyOwners();

        this.sessionCryptoSpec = SymmetricKeyCryptoSpec.fromSpecString(communicationPolicyTable.getSessionCryptoSpec());

        this.absValidity = communicationPolicyTable.getAbsValidity();
        this.relValidity = communicationPolicyTable.getRelValidity();
    }

    public String getReqGroup() {
        return reqGroup;
    }
    public CommunicationTargetType getTargetType() {
        return targetType;
    }
    public String getTarget() {
        return target;
    }
    public int getMaxNumSessionKeyOwners() {
        return maxNumSessionKeyOwners;
    }

    public SymmetricKeyCryptoSpec getSessionCryptoSpec() {
        return sessionCryptoSpec;
    }

    public long getAbsValidity() {
        return absValidity;
    }
    public long getRelValidity() {
        return relValidity;
    }

    public String toString() {
        return "RequestingGroup: " + reqGroup + "\tTargetType: " + targetType + "\tTarget: " + target +
                "\t" + sessionCryptoSpec.toString() +
                "\tAbsoluteValidity: " + absValidity + "\tRelativeValidity: " + relValidity;
    }


    private String reqGroup;
    private CommunicationTargetType targetType;
    private String target;
    private int maxNumSessionKeyOwners;

    private SymmetricKeyCryptoSpec sessionCryptoSpec;

    private long absValidity;
    private long relValidity;

}
