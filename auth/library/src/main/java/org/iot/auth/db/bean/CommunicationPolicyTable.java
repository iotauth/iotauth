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

import org.iot.auth.db.CommunicationTargetType;
import org.iot.auth.util.DateHelper;
import org.json.simple.JSONObject;

import java.sql.ResultSet;
import java.sql.SQLException;

/**
 * Communication Policy Table schema definition.  <br>
 * It is not a formal BEAN but it is inspired by the concept.  <br>
 * This class will store and process the data used to define the communication policy. <br>
 * The communication policy is stored on a sqlite database.
 *
 * @author Salomon Lee, Hokeun Kim
 */
public class CommunicationPolicyTable {
    public static final String T_COMMUNICATION_POLICY = "communication_policy";

    public enum c {
        RequestingGroup,
        TargetType,
        Target,
        MaxNumSessionKeyOwners,
        SessionCryptoSpec,
        AbsoluteValidity,
        RelativeValidity
    }

    private String reqGroup;
    private CommunicationTargetType targetType;
    private String targetTypeVal;
    private String target;
    private int maxNumSessionKeyOwners;
    private long absValidity;
    private String absValidityStr;
    private long relValidity;
    private String relValidityStr;
    private String sessionCryptoSpec;

    /**
     * Gets the requesting group type
     * @return the requesting group
     */
    public String getReqGroup() {
        return reqGroup;
    }

    /**
     * Sets the value for requesting group
     * @param reqGroup the requesting group
     */
    public CommunicationPolicyTable setReqGroup(String reqGroup) {
        this.reqGroup = reqGroup;
        return this;
    }

    /**
     * Gets the communication target type. <br>
     * For more information {@link CommunicationTargetType}
     * @return the CommunicationTargetType
     */
    public CommunicationTargetType getTargetType() {
        return targetType;
    }

    /**
     * Sets the value for the communication target type.<br>
     * For more information {@link CommunicationTargetType}
     * @param targetType Given type of communication target
     */
    public CommunicationPolicyTable setTargetType(CommunicationTargetType targetType) {
        this.targetType = targetType;
        return this;
    }

    /**
     * Gets the target to communicate
     * @return target
     */
    public String getTarget() {
        return target;
    }

    /**
     * Sets the target to communicate
     * @param target Given communication target
     */
    public CommunicationPolicyTable setTarget(String target) {
        this.target = target;
        return this;
    }


    public int getMaxNumSessionKeyOwners() {
        return maxNumSessionKeyOwners;
    }

    public CommunicationPolicyTable setMaxNumSessionKeyOwners(int maxNumSessionKeyOwners) {
        this.maxNumSessionKeyOwners = maxNumSessionKeyOwners;
        return this;
    }

    public long getAbsValidity() {
        return absValidity;
    }

    private void setAbsValidity(long absValidity) {
        this.absValidity = absValidity;
    }

    public long getRelValidity() {
        return relValidity;
    }

    private void setRelValidity(long relValidity) {
        this.relValidity = relValidity;
    }

    public String getSessionCryptoSpec() {
        return sessionCryptoSpec;
    }

    public CommunicationPolicyTable setSessionCryptoSpec(String sessionCryptoSpec) {
        this.sessionCryptoSpec = sessionCryptoSpec;
        return this;
    }

    public String getTargetTypeVal() {
        return targetTypeVal;
    }

    public CommunicationPolicyTable setTargetTypeVal(String targetTypeVal) {
        this.targetTypeVal = targetTypeVal;
        return this;
    }

    public String toString() {
        return toJSONObject().toJSONString();
    }

    public String getAbsValidityStr() {
        return absValidityStr;
    }

    public CommunicationPolicyTable setAbsValidityStr(String absValidityStr) {
        this.absValidityStr = absValidityStr;
        return this;
    }

    public String getRelValidityStr() {
        return relValidityStr;
    }

    public CommunicationPolicyTable setRelValidityStr(String relValidityStr) {
        this.relValidityStr = relValidityStr;
        return this;
    }

    @SuppressWarnings("unchecked")
    public JSONObject toJSONObject(){
        JSONObject object = new JSONObject();
        object.put(c.RequestingGroup.name(),getReqGroup());
        object.put(c.TargetType.name(),getTargetTypeVal());
        object.put(c.Target.name(),getTarget());
        object.put(c.MaxNumSessionKeyOwners.name(), getMaxNumSessionKeyOwners());
        object.put(c.AbsoluteValidity.name()+"Str", getAbsValidityStr());
        object.put(c.RelativeValidity.name()+"Str", getRelValidityStr());
        object.put(c.AbsoluteValidity.name(), getAbsValidity());
        object.put(c.RelativeValidity.name(), getRelValidity());
        return object;
    }

    public static CommunicationPolicyTable createRecord(ResultSet r) throws SQLException {
        CommunicationPolicyTable policy = new CommunicationPolicyTable();
        policy.setReqGroup(r.getString(c.RequestingGroup.name()));
        policy.setTargetTypeVal(r.getString(c.TargetType.name()));
        policy.setTargetType(CommunicationTargetType.fromStringValue(r.getString(c.TargetType.name())));
        policy.setTarget(r.getString(c.Target.name()));
        policy.setMaxNumSessionKeyOwners(r.getInt(c.MaxNumSessionKeyOwners.name()));
        policy.setSessionCryptoSpec(r.getString(c.SessionCryptoSpec.name()));
        policy.setAbsValidity(DateHelper.parseTimePeriod(r.getString(c.AbsoluteValidity.name())));
        policy.setRelValidity(DateHelper.parseTimePeriod(r.getString(c.RelativeValidity.name())));
        return policy;
    }
}
