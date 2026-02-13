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

import org.iot.auth.db.bean.PrivilegeTable;

/**
 * A class for describing the privilege.
 * @author Sunyoung Kim
 */
public class Privilege {
    public Privilege(PrivilegeTable privilegeTable)
    {
        this.privilegeType = privilegeTable.getPrivilegeType();
        this.privilegedEntity = privilegeTable.getPrivilegedEntity();
        this.subject = privilegeTable.getSubject();
        this.object = privilegeTable.getObject();
        this.validity = privilegeTable.getValidity();
    }

    public String getPrivilegeType() {
        return privilegeType;
    }
    public String getPrivilegedEntity() {
        return privilegedEntity;
    }
    public String getSubject() {
        return subject;
    }
    public String getObject() {
        return object;
    }
    public String getValidity() {
        return validity;
    }

    public String toString() {
        return "PrivilegeType: " + privilegeType + "\tPrivilegedEntity: " + privilegedEntity + "\tSubject: " + subject +
                "\tObject: " + object + "\tValidity: " + validity;
    }


    private String privilegeType;
    private String privilegedEntity;
    private String subject;
    private String object;
    private String validity;
}
