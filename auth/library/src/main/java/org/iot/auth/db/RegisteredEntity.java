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
import org.iot.auth.io.Buffer;

import java.security.PublicKey;

/**
 * A class for a registered entity instance.
 * @author Hokeun Kim
 */
public class RegisteredEntity {
    public RegisteredEntity(String name, String group, PublicKey publicKey, long distKeyValidity,
                            SymmetricKeyCryptoSpec distCryptoSpec)
    {
        this.name = name;
        this.group = group;
        this.publicKey = publicKey;
        this.distKeyValidity = distKeyValidity;
        this.distCryptoSpec = distCryptoSpec;
    }
    public String getName() {
        return name;
    }
    public String getGroup() {
        return group;
    }
    public PublicKey getPublicKey() {
        return publicKey;
    }
    public long getDisKeyValidity() {
        return distKeyValidity;
    }
    public DistributionKey getDistributionKey() {
        return distributionKey;
    }
    public SymmetricKeyCryptoSpec getDistCryptoSpec() {
        return distCryptoSpec;
    }
    public String toString() {
        String ret = "Name: " + name + "\tGroup: " + group + "\tDistKeyValidity: " + +distKeyValidity +
                "\tDistCryptoSpec: " + distCryptoSpec.toString();
        ret += "\tDistKey: ";
        if (distributionKey == null) {
            ret += "NULL";
        }
        else {
            ret += distributionKey.toString();
        }
        ret += "\tPublicKey: " + Buffer.toHexString(publicKey.getEncoded());
        return ret;
    }
    public void setDistributionKey(DistributionKey distributionKey) {
        this.distributionKey = distributionKey;
    }
    private String name;
    private String group;
    private PublicKey publicKey;
    private long distKeyValidity;
    private SymmetricKeyCryptoSpec distCryptoSpec;
    private DistributionKey distributionKey = null;
}
