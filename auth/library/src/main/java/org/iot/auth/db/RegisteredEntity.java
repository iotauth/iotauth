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

import org.iot.auth.crypto.DistributionKey;
import org.iot.auth.crypto.MigrationToken;
import org.iot.auth.crypto.PublicKeyCryptoSpec;
import org.iot.auth.crypto.SymmetricKeyCryptoSpec;
import org.iot.auth.db.bean.RegisteredEntityTable;
import org.iot.auth.io.Buffer;
import org.iot.auth.io.BufferedString;
import org.iot.auth.io.VariableLengthInt;
import org.iot.auth.util.DateHelper;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

/**
 * A class for a registered entity instance.
 * @author Hokeun Kim
 */
public class RegisteredEntity {
    private String name;
    private String group;
    private String distProtocol;
    private boolean usePermanentDistKey;
    private PublicKeyCryptoSpec publicKeyCryptoSpec;
    private long distKeyValidityPeriod;
    private int maxSessionKeysPerRequest;
    private SymmetricKeyCryptoSpec distCryptoSpec;
    private boolean active;
    private int[] backupToAuthIDs = new int[0];
    private int backupFromAuthID = -1;
    private DistributionKey distributionKey = null;
    private PublicKey publicKey;
    private MigrationToken migrationToken = null;

    private static int[] convertStringBackupToAuthIDsToArray(String strBackupToAuthIDs) {
        if (strBackupToAuthIDs == null || strBackupToAuthIDs.length() == 0) {
            return new int[0];
        }
        String[] backupToAuthStrIDs = strBackupToAuthIDs.split(",");
        int[] ret = new int[backupToAuthStrIDs.length];
        for (int i = 0; i < backupToAuthStrIDs.length; i++) {
            ret[i] = Integer.parseInt(backupToAuthStrIDs[i]);
        }
        return ret;
    }

    private static String convertBackuptoAuthIDsToString(int[] backupToAuthIDs) {
        String ret = "";

        for (int i = 0; i < backupToAuthIDs.length; i++) {
            if (i != 0) {
                ret += ",";
            }
            ret += backupToAuthIDs[i];
        }
        return ret;
    }

    public RegisteredEntity(RegisteredEntityTable tableElement, DistributionKey distributionKey)
    {
        this.name = tableElement.getName();
        this.group = tableElement.getGroup();
        this.distProtocol = tableElement.getDistProtocol();
        this.usePermanentDistKey = tableElement.getUsePermanentDistKey();
        if (tableElement.getPublicKeyCryptoSpec() != null) {
            this.publicKeyCryptoSpec = PublicKeyCryptoSpec.fromSpecString(tableElement.getPublicKeyCryptoSpec());
        }
        this.distKeyValidityPeriod = DateHelper.parseTimePeriod(tableElement.getDistKeyValidityPeriod());
        this.maxSessionKeysPerRequest = tableElement.getMaxSessionKeysPerRequest();
        this.distCryptoSpec = SymmetricKeyCryptoSpec.fromSpecString(tableElement.getDistCryptoSpec());
        this.active = tableElement.isActive();
        this.backupToAuthIDs = convertStringBackupToAuthIDsToArray(tableElement.getBackupToAuthIDs());
        this.backupFromAuthID = tableElement.getBackupFromAuthID();
        this.distributionKey = distributionKey; // Decrypted from database
        this.publicKey = tableElement.getPublicKey();
        if (tableElement.getMigrationTokenVal() != null) {
            this.migrationToken = new MigrationToken(this.distCryptoSpec.makeMacOnly(),
                    new Buffer(tableElement.getMigrationTokenVal()));
        }
    }

    public RegisteredEntityTable toRegisteredEntityTable(Buffer serializedDistributionKeyValue,
                                                         long distKeyExpirationTime) {
        RegisteredEntityTable tableElement = new RegisteredEntityTable();
        tableElement.setName(name);
        tableElement.setGroup(group);
        tableElement.setDistProtocol(distProtocol);
        tableElement.setUsePermanentDistKey(usePermanentDistKey);
        if (publicKeyCryptoSpec != null) {
            tableElement.setPublicKeyCryptoSpec(publicKeyCryptoSpec.toSpecString());
        }
        tableElement.setDistKeyValidityPeriod("" + distKeyValidityPeriod);
        tableElement.setMaxSessionKeysPerRequest(maxSessionKeysPerRequest);
        tableElement.setDistCryptoSpec(distCryptoSpec.toSpecString());
        tableElement.setActive(active);
        String strBackupToAuthIDs = "";
        for (int i = 0; i < backupToAuthIDs.length; i++) {
            if (i != 0) {
                strBackupToAuthIDs += ",";
            }
            strBackupToAuthIDs += backupToAuthIDs[i];
        }
        tableElement.setBackupToAuthIDs(strBackupToAuthIDs);
        tableElement.setBackupFromAuthID(backupFromAuthID);
        if (usePermanentDistKey) {
            if (serializedDistributionKeyValue == null || distKeyExpirationTime < 0) {
                throw new RuntimeException("Wrong registered entity information, " +
                        "uses permanent dist key but no dist key specified.");
            }
            else {
                tableElement.setDistKeyVal(serializedDistributionKeyValue.getRawBytes());
                tableElement.setDistKeyExpirationTime(distKeyExpirationTime);
            }
        }
        else {
            tableElement.setPublicKey(publicKey);
            /*
            if (publicKeyFilePath == null) {
                throw new RuntimeException("Wrong registered entity information, " +
                        "does not use permanent dist key but no public key specified.");
            }
            else {
                tableElement.setPublicKeyFile(publicKeyFilePath);
            }*/
        }
        if (migrationToken != null) {
            tableElement.setMigrationTokenVal(migrationToken.serialize().getRawBytes());
        }
        return tableElement;
    }

    public String getName() {
        return name;
    }
    public String getGroup() {
        return group;
    }
    public String getDistProtocol() {
        return distProtocol;
    }
    public boolean getUsePermanentDistKey() {
        return usePermanentDistKey;
    }
    public int getMaxSessionKeysPerRequest() {
        return maxSessionKeysPerRequest;
    }
    public PublicKey getPublicKey() {
        return publicKey;
    }
    public long getDistKeyValidityPeriod() {
        return distKeyValidityPeriod;
    }
    public DistributionKey getDistributionKey() {
        return distributionKey;
    }
    public SymmetricKeyCryptoSpec getDistCryptoSpec() {
        return distCryptoSpec;
    }
    public PublicKeyCryptoSpec getPublicKeyCryptoSpec() {
        return publicKeyCryptoSpec;
    }

    public void setActive(boolean active) { this.active = active; }
    public boolean isActive() {
        return active;
    }

    public void setBackupToAuthIDs(int[] backupToAuthIDs) {
        this.backupToAuthIDs = backupToAuthIDs;
    }
    public int[] getBackupToAuthIDs() {
        return backupToAuthIDs;
    }

    public void setBackupFromAuthID(int backupFromAuthID) {
        this.backupFromAuthID = backupFromAuthID;
    }
    public int getBackupFromAuthID() {
        return backupFromAuthID;
    }

    public String toString() {
        String ret = "Name: " + name + "\tGroup: " + group +
                "\tDistProtocol: " + distProtocol +
                "\tUsePermanentKey: " + usePermanentDistKey +
                "\tDistKeyValidityPeriod: " + distKeyValidityPeriod +
                "\tDistCryptoSpec: " + distCryptoSpec.toString() +
                "\tActive: " + active +
                "\tBackupToAuthIDs: " + Arrays.toString(backupToAuthIDs) +
                "\tBackupFromAuthID: " + backupFromAuthID;

        if (!usePermanentDistKey) {
            ret += "\tPublicKeyCryptoSpec: " + publicKeyCryptoSpec;
        }

        ret += "\tDistKey: ";
        if (distributionKey == null) {
            ret += "NULL";
        }
        else {
            ret += distributionKey.toString();
        }
        if (!usePermanentDistKey) {
            ret += "\tPublicKey: " + Buffer.toHexString(publicKey.getEncoded());
        }
        return ret;
    }
    public void setDistributionKey(DistributionKey distributionKey) {
        this.distributionKey = distributionKey;
    }

    public void setMigrationToken(MigrationToken migrationToken) {
        this.migrationToken = migrationToken;
    }
    public MigrationToken getMigrationToken() {
        return migrationToken;
    }

    private int REG_ENTITY_INT_SIZE = 4;

    // TODO: record the buffer length when concatenating this
    public Buffer serialize() {
        // UsePermanentDistKey | Active -> Byte
        // MaxSessionKeysPerRequest -> INT
        // BackupFromAuthID -> INT
        // DistKeyValidityPeriod -> LONG
        Buffer buffer = new Buffer(Buffer.BYTE_SIZE + 2 * Buffer.INT_SIZE + Buffer.LONG_SIZE);

        // This byte indicates whether the entity uses permanent distribution key and
        // whether the entity is active in bits.
        // That is, 0000 00PA, where P is for use of Permanent distribution key and A is for Active.
        byte usePermanentDistKeyActive = 0;
        if (usePermanentDistKey) {
            usePermanentDistKeyActive += (byte)2;
        }
        if (active) {
            usePermanentDistKeyActive += (byte)1;
        }
        int curIndex = 0;

        buffer.putByte(usePermanentDistKeyActive, curIndex);
        curIndex += Buffer.BYTE_SIZE;
        buffer.putInt(maxSessionKeysPerRequest, curIndex);
        curIndex += Buffer.INT_SIZE;
        buffer.putInt(backupFromAuthID, curIndex);
        curIndex += Buffer.INT_SIZE;
        buffer.putLong(distKeyValidityPeriod, curIndex);
        curIndex += Buffer.LONG_SIZE;

        // BackupToAuthIDs -> String
        buffer.concat(new BufferedString(convertBackuptoAuthIDsToString(backupToAuthIDs)).serialize());

        // String data
        buffer.concat(new BufferedString(name).serialize());
        buffer.concat(new BufferedString(group).serialize());
        buffer.concat(new BufferedString(distProtocol).serialize());
        if (publicKeyCryptoSpec == null) {
            buffer.concat(new BufferedString("").serialize());
        }
        else {
            buffer.concat(new BufferedString(publicKeyCryptoSpec.toSpecString()).serialize());
        }
        buffer.concat(new BufferedString(distCryptoSpec.toSpecString()).serialize());

        Buffer keyBuffer;
        if (usePermanentDistKey) {
            keyBuffer = distributionKey.serialize();
        }
        else {
            keyBuffer = new Buffer(publicKey.getEncoded());
        }
        buffer.concat(new VariableLengthInt(keyBuffer.length()).serialize());
        buffer.concat(keyBuffer);

        if (migrationToken == null) {
            buffer.concat(new VariableLengthInt(0).serialize());
        }
        else {
            Buffer migrationTokenBuffer = migrationToken.serialize();
            buffer.concat(new VariableLengthInt(migrationTokenBuffer.length()).serialize());
            buffer.concat(migrationTokenBuffer);
        }
        return buffer;
    }

    public RegisteredEntity(Buffer buffer) throws NoSuchAlgorithmException, InvalidKeySpecException {
        int curIndex = 0;

        byte usePermanentDistKeyActive = buffer.getByte(curIndex);
        curIndex += Buffer.BYTE_SIZE;

        this.usePermanentDistKey = (usePermanentDistKeyActive & 2) != 0;
        this.active = (usePermanentDistKeyActive & 1) != 0;

        this.maxSessionKeysPerRequest = buffer.getInt(curIndex);
        curIndex += Buffer.INT_SIZE;
        this.backupFromAuthID  = buffer.getInt(curIndex);
        curIndex += Buffer.INT_SIZE;
        this.distKeyValidityPeriod  = buffer.getLong(curIndex);
        curIndex += Buffer.LONG_SIZE;

        BufferedString bufString;
        bufString = buffer.getBufferedString(curIndex);
        curIndex += bufString.length();
        this.backupToAuthIDs = convertStringBackupToAuthIDsToArray(bufString.getString());

        bufString = buffer.getBufferedString(curIndex);
        curIndex += bufString.length();
        this.name = bufString.getString();

        bufString = buffer.getBufferedString(curIndex);
        curIndex += bufString.length();
        this.group = bufString.getString();
        bufString = buffer.getBufferedString(curIndex);
        curIndex += bufString.length();
        this.distProtocol = bufString.getString();
        bufString = buffer.getBufferedString(curIndex);
        curIndex += bufString.length();
        String strPublicKeyCryptoSpec = bufString.getString();
        if (strPublicKeyCryptoSpec.length() == 0) {
            this.publicKeyCryptoSpec = null;
        }
        else {
            this.publicKeyCryptoSpec = PublicKeyCryptoSpec.fromSpecString(strPublicKeyCryptoSpec);
        }
        bufString = buffer.getBufferedString(curIndex);
        curIndex += bufString.length();
        this.distCryptoSpec = SymmetricKeyCryptoSpec.fromSpecString(bufString.getString());

        VariableLengthInt varLenInt = buffer.getVariableLengthInt(curIndex);
        curIndex += varLenInt.getRawBytes().length;
        int keyBufferLength = varLenInt.getNum();

        Buffer keyBuffer = buffer.slice(curIndex, curIndex + keyBufferLength);
        curIndex += keyBufferLength;

        if (this.usePermanentDistKey) {
            // parse this to distribution key
            this.distributionKey = DistributionKey.fromBuffer(this.distCryptoSpec, keyBuffer);
            //keyBuffer
        }
        else {
            // decode public key
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            X509EncodedKeySpec pubSpec = new X509EncodedKeySpec(keyBuffer.getRawBytes());
            this.publicKey = keyFactory.generatePublic(pubSpec);
        }

        varLenInt = buffer.getVariableLengthInt(curIndex);
        curIndex += varLenInt.getRawBytes().length;
        if (varLenInt.getNum() > 0) {
            this.migrationToken = new MigrationToken(this.distCryptoSpec.makeMacOnly(),
                    buffer.slice(curIndex, curIndex + varLenInt.getNum()));
        }
        curIndex += varLenInt.getNum();
    }
}
