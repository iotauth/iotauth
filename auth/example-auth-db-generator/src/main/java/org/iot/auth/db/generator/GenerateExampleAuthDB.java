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

package org.iot.auth.db.generator;

import org.iot.auth.db.bean.CommunicationPolicyTable;
import org.iot.auth.db.bean.MetaDataTable;
import org.iot.auth.db.bean.RegisteredEntityTable;
import org.iot.auth.db.bean.TrustedAuthTable;
import org.iot.auth.db.dao.SQLiteConnector;
import org.iot.auth.util.DateHelper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.FileInputStream;
import java.io.IOException;
import java.sql.SQLException;
import java.util.Arrays;
import java.util.Date;

/**
 * A program to generate example Auth databases for two example Auths with ID 101 and ID 102.
 * @author Hokeun Kim
 */
public class GenerateExampleAuthDB {
    public static void main(String[] args) throws Exception {
        generateAuthDatabase(101);
        generateAuthDatabase(102);
    }

    private static void generateAuthDatabase(int authID) throws Exception {
        String networkName = "";
        SQLiteConnector sqLiteConnector = null;

        if (authID == 101) {
            String authDatabaseDir = "databases/auth101/";
            networkName = "net1";

            String authDBPath = authDatabaseDir + "/auth.db";
            sqLiteConnector = new SQLiteConnector(authDBPath);
            sqLiteConnector.createTablesIfNotExists();
            initTrustedAuthTable(sqLiteConnector, 102, "localhost", 22901, "../credentials/certs/Auth102InternetCert.pem");
        }
        else if (authID == 102) {
            String authDatabaseDir = "databases/auth102/";
            networkName = "net2";

            String authDBPath = authDatabaseDir + "/auth.db";
            sqLiteConnector = new SQLiteConnector(authDBPath);
            sqLiteConnector.createTablesIfNotExists();
            initTrustedAuthTable(sqLiteConnector, 101, "localhost", 21901, "../credentials/certs/Auth101InternetCert.pem");
        }
        else {
            logger.error("No such AuthID {}", authID);
            return;
        }

        initRegisteredEntityTable(sqLiteConnector, networkName);
        initCommPolicyTable(sqLiteConnector);
        initMetaDataTable(sqLiteConnector);
    }

    private static void initMetaDataTable(SQLiteConnector sqLiteConnector) throws ClassNotFoundException, SQLException
    {
        MetaDataTable metaData = new MetaDataTable();

        metaData.setKey(MetaDataTable.key.SessionKeyCount.name());
        metaData.setValue(Long.toString(0));
        sqLiteConnector.insertRecords(metaData);
    }

    private static void initRegisteredEntityTable(SQLiteConnector sqLiteConnector, String networkName)
            throws ClassNotFoundException, SQLException, IOException
    {
        String entityPrefix = networkName + ".";
        RegisteredEntityTable registeredEntity;

        registeredEntity = new RegisteredEntityTable();
        registeredEntity.setName(entityPrefix + "server");
        registeredEntity.setGroup("Servers");
        registeredEntity.setUsePermanentDistKey(false);
        registeredEntity.setMaxSessionKeysPerRequest(1);
        registeredEntity.setPublicKeyFile("certs/ServerCert.pem");
        registeredEntity.setDistValidityPeriod("1*hour");
        registeredEntity.setDistCipherAlgo("AES-128-CBC");
        registeredEntity.setDistHashAlgo("SHA256");
        sqLiteConnector.insertRecords(registeredEntity);

        registeredEntity = new RegisteredEntityTable();
        registeredEntity.setName(entityPrefix + "client");
        registeredEntity.setGroup("Clients");
        registeredEntity.setUsePermanentDistKey(false);
        registeredEntity.setMaxSessionKeysPerRequest(5);
        registeredEntity.setPublicKeyFile("certs/ClientCert.pem");
        registeredEntity.setDistValidityPeriod("1*hour");
        registeredEntity.setDistCipherAlgo("AES-128-CBC");
        registeredEntity.setDistHashAlgo("SHA256");
        sqLiteConnector.insertRecords(registeredEntity);

        registeredEntity = new RegisteredEntityTable();
        registeredEntity.setName(entityPrefix + "ptServer");
        registeredEntity.setGroup("PtServers");
        registeredEntity.setUsePermanentDistKey(false);
        registeredEntity.setMaxSessionKeysPerRequest(1);
        registeredEntity.setPublicKeyFile("certs/PtServerCert.pem");
        registeredEntity.setDistValidityPeriod("3*sec");
        registeredEntity.setDistCipherAlgo("AES-128-CBC");
        registeredEntity.setDistHashAlgo("SHA256");
        sqLiteConnector.insertRecords(registeredEntity);

        registeredEntity = new RegisteredEntityTable();
        registeredEntity.setName(entityPrefix + "ptClient");
        registeredEntity.setGroup("PtClients");
        registeredEntity.setUsePermanentDistKey(false);
        registeredEntity.setMaxSessionKeysPerRequest(5);
        registeredEntity.setPublicKeyFile("certs/PtClientCert.pem");
        registeredEntity.setDistValidityPeriod("3*sec");
        registeredEntity.setDistCipherAlgo("AES-128-CBC");
        registeredEntity.setDistHashAlgo("SHA256");
        sqLiteConnector.insertRecords(registeredEntity);

        // resource-constrained server - no public key file specified
        registeredEntity = new RegisteredEntityTable();
        registeredEntity.setName(entityPrefix + "rcServer");
        registeredEntity.setGroup("Servers");
        registeredEntity.setUsePermanentDistKey(true);
        registeredEntity.setMaxSessionKeysPerRequest(30);
        registeredEntity.setDistValidityPeriod("1*hour");
        registeredEntity.setDistCipherAlgo("AES-128-CBC");
        registeredEntity.setDistHashAlgo("SHA256");
        registeredEntity.setDistKeyVal(readSymmetricKey("../entity/credentials/keys/" + networkName + "/RcServerKey.key"));
        registeredEntity.setDistKeyExpirationTime(new Date().getTime() + DateHelper.parseTimePeriod("365*day"));
        sqLiteConnector.insertRecords(registeredEntity);

        // resource-constrained client - no public key file specified
        registeredEntity = new RegisteredEntityTable();
        registeredEntity.setName(entityPrefix + "rcClient");
        registeredEntity.setGroup("Clients");
        registeredEntity.setUsePermanentDistKey(true);
        registeredEntity.setMaxSessionKeysPerRequest(30);
        registeredEntity.setDistValidityPeriod("1*hour");
        registeredEntity.setDistCipherAlgo("AES-128-CBC");
        registeredEntity.setDistHashAlgo("SHA256");
        registeredEntity.setDistKeyVal(readSymmetricKey("../entity/credentials/keys/" + networkName + "/RcClientKey.key"));
        registeredEntity.setDistKeyExpirationTime(new Date().getTime() + DateHelper.parseTimePeriod("365*day"));
        sqLiteConnector.insertRecords(registeredEntity);

        registeredEntity = new RegisteredEntityTable();
        registeredEntity.setName(entityPrefix + "ptPublisher");
        registeredEntity.setGroup("PtPublishers");
        registeredEntity.setUsePermanentDistKey(false);
        registeredEntity.setMaxSessionKeysPerRequest(5);
        registeredEntity.setPublicKeyFile("certs/PtPublisherCert.pem");
        registeredEntity.setDistValidityPeriod("3*sec");
        registeredEntity.setDistCipherAlgo("AES-128-CBC");
        registeredEntity.setDistHashAlgo("SHA256");
        sqLiteConnector.insertRecords(registeredEntity);

        registeredEntity = new RegisteredEntityTable();
        registeredEntity.setName(entityPrefix + "ptSubscriber");
        registeredEntity.setGroup("PtSubscribers");
        registeredEntity.setUsePermanentDistKey(false);
        registeredEntity.setMaxSessionKeysPerRequest(5);
        registeredEntity.setPublicKeyFile("certs/PtSubscriberCert.pem");
        registeredEntity.setDistValidityPeriod("3*sec");
        registeredEntity.setDistCipherAlgo("AES-128-CBC");
        registeredEntity.setDistHashAlgo("SHA256");
        sqLiteConnector.insertRecords(registeredEntity);
    }

    private static void initCommPolicyTable(SQLiteConnector sqLiteConnector)
            throws ClassNotFoundException, SQLException
    {
        CommunicationPolicyTable communicationPolicyTable = new CommunicationPolicyTable();

        communicationPolicyTable.setReqGroup("Clients");
        communicationPolicyTable.setTargetTypeVal("Group");
        communicationPolicyTable.setTarget("Servers");
        communicationPolicyTable.setCipherAlgo("AES-128-CBC");
        communicationPolicyTable.setHashAlgo("SHA256");
        communicationPolicyTable.setAbsValidityStr("1*day");
        communicationPolicyTable.setRelValidityStr("20*sec");
        sqLiteConnector.insertRecords(communicationPolicyTable);

        communicationPolicyTable.setReqGroup("Clients");
        communicationPolicyTable.setTargetTypeVal("Group");
        communicationPolicyTable.setTarget("PtServers");
        communicationPolicyTable.setCipherAlgo("AES-128-CBC");
        communicationPolicyTable.setHashAlgo("SHA256");
        communicationPolicyTable.setAbsValidityStr("1*hour");
        communicationPolicyTable.setRelValidityStr("20*sec");
        sqLiteConnector.insertRecords(communicationPolicyTable);

        communicationPolicyTable.setReqGroup("PtClients");
        communicationPolicyTable.setTargetTypeVal("Group");
        communicationPolicyTable.setTarget("Servers");
        communicationPolicyTable.setCipherAlgo("AES-128-CBC");
        communicationPolicyTable.setHashAlgo("SHA256");
        communicationPolicyTable.setAbsValidityStr("1*day");
        communicationPolicyTable.setRelValidityStr("2*hour");
        sqLiteConnector.insertRecords(communicationPolicyTable);

        communicationPolicyTable.setReqGroup("PtClients");
        communicationPolicyTable.setTargetTypeVal("Group");
        communicationPolicyTable.setTarget("PtServers");
        communicationPolicyTable.setCipherAlgo("AES-128-CBC");
        communicationPolicyTable.setHashAlgo("SHA256");
        communicationPolicyTable.setAbsValidityStr("2*hour");
        communicationPolicyTable.setRelValidityStr("20*sec");
        sqLiteConnector.insertRecords(communicationPolicyTable);

        communicationPolicyTable.setReqGroup("Clients");
        communicationPolicyTable.setTargetTypeVal("PubTopic");
        communicationPolicyTable.setTarget("Ptopic");
        communicationPolicyTable.setCipherAlgo("AES-128-CBC");
        communicationPolicyTable.setHashAlgo("SHA256");
        communicationPolicyTable.setAbsValidityStr("6*hour");
        communicationPolicyTable.setRelValidityStr("3*hour");
        sqLiteConnector.insertRecords(communicationPolicyTable);

        communicationPolicyTable.setReqGroup("Servers");
        communicationPolicyTable.setTargetTypeVal("SubTopic");
        communicationPolicyTable.setTarget("Ptopic");
        communicationPolicyTable.setCipherAlgo("AES-128-CBC");
        communicationPolicyTable.setHashAlgo("SHA256");
        communicationPolicyTable.setAbsValidityStr("6*hour");
        communicationPolicyTable.setRelValidityStr("3*hour");
        sqLiteConnector.insertRecords(communicationPolicyTable);

        communicationPolicyTable.setReqGroup("Clients");
        communicationPolicyTable.setTargetTypeVal("SubTopic");
        communicationPolicyTable.setTarget("Ptopic");
        communicationPolicyTable.setCipherAlgo("AES-128-CBC");
        communicationPolicyTable.setHashAlgo("SHA256");
        communicationPolicyTable.setAbsValidityStr("6*hour");
        communicationPolicyTable.setRelValidityStr("3*hour");
        sqLiteConnector.insertRecords(communicationPolicyTable);

        communicationPolicyTable.setReqGroup("Servers");
        communicationPolicyTable.setTargetTypeVal("PubTopic");
        communicationPolicyTable.setTarget("Ptopic");
        communicationPolicyTable.setCipherAlgo("AES-128-CBC");
        communicationPolicyTable.setHashAlgo("SHA256");
        communicationPolicyTable.setAbsValidityStr("6*hour");
        communicationPolicyTable.setRelValidityStr("3*hour");
        sqLiteConnector.insertRecords(communicationPolicyTable);

        communicationPolicyTable.setReqGroup("PtPublishers");
        communicationPolicyTable.setTargetTypeVal("PubTopic");
        communicationPolicyTable.setTarget("Ptopic");
        communicationPolicyTable.setCipherAlgo("AES-128-CBC");
        communicationPolicyTable.setHashAlgo("SHA256");
        communicationPolicyTable.setAbsValidityStr("6*hour");
        communicationPolicyTable.setRelValidityStr("3*hour");
        sqLiteConnector.insertRecords(communicationPolicyTable);

        communicationPolicyTable.setReqGroup("PtSubscribers");
        communicationPolicyTable.setTargetTypeVal("SubTopic");
        communicationPolicyTable.setTarget("Ptopic");
        communicationPolicyTable.setCipherAlgo("AES-128-CBC");
        communicationPolicyTable.setHashAlgo("SHA256");
        communicationPolicyTable.setAbsValidityStr("6*hour");
        communicationPolicyTable.setRelValidityStr("3*hour");
        sqLiteConnector.insertRecords(communicationPolicyTable);
    }

    private static void initTrustedAuthTable(SQLiteConnector sqLiteConnector, int id, String host, int port,
                                             String certificatePath) throws ClassNotFoundException, SQLException {
        sqLiteConnector.DEBUG = true;
        TrustedAuthTable trustedAuth = new TrustedAuthTable();
        trustedAuth.setId(id);
        trustedAuth.setHost(host);
        trustedAuth.setPort(port);
        trustedAuth.setCertificatePath(certificatePath);
        sqLiteConnector.insertRecords(trustedAuth);
    }

    private static byte[] readSymmetricKey(String filePath) throws IOException {
        final int MAX_SYMMETRIC_KEY_SIZE = 32;  // Max symmetric key size: 256 bits
        FileInputStream inStream = new FileInputStream(filePath);
        byte[] byteArray = new byte[MAX_SYMMETRIC_KEY_SIZE];
        int numBytes = inStream.read(byteArray);
        return Arrays.copyOfRange(byteArray, 0, numBytes);
    }

    private static final Logger logger = LoggerFactory.getLogger(GenerateExampleAuthDB.class);
}
