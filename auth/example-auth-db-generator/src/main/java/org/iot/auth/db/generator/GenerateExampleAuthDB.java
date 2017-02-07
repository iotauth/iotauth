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

import org.iot.auth.crypto.AuthCrypto;
import org.iot.auth.crypto.SymmetricKey;
import org.iot.auth.db.AuthDB;
import org.iot.auth.db.bean.CommunicationPolicyTable;
import org.iot.auth.db.bean.MetaDataTable;
import org.iot.auth.db.bean.RegisteredEntityTable;
import org.iot.auth.db.bean.TrustedAuthTable;
import org.iot.auth.db.dao.SQLiteConnector;
import org.iot.auth.exception.InvalidDBDataTypeException;
import org.iot.auth.exception.UseOfExpiredKeyException;
import org.iot.auth.io.Buffer;
import org.iot.auth.util.DateHelper;
import org.iot.auth.util.ExceptionToString;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.FileInputStream;
import java.io.FileReader;
import java.io.IOException;
import java.security.PublicKey;
import java.sql.SQLException;
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
        String databasePublicKeyPath = "";
        SQLiteConnector sqLiteConnector = null;

        if (authID == 101) {
            String authDatabaseDir = "databases/auth101/";
            networkName = "net1";

            String authDBPath = authDatabaseDir + "/auth.db";
            sqLiteConnector = new SQLiteConnector(authDBPath);
            //sqLiteConnector.DEBUG = true;
            sqLiteConnector.createTablesIfNotExists();
            initTrustedAuthTable(sqLiteConnector, 102, "localhost", 22901, "../credentials/certs/Auth102InternetCert.pem");
            databasePublicKeyPath =  "credentials/certs/Auth101DatabaseCert.pem";
        }
        else if (authID == 102) {
            String authDatabaseDir = "databases/auth102/";
            networkName = "net2";

            String authDBPath = authDatabaseDir + "/auth.db";
            sqLiteConnector = new SQLiteConnector(authDBPath);
            //sqLiteConnector.DEBUG = true;
            sqLiteConnector.createTablesIfNotExists();
            initTrustedAuthTable(sqLiteConnector, 101, "localhost", 21901, "../credentials/certs/Auth101InternetCert.pem");
            databasePublicKeyPath =  "credentials/certs/Auth102DatabaseCert.pem";
        }
        else {
            logger.error("No such AuthID {}", authID);
            return;
        }
        SymmetricKey databaseKey = new SymmetricKey(
                AuthDB.AUTH_DB_CRYPTO_SPEC,
                new Date().getTime() + DateHelper.parseTimePeriod(AuthDB.AUTH_DB_KEY_ABSOLUTE_VALIDITY)
        );
        initMetaDataTable(sqLiteConnector, databasePublicKeyPath, databaseKey);
        initRegisteredEntityTable(sqLiteConnector, authID, databaseKey);
        initCommPolicyTable(sqLiteConnector);
    }

    private static void initMetaDataTable(SQLiteConnector sqLiteConnector,
                                          String databasePublicKeyPath, SymmetricKey databaseKey)
            throws ClassNotFoundException, SQLException
    {
        MetaDataTable metaData;

        metaData = new MetaDataTable();
        metaData.setKey(MetaDataTable.key.SessionKeyCount.name());
        metaData.setValue(Long.toString(0));
        sqLiteConnector.insertRecords(metaData);

        metaData = new MetaDataTable();
        metaData.setKey(MetaDataTable.key.EncryptedDatabaseKey.name());
        PublicKey databasePublicKey = AuthCrypto.loadPublicKey(databasePublicKeyPath);
        Buffer encryptedDatabaseKey = AuthCrypto.publicEncrypt(databaseKey.getSerializedKeyVal(), databasePublicKey,
                AuthDB.AUTH_DB_PUBLIC_CIPHER);

        metaData.setValue(encryptedDatabaseKey.toBase64());
        sqLiteConnector.insertRecords(metaData);
    }

    private static void initRegisteredEntityTable(SQLiteConnector sqLiteConnector, int authID,
                                                  SymmetricKey databaseKey)
            throws ClassNotFoundException, SQLException, IOException, UseOfExpiredKeyException
    {
        JSONParser parser = new JSONParser();
        String registeredEntityTableConfigFilePath
                = "../entity/node/example_entities/configs/Auth/Auth" + authID + "RegisteredEntityTable.config";
        RegisteredEntityTable registeredEntity;

        try {
            JSONArray jsonArray = (JSONArray)parser.parse(new FileReader(registeredEntityTableConfigFilePath));

            for (Object objElement : jsonArray) {
                registeredEntity = new RegisteredEntityTable();
                JSONObject jsonObject =  (JSONObject)objElement;

                registeredEntity.setName((String)jsonObject.get(RegisteredEntityTable.c.Name.name()));
                registeredEntity.setGroup((String)jsonObject.get(RegisteredEntityTable.c.Group.name()));
                registeredEntity.setDistProtocol((String)jsonObject.get(RegisteredEntityTable.c.DistProtocol.name()));
                boolean usePermanentDistKey = (Boolean)jsonObject.get(RegisteredEntityTable.c.UsePermanentDistKey.name());
                registeredEntity.setUsePermanentDistKey(usePermanentDistKey);
                Object maxSessionKeysPerRequest = jsonObject.get(RegisteredEntityTable.c.MaxSessionKeysPerRequest.name());
                if (maxSessionKeysPerRequest.getClass() == Integer.class) {
                    registeredEntity.setMaxSessionKeysPerRequest((Integer)maxSessionKeysPerRequest);
                }
                else if (maxSessionKeysPerRequest.getClass() == Long.class) {
                    registeredEntity.setMaxSessionKeysPerRequest(((Long)maxSessionKeysPerRequest).intValue());
                }
                else {
                    throw new InvalidDBDataTypeException("MaxSessionKeysPerRequest value is neither Integer nor Long.");
                }
                String distValidityPeriod = (String)jsonObject.get(RegisteredEntityTable.c.DistValidityPeriod.name());
                registeredEntity.setDistValidityPeriod(distValidityPeriod);
                registeredEntity.setDistCryptoSpec((String)jsonObject.get(RegisteredEntityTable.c.DistCryptoSpec.name()));
                if (usePermanentDistKey) {
                    registeredEntity.setDistKeyVal(loadEncryptDistributionKey(databaseKey,
                            (String)jsonObject.get("DistCipherKeyFilePath"),
                            (String)jsonObject.get("DistMacKeyFilePath")));
                    registeredEntity.setDistKeyExpirationTime(new Date().getTime() + DateHelper.parseTimePeriod(distValidityPeriod));
                }
                else {
                    registeredEntity.setPublicKeyFile((String)jsonObject.get(RegisteredEntityTable.c.PublKeyFile.name()));
                }

                sqLiteConnector.insertRecords(registeredEntity);
            }
        }
        catch (ParseException e) {
            logger.error("ParseException {}", ExceptionToString.convertExceptionToStackTrace(e));
        }
        catch (InvalidDBDataTypeException e) {
            logger.error("InvalidDBDataTypeException {}", ExceptionToString.convertExceptionToStackTrace(e));
        }
/*
        registeredEntity = new RegisteredEntityTable();
        registeredEntity.setName(entityPrefix + "server");
        registeredEntity.setGroup("Servers");
        registeredEntity.setDistProtocol("TCP");
        registeredEntity.setUsePermanentDistKey(false);
        registeredEntity.setMaxSessionKeysPerRequest(1);
        registeredEntity.setPublicKeyFile("certs/ServerCert.pem");
        registeredEntity.setDistValidityPeriod("1*hour");
        registeredEntity.setDistCryptoSpec("AES-128-CBC:SHA256");
        sqLiteConnector.insertRecords(registeredEntity);

        registeredEntity = new RegisteredEntityTable();
        registeredEntity.setName(entityPrefix + "client");
        registeredEntity.setGroup("Clients");
        registeredEntity.setDistProtocol("TCP");
        registeredEntity.setUsePermanentDistKey(false);
        registeredEntity.setMaxSessionKeysPerRequest(5);
        registeredEntity.setPublicKeyFile("certs/ClientCert.pem");
        registeredEntity.setDistValidityPeriod("1*hour");
        registeredEntity.setDistCryptoSpec("AES-128-CBC:SHA256");
        sqLiteConnector.insertRecords(registeredEntity);

        registeredEntity = new RegisteredEntityTable();
        registeredEntity.setName(entityPrefix + "ptServer");
        registeredEntity.setGroup("PtServers");
        registeredEntity.setDistProtocol("TCP");
        registeredEntity.setUsePermanentDistKey(false);
        registeredEntity.setMaxSessionKeysPerRequest(1);
        registeredEntity.setPublicKeyFile("certs/PtServerCert.pem");
        registeredEntity.setDistValidityPeriod("3*sec");
        registeredEntity.setDistCryptoSpec("AES-128-CBC:SHA256");
        sqLiteConnector.insertRecords(registeredEntity);

        registeredEntity = new RegisteredEntityTable();
        registeredEntity.setName(entityPrefix + "ptClient");
        registeredEntity.setGroup("PtClients");
        registeredEntity.setDistProtocol("TCP");
        registeredEntity.setUsePermanentDistKey(false);
        registeredEntity.setMaxSessionKeysPerRequest(5);
        registeredEntity.setPublicKeyFile("certs/PtClientCert.pem");
        registeredEntity.setDistValidityPeriod("3*sec");
        registeredEntity.setDistCryptoSpec("AES-128-CBC:SHA256");
        sqLiteConnector.insertRecords(registeredEntity);

        // resource-constrained server - no public key file specified
        registeredEntity = new RegisteredEntityTable();
        registeredEntity.setName(entityPrefix + "rcServer");
        registeredEntity.setGroup("Servers");
        registeredEntity.setDistProtocol("TCP");
        registeredEntity.setUsePermanentDistKey(true);
        registeredEntity.setMaxSessionKeysPerRequest(30);
        registeredEntity.setDistValidityPeriod("1*hour");
        registeredEntity.setDistCryptoSpec("AES-128-CBC:SHA256");
        registeredEntity.setDistKeyVal(loadEncryptDistributionKey(databaseKey,
                "../entity/credentials/keys/" + networkName + "/RcServerCipherKey.key",
                "../entity/credentials/keys/" + networkName + "/RcServerMacKey.key"));
        registeredEntity.setDistKeyExpirationTime(new Date().getTime() + DateHelper.parseTimePeriod("365*day"));
        sqLiteConnector.insertRecords(registeredEntity);

        // resource-constrained client - no public key file specified
        registeredEntity = new RegisteredEntityTable();
        registeredEntity.setName(entityPrefix + "rcClient");
        registeredEntity.setGroup("Clients");
        registeredEntity.setDistProtocol("TCP");
        registeredEntity.setUsePermanentDistKey(true);
        registeredEntity.setMaxSessionKeysPerRequest(30);
        registeredEntity.setDistValidityPeriod("1*hour");
        registeredEntity.setDistCryptoSpec("AES-128-CBC:SHA256");
        registeredEntity.setDistKeyVal(loadEncryptDistributionKey(databaseKey,
                "../entity/credentials/keys/" + networkName + "/RcClientCipherKey.key",
                "../entity/credentials/keys/" + networkName + "/RcClientMacKey.key"));
        registeredEntity.setDistKeyExpirationTime(new Date().getTime() + DateHelper.parseTimePeriod("365*day"));
        sqLiteConnector.insertRecords(registeredEntity);

        // resource-constrained UDP server - no public key file specified
        registeredEntity = new RegisteredEntityTable();
        registeredEntity.setName(entityPrefix + "rcUdpServer");
        registeredEntity.setGroup("Servers");
        registeredEntity.setDistProtocol("UDP");
        registeredEntity.setUsePermanentDistKey(true);
        registeredEntity.setMaxSessionKeysPerRequest(30);
        registeredEntity.setDistValidityPeriod("1*hour");
        registeredEntity.setDistCryptoSpec("AES-128-CBC:SHA256");
        registeredEntity.setDistKeyVal(loadEncryptDistributionKey(databaseKey,
                "../entity/credentials/keys/" + networkName + "/RcUdpServerCipherKey.key",
                "../entity/credentials/keys/" + networkName + "/RcUdpServerMacKey.key"));
        registeredEntity.setDistKeyExpirationTime(new Date().getTime() + DateHelper.parseTimePeriod("365*day"));
        sqLiteConnector.insertRecords(registeredEntity);

        // resource-constrained UDP client - no public key file specified
        registeredEntity = new RegisteredEntityTable();
        registeredEntity.setName(entityPrefix + "rcUdpClient");
        registeredEntity.setGroup("Clients");
        registeredEntity.setDistProtocol("UDP");
        registeredEntity.setUsePermanentDistKey(true);
        registeredEntity.setMaxSessionKeysPerRequest(30);
        registeredEntity.setDistValidityPeriod("1*hour");
        registeredEntity.setDistCryptoSpec("AES-128-CBC:SHA256");
        registeredEntity.setDistKeyVal(loadEncryptDistributionKey(databaseKey,
                "../entity/credentials/keys/" + networkName + "/RcUdpClientCipherKey.key",
                "../entity/credentials/keys/" + networkName + "/RcUdpClientMacKey.key"));
        registeredEntity.setDistKeyExpirationTime(new Date().getTime() + DateHelper.parseTimePeriod("365*day"));
        sqLiteConnector.insertRecords(registeredEntity);

        registeredEntity = new RegisteredEntityTable();
        registeredEntity.setName(entityPrefix + "ptPublisher");
        registeredEntity.setGroup("PtPublishers");
        registeredEntity.setDistProtocol("TCP");
        registeredEntity.setUsePermanentDistKey(false);
        registeredEntity.setMaxSessionKeysPerRequest(5);
        registeredEntity.setPublicKeyFile("certs/PtPublisherCert.pem");
        registeredEntity.setDistValidityPeriod("3*sec");
        registeredEntity.setDistCryptoSpec("AES-128-CBC:SHA256");
        sqLiteConnector.insertRecords(registeredEntity);

        registeredEntity = new RegisteredEntityTable();
        registeredEntity.setName(entityPrefix + "ptSubscriber");
        registeredEntity.setGroup("PtSubscribers");
        registeredEntity.setDistProtocol("TCP");
        registeredEntity.setUsePermanentDistKey(false);
        registeredEntity.setMaxSessionKeysPerRequest(5);
        registeredEntity.setPublicKeyFile("certs/PtSubscriberCert.pem");
        registeredEntity.setDistValidityPeriod("3*sec");
        registeredEntity.setDistCryptoSpec("AES-128-CBC:SHA256");
        sqLiteConnector.insertRecords(registeredEntity);

        registeredEntity = new RegisteredEntityTable();
        registeredEntity.setName(entityPrefix + "udpServer");
        registeredEntity.setGroup("Servers");
        registeredEntity.setDistProtocol("UDP");
        registeredEntity.setUsePermanentDistKey(false);
        registeredEntity.setMaxSessionKeysPerRequest(1);
        registeredEntity.setPublicKeyFile("certs/UdpServerCert.pem");
        registeredEntity.setDistValidityPeriod("1*hour");
        registeredEntity.setDistCryptoSpec("AES-128-CBC:SHA256");
        sqLiteConnector.insertRecords(registeredEntity);

        registeredEntity = new RegisteredEntityTable();
        registeredEntity.setName(entityPrefix + "udpClient");
        registeredEntity.setGroup("Clients");
        registeredEntity.setDistProtocol("UDP");
        registeredEntity.setUsePermanentDistKey(false);
        registeredEntity.setMaxSessionKeysPerRequest(5);
        registeredEntity.setPublicKeyFile("certs/UdpClientCert.pem");
        registeredEntity.setDistValidityPeriod("1*hour");
        registeredEntity.setDistCryptoSpec("AES-128-CBC:SHA256");
        sqLiteConnector.insertRecords(registeredEntity);

        registeredEntity = new RegisteredEntityTable();
        registeredEntity.setName(entityPrefix + "safetyCriticalServer");
        registeredEntity.setGroup("Servers");
        registeredEntity.setDistProtocol("TCP");
        registeredEntity.setUsePermanentDistKey(false);
        registeredEntity.setMaxSessionKeysPerRequest(1);
        registeredEntity.setPublicKeyFile("certs/SafetyCriticalServerCert.pem");
        registeredEntity.setDistValidityPeriod("1*hour");
        registeredEntity.setDistCryptoSpec("AES-128-CBC:SHA256");
        sqLiteConnector.insertRecords(registeredEntity);

        registeredEntity = new RegisteredEntityTable();
        registeredEntity.setName(entityPrefix + "safetyCriticalClient");
        registeredEntity.setGroup("Clients");
        registeredEntity.setDistProtocol("TCP");
        registeredEntity.setUsePermanentDistKey(false);
        registeredEntity.setMaxSessionKeysPerRequest(5);
        registeredEntity.setPublicKeyFile("certs/SafetyCriticalClientCert.pem");
        registeredEntity.setDistValidityPeriod("1*hour");
        registeredEntity.setDistCryptoSpec("AES-128-CBC:SHA256");
        sqLiteConnector.insertRecords(registeredEntity);
        */
    }

    private static void initCommPolicyTable(SQLiteConnector sqLiteConnector)
            throws ClassNotFoundException, SQLException
    {
        CommunicationPolicyTable communicationPolicyTable;

        communicationPolicyTable = new CommunicationPolicyTable();
        communicationPolicyTable.setReqGroup("Clients");
        communicationPolicyTable.setTargetTypeVal("Group");
        communicationPolicyTable.setTarget("Servers");
        communicationPolicyTable.setMaxNumSessionKeyOwners(2);
        communicationPolicyTable.setSessionCryptoSpec("AES-128-CBC:SHA256");
        communicationPolicyTable.setAbsValidityStr("1*day");
        communicationPolicyTable.setRelValidityStr("2*hour");
        sqLiteConnector.insertRecords(communicationPolicyTable);

        communicationPolicyTable = new CommunicationPolicyTable();
        communicationPolicyTable.setReqGroup("Clients");
        communicationPolicyTable.setTargetTypeVal("Group");
        communicationPolicyTable.setTarget("PtServers");
        communicationPolicyTable.setMaxNumSessionKeyOwners(2);
        communicationPolicyTable.setSessionCryptoSpec("AES-128-CBC:SHA256");
        communicationPolicyTable.setAbsValidityStr("1*hour");
        communicationPolicyTable.setRelValidityStr("20*sec");
        sqLiteConnector.insertRecords(communicationPolicyTable);

        communicationPolicyTable = new CommunicationPolicyTable();
        communicationPolicyTable.setReqGroup("PtClients");
        communicationPolicyTable.setTargetTypeVal("Group");
        communicationPolicyTable.setTarget("Servers");
        communicationPolicyTable.setMaxNumSessionKeyOwners(2);
        communicationPolicyTable.setSessionCryptoSpec("AES-128-CBC:SHA256");
        communicationPolicyTable.setAbsValidityStr("1*day");
        communicationPolicyTable.setRelValidityStr("2*hour");
        sqLiteConnector.insertRecords(communicationPolicyTable);

        communicationPolicyTable = new CommunicationPolicyTable();
        communicationPolicyTable.setReqGroup("PtClients");
        communicationPolicyTable.setTargetTypeVal("Group");
        communicationPolicyTable.setTarget("PtServers");
        communicationPolicyTable.setMaxNumSessionKeyOwners(2);
        communicationPolicyTable.setSessionCryptoSpec("AES-128-CBC:SHA256");
        communicationPolicyTable.setAbsValidityStr("2*hour");
        communicationPolicyTable.setRelValidityStr("20*sec");
        sqLiteConnector.insertRecords(communicationPolicyTable);

        communicationPolicyTable = new CommunicationPolicyTable();
        communicationPolicyTable.setReqGroup("Clients");
        communicationPolicyTable.setTargetTypeVal("PubTopic");
        communicationPolicyTable.setTarget("Ptopic");
        communicationPolicyTable.setMaxNumSessionKeyOwners(64);
        communicationPolicyTable.setSessionCryptoSpec("AES-128-CBC:SHA256");
        communicationPolicyTable.setAbsValidityStr("6*hour");
        communicationPolicyTable.setRelValidityStr("3*hour");
        sqLiteConnector.insertRecords(communicationPolicyTable);

        communicationPolicyTable = new CommunicationPolicyTable();
        communicationPolicyTable.setReqGroup("Servers");
        communicationPolicyTable.setTargetTypeVal("SubTopic");
        communicationPolicyTable.setTarget("Ptopic");
        communicationPolicyTable.setMaxNumSessionKeyOwners(64);
        communicationPolicyTable.setSessionCryptoSpec("AES-128-CBC:SHA256");
        communicationPolicyTable.setAbsValidityStr("6*hour");
        communicationPolicyTable.setRelValidityStr("3*hour");
        sqLiteConnector.insertRecords(communicationPolicyTable);

        communicationPolicyTable = new CommunicationPolicyTable();
        communicationPolicyTable.setReqGroup("Clients");
        communicationPolicyTable.setTargetTypeVal("SubTopic");
        communicationPolicyTable.setTarget("Ptopic");
        communicationPolicyTable.setMaxNumSessionKeyOwners(64);
        communicationPolicyTable.setSessionCryptoSpec("AES-128-CBC:SHA256");
        communicationPolicyTable.setAbsValidityStr("6*hour");
        communicationPolicyTable.setRelValidityStr("3*hour");
        sqLiteConnector.insertRecords(communicationPolicyTable);

        communicationPolicyTable = new CommunicationPolicyTable();
        communicationPolicyTable.setReqGroup("Servers");
        communicationPolicyTable.setTargetTypeVal("PubTopic");
        communicationPolicyTable.setTarget("Ptopic");
        communicationPolicyTable.setMaxNumSessionKeyOwners(64);
        communicationPolicyTable.setSessionCryptoSpec("AES-128-CBC:SHA256");
        communicationPolicyTable.setAbsValidityStr("6*hour");
        communicationPolicyTable.setRelValidityStr("3*hour");
        sqLiteConnector.insertRecords(communicationPolicyTable);

        communicationPolicyTable = new CommunicationPolicyTable();
        communicationPolicyTable.setReqGroup("PtPublishers");
        communicationPolicyTable.setTargetTypeVal("PubTopic");
        communicationPolicyTable.setTarget("Ptopic");
        communicationPolicyTable.setMaxNumSessionKeyOwners(64);
        communicationPolicyTable.setSessionCryptoSpec("AES-128-CBC:SHA256");
        communicationPolicyTable.setAbsValidityStr("6*hour");
        communicationPolicyTable.setRelValidityStr("3*hour");
        sqLiteConnector.insertRecords(communicationPolicyTable);

        communicationPolicyTable = new CommunicationPolicyTable();
        communicationPolicyTable.setReqGroup("PtSubscribers");
        communicationPolicyTable.setTargetTypeVal("SubTopic");
        communicationPolicyTable.setTarget("Ptopic");
        communicationPolicyTable.setMaxNumSessionKeyOwners(64);
        communicationPolicyTable.setSessionCryptoSpec("AES-128-CBC:SHA256");
        communicationPolicyTable.setAbsValidityStr("6*hour");
        communicationPolicyTable.setRelValidityStr("3*hour");
        sqLiteConnector.insertRecords(communicationPolicyTable);
    }

    private static void initTrustedAuthTable(SQLiteConnector sqLiteConnector, int id, String host, int port,
                                             String certificatePath) throws ClassNotFoundException, SQLException {
        TrustedAuthTable trustedAuth = new TrustedAuthTable();
        trustedAuth.setId(id);
        trustedAuth.setHost(host);
        trustedAuth.setPort(port);
        trustedAuth.setCertificatePath(certificatePath);
        sqLiteConnector.insertRecords(trustedAuth);
    }

    private static Buffer readSymmetricKey(String filePath) throws IOException {
        final int MAX_SYMMETRIC_KEY_SIZE = 64;  // Max symmetric key size: 256 bits
        FileInputStream inStream = new FileInputStream(filePath);
        byte[] byteArray = new byte[MAX_SYMMETRIC_KEY_SIZE];
        int numBytes = inStream.read(byteArray);
        return new Buffer(byteArray, numBytes);
    }

    private static byte[] loadEncryptDistributionKey(SymmetricKey databaseKey,
                                                     String cipherKeyPath,
                                                     String macKeyPath) throws IOException, UseOfExpiredKeyException {
        Buffer rawCipherKeyVal = readSymmetricKey(cipherKeyPath);
        Buffer rawMackeyVal = readSymmetricKey(macKeyPath);
        Buffer serializedKeyVal = SymmetricKey.getSerializedKeyVal(rawCipherKeyVal, rawMackeyVal);
        return databaseKey.encryptAuthenticate(serializedKeyVal).getRawBytes();
    }

    private static final Logger logger = LoggerFactory.getLogger(GenerateExampleAuthDB.class);
}
