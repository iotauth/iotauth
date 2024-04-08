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

package org.iot.auth.test;

import org.iot.auth.config.AuthServerProperties;
import org.iot.auth.config.constants.C;
import org.iot.auth.config.constants.ConstantType;
import org.iot.auth.crypto.AuthCrypto;
import org.iot.auth.crypto.SymmetricKey;
import org.iot.auth.db.AuthDBProtectionMethod;
import org.iot.auth.db.bean.CommunicationPolicyTable;
import org.iot.auth.db.bean.RegisteredEntityTable;
import org.iot.auth.db.bean.TrustedAuthTable;
import org.iot.auth.db.dao.SQLiteConnector;
import org.iot.auth.io.Buffer;
import org.iot.auth.message.MessageType;
import org.iot.auth.message.impl.AuthHello;
import org.iot.auth.util.DateHelper;
import org.junit.Test;
import org.junit.experimental.categories.Category;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.IOException;
import java.security.cert.CertificateEncodingException;
import java.sql.SQLException;
import java.util.Date;
import java.util.UUID;

/**
 * @author Salomon Lee
 */
public class AppTest {
    private static final Logger logger = LoggerFactory.getLogger(AppTest.class);
    private static final String testDbPath = "../library/src/test/test_files/databases/";
    SymmetricKey databaseKey;
    private String testFilesDir = "../library/src/test/test_files/";
    private AuthDBProtectionMethod authDBProtectionMethod =
            AuthDBProtectionMethod.ENCRYPT_CREDENTIALS;
    @Test
    @Category(org.iot.auth.config.constants.C.class)
    public void testConstant(){
        logger.info("{}, {}",ConstantType.AUTH_NONCE_SIZE, C.AUTH_NONCE_SIZE);
    }

    @Test
    @Category(org.iot.auth.message.MessageType.class)
    public void testMessageType(){
        logger.info("{} {}", MessageType.AUTH_HELLO.toString(), MessageType.AUTH_HELLO.getValue());
        logger.info("{} {}", MessageType.AUTH_SESSION_KEY_REQ.toString(), MessageType.AUTH_SESSION_KEY_REQ.getValue());
        logger.info("{} {}", MessageType.AUTH_SESSION_KEY_RESP.toString(), MessageType.AUTH_SESSION_KEY_RESP.getValue());
        logger.info("{} {}", MessageType.SESSION_KEY_REQ_IN_PUB_ENC.toString(), MessageType.SESSION_KEY_REQ_IN_PUB_ENC.getValue());
        logger.info("{} {}", MessageType.SESSION_KEY_RESP_WITH_DIST_KEY.toString(), MessageType.SESSION_KEY_RESP_WITH_DIST_KEY.getValue());
        logger.info("{} {}", MessageType.SESSION_KEY_REQ.toString(), MessageType.SESSION_KEY_REQ.getValue());
        logger.info("{} {}", MessageType.SESSION_KEY_RESP.toString(), MessageType.SESSION_KEY_RESP.getValue());
        logger.info("{} {}", MessageType.SKEY_HANDSHAKE_1.toString(), MessageType.SKEY_HANDSHAKE_1.getValue());
        logger.info("{} {}", MessageType.SKEY_HANDSHAKE_2.toString(), MessageType.SKEY_HANDSHAKE_2.getValue());
        logger.info("{} {}", MessageType.SKEY_HANDSHAKE_3.toString(), MessageType.SKEY_HANDSHAKE_3.getValue());
        logger.info("{} {}", MessageType.SECURE_COMM_MSG.toString(), MessageType.SECURE_COMM_MSG.getValue());
        logger.info("{} {}", MessageType.FIN_SECURE_COMM.toString(), MessageType.FIN_SECURE_COMM.getValue());
        logger.info("{} {}", MessageType.SECURE_PUB.toString(), MessageType.SECURE_PUB.getValue());
    }

    @Test
    @Category(org.iot.auth.message.impl.AuthHello.class)
    public void testAuthHello(){
        AuthHello authHello = new AuthHello();
        authHello.setMessageType(MessageType.AUTH_HELLO);
        authHello.setAuthId(UUID.randomUUID().toString().getBytes());
        Buffer nonce = new Buffer(UUID.randomUUID().toString().getBytes());
        authHello.setNonce(nonce);
        Buffer message = new Buffer("Hello Message".getBytes());
        authHello.setBuffer(message);
        authHello.setPayLoadLength(
                authHello.getNonce().getRawBytes().length +
                        1 + //authHello.getMessageType()
                        authHello.getAuthId().length +
                        authHello.getBuffer().getRawBytes().length +
                        authHello.getNonce().getRawBytes().length
        );
        logger.info("MessageType, {}", authHello.getMessageType());
        logger.info("AuthId, {}", authHello.getAuthId());
        logger.info("Nonce, {}", authHello.getNonce().getRawBytes());
        logger.info("Buffer, {}", authHello.getBuffer().getRawBytes());
        logger.info("PayLoadLength, {}", authHello.getPayLoadLength());
    }

    public void createTestAuthDB(String testDbFileName) throws SQLException, ClassNotFoundException, IOException {
        SQLiteConnector sqLiteConnector = new SQLiteConnector(testDbFileName, authDBProtectionMethod);
        databaseKey = new SymmetricKey(
                SQLiteConnector.AUTH_DB_CRYPTO_SPEC,
                new Date().getTime() +
                        DateHelper.parseTimePeriod(SQLiteConnector.AUTH_DB_KEY_ABSOLUTE_VALIDITY)
        );
        sqLiteConnector.initialize(databaseKey);
        sqLiteConnector.DEBUG = true;
        sqLiteConnector.createTablesIfNotExists();
        sqLiteConnector.close();
    }

    public void destroyTestAuthDB(String testDbFileName) {
        File file = new File(testDbFileName);
        file.delete();
    }

    @Test
    @Category(org.iot.auth.db.RegisteredEntity.class)
    public void testRegEntityInsertionAndSelectAll() throws SQLException, ClassNotFoundException, IOException {
        final String testDbFileName = testDbPath + "testRegEntityInsertionAndSelectAll" + "_auth.db";
        destroyTestAuthDB(testDbFileName);
        createTestAuthDB(testDbFileName);
        SQLiteConnector sqLiteConnector = new SQLiteConnector(testDbFileName, authDBProtectionMethod);
        sqLiteConnector.initialize(databaseKey);
        sqLiteConnector.DEBUG = true;
        RegisteredEntityTable regEntity = new RegisteredEntityTable();
        regEntity.setName("net1.client");
        regEntity.setGroup("Clients");
        regEntity.setDistProtocol("TCP");
        regEntity.setUsePermanentDistKey(false);
        regEntity.setPublicKeyCryptoSpec("RSA-SHA256");
        regEntity.setMaxSessionKeysPerRequest(5);
        regEntity.setDistKeyValidityPeriod("1*hour");
        regEntity.setPublicKey(
                AuthCrypto.loadPublicKeyFromFile(testFilesDir + "entity_certs/Net1.ClientCert.pem"));
        regEntity.setDistCryptoSpec("AES-128-CBC:SHA256");
        regEntity.setActive(true);
        regEntity.setBackupToAuthIDs("102,103");
        regEntity.setBackupFromAuthID(-1);
        sqLiteConnector.insertRecords(regEntity);

        regEntity.setName("net1.ptClient");
        regEntity.setGroup("PtClients");
        regEntity.setDistProtocol("TCP");
        regEntity.setUsePermanentDistKey(false);
        regEntity.setPublicKeyCryptoSpec("RSA-SHA256");
        regEntity.setMaxSessionKeysPerRequest(5);
        regEntity.setDistKeyValidityPeriod("3*sec");
        regEntity.setPublicKey(
                AuthCrypto.loadPublicKeyFromFile(testFilesDir + "entity_certs/Net1.PtClientCert.pem"));
        regEntity.setDistCryptoSpec("AES-128-CBC:SHA256");
        regEntity.setActive(true);
        regEntity.setBackupToAuthIDs("102");
        regEntity.setBackupFromAuthID(-1);
        sqLiteConnector.insertRecords(regEntity);

        regEntity.setName("net1.server");
        regEntity.setGroup("Servers");
        regEntity.setDistProtocol("TCP");
        regEntity.setUsePermanentDistKey(false);
        regEntity.setPublicKeyCryptoSpec("RSA-SHA256");
        regEntity.setMaxSessionKeysPerRequest(5);
        regEntity.setDistKeyValidityPeriod("1*hour");
        regEntity.setPublicKey(
                AuthCrypto.loadPublicKeyFromFile(testFilesDir + "entity_certs/Net1.ServerCert.pem"));
        regEntity.setDistCryptoSpec("AES-128-CBC:SHA256");
        regEntity.setActive(true);
        regEntity.setBackupToAuthIDs("102,103");
        regEntity.setBackupFromAuthID(-1);
        sqLiteConnector.insertRecords(regEntity);

        regEntity.setName("net1.ptServer");
        regEntity.setGroup("PtServers");
        regEntity.setDistProtocol("TCP");
        regEntity.setUsePermanentDistKey(false);
        regEntity.setPublicKeyCryptoSpec("RSA-SHA256");
        regEntity.setMaxSessionKeysPerRequest(5);
        regEntity.setDistKeyValidityPeriod("3*sec");
        regEntity.setPublicKey(
                AuthCrypto.loadPublicKeyFromFile(testFilesDir + "entity_certs/Net1.PtServerCert.pem"));
        regEntity.setDistCryptoSpec("AES-128-CBC:SHA256");
        regEntity.setActive(true);
        regEntity.setBackupToAuthIDs("102");
        regEntity.setBackupFromAuthID(-1);
        sqLiteConnector.insertRecords(regEntity);

        C.PROPERTIES = new AuthServerProperties(testFilesDir + "properties/exampleAuth101.properties", null);
        sqLiteConnector.selectAllRegEntities();
        sqLiteConnector.close();
        destroyTestAuthDB(testDbFileName);
    }

    @Test
    @Category(org.iot.auth.db.CommunicationPolicy.class)
    public void testCommPolicyInsertionAndSelectAll() throws SQLException, ClassNotFoundException, IOException {
        final String testDbFileName = testDbPath + "testCommPolicyInsertionAndSelectAll" + "_auth.db";
        destroyTestAuthDB(testDbFileName);
        createTestAuthDB(testDbFileName);
        SQLiteConnector sqLiteConnector = new SQLiteConnector(testDbFileName, authDBProtectionMethod);
        sqLiteConnector.initialize(databaseKey);
        sqLiteConnector.DEBUG = true;
        CommunicationPolicyTable communicationPolicyTable = new CommunicationPolicyTable();

        communicationPolicyTable.setReqGroup("Clients");
        communicationPolicyTable.setTargetTypeVal("Group");
        communicationPolicyTable.setTarget("Servers");
        communicationPolicyTable.setMaxNumSessionKeyOwners(2);
        communicationPolicyTable.setSessionCryptoSpec("AES-128-CBC:SHA256");
        communicationPolicyTable.setAbsValidityStr("1*day");
        communicationPolicyTable.setRelValidityStr("20*sec");
        sqLiteConnector.insertRecords(communicationPolicyTable);

        communicationPolicyTable.setReqGroup("Clients");
        communicationPolicyTable.setTargetTypeVal("Group");
        communicationPolicyTable.setTarget("PtServers");
        communicationPolicyTable.setMaxNumSessionKeyOwners(2);
        communicationPolicyTable.setSessionCryptoSpec("AES-128-CBC:SHA256");
        communicationPolicyTable.setAbsValidityStr("1*hour");
        communicationPolicyTable.setRelValidityStr("20*sec");
        sqLiteConnector.insertRecords(communicationPolicyTable);

        communicationPolicyTable.setReqGroup("PtClients");
        communicationPolicyTable.setTargetTypeVal("Group");
        communicationPolicyTable.setTarget("Servers");
        communicationPolicyTable.setMaxNumSessionKeyOwners(2);
        communicationPolicyTable.setSessionCryptoSpec("AES-128-CBC:SHA256");
        communicationPolicyTable.setAbsValidityStr("1*day");
        communicationPolicyTable.setRelValidityStr("2*hour");
        sqLiteConnector.insertRecords(communicationPolicyTable);

        communicationPolicyTable.setReqGroup("PtClients");
        communicationPolicyTable.setTargetTypeVal("Group");
        communicationPolicyTable.setTarget("PtServers");
        communicationPolicyTable.setMaxNumSessionKeyOwners(2);
        communicationPolicyTable.setSessionCryptoSpec("AES-128-CBC:SHA256");
        communicationPolicyTable.setAbsValidityStr("2*hour");
        communicationPolicyTable.setRelValidityStr("20*sec");
        sqLiteConnector.insertRecords(communicationPolicyTable);

        communicationPolicyTable.setReqGroup("Clients");
        communicationPolicyTable.setTargetTypeVal("PubTopic");
        communicationPolicyTable.setTarget("Ptopic");
        communicationPolicyTable.setMaxNumSessionKeyOwners(64);
        communicationPolicyTable.setSessionCryptoSpec("AES-128-CBC:SHA256");
        communicationPolicyTable.setAbsValidityStr("6*hour");
        communicationPolicyTable.setRelValidityStr("3*hour");
        sqLiteConnector.insertRecords(communicationPolicyTable);

        communicationPolicyTable.setReqGroup("Servers");
        communicationPolicyTable.setTargetTypeVal("SubTopic");
        communicationPolicyTable.setTarget("Ptopic");
        communicationPolicyTable.setMaxNumSessionKeyOwners(64);
        communicationPolicyTable.setSessionCryptoSpec("AES-128-CBC:SHA256");
        communicationPolicyTable.setAbsValidityStr("6*hour");
        communicationPolicyTable.setRelValidityStr("3*hour");
        sqLiteConnector.insertRecords(communicationPolicyTable);

        communicationPolicyTable.setReqGroup("Clients");
        communicationPolicyTable.setTargetTypeVal("SubTopic");
        communicationPolicyTable.setTarget("Ptopic");
        communicationPolicyTable.setMaxNumSessionKeyOwners(64);
        communicationPolicyTable.setSessionCryptoSpec("AES-128-CBC:SHA256");
        communicationPolicyTable.setAbsValidityStr("6*hour");
        communicationPolicyTable.setRelValidityStr("3*hour");
        sqLiteConnector.insertRecords(communicationPolicyTable);

        communicationPolicyTable.setReqGroup("Servers");
        communicationPolicyTable.setTargetTypeVal("PubTopic");
        communicationPolicyTable.setTarget("Ptopic");
        communicationPolicyTable.setMaxNumSessionKeyOwners(64);
        communicationPolicyTable.setSessionCryptoSpec("AES-128-CBC:SHA256");
        communicationPolicyTable.setAbsValidityStr("6*hour");
        communicationPolicyTable.setRelValidityStr("3*hour");
        sqLiteConnector.insertRecords(communicationPolicyTable);

        // Test Select All.
        sqLiteConnector.selectAllPolicies();
        sqLiteConnector.close();
        destroyTestAuthDB(testDbFileName);
    }

    @Test
    @Category(org.iot.auth.db.TrustedAuth.class)
    public void testTrustedAuthInsertionAndSelectAll() throws SQLException, ClassNotFoundException, CertificateEncodingException,
            IOException
    {
        final String testDbFileName = testDbPath + "testTrustedAuthInsertionAndSelectAll" + "_auth.db";
        destroyTestAuthDB(testDbFileName);
        createTestAuthDB(testDbFileName);
        SQLiteConnector sqLiteConnector = new SQLiteConnector(testDbFileName, authDBProtectionMethod);
        sqLiteConnector.initialize(databaseKey);
        sqLiteConnector.DEBUG = true;
        TrustedAuthTable trustedAuth = new TrustedAuthTable();
        trustedAuth.setId(102);
        trustedAuth.setHost("localhost");
        trustedAuth.setEntityHost("localhost");
        trustedAuth.setPort(22901);
        trustedAuth.setInternetCertificate(
                AuthCrypto.loadCertificateFromFile(testFilesDir + "trusted_auth_certs/Auth102InternetCert.pem"));
        trustedAuth.setEntityCertificate(
                AuthCrypto.loadCertificateFromFile(testFilesDir + "trusted_auth_certs/Auth102EntityCert.pem"));
        trustedAuth.setHeartbeatPeriod(3);
        trustedAuth.setFailureThreshold(4);
        sqLiteConnector.insertRecords(trustedAuth);

        // Test Select All.
        sqLiteConnector.selectAllTrustedAuth();
        sqLiteConnector.close();
        destroyTestAuthDB(testDbFileName);
    }
}