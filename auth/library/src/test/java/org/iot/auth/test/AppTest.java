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

import java.io.File;
import java.io.IOException;
import java.security.cert.CertificateEncodingException;
import java.sql.SQLException;
import java.util.Date;
import java.util.UUID;

import org.iot.auth.config.AuthServerProperties;
import org.iot.auth.config.constants.C;
import org.iot.auth.config.constants.ConstantType;
import org.iot.auth.crypto.AuthCrypto;
import org.iot.auth.crypto.SymmetricKey;
import org.iot.auth.db.AuthDBProtectionMethod;
import org.iot.auth.db.bean.CachedSessionKeyTable;
import org.iot.auth.db.bean.CommunicationPolicyTable;
import org.iot.auth.db.bean.DelegationInfoTable;
import org.iot.auth.db.bean.DelegationPrivilegeTable;
import org.iot.auth.db.bean.FileSharingTable;
import org.iot.auth.db.bean.MetaDataTable;
import org.iot.auth.db.bean.RegisteredEntityTable;
import org.iot.auth.db.bean.TrustedAuthTable;
import org.iot.auth.db.dao.SQLiteConnector;
import org.iot.auth.io.Buffer;
import org.iot.auth.message.MessageType;
import org.iot.auth.message.impl.AuthHello;
import org.iot.auth.util.DateHelper;
import org.json.simple.JSONObject;
import org.junit.Assert;
import org.junit.Test;
import org.junit.experimental.categories.Category;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;


/**
 * @author Salomon Lee, Hokeun Kim, Sunyoung Kim
 */
public class AppTest {
    private static final Logger logger = LoggerFactory.getLogger(AppTest.class);
    private static final String testDbPath = "../library/src/test/test_files/databases/";
    SymmetricKey databaseKey;
    private final String testFilesDir = "../library/src/test/test_files/";
    private final AuthDBProtectionMethod authDBProtectionMethod =
            AuthDBProtectionMethod.ENCRYPT_CREDENTIALS;
    /**
     * Verifies that {@code C.AUTH_NONCE_SIZE} equals 8 and that {@link C#getValueOf} returns the
     * same value for {@link ConstantType#AUTH_NONCE_SIZE}.
     */
    @Test
    @Category(org.iot.auth.config.constants.C.class)
    public void testConstant(){
        logger.info("{}, {}",ConstantType.AUTH_NONCE_SIZE, C.AUTH_NONCE_SIZE);
        Assert.assertEquals(8, C.AUTH_NONCE_SIZE);
        Assert.assertEquals(C.AUTH_NONCE_SIZE, C.getValueOf(ConstantType.AUTH_NONCE_SIZE));
    }

    /**
     * Verifies that each {@link MessageType} enum constant has the expected numeric byte value and
     * that {@link MessageType#fromByte} round-trips back to the original enum constant.
     */
    @Test
    @Category(org.iot.auth.message.MessageType.class)
    public void testMessageType(){
        logger.info("{} {}", MessageType.AUTH_HELLO, MessageType.AUTH_HELLO.getValue());
        logger.info("{} {}", MessageType.ENTITY_HELLO, MessageType.ENTITY_HELLO.getValue());
        logger.info("{} {}", MessageType.AUTH_SESSION_KEY_REQ, MessageType.AUTH_SESSION_KEY_REQ.getValue());
        logger.info("{} {}", MessageType.AUTH_SESSION_KEY_RESP, MessageType.AUTH_SESSION_KEY_RESP.getValue());
        logger.info("{} {}", MessageType.SESSION_KEY_REQ_IN_PUB_ENC, MessageType.SESSION_KEY_REQ_IN_PUB_ENC.getValue());
        logger.info("{} {}", MessageType.SESSION_KEY_RESP_WITH_DIST_KEY, MessageType.SESSION_KEY_RESP_WITH_DIST_KEY.getValue());
        logger.info("{} {}", MessageType.SESSION_KEY_REQ, MessageType.SESSION_KEY_REQ.getValue());
        logger.info("{} {}", MessageType.SESSION_KEY_RESP, MessageType.SESSION_KEY_RESP.getValue());
        logger.info("{} {}", MessageType.SESSION_KEY_RESP_FOR_DELEGATION, MessageType.SESSION_KEY_RESP_FOR_DELEGATION.getValue());
        logger.info("{} {}", MessageType.SESSION_KEY_RESP_FOR_DELEGATION_WITH_DIST_KEY, MessageType.SESSION_KEY_RESP_FOR_DELEGATION_WITH_DIST_KEY.getValue());
        logger.info("{} {}", MessageType.SKEY_HANDSHAKE_1, MessageType.SKEY_HANDSHAKE_1.getValue());
        logger.info("{} {}", MessageType.SKEY_HANDSHAKE_2, MessageType.SKEY_HANDSHAKE_2.getValue());
        logger.info("{} {}", MessageType.SKEY_HANDSHAKE_3, MessageType.SKEY_HANDSHAKE_3.getValue());
        logger.info("{} {}", MessageType.SECURE_COMM_MSG, MessageType.SECURE_COMM_MSG.getValue());
        logger.info("{} {}", MessageType.FIN_SECURE_COMM, MessageType.FIN_SECURE_COMM.getValue());
        logger.info("{} {}", MessageType.SECURE_PUB, MessageType.SECURE_PUB.getValue());
        logger.info("{} {}", MessageType.MIGRATION_REQ_WITH_SIGN, MessageType.MIGRATION_REQ_WITH_SIGN.getValue());
        logger.info("{} {}", MessageType.MIGRATION_RESP_WITH_SIGN, MessageType.MIGRATION_RESP_WITH_SIGN.getValue());
        logger.info("{} {}", MessageType.MIGRATION_REQ_WITH_MAC, MessageType.MIGRATION_REQ_WITH_MAC.getValue());
        logger.info("{} {}", MessageType.MIGRATION_RESP_WITH_MAC, MessageType.MIGRATION_RESP_WITH_MAC.getValue());
        logger.info("{} {}", MessageType.ADD_READER_REQ_IN_PUB_ENC, MessageType.ADD_READER_REQ_IN_PUB_ENC.getValue());
        logger.info("{} {}", MessageType.ADD_READER_RESP_WITH_DIST_KEY, MessageType.ADD_READER_RESP_WITH_DIST_KEY.getValue());
        logger.info("{} {}", MessageType.ADD_READER_REQ, MessageType.ADD_READER_REQ.getValue());
        logger.info("{} {}", MessageType.ADD_READER_RESP, MessageType.ADD_READER_RESP.getValue());
        logger.info("{} {}", MessageType.DELEGATED_ACCESS_REQ_IN_PUB_ENC, MessageType.DELEGATED_ACCESS_REQ_IN_PUB_ENC.getValue());
        logger.info("{} {}", MessageType.DELEGATED_ACCESS_RESP_WITH_DIST_KEY, MessageType.DELEGATED_ACCESS_RESP_WITH_DIST_KEY.getValue());
        logger.info("{} {}", MessageType.DELEGATED_ACCESS_REQ, MessageType.DELEGATED_ACCESS_REQ.getValue());
        logger.info("{} {}", MessageType.DELEGATED_ACCESS_RESP, MessageType.DELEGATED_ACCESS_RESP.getValue());
        logger.info("{} {}", MessageType.PRIVILEGED_REQ_IN_PUB_ENC, MessageType.PRIVILEGED_REQ_IN_PUB_ENC.getValue());
        logger.info("{} {}", MessageType.PRIVILEGED_RESP_WITH_DIST_KEY, MessageType.PRIVILEGED_RESP_WITH_DIST_KEY.getValue());
        logger.info("{} {}", MessageType.PRIVILEGED_REQ, MessageType.PRIVILEGED_REQ.getValue());
        logger.info("{} {}", MessageType.PRIVILEGED_RESP, MessageType.PRIVILEGED_RESP.getValue());
        logger.info("{} {}", MessageType.AUTH_ALERT, MessageType.AUTH_ALERT.getValue());

        Assert.assertEquals((byte)  0, MessageType.AUTH_HELLO.getValue());
        Assert.assertEquals((byte)  1, MessageType.ENTITY_HELLO.getValue());
        Assert.assertEquals((byte) 10, MessageType.AUTH_SESSION_KEY_REQ.getValue());
        Assert.assertEquals((byte) 11, MessageType.AUTH_SESSION_KEY_RESP.getValue());
        Assert.assertEquals((byte) 20, MessageType.SESSION_KEY_REQ_IN_PUB_ENC.getValue());
        Assert.assertEquals((byte) 21, MessageType.SESSION_KEY_RESP_WITH_DIST_KEY.getValue());
        Assert.assertEquals((byte) 22, MessageType.SESSION_KEY_REQ.getValue());
        Assert.assertEquals((byte) 23, MessageType.SESSION_KEY_RESP.getValue());
        Assert.assertEquals((byte) 24, MessageType.SESSION_KEY_RESP_FOR_DELEGATION.getValue());
        Assert.assertEquals((byte) 25, MessageType.SESSION_KEY_RESP_FOR_DELEGATION_WITH_DIST_KEY.getValue());
        Assert.assertEquals((byte) 30, MessageType.SKEY_HANDSHAKE_1.getValue());
        Assert.assertEquals((byte) 31, MessageType.SKEY_HANDSHAKE_2.getValue());
        Assert.assertEquals((byte) 32, MessageType.SKEY_HANDSHAKE_3.getValue());
        Assert.assertEquals((byte) 33, MessageType.SECURE_COMM_MSG.getValue());
        Assert.assertEquals((byte) 34, MessageType.FIN_SECURE_COMM.getValue());
        Assert.assertEquals((byte) 40, MessageType.SECURE_PUB.getValue());
        Assert.assertEquals((byte) 50, MessageType.MIGRATION_REQ_WITH_SIGN.getValue());
        Assert.assertEquals((byte) 51, MessageType.MIGRATION_RESP_WITH_SIGN.getValue());
        Assert.assertEquals((byte) 52, MessageType.MIGRATION_REQ_WITH_MAC.getValue());
        Assert.assertEquals((byte) 53, MessageType.MIGRATION_RESP_WITH_MAC.getValue());
        Assert.assertEquals((byte) 60, MessageType.ADD_READER_REQ_IN_PUB_ENC.getValue());
        Assert.assertEquals((byte) 61, MessageType.ADD_READER_RESP_WITH_DIST_KEY.getValue());
        Assert.assertEquals((byte) 62, MessageType.ADD_READER_REQ.getValue());
        Assert.assertEquals((byte) 63, MessageType.ADD_READER_RESP.getValue());
        Assert.assertEquals((byte) 70, MessageType.DELEGATED_ACCESS_REQ_IN_PUB_ENC.getValue());
        Assert.assertEquals((byte) 71, MessageType.DELEGATED_ACCESS_RESP_WITH_DIST_KEY.getValue());
        Assert.assertEquals((byte) 72, MessageType.DELEGATED_ACCESS_REQ.getValue());
        Assert.assertEquals((byte) 73, MessageType.DELEGATED_ACCESS_RESP.getValue());
        Assert.assertEquals((byte) 80, MessageType.PRIVILEGED_REQ_IN_PUB_ENC.getValue());
        Assert.assertEquals((byte) 81, MessageType.PRIVILEGED_RESP_WITH_DIST_KEY.getValue());
        Assert.assertEquals((byte) 82, MessageType.PRIVILEGED_REQ.getValue());
        Assert.assertEquals((byte) 83, MessageType.PRIVILEGED_RESP.getValue());
        Assert.assertEquals((byte) 100, MessageType.AUTH_ALERT.getValue());

        for (MessageType type : MessageType.values()) {
            Assert.assertEquals(type, MessageType.fromByte(type.getValue()));
        }
    }

    /**
     * Constructs an {@link AuthHello} message with a random auth ID, nonce, and a fixed payload,
     * then asserts that the message type byte, auth ID, nonce, buffer content, and computed payload
     * length are all set correctly.
     */
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
        int expectedPayloadLength =
                authHello.getNonce().getRawBytes().length +
                        1 + //authHello.getMessageType()
                        authHello.getAuthId().length +
                        authHello.getBuffer().getRawBytes().length +
                        authHello.getNonce().getRawBytes().length;
        authHello.setPayLoadLength(expectedPayloadLength);
        logger.info("MessageType, {}", authHello.getMessageType());
        logger.info("AuthId, {}", authHello.getAuthId());
        logger.info("Nonce, {}", authHello.getNonce().getRawBytes());
        logger.info("Buffer, {}", authHello.getBuffer().getRawBytes());
        logger.info("PayLoadLength, {}", authHello.getPayLoadLength());

        Assert.assertEquals(MessageType.AUTH_HELLO.getValue(), authHello.getMessageType());
        Assert.assertNotNull(authHello.getAuthId());
        Assert.assertNotNull(authHello.getNonce());
        Assert.assertArrayEquals("Hello Message".getBytes(), authHello.getBuffer().getRawBytes());
        Assert.assertEquals(expectedPayloadLength, authHello.getPayLoadLength());
    }

    /**
     * Creates a fresh SQLite auth database at the given path, initializes it with a newly generated
     * symmetric database key, and creates all required tables.
     *
     * @param testDbFileName absolute or relative path where the test database file should be created
     * @throws SQLException            if a database access error occurs
     * @throws ClassNotFoundException  if the SQLite JDBC driver is not on the classpath
     * @throws IOException             if the database file cannot be written
     */
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

    /**
     * Deletes the test database file at the given path. Silently succeeds if the file does not
     * exist, making it safe to call before {@link #createTestAuthDB} as a cleanup step.
     *
     * @param testDbFileName path to the test database file to delete
     */
    public void destroyTestAuthDB(String testDbFileName) {
        File file = new File(testDbFileName);
        file.delete();
    }

    /**
     * Inserts four {@link RegisteredEntityTable} records representing different entity groups
     * (Clients, PtClients, Servers, PtServers) and verifies that {@code selectAllRegEntities}
     * retrieves them without error.
     *
     * @throws SQLException            if a database access error occurs
     * @throws ClassNotFoundException  if the SQLite JDBC driver is not on the classpath
     * @throws IOException             if a certificate or properties file cannot be read
     */
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
        Assert.assertTrue(sqLiteConnector.insertRecords(regEntity));

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
        Assert.assertTrue(sqLiteConnector.insertRecords(regEntity));

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
        Assert.assertTrue(sqLiteConnector.insertRecords(regEntity));

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
        Assert.assertTrue(sqLiteConnector.insertRecords(regEntity));

        C.PROPERTIES = new AuthServerProperties(testFilesDir + "properties/exampleAuth101.properties", null);
        sqLiteConnector.selectAllRegEntities();
        sqLiteConnector.close();
        destroyTestAuthDB(testDbFileName);
    }

    /**
     * Inserts eight {@link CommunicationPolicyTable} records covering unicast (Group), publish
     * (PubTopic), and subscribe (SubTopic) target types, then verifies that
     * {@code selectAllPolicies} retrieves all records without error.
     *
     * @throws SQLException            if a database access error occurs
     * @throws ClassNotFoundException  if the SQLite JDBC driver is not on the classpath
     * @throws IOException             if the database file cannot be accessed
     */
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

        communicationPolicyTable.setID(0);
        communicationPolicyTable.setReqGroup("Clients");
        communicationPolicyTable.setTargetTypeVal("Group");
        communicationPolicyTable.setTarget("Servers");
        communicationPolicyTable.setMaxNumSessionKeyOwners(2);
        communicationPolicyTable.setSessionCryptoSpec("AES-128-CBC:SHA256");
        communicationPolicyTable.setAbsValidityStr("1*day");
        communicationPolicyTable.setRelValidityStr("20*sec");
        Assert.assertTrue(sqLiteConnector.insertRecords(communicationPolicyTable));

        communicationPolicyTable.setID(1);
        communicationPolicyTable.setReqGroup("Clients");
        communicationPolicyTable.setTargetTypeVal("Group");
        communicationPolicyTable.setTarget("PtServers");
        communicationPolicyTable.setMaxNumSessionKeyOwners(2);
        communicationPolicyTable.setSessionCryptoSpec("AES-128-CBC:SHA256");
        communicationPolicyTable.setAbsValidityStr("1*hour");
        communicationPolicyTable.setRelValidityStr("20*sec");
        Assert.assertTrue(sqLiteConnector.insertRecords(communicationPolicyTable));

        communicationPolicyTable.setID(2);
        communicationPolicyTable.setReqGroup("PtClients");
        communicationPolicyTable.setTargetTypeVal("Group");
        communicationPolicyTable.setTarget("Servers");
        communicationPolicyTable.setMaxNumSessionKeyOwners(2);
        communicationPolicyTable.setSessionCryptoSpec("AES-128-CBC:SHA256");
        communicationPolicyTable.setAbsValidityStr("1*day");
        communicationPolicyTable.setRelValidityStr("2*hour");
        Assert.assertTrue(sqLiteConnector.insertRecords(communicationPolicyTable));

        communicationPolicyTable.setID(3);
        communicationPolicyTable.setReqGroup("PtClients");
        communicationPolicyTable.setTargetTypeVal("Group");
        communicationPolicyTable.setTarget("PtServers");
        communicationPolicyTable.setMaxNumSessionKeyOwners(2);
        communicationPolicyTable.setSessionCryptoSpec("AES-128-CBC:SHA256");
        communicationPolicyTable.setAbsValidityStr("2*hour");
        communicationPolicyTable.setRelValidityStr("20*sec");
        Assert.assertTrue(sqLiteConnector.insertRecords(communicationPolicyTable));

        communicationPolicyTable.setID(4);
        communicationPolicyTable.setReqGroup("Clients");
        communicationPolicyTable.setTargetTypeVal("PubTopic");
        communicationPolicyTable.setTarget("Ptopic");
        communicationPolicyTable.setMaxNumSessionKeyOwners(64);
        communicationPolicyTable.setSessionCryptoSpec("AES-128-CBC:SHA256");
        communicationPolicyTable.setAbsValidityStr("6*hour");
        communicationPolicyTable.setRelValidityStr("3*hour");
        Assert.assertTrue(sqLiteConnector.insertRecords(communicationPolicyTable));

        communicationPolicyTable.setID(5);
        communicationPolicyTable.setReqGroup("Servers");
        communicationPolicyTable.setTargetTypeVal("SubTopic");
        communicationPolicyTable.setTarget("Ptopic");
        communicationPolicyTable.setMaxNumSessionKeyOwners(64);
        communicationPolicyTable.setSessionCryptoSpec("AES-128-CBC:SHA256");
        communicationPolicyTable.setAbsValidityStr("6*hour");
        communicationPolicyTable.setRelValidityStr("3*hour");
        Assert.assertTrue(sqLiteConnector.insertRecords(communicationPolicyTable));

        communicationPolicyTable.setID(6);
        communicationPolicyTable.setReqGroup("Clients");
        communicationPolicyTable.setTargetTypeVal("SubTopic");
        communicationPolicyTable.setTarget("Ptopic");
        communicationPolicyTable.setMaxNumSessionKeyOwners(64);
        communicationPolicyTable.setSessionCryptoSpec("AES-128-CBC:SHA256");
        communicationPolicyTable.setAbsValidityStr("6*hour");
        communicationPolicyTable.setRelValidityStr("3*hour");
        Assert.assertTrue(sqLiteConnector.insertRecords(communicationPolicyTable));

        communicationPolicyTable.setID(7);
        communicationPolicyTable.setReqGroup("Servers");
        communicationPolicyTable.setTargetTypeVal("PubTopic");
        communicationPolicyTable.setTarget("Ptopic");
        communicationPolicyTable.setMaxNumSessionKeyOwners(64);
        communicationPolicyTable.setSessionCryptoSpec("AES-128-CBC:SHA256");
        communicationPolicyTable.setAbsValidityStr("6*hour");
        communicationPolicyTable.setRelValidityStr("3*hour");
        Assert.assertTrue(sqLiteConnector.insertRecords(communicationPolicyTable));

        // Test Select All.
        sqLiteConnector.selectAllPolicies();
        sqLiteConnector.close();
        destroyTestAuthDB(testDbFileName);
    }

    /**
     * Inserts a {@link TrustedAuthTable} record for Auth 102 loaded from PEM certificate files
     * and verifies that {@code selectAllTrustedAuths} completes without error.
     *
     * @throws SQLException                  if a database access error occurs
     * @throws ClassNotFoundException        if the SQLite JDBC driver is not on the classpath
     * @throws CertificateEncodingException  if a certificate cannot be DER-encoded
     * @throws IOException                   if a certificate file cannot be read
     */
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
        Assert.assertTrue(sqLiteConnector.insertRecords(trustedAuth));

        // Test Select All.
        sqLiteConnector.selectAllTrustedAuths();
        sqLiteConnector.close();
        destroyTestAuthDB(testDbFileName);
    }

    /**
     * Inserts two {@link FileSharingTable} records — one with reader type {@code "entity"} and one
     * with {@code "group"} — and verifies both insertions succeed.
     *
     * @throws SQLException            if a database access error occurs
     * @throws IOException             if the database file cannot be accessed
     * @throws ClassNotFoundException  if the SQLite JDBC driver is not on the classpath
     */
    @Test
    @Category(org.iot.auth.db.bean.FileSharingTable.class)
    public void testFileSharingTable() throws SQLException, IOException, ClassNotFoundException {
        final String testDbFileName = testDbPath + "testTrustedAuthInsertionAndSelectAll" + "_auth.db";
        destroyTestAuthDB(testDbFileName);
        createTestAuthDB(testDbFileName);
        SQLiteConnector sqLiteConnector = new SQLiteConnector(testDbFileName, authDBProtectionMethod);
        sqLiteConnector.initialize(databaseKey);
        sqLiteConnector.DEBUG = true;

        FileSharingTable fileSharing = new FileSharingTable();
        fileSharing.setOwner("Alice");
        fileSharing.setReader("Bob");
        fileSharing.setReaderType("entity");
        Assert.assertTrue(sqLiteConnector.insertRecords(fileSharing));

        fileSharing.setOwner("Alice");
        fileSharing.setReader("TeamA");
        fileSharing.setReaderType("group");
        Assert.assertTrue(sqLiteConnector.insertRecords(fileSharing));

        // TODO (@hokeun): Implement selectAllFileSharing and add test for it.
    }

    /**
     * Constructs a {@link CachedSessionKeyTable} instance pre-populated with common test defaults
     * (max 2 owners, 20-second relative validity, AES-128-CBC:SHA256 crypto spec, 16-byte zero key).
     *
     * @param id          numeric session key identifier
     * @param owner       initial owner entity name, or {@code null} if no owner is set yet
     * @param purpose     session key purpose string (e.g., {@code "Clients:Group:Servers"})
     * @param absValidity absolute expiry timestamp in milliseconds since epoch
     * @return a fully initialized {@link CachedSessionKeyTable} ready for insertion
     */
    private CachedSessionKeyTable buildCachedSessionKey(long id, String owner, String purpose, long absValidity) {
        CachedSessionKeyTable key = new CachedSessionKeyTable();
        key.setID(id);
        key.setOwner(owner);
        key.setMaxNumOwners(2);
        key.setPurpose(purpose);
        key.setAbsValidity(absValidity);
        key.setRelValidity(DateHelper.parseTimePeriod("20*sec"));
        key.setSessionCryptoSpec("AES-128-CBC:SHA256");
        key.setKeyVal(new byte[16]);
        key.setExpectedOwnerGroups("Clients,Servers");
        return key;
    }

    /**
     * Inserts two {@link CachedSessionKeyTable} records with different purposes and verifies that
     * {@code selectAllCachedSessionKeys} returns exactly two entries.
     *
     * @throws SQLException            if a database access error occurs
     * @throws ClassNotFoundException  if the SQLite JDBC driver is not on the classpath
     * @throws IOException             if the database file cannot be accessed
     */
    @Test
    @Category(org.iot.auth.db.bean.CachedSessionKeyTable.class)
    public void testCachedSessionKeyInsertionAndSelectAll() throws SQLException, ClassNotFoundException, IOException {
        final String testDbFileName = testDbPath + "testCachedSessionKeyInsertionAndSelectAll" + "_auth.db";
        destroyTestAuthDB(testDbFileName);
        createTestAuthDB(testDbFileName);
        SQLiteConnector sqLiteConnector = new SQLiteConnector(testDbFileName, authDBProtectionMethod);
        sqLiteConnector.initialize(databaseKey);
        sqLiteConnector.DEBUG = true;

        long futureTime = new Date().getTime() + DateHelper.parseTimePeriod("1*hour");
        sqLiteConnector.insertRecords(buildCachedSessionKey(1L, "net1.client", "Clients:Group:Servers", futureTime));
        sqLiteConnector.insertRecords(buildCachedSessionKey(2L, "net1.ptClient", "PtClients:Group:PtServers", futureTime));

        List<CachedSessionKeyTable> keys = sqLiteConnector.selectAllCachedSessionKeys();
        Assert.assertEquals(2, keys.size());
        sqLiteConnector.close();
        destroyTestAuthDB(testDbFileName);
    }

    /**
     * Inserts a single {@link CachedSessionKeyTable} record with a known ID and verifies that
     * {@code selectCachedSessionKeyByID} retrieves it with the correct ID and purpose.
     *
     * @throws SQLException            if a database access error occurs
     * @throws ClassNotFoundException  if the SQLite JDBC driver is not on the classpath
     * @throws IOException             if the database file cannot be accessed
     */
    @Test
    @Category(org.iot.auth.db.bean.CachedSessionKeyTable.class)
    public void testCachedSessionKeySelectById() throws SQLException, ClassNotFoundException, IOException {
        final String testDbFileName = testDbPath + "testCachedSessionKeySelectById" + "_auth.db";
        destroyTestAuthDB(testDbFileName);
        createTestAuthDB(testDbFileName);
        SQLiteConnector sqLiteConnector = new SQLiteConnector(testDbFileName, authDBProtectionMethod);
        sqLiteConnector.initialize(databaseKey);
        sqLiteConnector.DEBUG = true;

        long futureTime = new Date().getTime() + DateHelper.parseTimePeriod("1*hour");
        sqLiteConnector.insertRecords(buildCachedSessionKey(42L, "net1.client", "Clients:Group:Servers", futureTime));

        CachedSessionKeyTable found = sqLiteConnector.selectCachedSessionKeyByID(42L);
        Assert.assertNotNull(found);
        Assert.assertEquals(42L, found.getID());
        Assert.assertEquals("Clients:Group:Servers", found.getPurpose());
        sqLiteConnector.close();
        destroyTestAuthDB(testDbFileName);
    }

    /**
     * Inserts two {@link CachedSessionKeyTable} records with different purposes and verifies that
     * {@code selectCachedSessionKeysByPurpose} returns only the record matching the requested
     * entity and purpose string.
     *
     * @throws SQLException            if a database access error occurs
     * @throws ClassNotFoundException  if the SQLite JDBC driver is not on the classpath
     * @throws IOException             if the database file cannot be accessed
     */
    @Test
    @Category(org.iot.auth.db.bean.CachedSessionKeyTable.class)
    public void testCachedSessionKeySelectByPurpose() throws SQLException, ClassNotFoundException, IOException {
        final String testDbFileName = testDbPath + "testCachedSessionKeySelectByPurpose" + "_auth.db";
        destroyTestAuthDB(testDbFileName);
        createTestAuthDB(testDbFileName);
        SQLiteConnector sqLiteConnector = new SQLiteConnector(testDbFileName, authDBProtectionMethod);
        sqLiteConnector.initialize(databaseKey);
        sqLiteConnector.DEBUG = true;

        long futureTime = new Date().getTime() + DateHelper.parseTimePeriod("1*hour");
        sqLiteConnector.insertRecords(buildCachedSessionKey(1L, "net1.server", "Clients:Group:Servers", futureTime));
        sqLiteConnector.insertRecords(buildCachedSessionKey(2L, "net1.server", "PtClients:Group:PtServers", futureTime));

        List<CachedSessionKeyTable> results = sqLiteConnector.selectCachedSessionKeysByPurpose(
                "net1.client", "Clients:Group:Servers");
        Assert.assertEquals(1, results.size());
        Assert.assertEquals("Clients:Group:Servers", results.get(0).getPurpose());
        sqLiteConnector.close();
        destroyTestAuthDB(testDbFileName);
    }

    /**
     * Inserts a {@link CachedSessionKeyTable} record with no initial owner, appends two owner
     * entity names via {@code appendSessionKeyOwner}, and confirms both names appear in the
     * retrieved owner field.
     *
     * @throws SQLException            if a database access error occurs
     * @throws ClassNotFoundException  if the SQLite JDBC driver is not on the classpath
     * @throws IOException             if the database file cannot be accessed
     */
    @Test
    @Category(org.iot.auth.db.bean.CachedSessionKeyTable.class)
    public void testCachedSessionKeyAppendOwner() throws SQLException, ClassNotFoundException, IOException {
        final String testDbFileName = testDbPath + "testCachedSessionKeyAppendOwner" + "_auth.db";
        destroyTestAuthDB(testDbFileName);
        createTestAuthDB(testDbFileName);
        SQLiteConnector sqLiteConnector = new SQLiteConnector(testDbFileName, authDBProtectionMethod);
        sqLiteConnector.initialize(databaseKey);
        sqLiteConnector.DEBUG = true;

        long futureTime = new Date().getTime() + DateHelper.parseTimePeriod("1*hour");
        sqLiteConnector.insertRecords(buildCachedSessionKey(1L, null, "Clients:Group:Servers", futureTime));

        sqLiteConnector.appendSessionKeyOwner(1L, "net1.client");
        sqLiteConnector.appendSessionKeyOwner(1L, "net1.server");

        CachedSessionKeyTable found = sqLiteConnector.selectCachedSessionKeyByID(1L);
        Assert.assertNotNull(found);
        Assert.assertTrue(found.getOwner().contains("net1.client"));
        Assert.assertTrue(found.getOwner().contains("net1.server"));
        sqLiteConnector.close();
        destroyTestAuthDB(testDbFileName);
    }

    /**
     * Inserts two {@link CachedSessionKeyTable} records, calls {@code deleteAllCachedSessionKeys},
     * and verifies that a subsequent {@code selectAllCachedSessionKeys} returns an empty list.
     *
     * @throws SQLException            if a database access error occurs
     * @throws ClassNotFoundException  if the SQLite JDBC driver is not on the classpath
     * @throws IOException             if the database file cannot be accessed
     */
    @Test
    @Category(org.iot.auth.db.bean.CachedSessionKeyTable.class)
    public void testCachedSessionKeyDeleteAll() throws SQLException, ClassNotFoundException, IOException {
        final String testDbFileName = testDbPath + "testCachedSessionKeyDeleteAll" + "_auth.db";
        destroyTestAuthDB(testDbFileName);
        createTestAuthDB(testDbFileName);
        SQLiteConnector sqLiteConnector = new SQLiteConnector(testDbFileName, authDBProtectionMethod);
        sqLiteConnector.initialize(databaseKey);
        sqLiteConnector.DEBUG = true;

        long futureTime = new Date().getTime() + DateHelper.parseTimePeriod("1*hour");
        sqLiteConnector.insertRecords(buildCachedSessionKey(1L, "net1.client", "Clients:Group:Servers", futureTime));
        sqLiteConnector.insertRecords(buildCachedSessionKey(2L, "net1.server", "PtClients:Group:PtServers", futureTime));

        sqLiteConnector.deleteAllCachedSessionKeys();
        List<CachedSessionKeyTable> keys = sqLiteConnector.selectAllCachedSessionKeys();
        Assert.assertEquals(0, keys.size());
        sqLiteConnector.close();
        destroyTestAuthDB(testDbFileName);
    }

    /**
     * Inserts two {@link FileSharingTable} records for the same owner — one granting access to a
     * specific entity and one to a group — and verifies that {@code selectFileSharingInfoByOwner}
     * returns both reader identifiers.
     *
     * @throws SQLException            if a database access error occurs
     * @throws ClassNotFoundException  if the SQLite JDBC driver is not on the classpath
     * @throws IOException             if the database file cannot be accessed
     */
    @Test
    @Category(org.iot.auth.db.bean.FileSharingTable.class)
    public void testFileSharingInsertionAndSelectByOwner() throws SQLException, ClassNotFoundException, IOException {
        final String testDbFileName = testDbPath + "testFileSharingInsertionAndSelectByOwner" + "_auth.db";
        destroyTestAuthDB(testDbFileName);
        createTestAuthDB(testDbFileName);
        SQLiteConnector sqLiteConnector = new SQLiteConnector(testDbFileName, authDBProtectionMethod);
        sqLiteConnector.initialize(databaseKey);
        sqLiteConnector.DEBUG = true;

        FileSharingTable entry1 = new FileSharingTable();
        entry1.setOwner("net1.server");
        entry1.setReaderType("entity");
        entry1.setReader("net1.client");
        Assert.assertTrue(sqLiteConnector.insertRecords(entry1));

        FileSharingTable entry2 = new FileSharingTable();
        entry2.setOwner("net1.server");
        entry2.setReaderType("group");
        entry2.setReader("Clients");
        Assert.assertTrue(sqLiteConnector.insertRecords(entry2));

        List<String> readers = sqLiteConnector.selectFileSharingInfoByOwner("net1.server");
        Assert.assertEquals(2, readers.size());
        Assert.assertTrue(readers.contains("net1.client"));
        Assert.assertTrue(readers.contains("Clients"));
        sqLiteConnector.close();
        destroyTestAuthDB(testDbFileName);
    }

    /**
     * Inserts two {@link DelegationPrivilegeTable} records — one DELEGATE privilege for
     * {@code HighTrustAgents} and one READ privilege for {@code Users} — then verifies that
     * {@code selectAllPrivileges} returns both records and that filtering by privileged group
     * {@code "HighTrustAgents"} returns only the DELEGATE entry.
     *
     * @throws SQLException                          if a database access error occurs
     * @throws ClassNotFoundException                if the SQLite JDBC driver is not on the classpath
     * @throws IOException                           if the database file cannot be accessed
     * @throws org.json.simple.parser.ParseException if privilege info JSON cannot be parsed
     */
    @Test
    @Category(org.iot.auth.db.DelegationPrivilege.class)
    public void testDelegationPrivilegeInsertionAndSelectAll()
            throws SQLException, ClassNotFoundException, IOException, org.json.simple.parser.ParseException {
        final String testDbFileName = testDbPath + "testDelegationPrivilegeInsertionAndSelectAll" + "_auth.db";
        destroyTestAuthDB(testDbFileName);
        createTestAuthDB(testDbFileName);
        SQLiteConnector sqLiteConnector = new SQLiteConnector(testDbFileName, authDBProtectionMethod);
        sqLiteConnector.initialize(databaseKey);
        sqLiteConnector.DEBUG = true;

        DelegationPrivilegeTable priv1 = new DelegationPrivilegeTable();
        priv1.setPrivilegeType("DELEGATE");
        priv1.setprivilegedGroup("HighTrustAgents");
        priv1.setSubject("net1.highTrustAgent");
        priv1.setObject("LowTrustAgents");
        priv1.setValidity("1*day");
        priv1.setInfo("{\"note\":\"test delegation\"}");
        Assert.assertTrue(sqLiteConnector.insertRecords(priv1));

        DelegationPrivilegeTable priv2 = new DelegationPrivilegeTable();
        priv2.setPrivilegeType("READ");
        priv2.setprivilegedGroup("Users");
        priv2.setSubject("net1.rcUser");
        priv2.setObject("Website");
        priv2.setValidity("2*hour");
        priv2.setInfo("{\"note\":\"read privilege\"}");
        Assert.assertTrue(sqLiteConnector.insertRecords(priv2));

        List<DelegationPrivilegeTable> all = sqLiteConnector.selectAllPrivileges();
        Assert.assertEquals(2, all.size());

        List<DelegationPrivilegeTable> highTrustPrivs = sqLiteConnector.selectPrivilegeByPrivilegedGroup("HighTrustAgents");
        Assert.assertEquals(1, highTrustPrivs.size());
        Assert.assertEquals("DELEGATE", highTrustPrivs.get(0).getPrivilegeType());
        sqLiteConnector.close();
        destroyTestAuthDB(testDbFileName);
    }

    /**
     * Inserts parent and child {@link CommunicationPolicyTable} records required by foreign-key
     * constraints, then inserts a {@link DelegationInfoTable} record linking them. Verifies that if
     * {@code getAllChildren} returns all cascading descendant policy IDs for a given parent policy ID.
     * {@code selectParentById} for returns the correct parent policy ID for a given child policy ID.
     *
     * @throws SQLException            if a database access error occurs
     * @throws ClassNotFoundException  if the SQLite JDBC driver is not on the classpath
     * @throws IOException             if the database file cannot be accessed
     */
    @Test
    @Category(org.iot.auth.db.bean.DelegationInfoTable.class)
    public void testDelegationInfoInsertionAndGetChildren()
            throws SQLException, ClassNotFoundException, IOException {
        final String testDbFileName = testDbPath + "testDelegationInfoInsertionAndGetChildren" + "_auth.db";
        destroyTestAuthDB(testDbFileName);
        createTestAuthDB(testDbFileName);
        SQLiteConnector sqLiteConnector = new SQLiteConnector(testDbFileName, authDBProtectionMethod);
        sqLiteConnector.initialize(databaseKey);
        sqLiteConnector.DEBUG = true;

        // Insert parent and child communication policies (required by FK constraints).
        CommunicationPolicyTable parent = new CommunicationPolicyTable();
        parent.setID(100);
        parent.setReqGroup("Users");
        parent.setTargetTypeVal("Group");
        parent.setTarget("Website");
        parent.setMaxNumSessionKeyOwners(2);
        parent.setSessionCryptoSpec("AES-128-CBC:SHA256");
        parent.setAbsValidityStr("1*day");
        parent.setRelValidityStr("20*sec");
        Assert.assertTrue(sqLiteConnector.insertRecords(parent));

        CommunicationPolicyTable child = new CommunicationPolicyTable();
        child.setID(101);
        child.setReqGroup("Users");
        child.setTargetTypeVal("Group");
        child.setTarget("HighTrustAgents");
        child.setMaxNumSessionKeyOwners(2);
        child.setSessionCryptoSpec("AES-128-CBC:SHA256");
        child.setAbsValidityStr("1*hour");
        child.setRelValidityStr("20*sec");
        Assert.assertTrue(sqLiteConnector.insertRecords(child));

        CommunicationPolicyTable grandChild = new CommunicationPolicyTable();
        grandChild.setID(102);
        grandChild.setReqGroup("HighTrustAgents");
        grandChild.setTargetTypeVal("Group");
        grandChild.setTarget("LowTrustAgents");
        grandChild.setMaxNumSessionKeyOwners(2);
        grandChild.setSessionCryptoSpec("AES-128-CBC:SHA256");
        grandChild.setAbsValidityStr("1*hour");
        grandChild.setRelValidityStr("20*sec");
        Assert.assertTrue(sqLiteConnector.insertRecords(grandChild));

        DelegationInfoTable delegationInfo = new DelegationInfoTable();
        delegationInfo.setCPTId(101L);
        delegationInfo.setParent(100L);
        delegationInfo.setDelegatedTime(new Date().getTime());
        delegationInfo.setRevokedTime(0L);
        Assert.assertTrue(sqLiteConnector.insertRecords(delegationInfo));

        delegationInfo.setCPTId(102L);
        delegationInfo.setParent(101L);
        delegationInfo.setDelegatedTime(new Date().getTime());
        delegationInfo.setRevokedTime(0L);
        Assert.assertTrue(sqLiteConnector.insertRecords(delegationInfo));

        List<String> children = sqLiteConnector.getAllChildren("100");
        Assert.assertEquals(2, children.size());
        Assert.assertEquals("101", children.get(0));
        Assert.assertEquals("102", children.get(1));

        String parentId = sqLiteConnector.selectParentById("101");
        Assert.assertEquals("100", parentId);

        String childId = sqLiteConnector.selectParentById("102");
        Assert.assertEquals("101", childId);

        sqLiteConnector.close();
        destroyTestAuthDB(testDbFileName);
    }

    /**
     * Inserts a {@link MetaDataTable} record for {@code SessionKeyCount} with an initial value of
     * {@code "0"}, reads it back to confirm the insert, updates it to {@code "5"} via
     * {@code updateMetaData}, and verifies the updated value is persisted correctly.
     *
     * @throws SQLException            if a database access error occurs
     * @throws ClassNotFoundException  if the SQLite JDBC driver is not on the classpath
     * @throws IOException             if the database file cannot be accessed
     */
    @Test
    @Category(org.iot.auth.db.bean.MetaDataTable.class)
    public void testMetaDataInsertionAndUpdate() throws SQLException, ClassNotFoundException, IOException {
        final String testDbFileName = testDbPath + "testMetaDataInsertionAndUpdate" + "_auth.db";
        destroyTestAuthDB(testDbFileName);
        createTestAuthDB(testDbFileName);
        SQLiteConnector sqLiteConnector = new SQLiteConnector(testDbFileName, authDBProtectionMethod);
        sqLiteConnector.initialize(databaseKey);
        sqLiteConnector.DEBUG = true;

        MetaDataTable metaData = new MetaDataTable();
        metaData.setKey(MetaDataTable.key.SessionKeyCount.name());
        metaData.setValue("0");
        Assert.assertTrue(sqLiteConnector.insertRecords(metaData));

        String value = sqLiteConnector.selectMetaDataValue(MetaDataTable.key.SessionKeyCount.name());
        Assert.assertEquals("0", value);

        sqLiteConnector.updateMetaData(MetaDataTable.key.SessionKeyCount.name(), "5");
        value = sqLiteConnector.selectMetaDataValue(MetaDataTable.key.SessionKeyCount.name());
        Assert.assertEquals("5", value);
        sqLiteConnector.close();
        destroyTestAuthDB(testDbFileName);
    }

    /**
     * Inserts a {@link CommunicationPolicyTable} record with a non-null Context JSON string and
     * verifies that the Context is persisted and retrieved correctly from the database.
     *
     * @throws SQLException            if a database access error occurs
     * @throws ClassNotFoundException  if the SQLite JDBC driver is not on the classpath
     * @throws IOException             if the database file cannot be accessed
     */
    @Test
    @Category(org.iot.auth.db.CommunicationPolicy.class)
    public void testCommPolicyContextColumn() throws SQLException, ClassNotFoundException, IOException {
        final String testDbFileName = testDbPath + "testCommPolicyContextColumn" + "_auth.db";
        destroyTestAuthDB(testDbFileName);
        createTestAuthDB(testDbFileName);
        SQLiteConnector sqLiteConnector = new SQLiteConnector(testDbFileName, authDBProtectionMethod);
        sqLiteConnector.initialize(databaseKey);
        sqLiteConnector.DEBUG = true;

        String contextJson = "{\"Number of People\":{\"Max\":3},"
                + "\"Location\":{\"Allowed\":[\"Classroom\",\"Meeting Room\"]},"
                + "\"Time of Day\":{\"Min\":\"09:00\",\"Max\":\"18:00\"}}";

        CommunicationPolicyTable policy = new CommunicationPolicyTable();
        policy.setID(0);
        policy.setReqGroup("Clients");
        policy.setTargetTypeVal("Group");
        policy.setTarget("Servers");
        policy.setMaxNumSessionKeyOwners(2);
        policy.setSessionCryptoSpec("AES-128-CBC:SHA256");
        policy.setAbsValidityStr("1*day");
        policy.setRelValidityStr("20*sec");
        policy.setContext(contextJson);
        Assert.assertTrue(sqLiteConnector.insertRecords(policy));

        // policy with null Context
        policy.setID(1);
        policy.setReqGroup("PtClients");
        policy.setTarget("PtServers");
        policy.setContext(null);
        Assert.assertTrue(sqLiteConnector.insertRecords(policy));

        List<CommunicationPolicyTable> policies = sqLiteConnector.selectAllPolicies();
        Assert.assertEquals(2, policies.size());

        CommunicationPolicyTable withContext = policies.get(0);
        Assert.assertEquals(contextJson, withContext.getContext());

        CommunicationPolicyTable withoutContext = policies.get(1);
        Assert.assertNull(withoutContext.getContext());

        sqLiteConnector.close();
        destroyTestAuthDB(testDbFileName);
    }

    /**
     * Verifies that {@link org.iot.auth.db.ContextVerifier} correctly evaluates all three
     * supported condition types: numeric Max, Allowed list, and Time-of-Day Min/Max range.
     */
    @Test
    public void testContextVerifier() {
        String policyContextJson = "{\"Number of People\":{\"Max\":3},"
                + "\"Location\":{\"Allowed\":[\"Classroom\",\"Meeting Room\"]},"
                + "\"Time of Day\":{\"Min\":\"09:00\",\"Max\":\"18:00\"}}";

        // Passing context: all conditions satisfied
        JSONObject passing = new JSONObject();
        passing.put("Number of People", 2L);
        passing.put("Location", "Classroom");
        passing.put("Time of Day", "10:30");
        Assert.assertTrue(org.iot.auth.db.ContextVerifier.verifyContext(policyContextJson, passing));

        // Failing: Number of People exceeds Max
        JSONObject tooManyPeople = new JSONObject();
        tooManyPeople.put("Number of People", 5L);
        tooManyPeople.put("Location", "Classroom");
        tooManyPeople.put("Time of Day", "10:30");
        Assert.assertFalse(org.iot.auth.db.ContextVerifier.verifyContext(policyContextJson, tooManyPeople));

        // Failing: Location not in Allowed list
        JSONObject wrongLocation = new JSONObject();
        wrongLocation.put("Number of People", 2L);
        wrongLocation.put("Location", "Cafeteria");
        wrongLocation.put("Time of Day", "10:30");
        Assert.assertFalse(org.iot.auth.db.ContextVerifier.verifyContext(policyContextJson, wrongLocation));

        // Failing: Time of Day outside range
        JSONObject outsideHours = new JSONObject();
        outsideHours.put("Number of People", 2L);
        outsideHours.put("Location", "Meeting Room");
        outsideHours.put("Time of Day", "20:00");
        Assert.assertFalse(org.iot.auth.db.ContextVerifier.verifyContext(policyContextJson, outsideHours));

        // Null policy context: always passes
        Assert.assertTrue(org.iot.auth.db.ContextVerifier.verifyContext(null, null));

        // Non-null policy context but no request context: fails
        // Non-null policy context but no request context: fails
        Assert.assertFalse(org.iot.auth.db.ContextVerifier.verifyContext(policyContextJson, null));

        // Malformed policy context JSON: fails gracefully
        Assert.assertFalse(org.iot.auth.db.ContextVerifier.verifyContext(
                "{not valid json", new JSONObject()));

        // Boundary values are inclusive for both numeric and time ranges.
        JSONObject boundary = new JSONObject();
        boundary.put("Number of People", 3L);
        boundary.put("Location", "Meeting Room");
        boundary.put("Time of Day", "09:00");
        Assert.assertTrue(org.iot.auth.db.ContextVerifier.verifyContext(policyContextJson, boundary));

        // Time given in HH:mm:ss format is accepted and compared correctly.
        JSONObject withSeconds = new JSONObject();
        withSeconds.put("Number of People", 1L);
        withSeconds.put("Location", "Classroom");
        withSeconds.put("Time of Day", "17:59:59");
        Assert.assertTrue(org.iot.auth.db.ContextVerifier.verifyContext(policyContextJson, withSeconds));

        // Format mismatch: time condition but an integer-formatted value is provided.
        JSONObject timeFormatMismatch = new JSONObject();
        timeFormatMismatch.put("Number of People", 2L);
        timeFormatMismatch.put("Location", "Classroom");
        timeFormatMismatch.put("Time of Day", 1030L);
        Assert.assertFalse(org.iot.auth.db.ContextVerifier.verifyContext(policyContextJson, timeFormatMismatch));

        // Numeric range with both Min and Max (integers), value within bounds.
        String numericRangePolicy = "{\"Temperature\":{\"Min\":18,\"Max\":26}}";
        JSONObject inRange = new JSONObject();
        inRange.put("Temperature", 22L);
        Assert.assertTrue(org.iot.auth.db.ContextVerifier.verifyContext(numericRangePolicy, inRange));

        // Numeric range, value below Min: fails.
        JSONObject belowMin = new JSONObject();
        belowMin.put("Temperature", 10L);
        Assert.assertFalse(org.iot.auth.db.ContextVerifier.verifyContext(numericRangePolicy, belowMin));

        // Format mismatch: numeric range but a time-formatted value is provided.
        JSONObject numericFormatMismatch = new JSONObject();
        numericFormatMismatch.put("Temperature", "12:00");
        Assert.assertFalse(org.iot.auth.db.ContextVerifier.verifyContext(numericRangePolicy, numericFormatMismatch));

        // Time range expressed with only a Max bound (single-bound, time format).
        String maxOnlyTimePolicy = "{\"Curfew\":{\"Max\":\"22:00\"}}";
        JSONObject beforeCurfew = new JSONObject();
        beforeCurfew.put("Curfew", "21:30");
        Assert.assertTrue(org.iot.auth.db.ContextVerifier.verifyContext(maxOnlyTimePolicy, beforeCurfew));
        JSONObject afterCurfew = new JSONObject();
        afterCurfew.put("Curfew", "23:00");
        Assert.assertFalse(org.iot.auth.db.ContextVerifier.verifyContext(maxOnlyTimePolicy, afterCurfew));
    }
}
