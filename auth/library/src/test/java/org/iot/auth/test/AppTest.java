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
    @Test
    @Category(org.iot.auth.config.constants.C.class)
    public void testConstant(){
        logger.info("{}, {}",ConstantType.AUTH_NONCE_SIZE, C.AUTH_NONCE_SIZE);
    }

    @Test
    @Category(org.iot.auth.message.MessageType.class)
    public void testMessageType(){
        logger.info("{} {}", MessageType.AUTH_HELLO, MessageType.AUTH_HELLO.getValue());
        logger.info("{} {}", MessageType.AUTH_SESSION_KEY_REQ, MessageType.AUTH_SESSION_KEY_REQ.getValue());
        logger.info("{} {}", MessageType.AUTH_SESSION_KEY_RESP, MessageType.AUTH_SESSION_KEY_RESP.getValue());
        logger.info("{} {}", MessageType.SESSION_KEY_REQ_IN_PUB_ENC, MessageType.SESSION_KEY_REQ_IN_PUB_ENC.getValue());
        logger.info("{} {}", MessageType.SESSION_KEY_RESP_WITH_DIST_KEY, MessageType.SESSION_KEY_RESP_WITH_DIST_KEY.getValue());
        logger.info("{} {}", MessageType.SESSION_KEY_REQ, MessageType.SESSION_KEY_REQ.getValue());
        logger.info("{} {}", MessageType.SESSION_KEY_RESP, MessageType.SESSION_KEY_RESP.getValue());
        logger.info("{} {}", MessageType.SKEY_HANDSHAKE_1, MessageType.SKEY_HANDSHAKE_1.getValue());
        logger.info("{} {}", MessageType.SKEY_HANDSHAKE_2, MessageType.SKEY_HANDSHAKE_2.getValue());
        logger.info("{} {}", MessageType.SKEY_HANDSHAKE_3, MessageType.SKEY_HANDSHAKE_3.getValue());
        logger.info("{} {}", MessageType.SECURE_COMM_MSG, MessageType.SECURE_COMM_MSG.getValue());
        logger.info("{} {}", MessageType.FIN_SECURE_COMM, MessageType.FIN_SECURE_COMM.getValue());
        logger.info("{} {}", MessageType.SECURE_PUB, MessageType.SECURE_PUB.getValue());
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
        sqLiteConnector.insertRecords(entry1);

        FileSharingTable entry2 = new FileSharingTable();
        entry2.setOwner("net1.server");
        entry2.setReaderType("group");
        entry2.setReader("Clients");
        sqLiteConnector.insertRecords(entry2);

        List<String> readers = sqLiteConnector.selectFileSharingInfoByOwner("net1.server");
        Assert.assertEquals(2, readers.size());
        Assert.assertTrue(readers.contains("net1.client"));
        Assert.assertTrue(readers.contains("Clients"));
        sqLiteConnector.close();
        destroyTestAuthDB(testDbFileName);
    }

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
        priv1.setprivilegedGroup("Admins");
        priv1.setSubject("net1.client");
        priv1.setObject("Servers");
        priv1.setValidity("1*day");
        priv1.setInfo("{\"note\":\"test delegation\"}");
        sqLiteConnector.insertRecords(priv1);

        DelegationPrivilegeTable priv2 = new DelegationPrivilegeTable();
        priv2.setPrivilegeType("READ");
        priv2.setprivilegedGroup("Clients");
        priv2.setSubject("net1.ptClient");
        priv2.setObject("PtServers");
        priv2.setValidity("2*hour");
        priv2.setInfo("{\"note\":\"read privilege\"}");
        sqLiteConnector.insertRecords(priv2);

        List<DelegationPrivilegeTable> all = sqLiteConnector.selectAllPrivileges();
        Assert.assertEquals(2, all.size());

        List<DelegationPrivilegeTable> adminsPrivs = sqLiteConnector.selectPrivilegeByPrivilegedGroup("Admins");
        Assert.assertEquals(1, adminsPrivs.size());
        Assert.assertEquals("DELEGATE", adminsPrivs.get(0).getPrivilegeType());
        sqLiteConnector.close();
        destroyTestAuthDB(testDbFileName);
    }

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
        parent.setReqGroup("Clients");
        parent.setTargetTypeVal("Group");
        parent.setTarget("Servers");
        parent.setMaxNumSessionKeyOwners(2);
        parent.setSessionCryptoSpec("AES-128-CBC:SHA256");
        parent.setAbsValidityStr("1*day");
        parent.setRelValidityStr("20*sec");
        sqLiteConnector.insertRecords(parent);

        CommunicationPolicyTable child = new CommunicationPolicyTable();
        child.setID(101);
        child.setReqGroup("Clients");
        child.setTargetTypeVal("Group");
        child.setTarget("PtServers");
        child.setMaxNumSessionKeyOwners(2);
        child.setSessionCryptoSpec("AES-128-CBC:SHA256");
        child.setAbsValidityStr("1*hour");
        child.setRelValidityStr("20*sec");
        sqLiteConnector.insertRecords(child);

        DelegationInfoTable delegationInfo = new DelegationInfoTable();
        delegationInfo.setCPTId(101L);
        delegationInfo.setParent(100L);
        delegationInfo.setDelegatedTime(new Date().getTime());
        delegationInfo.setRevokedTime(0L);
        sqLiteConnector.insertRecords(delegationInfo);

        List<String> children = sqLiteConnector.getAllChildren("100");
        Assert.assertEquals(1, children.size());
        Assert.assertEquals("101", children.get(0));
        sqLiteConnector.close();
        destroyTestAuthDB(testDbFileName);
    }

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
        sqLiteConnector.insertRecords(metaData);

        String value = sqLiteConnector.selectMetaDataValue(MetaDataTable.key.SessionKeyCount.name());
        Assert.assertEquals("0", value);

        sqLiteConnector.updateMetaData(MetaDataTable.key.SessionKeyCount.name(), "5");
        value = sqLiteConnector.selectMetaDataValue(MetaDataTable.key.SessionKeyCount.name());
        Assert.assertEquals("5", value);
        sqLiteConnector.close();
        destroyTestAuthDB(testDbFileName);
    }
}
