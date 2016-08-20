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

import org.iot.auth.AuthServer;
import org.iot.auth.config.AuthServerProperties;
import org.iot.auth.config.constants.C;
import org.iot.auth.config.constants.ConstantType;
import org.iot.auth.db.bean.CommunicationPolicyTable;
import org.iot.auth.db.bean.RegisteredEntityTable;
import org.iot.auth.db.bean.TrustedAuthTable;
import org.iot.auth.db.dao.SQLiteConnector;
import org.iot.auth.io.Buffer;
import org.iot.auth.message.MessageType;
import org.iot.auth.message.impl.AuthHello;
import org.junit.Test;
import org.junit.experimental.categories.Category;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.IOException;
import java.sql.SQLException;
import java.util.UUID;

/**
 * @author Salomon Lee
 */
public class AppTest {
    private static final Logger logger = LoggerFactory.getLogger(AppTest.class);
    private static final String _dbPath = "auth.db"; //"databases/auth101/auth.db";
    private boolean _dbCreated = false;
    private boolean _regEntityInserted = false;
    private boolean _commPolicyInserted = false;
    private boolean _trustedAuthInserted = false;
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

    public void testDBCreateion() throws SQLException, ClassNotFoundException {
        File file = new File(_dbPath);
        file.delete();
        SQLiteConnector sqLiteConnector = new SQLiteConnector(_dbPath);
        sqLiteConnector.DEBUG = true;
        sqLiteConnector.createTablesIfNotExists();
        _dbCreated = true;
    }

    public void testRegEntityInsertion() throws SQLException, ClassNotFoundException {
        if (!_dbCreated) {
            testDBCreateion();
        }
        SQLiteConnector sqLiteConnector = new SQLiteConnector(_dbPath);
        sqLiteConnector.DEBUG = true;
        RegisteredEntityTable regEntity = new RegisteredEntityTable();
        regEntity.setName("net1.server");
        regEntity.setGroup("Servers");
        regEntity.setPublicKeyFile("certs/ServerCert.pem");
        regEntity.setDistValidityPeriod("1*hour");
        regEntity.setDistCipherAlgo("AES-128-CBC");
        regEntity.setDistHashAlgo("SHA256");
        sqLiteConnector.insertRecords(regEntity);
        regEntity.setName("net1.client");
        regEntity.setGroup("Clients");
        regEntity.setPublicKeyFile("certs/ClientCert.pem");
        regEntity.setDistValidityPeriod("1*hour");
        regEntity.setDistCipherAlgo("AES-128-CBC");
        regEntity.setDistHashAlgo("SHA256");
        sqLiteConnector.insertRecords(regEntity);
        regEntity.setName("net1.ptServer");
        regEntity.setGroup("PtServers");
        regEntity.setPublicKeyFile("certs/PtServerCert.pem");
        regEntity.setDistValidityPeriod("3*sec");
        regEntity.setDistCipherAlgo("AES-128-CBC");
        regEntity.setDistHashAlgo("SHA256");
        sqLiteConnector.insertRecords(regEntity);
        regEntity.setName("net1.ptClient");
        regEntity.setGroup("PtClients");
        regEntity.setPublicKeyFile("certs/PtClientCert.pem");
        regEntity.setDistValidityPeriod("3*sec");
        regEntity.setDistCipherAlgo("AES-128-CBC");
        regEntity.setDistHashAlgo("SHA256");
        sqLiteConnector.insertRecords(regEntity);
        _regEntityInserted = true;
    }

    public void testCommPolicyInsertion() throws SQLException, ClassNotFoundException {
        if (!_dbCreated) {
            testDBCreateion();
        }
        SQLiteConnector sqLiteConnector = new SQLiteConnector(_dbPath);
        sqLiteConnector.DEBUG = true;
        CommunicationPolicyTable CommunicationPolicyTable = new CommunicationPolicyTable();

        CommunicationPolicyTable.setReqGroup("Clients");
        CommunicationPolicyTable.setTargetTypeVal("Group");
        CommunicationPolicyTable.setTarget("Servers");
        CommunicationPolicyTable.setCipherAlgo("AES-128-CBC");
        CommunicationPolicyTable.setHashAlgo("SHA256");
        CommunicationPolicyTable.setAbsValidityStr("1*day");
        CommunicationPolicyTable.setRelValidityStr("20*sec");
        sqLiteConnector.insertRecords(CommunicationPolicyTable);

        CommunicationPolicyTable.setReqGroup("Clients");
        CommunicationPolicyTable.setTargetTypeVal("Group");
        CommunicationPolicyTable.setTarget("PtServers");
        CommunicationPolicyTable.setCipherAlgo("AES-128-CBC");
        CommunicationPolicyTable.setHashAlgo("SHA256");
        CommunicationPolicyTable.setAbsValidityStr("1*hour");
        CommunicationPolicyTable.setRelValidityStr("20*sec");
        sqLiteConnector.insertRecords(CommunicationPolicyTable);

        CommunicationPolicyTable.setReqGroup("PtClients");
        CommunicationPolicyTable.setTargetTypeVal("Group");
        CommunicationPolicyTable.setTarget("Servers");
        CommunicationPolicyTable.setCipherAlgo("AES-128-CBC");
        CommunicationPolicyTable.setHashAlgo("SHA256");
        CommunicationPolicyTable.setAbsValidityStr("1*day");
        CommunicationPolicyTable.setRelValidityStr("2*hour");
        sqLiteConnector.insertRecords(CommunicationPolicyTable);

        CommunicationPolicyTable.setReqGroup("PtClients");
        CommunicationPolicyTable.setTargetTypeVal("Group");
        CommunicationPolicyTable.setTarget("PtServers");
        CommunicationPolicyTable.setCipherAlgo("AES-128-CBC");
        CommunicationPolicyTable.setHashAlgo("SHA256");
        CommunicationPolicyTable.setAbsValidityStr("2*hour");
        CommunicationPolicyTable.setRelValidityStr("20*sec");
        sqLiteConnector.insertRecords(CommunicationPolicyTable);

        CommunicationPolicyTable.setReqGroup("Clients");
        CommunicationPolicyTable.setTargetTypeVal("PubTopic");
        CommunicationPolicyTable.setTarget("Ptopic");
        CommunicationPolicyTable.setCipherAlgo("AES-128-CBC");
        CommunicationPolicyTable.setHashAlgo("SHA256");
        CommunicationPolicyTable.setAbsValidityStr("6*hour");
        CommunicationPolicyTable.setRelValidityStr("3*hour");
        sqLiteConnector.insertRecords(CommunicationPolicyTable);

        CommunicationPolicyTable.setReqGroup("Servers");
        CommunicationPolicyTable.setTargetTypeVal("SubTopic");
        CommunicationPolicyTable.setTarget("Ptopic");
        CommunicationPolicyTable.setCipherAlgo("AES-128-CBC");
        CommunicationPolicyTable.setHashAlgo("SHA256");
        CommunicationPolicyTable.setAbsValidityStr("6*hour");
        CommunicationPolicyTable.setRelValidityStr("3*hour");
        sqLiteConnector.insertRecords(CommunicationPolicyTable);

        CommunicationPolicyTable.setReqGroup("Clients");
        CommunicationPolicyTable.setTargetTypeVal("SubTopic");
        CommunicationPolicyTable.setTarget("Ptopic");
        CommunicationPolicyTable.setCipherAlgo("AES-128-CBC");
        CommunicationPolicyTable.setHashAlgo("SHA256");
        CommunicationPolicyTable.setAbsValidityStr("6*hour");
        CommunicationPolicyTable.setRelValidityStr("3*hour");
        sqLiteConnector.insertRecords(CommunicationPolicyTable);

        CommunicationPolicyTable.setReqGroup("Servers");
        CommunicationPolicyTable.setTargetTypeVal("PubTopic");
        CommunicationPolicyTable.setTarget("Ptopic");
        CommunicationPolicyTable.setCipherAlgo("AES-128-CBC");
        CommunicationPolicyTable.setHashAlgo("SHA256");
        CommunicationPolicyTable.setAbsValidityStr("6*hour");
        CommunicationPolicyTable.setRelValidityStr("3*hour");
        sqLiteConnector.insertRecords(CommunicationPolicyTable);
        _commPolicyInserted = true;
    }

    public void testTrustedAuthInsertion() throws SQLException, ClassNotFoundException {
        if (!_dbCreated) {
            testDBCreateion();
        }
        SQLiteConnector sqLiteConnector = new SQLiteConnector(_dbPath);
        sqLiteConnector.DEBUG = true;
        TrustedAuthTable trustedAuth = new TrustedAuthTable();
        trustedAuth.setId(102);
        trustedAuth.setHost("localhost");
        trustedAuth.setPort(22901);
        trustedAuth.setCertificatePath("credentials/certs/Auth102InternetCert.pem");
        sqLiteConnector.insertRecords(trustedAuth);
        _trustedAuthInserted = true;
    }

    @Test
    @Category(org.iot.auth.db.dao.SQLiteConnector.class)
    public void testSelectAllCommPolicies() throws SQLException, ClassNotFoundException {
        if (!_commPolicyInserted) {
            testCommPolicyInsertion();
        }
        SQLiteConnector sqLiteConnector = new SQLiteConnector(_dbPath);
        sqLiteConnector.DEBUG = true;
        sqLiteConnector.selectAllPolicies();
    }

    @Test
    @Category(org.iot.auth.db.dao.SQLiteConnector.class)
    public void testSelectAllRegEntities() throws SQLException, ClassNotFoundException, IOException {
        if (!_regEntityInserted) {
            testRegEntityInsertion();
        }
        SQLiteConnector sqLiteConnector = new SQLiteConnector(_dbPath);
        sqLiteConnector.DEBUG = true;
        AuthServer.PROPERTIES = new AuthServerProperties("exampleAuth101.properties");
        sqLiteConnector.selectAllRegEntities("databases/auth101");
    }

    @Test
    @Category(org.iot.auth.db.dao.SQLiteConnector.class)
    public void testSelectAllTrustedAuth() throws SQLException, ClassNotFoundException {
        if (!_trustedAuthInserted) {
            testTrustedAuthInsertion();
        }
        SQLiteConnector sqLiteConnector = new SQLiteConnector(_dbPath);
        sqLiteConnector.DEBUG = true;
        sqLiteConnector.selectAllTrustedAuth();
    }
}
