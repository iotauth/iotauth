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

package org.iot.auth.server;

import org.eclipse.jetty.client.api.ContentResponse;
import org.iot.auth.crypto.*;
import org.iot.auth.exception.*;
import org.slf4j.Logger;
import org.iot.auth.AuthServer;
import org.iot.auth.db.*;
import org.iot.auth.io.Buffer;
import org.iot.auth.io.BufferedString;
import org.iot.auth.io.VariableLengthInt;
import org.iot.auth.message.*;
import org.iot.auth.util.ExceptionToString;
import org.json.simple.JSONObject;
import org.json.simple.parser.ParseException;

import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.sql.SQLException;
import java.util.LinkedList;
import java.util.List;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeoutException;

/**
 * An abstract handler class for general connections from each entity that requests Auth service (e.g., session key requests)
 * @author Hokeun Kim
 */
public abstract class EntityConnectionHandler {
    private final int RSA_KEY_SIZE = 256; // 2048 bits

    private class SessionKeysAndSpec {
        private List<SessionKey> sessionKeys;
        private final SymmetricKeyCryptoSpec spec;
        public SessionKeysAndSpec(List<SessionKey> sessionKeys, SymmetricKeyCryptoSpec spec) {
            this.sessionKeys = sessionKeys;
            this.spec = spec;
        }
        public List<SessionKey> getSessionKeys() {
            return sessionKeys;
        }
        public SymmetricKeyCryptoSpec getSpec() {
            return spec;
        }
    }

    private class DecPayloadAndRegisteredEntity {
        private Buffer payload;
        private RegisteredEntity registeredEntity;
        public DecPayloadAndRegisteredEntity(Buffer payload, RegisteredEntity registeredEntity) {
            this.payload = payload;
            this.registeredEntity = registeredEntity;
        }
        public Buffer getPayload() {
            return payload;
        }
        public RegisteredEntity getRegisteredEntity() {
            return registeredEntity;
        }
    }
    private class DistributionKeyInfo {
        private Buffer distributionKeyInfo;
        private DistributionKey distributionKey;
        public DistributionKeyInfo(Buffer distributionKeyInfo, DistributionKey distributionKey) {
            this.distributionKeyInfo = distributionKeyInfo;
            this.distributionKey = distributionKey;
        }
        public Buffer getDistributionKeyInfoBuffer() {
            return distributionKeyInfo;
        }
        public DistributionKey getDistributionKey() {
            return distributionKey;
        }
    }
    protected EntityConnectionHandler(AuthServer server) {
        this.server = server;
    }
    /**
     * Send Auth Hello message to an entity that is connected to Auth, as soon as an entity is connected via TCP/IP
     * @param authNonce Random number generated by Auth, to be sent to the connected entity, to prohibit replay attacks.
     * @throws IOException When socket IO fails.
     */
    protected void sendAuthHello(Buffer authNonce) throws IOException {
        getLogger().info("Sending AUTH_HELLO to entity at Port {} with auth nonce {}",
                getRemoteAddress(), authNonce.toHexString());

        AuthHelloMessage authHello = new AuthHelloMessage(server.getAuthID(), authNonce);

        writeToSocket(authHello.serialize().getRawBytes());
    }

    private void handleEntityReqInternal(byte[] bytes, Buffer authNonce) throws InvalidSessionKeyTargetException,
            NoAvailableDistributionKeyException, TooManySessionKeysRequestedException, IOException,
            UseOfExpiredKeyException, SQLException, ClassNotFoundException, ParseException, UnrecognizedEntityException,
            CertificateEncodingException, InvalidSignatureException, InvalidNonceException,
            InvalidSymmetricKeyOperationException
    {
        Buffer buf = new Buffer(bytes);
        MessageType type = MessageType.fromByte(buf.getByte(0));

        VariableLengthInt valLenInt = buf.getVariableLengthInt(IoTSPMessage.MSG_TYPE_SIZE);
        // rest of this is payload
        Buffer payload = buf.slice(IoTSPMessage.MSG_TYPE_SIZE + valLenInt.getRawBytes().length);

        if (type == MessageType.SESSION_KEY_REQ_IN_PUB_ENC) {
            getLogger().info("Received session key request message encrypted with public key!");
            // parse signed data
            Buffer encPayload = payload.slice(0, payload.length() - RSA_KEY_SIZE);
            getLogger().debug("Encrypted data ({}): {}", encPayload.length(), encPayload.toHexString());
            Buffer signature = payload.slice(payload.length() - RSA_KEY_SIZE);
            Buffer decPayload = server.getCrypto().authPrivateDecrypt(encPayload);

            getLogger().debug("Decrypted data ({}): {}", decPayload.length(), decPayload.toHexString());
            SessionKeyReqMessage sessionKeyReqMessage = new SessionKeyReqMessage(type, decPayload);

            RegisteredEntity requestingEntity = server.getRegisteredEntity(sessionKeyReqMessage.getEntityName());
            if (requestingEntity == null) {
                throw new UnrecognizedEntityException("Error in SESSION_KEY_REQ_IN_PUB_ENC: Session key requester is not found!");
            }

            // checking signature
            try {
                if (!server.getCrypto().verifySignedData(encPayload, signature, requestingEntity.getPublicKey())) {
                    throw new InvalidSignatureException("Entity signature verification failed!!");
                }
                else {
                    getLogger().debug("Entity signature is correct!");
                }
            }
            catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
                throw new InvalidSignatureException("Entity signature verification failed!!");
            }

            SessionKeysAndSpec ret =
                    processSessionKeyReq(requestingEntity, sessionKeyReqMessage, authNonce);
            List<SessionKey> sessionKeyList = ret.getSessionKeys();
            SymmetricKeyCryptoSpec sessionCryptoSpec = ret.getSpec();

            DistributionKeyInfo distributionKey = GenerateDistributionKey(requestingEntity, sessionKeyReqMessage.getDiffieHellmanParam());

            Buffer encryptedDistKey = server.getCrypto().authPublicEncrypt(distributionKey.getDistributionKeyInfoBuffer(),
                    requestingEntity.getPublicKey());
            encryptedDistKey.concat(server.getCrypto().signWithPrivateKey(encryptedDistKey));

            sendSessionKeyResp(distributionKey.getDistributionKey(), sessionKeyReqMessage.getEntityNonce(),
                    sessionKeyList, sessionCryptoSpec, encryptedDistKey);
            close();
        }
        else if (type == MessageType.SESSION_KEY_REQ) {
            DecPayloadAndRegisteredEntity dec = decryptPayloadWithDistKey(payload);
            SessionKeyReqMessage sessionKeyReqMessage = new SessionKeyReqMessage(type, dec.getPayload());

            SessionKeysAndSpec ret =
                    processSessionKeyReq(dec.getRegisteredEntity(), sessionKeyReqMessage, authNonce);
            List<SessionKey> sessionKeyList = ret.getSessionKeys();
            SymmetricKeyCryptoSpec sessionCryptoSpec = ret.getSpec();

            sendSessionKeyResp(dec.getRegisteredEntity().getDistributionKey(), sessionKeyReqMessage.getEntityNonce(),
                    sessionKeyList, sessionCryptoSpec, null);
            close();
        }
        else if (type == MessageType.MIGRATION_REQ_WITH_SIGN) {
            getLogger().info("Received migration request with signature!");
            Buffer decPayload = payload.slice(0, payload.length() - RSA_KEY_SIZE);
            Buffer signature = payload.slice(payload.length() - RSA_KEY_SIZE);
            getLogger().info("Decrypted data (" + decPayload.length() + "): " + decPayload.toHexString());

            MigrationReqMessage migrationReq =
                    new MigrationReqMessage(MessageType.MIGRATION_REQ_WITH_SIGN, decPayload);

            RegisteredEntity requestingEntity = server.getRegisteredEntity(migrationReq.getEntityName());
            if (requestingEntity == null) {
                throw new UnrecognizedEntityException("Error in MIGRATION_REQ_WITH_SIGN: Migration requester is not found!");
            }
            getLogger().info("requestingEntity: " + requestingEntity);
            // checking signature
            try {
                if (!server.getCrypto().verifySignedData(decPayload, signature, requestingEntity.getPublicKey())) {
                    throw new InvalidSignatureException("Entity signature verification failed!!");
                }
                else {
                    getLogger().info("Entity signature is correct!");
                }
            }
            catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
                throw new InvalidSignatureException("Entity signature verification failed!!");
            }
            getLogger().info("Received auth nonce: " + migrationReq.getAuthNonce().toHexString());
            if (!authNonce.equals(migrationReq.getAuthNonce())) {
                throw new InvalidNonceException("Auth nonce does not match!");
            }
            else {
                getLogger().info("Auth nonce is correct!");
            }
            X509Certificate backupCertificate =
                    server.getTrustedAuthInfo(requestingEntity.getBackupFromAuthID()).getBackupCertificate();
            MigrationRespMessage migrationResp = new MigrationRespMessage(server.getAuthID(),
                    migrationReq.getEntityNonce(), backupCertificate);
            writeToSocket(migrationResp.serializeSign(server.getCrypto()).getRawBytes());
            close();
        }
        else if (type == MessageType.MIGRATION_REQ_WITH_MAC) {
            getLogger().info("Received migration request with MAC!");
            // find out requesting entity's name first
            MigrationReqMessage migrationReq =
                    new MigrationReqMessage(MessageType.MIGRATION_REQ_WITH_MAC, payload);
            getLogger().info("Requesting entity's name is :" + migrationReq.getEntityName());
            RegisteredEntity requestingEntity = server.getRegisteredEntity(migrationReq.getEntityName());
            if (requestingEntity == null) {
                throw new UnrecognizedEntityException("Error in MIGRATION_REQ_WITH_MAC: Migration requester is not found!");
            }
            getLogger().info("requestingEntity: " + requestingEntity);
            // check MAC
            MigrationToken migrationToken = requestingEntity.getMigrationToken();
            DistributionKey currentDistributionMacKey = migrationToken.getCurrentDistributionMacKey();
            try {
                currentDistributionMacKey.verifyMacExtractData(payload);
            } catch (InvalidMacException e) {
                getLogger().error("InvalidMacException: " + ExceptionToString.convertExceptionToStackTrace(e));
                throw new RuntimeException("Integrity error occurred during verifying MAC!");
            }
            // check nonce
            getLogger().info("Received auth nonce: " + migrationReq.getAuthNonce().toHexString());
            if (!authNonce.equals(migrationReq.getAuthNonce())) {
                throw new InvalidNonceException("Auth nonce does not match!");
            }
            else {
                getLogger().info("Auth nonce is correct!");
            }
            // send migration token
            MigrationRespMessage migrationResp = new MigrationRespMessage(server.getAuthID(),
                    migrationReq.getEntityNonce(), migrationToken.getEncryptedNewDistributionKey());
            writeToSocket(migrationResp.serializeAthenticate(currentDistributionMacKey).getRawBytes());
            close();
        }
        else if (type == MessageType.ADD_READER_REQ_IN_PUB_ENC) {
            getLogger().info("Received session key request message encrypted with public key!");
            // parse signed data
            Buffer encPayload = payload.slice(0, payload.length() - RSA_KEY_SIZE);
            getLogger().debug("Encrypted data ({}): {}", encPayload.length(), encPayload.toHexString());
            Buffer signature = payload.slice(payload.length() - RSA_KEY_SIZE);
            Buffer decPayload = server.getCrypto().authPrivateDecrypt(encPayload);
            getLogger().debug("Decrypted data ({}): {}", decPayload.length(), decPayload.toHexString());

            AddReaderReqMessage addReaderReqMessage = new AddReaderReqMessage(type, decPayload);

            RegisteredEntity requestingEntity = server.getRegisteredEntity(addReaderReqMessage.getEntityName());

            if (requestingEntity == null) {
                throw new UnrecognizedEntityException("Error in SESSION_KEY_REQ_IN_PUB_ENC: Session key requester is not found!");
            }

            // checking signature
            try {
                if (!server.getCrypto().verifySignedData(encPayload, signature, requestingEntity.getPublicKey())) {
                    throw new InvalidSignatureException("Entity signature verification failed!!");
                }
                else {
                    getLogger().debug("Entity signature is correct!");
                }
            }
            catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
                throw new InvalidSignatureException("Entity signature verification failed!!");
            }
            processAddReaderReq(requestingEntity, addReaderReqMessage, authNonce);

            DistributionKeyInfo distributionKeyInfo = GenerateDistributionKey(requestingEntity, addReaderReqMessage.getDiffieHellmanParam());
            Buffer encryptedDistKey = server.getCrypto().authPublicEncrypt(distributionKeyInfo.getDistributionKeyInfoBuffer(),
                    requestingEntity.getPublicKey());
            encryptedDistKey.concat(server.getCrypto().signWithPrivateKey(encryptedDistKey));
            sendAddReaderResp(distributionKeyInfo.getDistributionKey(), addReaderReqMessage.getEntityNonce(), encryptedDistKey);
        }
        else if (type == MessageType.ADD_READER_REQ) {
            DecPayloadAndRegisteredEntity dec = decryptPayloadWithDistKey(payload);
            AddReaderReqMessage addReaderReqMessage = new AddReaderReqMessage(type, dec.getPayload());
            processAddReaderReq(dec.getRegisteredEntity(), addReaderReqMessage, authNonce);
            sendAddReaderResp(dec.getRegisteredEntity().getDistributionKey(), addReaderReqMessage.getEntityNonce(), null);
        }
        else {
            getLogger().info("Received unrecognized message from the entity!");
            close();
        }
    }

    /**
     * Handle a session key request from the connected entity.
     * @param bytes Raw buffer bytes of the TCP packet received by an entity, to be processed in this method
     * @param authNonce Auth's random number that was sent to the entity, to be checked with the Auth nonce included
     *                  in the session key request.
     * @throws RuntimeException Any security checking fails, including entity's signature and Auth's nonce.
     * @throws IOException If any IO fails.
     * @throws ParseException When JSON parsing fails.
     * @throws SQLException When SQL DB fails.
     * @throws ClassNotFoundException When class is not found.
     */
    protected void handleEntityReq(byte[] bytes, Buffer authNonce) throws RuntimeException, IOException,
            ParseException, SQLException, ClassNotFoundException, CertificateEncodingException,
            InvalidSignatureException, InvalidNonceException, InvalidSymmetricKeyOperationException
    {
        try {
            handleEntityReqInternal(bytes, authNonce);
        }
        catch (InvalidSessionKeyTargetException e) {
            getLogger().info("InvalidSessionKeyTargetException: " + e.getMessage());
            sendAuthAlert(AuthAlertCode.INVALID_SESSION_KEY_REQ);
            close();
        }
        catch (UseOfExpiredKeyException e) {
            getLogger().info("UseOfExpiredKeyException: " + e.getMessage());
            sendAuthAlert(AuthAlertCode.INVALID_DISTRIBUTION_KEY);
            close();
        }
        catch (NoAvailableDistributionKeyException e) {
            getLogger().info("NoAvailableDistributionKeyException: " + e.getMessage());
            sendAuthAlert(AuthAlertCode.INVALID_DISTRIBUTION_KEY);
            close();
        }
        catch (TooManySessionKeysRequestedException e) {
            getLogger().info("TooManySessionKeysRequestedException: " + e.getMessage());
            sendAuthAlert(AuthAlertCode.INVALID_SESSION_KEY_REQ);
            close();
        }
        catch (UnrecognizedEntityException e) {
            getLogger().info("UnrecognizedEntityException: " + e.getMessage());
            sendAuthAlert(AuthAlertCode.INVALID_SESSION_KEY_REQ);
            close();
        }
    }

    /**
     * Send an alert message to the connected entity, when security problem arises.
     * @param authAlertCode Code for the alert, indicating what kind of problem happened.
     * @throws IOException If socket IO fails.
     */
    protected void sendAuthAlert(AuthAlertCode authAlertCode) throws IOException {
        writeToSocket(new AuthAlertMessage(authAlertCode).serialize().getRawBytes());
    }

    /**
     * Send a session key response to the requesting entity
     * @param distributionKey Distribution key used for sending session key response
     * @param entityNonce Random number generated by the requesting entity, to be included in the response
     * @param sessionKeyList A list of session keys to be included in the response
     * @param sessionCryptoSpec Cryptography specification for the session keys in the response
     * @param encryptedDistKey Can be null. If not null, it is the distribution key encrypted using public key
     *                         cryptography. If null, it means the session key request was encrypted with a distribution
     *                         key that is shared a priory, so no need to include it.
     * @throws IOException If TCP socket IO fails.
     * @throws UseOfExpiredKeyException When an expired key is used.
     */
    private void sendSessionKeyResp(DistributionKey distributionKey, Buffer entityNonce,
                                    List<SessionKey> sessionKeyList, SymmetricKeyCryptoSpec sessionCryptoSpec,
                                    Buffer encryptedDistKey) throws IOException, UseOfExpiredKeyException,
                                    InvalidSymmetricKeyOperationException
    {
        SessionKeyRespMessage sessionKeyResp;
        if (encryptedDistKey != null) {
            sessionKeyResp = new SessionKeyRespMessage(encryptedDistKey, entityNonce, sessionCryptoSpec, sessionKeyList);
        }
        else {
            sessionKeyResp = new SessionKeyRespMessage(entityNonce, sessionCryptoSpec, sessionKeyList);
        }
        writeToSocket(sessionKeyResp.serializeAndEncrypt(distributionKey).getRawBytes());
    }
    /**
     * Send an add reader response to the requesting entity
     * @param distributionKey Distribution key used for sending session key response
     * @param entityNonce Random number generated by the requesting entity, to be included in the response
     * @param encryptedDistKey it is the distribution key encrypted using public key cryptography.
     * @throws IOException If TCP socket IO fails.
     * @throws UseOfExpiredKeyException When an expired key is used.
     */
    private void sendAddReaderResp(DistributionKey distributionKey, Buffer entityNonce,
                                    Buffer encryptedDistKey) throws IOException, UseOfExpiredKeyException,
                                    InvalidSymmetricKeyOperationException
    {
        AddReaderRespMessage addReaderResp;
        if (encryptedDistKey != null) {
            addReaderResp = new AddReaderRespMessage(encryptedDistKey, entityNonce);
        }
        else {
            addReaderResp = new AddReaderRespMessage(entityNonce);
        }
        writeToSocket(addReaderResp.serializeAndEncrypt(distributionKey).getRawBytes());
    }    

    /**
     * Interpret a session key request from the entity, and process it. The process includes communication policy
     * checking, session key generation, and communicating with a trusted Auth to get the session key.
     * @param requestingEntity The entity who sent the session key request.
     * @param sessionKeyReqMessage The session key request message object.
     * @param authNonce Auth nonce to be checked with the nonce in the session key request message.
     * @return A pair of resulting session key list and usage (cryptography) specification for the session keys. The
     * session keys can be either generated or retrieved from a trusted Auth.
     * @throws IOException If IO fails.
     * @throws ParseException If JSON parsing fails.
     * @throws SQLException When there is a problem in SQL
     * @throws ClassNotFoundException When class is not found.
     * @throws InvalidSessionKeyTargetException If the target of session key request is not valid.
     * @throws TooManySessionKeysRequestedException If more keys requested than allowed for the entity.
     */
    private SessionKeysAndSpec processSessionKeyReq(
            RegisteredEntity requestingEntity, SessionKeyReqMessage sessionKeyReqMessage, Buffer authNonce)
            throws IOException, ParseException, SQLException, ClassNotFoundException, InvalidSessionKeyTargetException,
            TooManySessionKeysRequestedException, InvalidNonceException {
        getLogger().debug("Sender entity: {}", sessionKeyReqMessage.getEntityName());

        getLogger().debug("Received auth nonce: {}", sessionKeyReqMessage.getAuthNonce().toHexString());
        if (!authNonce.equals(sessionKeyReqMessage.getAuthNonce())) {
            throw new InvalidNonceException("Auth nonce does not match!");
        }
        else {
            getLogger().debug("Auth nonce is correct!");
        }
        if (sessionKeyReqMessage.getNumKeys() > requestingEntity.getMaxSessionKeysPerRequest()) {
            throw new TooManySessionKeysRequestedException("More session keys than allowed are requested!");
        }

        JSONObject purpose = sessionKeyReqMessage.getPurpose();
        SessionKeyReqPurpose reqPurpose = new SessionKeyReqPurpose(purpose);

        SymmetricKeyCryptoSpec cryptoSpec = null;
        List<SessionKey> sessionKeyList = null;
        switch (reqPurpose.getTargetType()) {
            // If a target or publish-topic is specified, generate new keys
            case TARGET_GROUP:
            case FILE_SHARING:
            case PUBLISH_TOPIC: {
                CommunicationPolicy communicationPolicy = server.getCommunicationPolicy(requestingEntity.getGroup(),
                        reqPurpose.getTargetType(), (String)reqPurpose.getTarget());
                if (communicationPolicy == null) {
                    throw new InvalidSessionKeyTargetException("Unrecognized Purpose: " + purpose);
                }
                cryptoSpec = communicationPolicy.getSessionCryptoSpec();
                // generate session keys
                SessionKeyPurpose sessionKeyPurpose =
                        new SessionKeyPurpose(reqPurpose.getTargetType(), (String)reqPurpose.getTarget());
                getLogger().debug("numKeys {}", sessionKeyReqMessage.getNumKeys());
                sessionKeyList = server.generateSessionKeys(requestingEntity.getName(),
                        sessionKeyReqMessage.getNumKeys(), communicationPolicy, sessionKeyPurpose);
                break;
            }
            // If a subscribe-topic is specified, derive the keys from DB
            case SUBSCRIBE_TOPIC: {
                CommunicationPolicy communicationPolicy = server.getCommunicationPolicy(requestingEntity.getGroup(),
                        reqPurpose.getTargetType(), (String)reqPurpose.getTarget());
                if (communicationPolicy == null) {
                    throw new InvalidSessionKeyTargetException("Unrecognized Purpose: " + purpose);
                }
                cryptoSpec = communicationPolicy.getSessionCryptoSpec();
                SessionKeyPurpose sessionKeyPurpose =
                        new SessionKeyPurpose(reqPurpose.getTargetType(), (String)reqPurpose.getTarget());
                sessionKeyList = server.getSessionKeysByPurpose(requestingEntity.getName(), sessionKeyPurpose);
                for (SessionKey sessionKey : sessionKeyList) {
                    server.addSessionKeyOwner(sessionKey.getID(), requestingEntity.getName());
                }
                break;
            }
            // If a session key id is specified, derive the keys from DB
            case SESSION_KEY_ID: {
                Object objTarget = reqPurpose.getTarget();
                getLogger().debug("objTarget class: {}", objTarget.getClass());
                long sessionKeyID = -1;
                if (objTarget.getClass() == Integer.class) {
                    sessionKeyID = (long)(Integer)objTarget;
                }
                else if (objTarget.getClass() == Long.class) {
                    sessionKeyID = (Long)objTarget;
                }
                else {
                    throw new RuntimeException("Wrong class for session key ID!");
                }
                int authID = AuthDB.decodeAuthIDFromSessionKeyID(sessionKeyID);
                getLogger().info("ID of Auth that generated this key: {}", authID);

                if (authID == server.getAuthID()) {
                    getLogger().info("This session key was generated by me.");
                    SessionKey sessionKey = server.getSessionKeyByID(sessionKeyID);

                    // Checks if session key ID meets the communication policy.
                    if (!CommunicationPolicyChecker.checkSessionKeyCommunicationPolicy(
                            server, requestingEntity.getGroup(), requestingEntity.getName(), sessionKey)) {
                        throw new RuntimeException("Session key communication policy check failed.");
                    }

                    sessionKeyList = new LinkedList<>();
                    sessionKeyList.add(sessionKey);
                    cryptoSpec = sessionKey.getCryptoSpec();
                    server.addSessionKeyOwner(sessionKeyID, requestingEntity.getName());
                }
                else {
                    // TODO: if authID is not my ID, then send request via HTTPS
                    getLogger().info("This session key was generated by someone else");
                    AuthSessionKeyReqMessage authSessionKeyReqMessage = new AuthSessionKeyReqMessage(sessionKeyID,
                            requestingEntity.getName(), requestingEntity.getGroup(), -1);
                    return sendAuthSessionKeyReq(authID, authSessionKeyReqMessage);
                }

                break;
            }
            // If ID of the Auth who caches the keys is specified, talk to that Auth.
            case CACHED_SESSION_KEYS: {
                Object objTarget = reqPurpose.getTarget();
                getLogger().debug("objTarget class: {}", objTarget.getClass());
                int authID = -1;
                if (objTarget.getClass() == Integer.class) {
                    authID = (Integer)objTarget;
                }
                else if (objTarget.getClass() == Long.class) {
                    authID = ((Long)objTarget).intValue();
                }
                else {
                    throw new RuntimeException("Wrong class for Auth ID for cached keys!");
                }

                if (authID == server.getAuthID()) {
                    getLogger().info("numKeys {}", sessionKeyReqMessage.getNumKeys());
                    SessionKeyPurpose sessionKeyPurpose =
                            new SessionKeyPurpose(CommunicationTargetType.TARGET_GROUP, requestingEntity.getGroup());
                    // get cached keys for this group
                    sessionKeyList = server.getSessionKeysByPurpose(requestingEntity.getName(), sessionKeyPurpose);
                    for (SessionKey sessionKey : sessionKeyList) {
                        server.addSessionKeyOwner(sessionKey.getID(), requestingEntity.getName());
                        if (cryptoSpec == null) {
                            cryptoSpec = sessionKey.getCryptoSpec();
                        }
                    }
                }
                else {
                    getLogger().info("This cached session key request was directed to someone else");
                    AuthSessionKeyReqMessage authSessionKeyReqMessage = new AuthSessionKeyReqMessage(-1,
                            requestingEntity.getName(), requestingEntity.getGroup(), authID);
                    return sendAuthSessionKeyReq(authID, authSessionKeyReqMessage);
                }
                break;
            }
            default: {
                getLogger().error("Unrecognized target for session key request! TargetType: " + reqPurpose.getTargetType().getValue());
                break;
            }
        }

        return new SessionKeysAndSpec(sessionKeyList, cryptoSpec);
    }

    /**
     * Send an Auth session key request to a trusted Auth, on behalf of the requesting entity.
     * @param trustedAuthID Identifier of the trusted Auth to which this method sends the request.
     * @param authSessionKeyReqMessage Session key's identifier specified in the original session key request by an entity.
     * @return A pair of the session key list and usage specification of the session keys
     * @throws IOException If IO fails.
     * @throws ParseException If JSON parsing fails.
     */
    private SessionKeysAndSpec sendAuthSessionKeyReq(
            int trustedAuthID, AuthSessionKeyReqMessage authSessionKeyReqMessage) throws ParseException
    {
        getLogger().info("Sending auth session key req to Auth {}", trustedAuthID);

        ContentResponse contentResponse;
        try {
            contentResponse = server.performPostRequestToTrustedAuth(trustedAuthID, authSessionKeyReqMessage);
        } catch (InterruptedException | ExecutionException | TimeoutException e) {
            getLogger().error("Exception {}", ExceptionToString.convertExceptionToStackTrace(e));
            throw new RuntimeException(e.getCause());
        }

        getLogger().info("Received contents via https {}", contentResponse.getContentAsString());

        AuthSessionKeyRespMessage authSessionKeyRespMessage = AuthSessionKeyRespMessage.fromHttpResponse(contentResponse);

        getLogger().info("Received AuthSessionKeyRespMessage: {}", authSessionKeyRespMessage);
        List<SessionKey> sessionKeyList = authSessionKeyRespMessage.getSessionKeyList();
        SymmetricKeyCryptoSpec sessionCryptoSpec;
        if (sessionKeyList.size() > 0) {
            sessionCryptoSpec = sessionKeyList.get(0).getCryptoSpec();
        }
        else {
            throw new RuntimeException("No session keys received!");
        }
        return new SessionKeysAndSpec(authSessionKeyRespMessage.getSessionKeyList(), sessionCryptoSpec);
    }

    /**
     * Interpret an add reader request from the entity, and process it. The process includes nonce checking
     * and adding a file reader in database for purpose.
     * @param requestingEntity The entity who sent the session key request.
     * @param addReaderReqMessage The add reader request message object.
     * @param authNonce Auth nonce to be checked with the nonce in the add reader request message.
     * @throws IOException If IO fails.
     * @throws ParseException If JSON parsing fails.
     * @throws SQLException When there is a problem in SQL
     * @throws ClassNotFoundException When class is not found.
     * @throws InvalidSessionKeyTargetException If the target of add reader request is not valid.
     * @throws InvalidNonceException If nonce does not match.
     */
    private void processAddReaderReq(
            RegisteredEntity requestingEntity, AddReaderReqMessage addReaderReqMessage, Buffer authNonce)
            throws IOException, ParseException, SQLException, ClassNotFoundException, InvalidSessionKeyTargetException,
            InvalidNonceException {
        getLogger().debug("Sender entity: {}", addReaderReqMessage.getEntityName());

        getLogger().debug("Received auth nonce: {}", addReaderReqMessage.getAuthNonce().toHexString());
        if (!authNonce.equals(addReaderReqMessage.getAuthNonce())) {
            throw new InvalidNonceException("Auth nonce does not match!");
        }
        else {
            getLogger().debug("Auth nonce is correct!");
        }
        JSONObject purpose = addReaderReqMessage.getPurpose();
        AddReaderReqPurpose objPurpose = new AddReaderReqPurpose(purpose);
        // StringTokenizer reqPurpose = new StringTokenizer(objPurpose.getTarget().toString() ,":",false);
        // String ownerGroup = reqPurpose.nextToken();
        // String reader = reqPurpose.nextToken();
        server.addFileReader(requestingEntity.getGroup(),objPurpose.getTarget().toString());
    }

    /**
     * Decrypt the input buffer with distribution key and get the requesting entity information.
     * @param payload input buffer to decrypt.
     * @return Decrypted input buffer and entity information requesting distribution key.
     */
    private DecPayloadAndRegisteredEntity decryptPayloadWithDistKey(
            Buffer payload) throws NoAvailableDistributionKeyException, UseOfExpiredKeyException, UnrecognizedEntityException, InvalidSignatureException, InvalidSymmetricKeyOperationException
    {
        getLogger().info("Received session key request message encrypted with distribution key!");
        BufferedString bufferedString = payload.getBufferedString(0);
        String requestingEntityName = bufferedString.getString();
        RegisteredEntity requestingEntity = server.getRegisteredEntity(requestingEntityName);

        if (requestingEntity == null) {
            throw new UnrecognizedEntityException("Error in SESSION_KEY_REQ: Session key requester is not found!");
        }
        // TODO: check distribution key validity here and if not, refuse request
        if (requestingEntity.getDistributionKey() == null) {
            throw new NoAvailableDistributionKeyException("No distribution key is available!");
        }
        else if (requestingEntity.getDistributionKey().isExpired()) {
            throw new UseOfExpiredKeyException("Trying to use an expired distribution key.");
        }

        Buffer encPayload = payload.slice(bufferedString.length());

        Buffer decPayload;
        try {
            decPayload = requestingEntity.getDistributionKey().decryptVerify(encPayload);
        } catch (InvalidMacException | MessageIntegrityException e) {
            getLogger().error("InvalidMacException | MessageIntegrityException {}",
                    ExceptionToString.convertExceptionToStackTrace(e));
            throw new RuntimeException("Integrity error occurred during decryptVerify!");
        }

        return new DecPayloadAndRegisteredEntity(decPayload, requestingEntity);
    }

    /**
     * Generate distribution key.
     * @param requestingEntity Entity to request the distribution key.
     * @param diffieHellmanParamBuffer Diffie-Hellman parameter buffer to get distribution key.
     * @return DistributionKeyInfo including the distribution key and the info buffer.
     */
    private DistributionKeyInfo GenerateDistributionKey(RegisteredEntity requestingEntity, Buffer diffieHellmanParamBuffer) throws ClassNotFoundException, SQLException, IOException
    {
        Buffer distributionKeyInfoBuffer;
        DistributionKey distributionKey;    // generated or derived distribution key
        if (requestingEntity.getPublicKeyCryptoSpec().getDiffieHellman() != null) {
            try {
                DistributionDiffieHellman distributionDiffieHellman = new DistributionDiffieHellman(
                        requestingEntity.getDistCryptoSpec(), "EC", "ECDH",
                        384, requestingEntity.getDistKeyValidityPeriod());
                distributionKeyInfoBuffer = distributionDiffieHellman.getSerializedBuffer();
                distributionKey =
                        distributionDiffieHellman.deriveDistributionKey(diffieHellmanParamBuffer);
            }
            catch (NoSuchAlgorithmException | InvalidKeySpecException | InvalidKeyException e) {
                throw new RuntimeException("Diffie-Hellman failed!" + e.getMessage());
            }
        }
        else {
            // generate distribution key
            // Assuming AES-CBC-128
            distributionKey = new DistributionKey(requestingEntity.getDistCryptoSpec(),
                            requestingEntity.getDistKeyValidityPeriod());
            distributionKeyInfoBuffer = distributionKey.serialize();
        }
        // update distribution key
        server.updateDistributionKey(requestingEntity.getName(), distributionKey);
        return new DistributionKeyInfo(distributionKeyInfoBuffer, distributionKey);
    }
    abstract protected Logger getLogger();
    abstract protected void writeToSocket(byte[] bytes) throws IOException;
    abstract protected void close();
    abstract protected String getRemoteAddress();
    private AuthServer server;
}
