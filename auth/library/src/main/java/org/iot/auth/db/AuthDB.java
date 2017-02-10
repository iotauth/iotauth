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

import org.iot.auth.crypto.AuthCrypto;
import org.iot.auth.config.AuthServerProperties;
import org.iot.auth.config.constants.C;
import org.iot.auth.crypto.SymmetricKey;
import org.iot.auth.crypto.SymmetricKeyCryptoSpec;
import org.iot.auth.db.bean.CachedSessionKeyTable;
import org.iot.auth.db.bean.MetaDataTable;
import org.iot.auth.db.bean.TrustedAuthTable;
import org.iot.auth.db.dao.SQLiteConnector;
import org.iot.auth.exception.UseOfExpiredKeyException;
import org.iot.auth.io.Buffer;
import org.iot.auth.server.CommunicationTargetType;
import org.iot.auth.util.DateHelper;
import org.iot.auth.util.ExceptionToString;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.sql.SQLException;
import java.util.*;

/**
 * A main class for Auth database, which include tables for registered entities, communication policies, trusted Auths,
 *
 * @author Hokeun Kim, Salomon Lee
 */
public class AuthDB {
    private AuthServerProperties prop = C.PROPERTIES;
    private static final Logger logger = LoggerFactory.getLogger(AuthDB.class);
    private static final String AUTH_DB_FILE_NAME = "auth.db";
    // FIXME: should be set by properties
    public static final String AUTH_DB_PUBLIC_CIPHER = "RSA/ECB/PKCS1PADDING";
    public static final String AUTH_DB_KEY_ABSOLUTE_VALIDITY = "3650*day";
    public static final SymmetricKeyCryptoSpec AUTH_DB_CRYPTO_SPEC =
            new SymmetricKeyCryptoSpec("AES/CBC/PKCS5Padding", 16, "HmacSHA256");

    public AuthDB(String authDatabaseDir)
    {
        this.authDatabaseDir = authDatabaseDir;
        this.sqLiteConnector = new SQLiteConnector(this.authDatabaseDir + "/" + AUTH_DB_FILE_NAME);
        //sqLiteConnector.DEBUG = true;

        this.registeredEntityMap = new HashMap<>();
        this.communicationPolicyList = new ArrayList<>();
        this.trustedAuthMap = new HashMap<>();
    }

    /**
     * Initializes Auth's database by loading database tables
     * @param authKeyStorePassword Password for key stores and trust store for storing certificates of trusted Auths
     * @throws IOException
     * @throws CertificateException
     * @throws NoSuchAlgorithmException
     * @throws KeyStoreException
     * @throws SQLException
     * @throws ClassNotFoundException
     */
    public void initialize(String authKeyStorePassword, String databaseKeystorePath) throws IOException, CertificateException,
            NoSuchAlgorithmException, KeyStoreException, SQLException, ClassNotFoundException, UnrecoverableEntryException
    {
        KeyStore databaseKeyStore = AuthCrypto.loadKeyStore(databaseKeystorePath, authKeyStorePassword);
        if (databaseKeyStore.size() != 1) {
            throw new IllegalArgumentException("Auth key store must contain one key entry.");
        }
        Enumeration<String> aliases = databaseKeyStore.aliases();

        KeyStore.ProtectionParameter protParam =
                new KeyStore.PasswordProtection(authKeyStorePassword.toCharArray());
        PrivateKey databasePrivateKey = null;
        while (aliases.hasMoreElements()) {
            String alias = aliases.nextElement();
            KeyStore.PrivateKeyEntry pkEntry = (KeyStore.PrivateKeyEntry) databaseKeyStore.getEntry(alias, protParam);
            logger.debug("Alias {}: , Cert: {}, Key: {}", alias, pkEntry.getCertificate(), pkEntry.getPrivateKey());
            databasePrivateKey = pkEntry.getPrivateKey();
        }

        String value = sqLiteConnector.selectMetaDataValue(MetaDataTable.key.EncryptedDatabaseKey.name());
        Buffer encryptedDatabaseKey = Buffer.fromBase64(value);
        this.databaseKey = new SymmetricKey(
                AUTH_DB_CRYPTO_SPEC,
                new Date().getTime() + DateHelper.parseTimePeriod(AUTH_DB_KEY_ABSOLUTE_VALIDITY),
                AuthCrypto.privateDecrypt(encryptedDatabaseKey, databasePrivateKey, AUTH_DB_PUBLIC_CIPHER)
        );

        loadRegEntityDB();
        loadCommPolicyDB();
        loadTrustedAuthDB(authKeyStorePassword);
    }

    /**
     * Get a registered entity by name.
     * @param entityName The name of the entity to be found.
     * @return The registered entity, if found, null, otherwise.
     */
    public RegisteredEntity getRegisteredEntity(String entityName) {
        return registeredEntityMap.get(entityName);
    }

    public CommunicationPolicy getCommunicationPolicy(String reqGroup, CommunicationTargetType targetType, String target) {
        for (CommunicationPolicy communicationPolicy : communicationPolicyList) {
            if (communicationPolicy.getReqGroup().equals(reqGroup) &&
                    communicationPolicy.getTargetType() == targetType &&
                    communicationPolicy.getTarget().equals(target)) {
                return communicationPolicy;
            }
        }
        return null;
    }

    /**
     * Update the distribution key of the specified entity.
     * @param entityName The name of the entity whose distribution key to be updated.
     * @param distributionKey New distribution key for the entity.
     * @throws SQLException When database SQL fails.
     * @throws ClassNotFoundException If the class cannot be located
     */
    public void updateDistributionKey(String entityName, DistributionKey distributionKey)
            throws SQLException, ClassNotFoundException
    {
        RegisteredEntity registeredEntity = getRegisteredEntity(entityName);
        registeredEntity.setDistributionKey(distributionKey);
        registeredEntityMap.put(registeredEntity.getName(), registeredEntity);

        sqLiteConnector.updateRegEntityDistKey(entityName, distributionKey.getRawExpirationTime(),
                encryptAuthDBData(distributionKey.getSerializedKeyVal()).getRawBytes());
    }

    /**
     *
     * @param authID
     * @param owner
     * @param numKeys
     * @param communicationPolicy
     * @return
     * @throws IOException
     * @throws SQLException
     * @throws ClassNotFoundException
     */
    public List<SessionKey> generateSessionKeys(int authID, String owner, int numKeys,
                                                CommunicationPolicy communicationPolicy,
                                                SessionKeyPurpose sessionKeyPurpose)
            throws IOException, SQLException, ClassNotFoundException
    {
        List<SessionKey> sessionKeyList = new LinkedList<SessionKey>();

        String value = sqLiteConnector.selectMetaDataValue(MetaDataTable.key.SessionKeyCount.name());
        long sessionKeyCount = Long.parseLong(value);

        // FIXME: Create SessionKeyPurpose class and handle it here
        String purpose = communicationPolicy.getTargetType().name() + ":" + communicationPolicy.getTarget();
        for (long i = 0; i < numKeys; i++) {
            long curSessionKeyIndex = sessionKeyCount + i;
            // TODO: work on authID encoding
            long sessionKeyID = encodeSessionKeyID(authID, curSessionKeyIndex);
            SessionKey sessionKey = new SessionKey(sessionKeyID, owner.split(SessionKey.SESSION_KEY_OWNER_NAME_DELIM),
                    communicationPolicy.getMaxNumSessionKeyOwners(), sessionKeyPurpose.toString(),
                    new Date().getTime() + communicationPolicy.getAbsValidity(), communicationPolicy.getRelValidity(),
                    communicationPolicy.getSessionCryptoSpec());
            sessionKeyList.add(sessionKey);
        }
        sessionKeyCount += numKeys;

        sqLiteConnector.updateMetaData(MetaDataTable.key.SessionKeyCount.name(), Long.toString(sessionKeyCount));

        for (SessionKey sessionKey: sessionKeyList) {
            CachedSessionKeyTable cachedSessionKey = CachedSessionKeyTable.fromSessionKey(sessionKey);
            cachedSessionKey.setKeyVal(encryptAuthDBData(new Buffer(cachedSessionKey.getKeyVal())).getRawBytes());
            sqLiteConnector.insertRecords(cachedSessionKey);
        }

        return sessionKeyList;
    }

    public SessionKey getSessionKeyByID(long keyID) throws SQLException, ClassNotFoundException {
        logger.debug("keyID: {}", keyID);
        CachedSessionKeyTable cachedSessionKey = sqLiteConnector.selectCachedSessionKeyByID(keyID);
        cachedSessionKey.setKeyVal(decryptAuthDBData(new Buffer(cachedSessionKey.getKeyVal())).getRawBytes());
        return cachedSessionKey.toSessionKey();
    }

    public List<SessionKey> getSessionKeysByPurpose(String requestingEntityName, SessionKeyPurpose sessionKeyPurpose)
            throws SQLException, ClassNotFoundException {
        List<CachedSessionKeyTable> cachedSessionKeyTableList =
                sqLiteConnector.selectCachedSessionKeysByPurpose(requestingEntityName, sessionKeyPurpose.toString());
        List<SessionKey> result = new ArrayList<>(cachedSessionKeyTableList.size());
        for (CachedSessionKeyTable cachedSessionKey: cachedSessionKeyTableList) {
            cachedSessionKey.setKeyVal(decryptAuthDBData(new Buffer(cachedSessionKey.getKeyVal())).getRawBytes());
            result.add(cachedSessionKey.toSessionKey());
        }
        return result;
    }

    public boolean addSessionKeyOwner(long keyID, String newOwner) throws SQLException, ClassNotFoundException {
        return sqLiteConnector.appendSessionKeyOwner(keyID, newOwner);
    }

    public void cleanExpiredSessionKeys() throws SQLException, ClassNotFoundException {
        sqLiteConnector.deleteExpiredCahcedSessionKeys();
    }

    public void deleteAllSessionKeys() throws SQLException, ClassNotFoundException {
        sqLiteConnector.deleteAllCachedSessionKeys();
    }

    public TrustedAuth getTrustedAuthInfo(int authID) {
        return trustedAuthMap.get(authID);
    }

    public String sessionKeysToString() throws SQLException, ClassNotFoundException {
        StringBuilder sb = new StringBuilder();

        List<CachedSessionKeyTable> cachedSessionKeyList = sqLiteConnector.selectAllCachedSessionKey();
        boolean init = true;
        for (CachedSessionKeyTable cachedSessionKey: cachedSessionKeyList) {
            if (init) {
                init = false;
            }
            else {
                sb.append("\n");
            }
            cachedSessionKey.setKeyVal(decryptAuthDBData(new Buffer(cachedSessionKey.getKeyVal())).getRawBytes());
            sb.append(cachedSessionKey.toSessionKey().toString());
        }
        return sb.toString();
    }

    public String registeredEntitiesToString() {
        StringBuilder sb = new StringBuilder();
        boolean init = true;
        for (RegisteredEntity registeredEntity : registeredEntityMap.values()) {
            if (init) {
                init = false;
            }
            else {
                sb.append("\n");
            }
            sb.append(registeredEntity.toString());
        }
        return sb.toString();
    }

    public String communicationPoliciesToString() {
        StringBuilder sb = new StringBuilder();
        boolean init = true;
        for (CommunicationPolicy communicationPolicy : communicationPolicyList) {
            if (init) {
                init = false;
            }
            else {
                sb.append("\n");
            }
            sb.append(communicationPolicy.toString());
        }
        return sb.toString();
    }

    public String trustedAuthsToString() {
        StringBuilder sb = new StringBuilder();
        boolean init = true;
        for (TrustedAuth trustedAuth: trustedAuthMap.values()) {
            if (init) {
                init = false;
            }
            else {
                sb.append("\n");
            }
            sb.append(trustedAuth.toBriefString());
        }
        return sb.toString();
    }

    public int getTrustedAuthIDByCertificate(X509Certificate cert) {
        try {
            String alias = trustStoreForTrustedAuths.getCertificateAlias(cert);
            return Integer.parseInt(alias);
        } catch (KeyStoreException e) {
            logger.error("KeyStoreException {}", ExceptionToString.convertExceptionToStackTrace(e));
            throw new RuntimeException("Unrecognized trusted Auth certificate!");
        }
    }

    private void loadRegEntityDB() throws SQLException, ClassNotFoundException {

        sqLiteConnector.selectAllRegEntities(authDatabaseDir).forEach(regEntityTable -> {
            DistributionKey distributionKey = null;
            if (regEntityTable.getDistKeyVal() != null) {
                distributionKey = new DistributionKey(
                    SymmetricKeyCryptoSpec.fromSpecString(regEntityTable.getDistCryptoSpec()),
                    regEntityTable.getDistKeyExpirationTime(),
                    decryptAuthDBData(new Buffer(regEntityTable.getDistKeyVal()))
                );
            }
            RegisteredEntity registeredEntity = new RegisteredEntity(regEntityTable, distributionKey);

            registeredEntityMap.put(registeredEntity.getName(), registeredEntity);
            logger.debug("registeredEntity: {}", registeredEntity.toString());
        });
    }

    private void loadCommPolicyDB() throws SQLException, ClassNotFoundException {
        sqLiteConnector.selectAllPolicies().forEach(c -> {
            CommunicationPolicy communicationPolicy = new CommunicationPolicy(c.getReqGroup(), c.getTargetType(), c.getTarget(),
                    c.getMaxNumSessionKeyOwners(), c.getSessionCryptoSpec(),
                    c.getAbsValidity(), c.getRelValidity());
            communicationPolicyList.add(communicationPolicy);
            logger.debug("communicationPolicy: {}", communicationPolicy.toString());
        });
    }

    private void loadTrustedAuthDB(String trustStorePassword) throws
            KeyStoreException, CertificateException, NoSuchAlgorithmException, SQLException, ClassNotFoundException, IOException
    {
        // TODO: replace this with password input
        trustStoreForTrustedAuths = KeyStore.getInstance(KeyStore.getDefaultType());
        trustStoreForTrustedAuths.load(null, trustStorePassword.toCharArray());

        for (TrustedAuthTable t: sqLiteConnector.selectAllTrustedAuth()) {
            TrustedAuth trustedAuth = new TrustedAuth(t.getId(), t.getHost(),
                    t.getPort(),
                    AuthCrypto.loadCertificate(t.getCertificatePath()));
            trustedAuthMap.put(trustedAuth.getID(), trustedAuth);
            // TODO: Add trust store for trusted auth
            trustStoreForTrustedAuths.setCertificateEntry("" + trustedAuth.getID(), trustedAuth.getCertificate());

            logger.debug("trustedAuth: {}", trustedAuth.toString());
        }
    }

    public static long encodeSessionKeyID(int authID, long keyIndex) {
        return authID * 100000 + keyIndex;
    }
    public static int decodeAuthIDFromSessionKeyID(long sessionKeyID) {
        return (int)(sessionKeyID / 100000);
    }

    private Buffer encryptAuthDBData(Buffer input) {
        try {
            return databaseKey.encryptAuthenticate(input);
        } catch (UseOfExpiredKeyException e) {
            logger.error("UseOfExpiredKeyException {}", ExceptionToString.convertExceptionToStackTrace(e));
            throw new RuntimeException("Exception occurred while encrypting Auth DB Data!");
        }
    }
    private Buffer decryptAuthDBData(Buffer input) {
        try {
            return databaseKey.decryptVerify(input);
        }
        catch (Exception e) {
            logger.error("Exception {}", ExceptionToString.convertExceptionToStackTrace(e));
            throw new RuntimeException("Exception occurred while decrypting Auth DB Data!");
        }
    }

    private String authDatabaseDir;

    private Map<String, RegisteredEntity> registeredEntityMap;
    private List<CommunicationPolicy> communicationPolicyList;
    private Map<Integer, TrustedAuth> trustedAuthMap;
    private KeyStore trustStoreForTrustedAuths;

    private SQLiteConnector sqLiteConnector;

    private SymmetricKey databaseKey;
}
