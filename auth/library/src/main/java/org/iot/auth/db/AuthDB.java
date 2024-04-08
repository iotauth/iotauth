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

import org.iot.auth.crypto.*;
import org.iot.auth.config.AuthServerProperties;
import org.iot.auth.config.constants.C;
import org.iot.auth.db.bean.*;
import org.iot.auth.db.dao.SQLiteConnector;
import org.iot.auth.io.Buffer;
import org.iot.auth.util.ExceptionToString;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateEncodingException;
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

    public AuthDB(String authDatabaseDir)
    {
        this.authDatabaseDir = authDatabaseDir;

        this.registeredEntityMap = new HashMap<>();
        this.communicationPolicyList = new ArrayList<>();
        this.trustedAuthMap = new HashMap<>();
    }

    /**
     * Initializes Auth's database by loading database tables
     * @param databaseKeystorePath File path for database keystore (public, private key pair)
     * @param authKeyStorePassword Password for key stores and trust store for storing certificates of trusted Auths
     * @param databaseEncryptionKeyPath File path for database encryption key (symmetric), ecrypted with public key
     * @param authDBProtectionMethod Type of protection method for Auth DB
     * @throws IOException When an error occurs in IO
     * @throws CertificateException When an error occurs while processing the certificate
     * @throws NoSuchAlgorithmException When there is no specified algorithm for keystores
     * @throws KeyStoreException When an error occurs while accessing the key store
     * @throws SQLException When an error occurs in database
     * @throws ClassNotFoundException When a specified class is not found
     * @throws UnrecoverableEntryException If an entry in keystore is not recoverable
     */
    public void initialize(String databaseKeystorePath, String authKeyStorePassword, String databaseEncryptionKeyPath,
                           AuthDBProtectionMethod authDBProtectionMethod)
            throws IOException, CertificateException, NoSuchAlgorithmException, KeyStoreException, SQLException,
            ClassNotFoundException, UnrecoverableEntryException
    {
        sqLiteConnector = new SQLiteConnector(this.authDatabaseDir + "/" + AUTH_DB_FILE_NAME, authDBProtectionMethod);
        sqLiteConnector.initialize(databaseKeystorePath, authKeyStorePassword, databaseEncryptionKeyPath);
        //sqLiteConnector.DEBUG = true;
        loadRegEntityDB();
        loadCommPolicyDB();
        loadTrustedAuthDB(authKeyStorePassword);
    }

    public void close() throws SQLException, IOException, InterruptedException {
        logger.info("Closing Auth DB...");
        sqLiteConnector.close();
    }

    /**
     * Get a registered entity by name.
     * @param entityName The name of the entity to be found.
     * @return The registered entity, if found, null, otherwise.
     */
    public RegisteredEntity getRegisteredEntity(String entityName) {
        return registeredEntityMap.get(entityName);
    }

    /**
     * Get all registered entities as a list.
     * @return A list of registered entities.
     */
    public List<RegisteredEntity> getAllRegisteredEntitiies() {
        return new ArrayList<>(registeredEntityMap.values());
    }

    private void insertOrReplaceRegisteredEntitiesHelper(boolean updateIfExists, List<RegisteredEntity> registeredEntities)
            throws IOException, SQLException, ClassNotFoundException
    {
        LinkedList<RegisteredEntityTable> tableElements = new LinkedList<>();
        for (RegisteredEntity registeredEntity: registeredEntities) {
            Buffer serializedDistributionKeyValue = null;
            String publicKeyFilePath = null;
            long distKeyExpirationTime = -1;
            // save keys first
            if (registeredEntity.getUsePermanentDistKey()) {
                // save distribution key as binary value
                serializedDistributionKeyValue = registeredEntity.getDistributionKey().getSerializedKeyVal();
                distKeyExpirationTime = registeredEntity.getDistributionKey().getExpirationTime().getTime();
            }
            RegisteredEntityTable tableElement = registeredEntity.toRegisteredEntityTable(
                    serializedDistributionKeyValue, distKeyExpirationTime);

            tableElements.push(tableElement);
            if (updateIfExists) {
                sqLiteConnector.insertRecordsOrUpdateIfExists(tableElement);
            }
            else {
                sqLiteConnector.insertRecords(tableElement);
            }
        }
    }

    public void insertRegisteredEntities(List<RegisteredEntity> registeredEntities) throws IOException,
            SQLException, ClassNotFoundException {
        insertOrReplaceRegisteredEntitiesHelper(false, registeredEntities);
    }

    public void insertRegisteredEntitiesOrUpdateIfExist(List<RegisteredEntity> registeredEntities) throws IOException,
            SQLException, ClassNotFoundException {
        insertOrReplaceRegisteredEntitiesHelper(true, registeredEntities);
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
                distributionKey.getSerializedKeyVal());
    }

    /**
     * Generate session keys and cache the generaged session keys.
     *
     * @param authID ID of the Auth who generates the session keys
     * @param owner Name of the owner (entity) for the generated session keys
     * @param numKeys Number of keys to be generated
     * @param communicationPolicy Corresponding communication policy for the generated session keys
     * @param sessionKeyPurpose Purpose specified by session key request
     * @return A list of generated session keys
     * @throws IOException When an error occurs in IO
     * @throws SQLException When an error occurs in database
     * @throws ClassNotFoundException When a specified class is not found
     */
    public List<SessionKey> generateSessionKeys(int authID, String owner, int numKeys,
                                                CommunicationPolicy communicationPolicy,
                                                SessionKeyPurpose sessionKeyPurpose)
            throws IOException, SQLException, ClassNotFoundException
    {
        List<SessionKey> sessionKeyList = new LinkedList<>();

        String value = sqLiteConnector.selectMetaDataValue(MetaDataTable.key.SessionKeyCount.name());
        long sessionKeyCount = Long.parseLong(value);

        //String purpose = communicationPolicy.getTargetType().name() + ":" + communicationPolicy.getTarget();
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
            sqLiteConnector.insertRecords(cachedSessionKey);
        }

        return sessionKeyList;
    }

    public SessionKey getSessionKeyByID(long keyID) throws SQLException, ClassNotFoundException {
        logger.debug("keyID: {}", keyID);
        CachedSessionKeyTable cachedSessionKey = sqLiteConnector.selectCachedSessionKeyByID(keyID);
        return cachedSessionKey.toSessionKey();
    }

    public List<SessionKey> getSessionKeysByPurpose(String requestingEntityName, SessionKeyPurpose sessionKeyPurpose)
            throws SQLException, ClassNotFoundException {
        List<CachedSessionKeyTable> cachedSessionKeyTableList =
                sqLiteConnector.selectCachedSessionKeysByPurpose(requestingEntityName, sessionKeyPurpose.toString());
        List<SessionKey> result = new ArrayList<>(cachedSessionKeyTableList.size());
        for (CachedSessionKeyTable cachedSessionKey: cachedSessionKeyTableList) {
            result.add(cachedSessionKey.toSessionKey());
        }
        return result;
    }

    public ArrayList<String> getFileSharingInfoByOwner(String fileOwner) {
        return sqLiteConnector.selectFileSharingInfoByOwner(fileOwner);
    }

    public boolean addSessionKeyOwner(long keyID, String newOwner) throws SQLException, ClassNotFoundException {
        return sqLiteConnector.appendSessionKeyOwner(keyID, newOwner);
    }

    public boolean addFileReader(String groupOwner, String reader) throws SQLException, ClassNotFoundException {
        return sqLiteConnector.appendFileReader(groupOwner, reader);
    }

    public void cleanExpiredSessionKeys() throws SQLException, ClassNotFoundException {
        sqLiteConnector.deleteExpiredCahcedSessionKeys();
    }

    public void deleteAllSessionKeys() throws SQLException, ClassNotFoundException {
        sqLiteConnector.deleteAllCachedSessionKeys();
    }

    /**
     * Get the information object of trusted Auth by its ID.
     * @param authID ID of the trusted Auth to be found.
     * @return Information object of trusted Auth.
     */
    public TrustedAuth getTrustedAuthInfo(int authID) {
        return trustedAuthMap.get(authID);
    }

    public int[] getAllTrustedAuthIDs() {
        int[] ret = new int[trustedAuthMap.size()];
        int index = 0;
        for (int trustedAuthID: trustedAuthMap.keySet()) {
            ret[index] = trustedAuthID;
            index++;
        }
        return ret;
    }

    /**
     * Convert session keys into string for display
     * @return String with session keys separated with newlines
     * @throws SQLException When an exception occurs in database
     * @throws ClassNotFoundException When a specified class is not found.
     */
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

        sqLiteConnector.selectAllRegEntities().forEach(regEntityTable -> {
            DistributionKey distributionKey = null;
            if (regEntityTable.getDistKeyVal() != null) {
                distributionKey = new DistributionKey(
                    SymmetricKeyCryptoSpec.fromSpecString(regEntityTable.getDistCryptoSpec()),
                    regEntityTable.getDistKeyExpirationTime(),
                    new Buffer(regEntityTable.getDistKeyVal())
                );
            }
            RegisteredEntity registeredEntity = new RegisteredEntity(regEntityTable, distributionKey);

            registeredEntityMap.put(registeredEntity.getName(), registeredEntity);
            logger.debug("registeredEntity: {}", registeredEntity.toString());
        });
    }

    public boolean deleteRegisteredEntities(List<String> registeredEntityNameList) throws SQLException {
        return sqLiteConnector.deleteRegisteredEntities(registeredEntityNameList);
    }

    public void deleteBackedUpRegisteredEntities() throws SQLException {
        sqLiteConnector.deleteBackedUpRegisteredEntities();
    }

    public void reloadRegEntityDB() throws SQLException, ClassNotFoundException {
        registeredEntityMap.clear();
        loadRegEntityDB();
    }

    public void reloadCommunicationPolicyDB() throws SQLException, ClassNotFoundException {
        communicationPolicyList.clear();
        loadCommPolicyDB();
    }

    private void loadCommPolicyDB() throws SQLException, ClassNotFoundException {
        sqLiteConnector.selectAllPolicies().forEach(communicationPolicyTable -> {
            CommunicationPolicy communicationPolicy = new CommunicationPolicy(communicationPolicyTable);
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
            TrustedAuth trustedAuth = new TrustedAuth(t.getId(), t.getHost(), t.getEntityHost(),
                    t.getPort(),
                    t.getHeartbeatPeriod(),
                    t.getFailureThreshold(),
                    t.getInternetCertificate(),
                    t.getEntityCertificate(),
                    t.getBackupCertificate());
            trustedAuthMap.put(trustedAuth.getID(), trustedAuth);
            // TODO: Add trust store for trusted auth
            trustStoreForTrustedAuths.setCertificateEntry("" + trustedAuth.getID(), trustedAuth.getInternetCertificate());

            logger.debug("trustedAuth: {}", trustedAuth.toString());
        }
    }

    private static long encodeSessionKeyID(int authID, long keyIndex) {
        return authID * 100000 + keyIndex;
    }
    public static int decodeAuthIDFromSessionKeyID(long sessionKeyID) {
        return (int)(sessionKeyID / 100000);
    }


    private String authDatabaseDir;

    private Map<String, RegisteredEntity> registeredEntityMap;
    private List<CommunicationPolicy> communicationPolicyList;
    private Map<Integer, TrustedAuth> trustedAuthMap;
    private KeyStore trustStoreForTrustedAuths;

    private SQLiteConnector sqLiteConnector;

    public boolean updateBackupCertificate(int backupFromAuthID, X509Certificate backupCertificate)
            throws SQLException, CertificateEncodingException
    {
        boolean ret = sqLiteConnector.updateBackupCertificate(backupFromAuthID, backupCertificate);
        TrustedAuth trustedAuth = getTrustedAuthInfo(backupFromAuthID);
        trustedAuth.setBackupCertificate(backupCertificate);
        trustedAuthMap.put(backupFromAuthID, trustedAuth);
        return ret;
    }

    public void insertCommunicationPolicy(CommunicationPolicyTable newCommunicationPolicyTable) throws SQLException, ClassNotFoundException {
        sqLiteConnector.insertRecords(newCommunicationPolicyTable);
    }
}