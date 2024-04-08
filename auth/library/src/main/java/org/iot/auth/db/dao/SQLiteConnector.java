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

package org.iot.auth.db.dao;

import org.iot.auth.crypto.AuthCrypto;
import org.iot.auth.crypto.SymmetricKey;
import org.iot.auth.crypto.SymmetricKeyCryptoSpec;
import org.iot.auth.db.AuthDBProtectionMethod;
import org.iot.auth.db.bean.*;
import org.iot.auth.exception.InvalidSymmetricKeyOperationException;
import org.iot.auth.exception.UseOfExpiredKeyException;
import org.iot.auth.io.Buffer;
import org.iot.auth.io.FileIOHelper;
import org.iot.auth.util.DateHelper;
import org.iot.auth.util.ExceptionToString;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.*;
import java.security.*;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.sql.*;
import java.util.*;
import java.util.Date;

/**
 * A SQLite connector Class for CRUD operations on Auth database.
 *
 * @author Salomon Lee, Hokeun Kim
 */
public class SQLiteConnector {
    public boolean DEBUG;
    private static final Logger logger = LoggerFactory.getLogger(SQLiteConnector.class);
    private Connection connection;
    private Statement statement;
    private final String dbPath;
    private SymmetricKey databaseKey;
    private boolean useInMemoryProtection;
    private boolean encryptCredentials;
    // FIXME: should be set by properties
    public static final String AUTH_DB_KEY_ABSOLUTE_VALIDITY = "3650*day";
    public static final SymmetricKeyCryptoSpec AUTH_DB_CRYPTO_SPEC =
            new SymmetricKeyCryptoSpec("AES/CBC/PKCS5Padding", 16, "HmacSHA256");
    public static final String AUTH_DB_PUBLIC_CIPHER = "RSA/ECB/PKCS1PADDING";

    /**
     * Constructor that stores the physical location of the database file.
     * @param dbPath Path for the SQLite database file.
     * @param authDBProtectionMethod Protection level of auth DB.
     */
    public SQLiteConnector(String dbPath, AuthDBProtectionMethod authDBProtectionMethod)
    {
        this.DEBUG = false;
        this.dbPath = dbPath;
        logger.info("Auth DB protection method selected: {}", authDBProtectionMethod.name());
        switch (authDBProtectionMethod) {
            case DEBUG:
                this.encryptCredentials = false;
                this.useInMemoryProtection = false;
                break;
            case ENCRYPT_CREDENTIALS:
                this.encryptCredentials = true;
                this.useInMemoryProtection = false;
                break;
            case ENCRYPT_ENTIRE_DB:
                this.encryptCredentials = true;
                this.useInMemoryProtection = true;
                break;
        }
        logger.info("Credential encryption - {}", this.encryptCredentials ? "ENABLED" : "DISABLED");
        logger.info("Entire DB encryption - {}", this.useInMemoryProtection ? "ENABLED" : "DISABLED");
    }

    /**
     * Load an encryption key for database.
     * @param databaseKeystorePath File path for database keystore (public, private key pair)
     * @param authKeyStorePassword Password for key stores and trust store for storing certificates of trusted Auths
     * @param databaseEncryptionKeyPath File path for database encryption key (symmetric), ecrypted with public key
     * @throws CertificateException When CertificateException occurs.
     * @throws NoSuchAlgorithmException When NoSuchAlgorithmException occurs.
     * @throws KeyStoreException When KeyStoreException occurs.
     * @throws IOException When IOException occurs.
     * @throws SQLException When SQLException occurs.
     * @throws ClassNotFoundException When ClassNotFoundException occurs.
     * @throws UnrecoverableEntryException When UnrecoverableEntryException occurs.
     */
    public void initialize(String databaseKeystorePath, String authKeyStorePassword, String databaseEncryptionKeyPath)
            throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException, SQLException,
            ClassNotFoundException, UnrecoverableEntryException
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
            logger.debug("Alias: {}, ", alias);
            logger.debug("Cert: {}, ", pkEntry.getCertificate());
            logger.debug("Key: {}", pkEntry.getPrivateKey());
            databasePrivateKey = pkEntry.getPrivateKey();
        }
        //String value = selectMetaDataValue(MetaDataTable.key.EncryptedDatabaseKey.name());

        Buffer encryptedDatabaseKey = new Buffer(AuthCrypto.readBinaryFile(databaseEncryptionKeyPath));

        initialize(new SymmetricKey(
                AUTH_DB_CRYPTO_SPEC,
                new Date().getTime() + DateHelper.parseTimePeriod(AUTH_DB_KEY_ABSOLUTE_VALIDITY),
                AuthCrypto.privateDecrypt(encryptedDatabaseKey, databasePrivateKey, AUTH_DB_PUBLIC_CIPHER)));
    }

    public void initialize(SymmetricKey databaseKey) throws SQLException, IOException, ClassNotFoundException {
        this.databaseKey = databaseKey;
        setConnection();
    }

    private Buffer encryptAuthDBData(Buffer input) {
        try {
            return databaseKey.encryptAuthenticate(input);
        } catch (UseOfExpiredKeyException e) {
            logger.error("UseOfExpiredKeyException {}", ExceptionToString.convertExceptionToStackTrace(e));
            throw new RuntimeException("Exception occurred while encrypting Auth DB Data!");
        } catch (InvalidSymmetricKeyOperationException e) {
            logger.error("InvalidSymmetricKeyOperationException {}", ExceptionToString.convertExceptionToStackTrace(e));
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

    private void setConnection() throws ClassNotFoundException, SQLException, IOException {
        Class.forName("org.sqlite.JDBC");
        if (useInMemoryProtection) {
            if (connection == null || connection.isClosed()) {
                connection = DriverManager.getConnection("jdbc:sqlite:");
                File dbFile = new File(dbPath);
                if (dbFile.exists() && !dbFile.isDirectory()) {
                    byte[] encryptedDBBytes = FileIOHelper.readFully(dbPath);
                    Buffer encryptedDBBuffer = new Buffer(encryptedDBBytes);
                    Buffer decryptedDBBuffer = decryptAuthDBData(encryptedDBBuffer);
                    String tempFilePath = dbPath + AuthCrypto.getRandomBytes(4).toConsecutiveHexString();
                    File tempFile = new File(tempFilePath);
                    FileIOHelper.writeFully(tempFilePath, decryptedDBBuffer.getRawBytes());
                    Statement stat = connection.createStatement();
                    stat.executeUpdate("restore from " + tempFilePath);
                    tempFile.delete();
                }
            }
        }
        else {
            if (connection == null || connection.isClosed()) {
                connection = DriverManager.getConnection("jdbc:sqlite:" + dbPath);
            }
        }
    }
    public void close() throws SQLException, IOException {
        if (useInMemoryProtection) {
            String tempFilePath = dbPath + AuthCrypto.getRandomBytes(4).toConsecutiveHexString();
            Statement stat = connection.createStatement();
            stat.executeUpdate("backup to " + tempFilePath );
            File tempFile = new File(tempFilePath);
            byte[] decryptedDBBytes = FileIOHelper.readFully(tempFilePath);
            tempFile.delete();
            Buffer decryptedDBBuffer = new Buffer(decryptedDBBytes);
            Buffer encryptedDBBuffer = encryptAuthDBData(decryptedDBBuffer);
            FileIOHelper.writeFully(dbPath, encryptedDBBuffer.getRawBytes());
        }
        connection.close();
    }
    /**
     * On cold start it will be needed to create a database and the related tables.
     * @throws SQLException if a database access error occurs;
     * this method is called on a closed <code>PreparedStatement</code>
     * or an argument is supplied to this method
     */
    public void createTablesIfNotExists() throws SQLException {
        String sql = "CREATE TABLE IF NOT EXISTS " + CommunicationPolicyTable.T_COMMUNICATION_POLICY + "(";
        sql += CommunicationPolicyTable.c.RequestingGroup.name() + " TEXT NOT NULL,";
        sql += CommunicationPolicyTable.c.TargetType.name() + " TEXT NOT NULL,";
        sql += CommunicationPolicyTable.c.Target.name() + " TEXT NOT NULL,";
        // MaxNumSessionKeyOwners should be greater than or equal to 2
        sql += CommunicationPolicyTable.c.MaxNumSessionKeyOwners.name() + " INT NOT NULL CHECK(" +
                CommunicationPolicyTable.c.MaxNumSessionKeyOwners.name() + " >= 2),";
        sql += CommunicationPolicyTable.c.SessionCryptoSpec.name() + " TEXT NOT NULL,";
        sql += CommunicationPolicyTable.c.AbsoluteValidity.name() + " TEXT NOT NULL,";
        sql += CommunicationPolicyTable.c.RelativeValidity.name() + " TEXT NOT NULL,";
        sql += "PRIMARY KEY (" + CommunicationPolicyTable.c.RequestingGroup.name() + ",";
        sql += CommunicationPolicyTable.c.TargetType.name() + ",";
        sql += CommunicationPolicyTable.c.Target.name() + "))";
        statement = connection.createStatement();
        if (DEBUG) logger.info(sql);
        if (statement.executeUpdate(sql) == 0)
            logger.info("Table {} created", CommunicationPolicyTable.T_COMMUNICATION_POLICY);
        else
            logger.info("Table {} already exists", CommunicationPolicyTable.T_COMMUNICATION_POLICY);
        closeStatement();

        statement = connection.createStatement();
        sql = "CREATE TABLE IF NOT EXISTS " + RegisteredEntityTable.T_REGISTERED_ENTITY + "(";
        sql += RegisteredEntityTable.c.Name.name() + " TEXT NOT NULL PRIMARY KEY,";
        sql += "'" + RegisteredEntityTable.c.Group.name() + "' TEXT NOT NULL,";
        sql += RegisteredEntityTable.c.DistProtocol.name() + " TEXT NOT NULL,";
        sql += RegisteredEntityTable.c.UsePermanentDistKey.name() + " BOOLEAN NOT NULL,";
        sql += RegisteredEntityTable.c.MaxSessionKeysPerRequest.name() + " INT NOT NULL,";
        sql += RegisteredEntityTable.c.PublicKeyValue.name() + " BLOB,";
        sql += RegisteredEntityTable.c.DistKeyValidityPeriod.name() + " TEXT NOT NULL,";
        sql += RegisteredEntityTable.c.PublicKeyCryptoSpec.name() + " TEXT,";
        sql += RegisteredEntityTable.c.DistCryptoSpec.name() + " TEXT NOT NULL,";
        sql += RegisteredEntityTable.c.DistKeyExpirationTime.name() + " INT,";
        sql += RegisteredEntityTable.c.DistKeyValue.name() + " BLOB,";
        sql += RegisteredEntityTable.c.Active.name() + " BOOLEAN NOT NULL,";
        sql += RegisteredEntityTable.c.BackupToAuthIDs.name() + " TEXT,";
        sql += RegisteredEntityTable.c.BackupFromAuthID.name() + " INT,";
        sql += RegisteredEntityTable.c.MigrationToken.name() + " BLOB)";
        if (DEBUG) logger.info(sql);
        if (statement.executeUpdate(sql) == 0)
            logger.info("Table {} created", RegisteredEntityTable.T_REGISTERED_ENTITY);
        else
            logger.info("Table {} already exists", RegisteredEntityTable.T_REGISTERED_ENTITY);
        closeStatement();

        statement = connection.createStatement();
        sql = "CREATE TABLE IF NOT EXISTS " + TrustedAuthTable.T_TRUSTED_AUTH + "(";
        sql += TrustedAuthTable.c.ID.name() + " INT NOT NULL PRIMARY KEY,";
        sql += TrustedAuthTable.c.Host.name() + " TEXT NOT NULL,";
        sql += TrustedAuthTable.c.EntityHost.name() + " TEXT NOT NULL,";
        sql += TrustedAuthTable.c.Port.name() + " INT NOT NULL,";
        sql += TrustedAuthTable.c.HeartbeatPeriod.name() + " INT NOT NULL,";
        sql += TrustedAuthTable.c.FailureThreshold.name() + " INT NOT NULL,";
        sql += TrustedAuthTable.c.InternetCertificateValue.name() + " BLOB NOT NULL,";
        sql += TrustedAuthTable.c.EntityCertificateValue.name() + " BLOB NOT NULL,";
        sql += TrustedAuthTable.c.BackupCertificateValue.name() + " BLOB)";
        if (DEBUG) logger.info(sql);
        if (statement.executeUpdate(sql) == 0)
            logger.info("Table {} created", TrustedAuthTable.T_TRUSTED_AUTH);
        else
            logger.info("Table {} already exists", TrustedAuthTable.T_TRUSTED_AUTH);
        closeStatement();

        statement = connection.createStatement();
        sql = "CREATE TABLE IF NOT EXISTS " + CachedSessionKeyTable.T_CACHED_SESSION_KEY + "(";
        sql += CachedSessionKeyTable.c.ID.name() + " INT NOT NULL PRIMARY KEY,";
        sql += CachedSessionKeyTable.c.Owners.name() + " TEXT NOT NULL,";
        sql += CachedSessionKeyTable.c.MaxNumOwners.name() + " INT NOT NULL,";
        sql += CachedSessionKeyTable.c.Purpose.name() + " TEXT NOT NULL,";
        sql += CachedSessionKeyTable.c.ExpirationTime.name() + " INT NOT NULL,";
        sql += CachedSessionKeyTable.c.RelValidity.name() + " INT NOT NULL,";
        sql += CachedSessionKeyTable.c.CryptoSpec.name() + " TEXT NOT NULL,";
        sql += CachedSessionKeyTable.c.KeyVal.name() + " BLOB NOT NULL)";
        if (DEBUG) logger.info(sql);
        if (statement.executeUpdate(sql) == 0)
            logger.info("Table {} created", CachedSessionKeyTable.T_CACHED_SESSION_KEY);
        else
            logger.info("Table {} already exists", CachedSessionKeyTable.T_CACHED_SESSION_KEY);
        closeStatement();

        statement = connection.createStatement();
        sql = "CREATE TABLE IF NOT EXISTS " + MetaDataTable.T_META_DATA + "(";
        sql += MetaDataTable.c.Key.name() + " INT NOT NULL PRIMARY KEY,";
        sql += MetaDataTable.c.Value.name() + " TEXT NOT NULL)";
        if (DEBUG) logger.info(sql);
        if (statement.executeUpdate(sql) == 0)
            logger.info("Table {} created", MetaDataTable.T_META_DATA);
        else
            logger.info("Table {} already exists", MetaDataTable.T_META_DATA);
        closeStatement();

        statement = connection.createStatement();
        sql = "CREATE TABLE IF NOT EXISTS " + FileSharingTable.T_File_Sharing + "(";
        sql += FileSharingTable.c.Owner.name() + " TEXT NOT NULL,";
        sql += FileSharingTable.c.ReaderType.name() + " TEXT NOT NULL,";
        sql += FileSharingTable.c.Reader.name() + " TEXT NOT NULL)";

        if (DEBUG) logger.info(sql);
        if (statement.executeUpdate(sql) == 0)
            logger.info("Table {} created", FileSharingTable.T_File_Sharing);
        else
            logger.info("Table {} already exists", FileSharingTable.T_File_Sharing);
        closeStatement();

        closeConnection();
    }

    /**
     * Insert records into CommunicationPolicyTable.
     *
     * @param policy the records needed to set a communication policy.
     * @return <code>true</code> if the insertion has been successful
     *         <code>false</code> if the insertion has failed
     * @throws SQLException if a database access error occurs;
     * this method is called on a closed <code>PreparedStatement</code>
     * or an argument is supplied to this method
     * @see CommunicationPolicyTable
     */
    public boolean insertRecords(CommunicationPolicyTable policy) throws SQLException {
        String sql = "INSERT INTO " + CommunicationPolicyTable.T_COMMUNICATION_POLICY + "(";
        sql += CommunicationPolicyTable.c.RequestingGroup.name() + ",";
        sql += CommunicationPolicyTable.c.TargetType.name() + ",";
        sql += CommunicationPolicyTable.c.Target.name() + ",";
        sql += CommunicationPolicyTable.c.MaxNumSessionKeyOwners.name() + ",";
        sql += CommunicationPolicyTable.c.SessionCryptoSpec.name() + ",";
        sql += CommunicationPolicyTable.c.AbsoluteValidity.name() + ",";
        sql += CommunicationPolicyTable.c.RelativeValidity.name() + ")";
        sql += " VALUES (?,?,?,?,?,?,?)";
        int index = 1;
        PreparedStatement preparedStatement = connection.prepareStatement(sql);
        preparedStatement.setString(index++,policy.getReqGroup());
        preparedStatement.setString(index++,policy.getTargetTypeVal());
        preparedStatement.setString(index++,policy.getTarget());
        preparedStatement.setInt(index++,policy.getMaxNumSessionKeyOwners());
        preparedStatement.setString(index++,policy.getSessionCryptoSpec());
        preparedStatement.setString(index++,policy.getAbsValidityStr());
        preparedStatement.setString(index++,policy.getRelValidityStr());
        if (DEBUG) logger.info(preparedStatement.toString());
        boolean result = preparedStatement.execute();
        preparedStatement.close();
        closeConnection();
        return result;
    }

    public RegisteredEntityTable encryptRecords(RegisteredEntityTable regEntity) {
        if (!encryptCredentials) {
            return regEntity;
        }
        if (regEntity.getDistKeyVal() != null) {
            regEntity.setDistKeyVal(encryptAuthDBData(new Buffer(regEntity.getDistKeyVal())).getRawBytes());
        }
        return regEntity;
    }
    public RegisteredEntityTable decryptRecords(RegisteredEntityTable regEntity) {
        if (!encryptCredentials) {
            return regEntity;
        }
        if (regEntity.getDistKeyVal() != null) {
            regEntity.setDistKeyVal(decryptAuthDBData(new Buffer(regEntity.getDistKeyVal())).getRawBytes());
        }
        return regEntity;
    }

    private boolean insertOrReplaceRecordsHelper(String sqlCommand, RegisteredEntityTable regEntity)
            throws SQLException
    {
        String sql = sqlCommand + " INTO " + RegisteredEntityTable.T_REGISTERED_ENTITY + "(";
        sql += RegisteredEntityTable.c.Name.name() + ",";
        sql += "'"+ RegisteredEntityTable.c.Group.name() + "',";
        sql += RegisteredEntityTable.c.DistProtocol.name() + ",";
        sql += RegisteredEntityTable.c.UsePermanentDistKey.name() + ",";
        sql += RegisteredEntityTable.c.MaxSessionKeysPerRequest.name() + ",";
        sql += RegisteredEntityTable.c.PublicKeyCryptoSpec.name() + ",";
        sql += RegisteredEntityTable.c.PublicKeyValue.name() + ",";
        sql += RegisteredEntityTable.c.DistKeyValidityPeriod.name() + ",";
        sql += RegisteredEntityTable.c.DistCryptoSpec.name() + ",";
        sql += RegisteredEntityTable.c.DistKeyExpirationTime.name() + ",";
        sql += RegisteredEntityTable.c.DistKeyValue.name() + ",";
        sql += RegisteredEntityTable.c.Active.name() + ",";
        sql += RegisteredEntityTable.c.BackupToAuthIDs.name() + ",";
        sql += RegisteredEntityTable.c.BackupFromAuthID.name() + ",";
        sql += RegisteredEntityTable.c.MigrationToken.name() + ")";
        sql += " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)";
        PreparedStatement preparedStatement = connection.prepareStatement(sql);
        regEntity = encryptRecords(regEntity);
        int index = 1;
        preparedStatement.setString(index++,regEntity.getName());
        preparedStatement.setString(index++,regEntity.getGroup());
        preparedStatement.setString(index++,regEntity.getDistProtocol());
        preparedStatement.setBoolean(index++,regEntity.getUsePermanentDistKey());
        preparedStatement.setInt(index++,regEntity.getMaxSessionKeysPerRequest());
        preparedStatement.setString(index++,regEntity.getPublicKeyCryptoSpec());
        PublicKey publicKey = regEntity.getPublicKey();
        if (publicKey != null) {
            preparedStatement.setBytes(index++,publicKey.getEncoded());
        }
        else {
            preparedStatement.setNull(index++, Types.BLOB);
        }
        preparedStatement.setString(index++,regEntity.getDistKeyValidityPeriod());
        preparedStatement.setString(index++,regEntity.getDistCryptoSpec());
        byte[] distKeyVal = regEntity.getDistKeyVal();
        if (distKeyVal != null) {
            preparedStatement.setLong(index++, regEntity.getDistKeyExpirationTime());
            preparedStatement.setBytes(index++,distKeyVal);
        }
        else {
            preparedStatement.setNull(index++, Types.INTEGER);
            preparedStatement.setNull(index++, Types.BLOB);
        }

        preparedStatement.setBoolean(index++, regEntity.isActive());
        preparedStatement.setString(index++, regEntity.getBackupToAuthIDs());
        preparedStatement.setInt(index++, regEntity.getBackupFromAuthID());
        byte[] migrationTokenVal = regEntity.getMigrationTokenVal();
        if (migrationTokenVal != null) {
            preparedStatement.setBytes(index++, migrationTokenVal);
        }
        else {
            preparedStatement.setNull(index++, Types.BLOB);
        }

        preparedStatement.toString();
        if (DEBUG) logger.info("{}",preparedStatement);
        boolean result = preparedStatement.execute();
        preparedStatement.close();
        closeConnection();
        return result;
    }

    /**
     * Insert records into RegistrationEntityTable
     *
     * @param regEntity the records registered as entity to be distributed among the clients.
     *
     * @return <code>true</code> if the insertion has been successful
     *         <code>false</code> if the insertion has failed
     * @throws SQLException  if a database access error occurs;
     * this method is called on a closed <code>PreparedStatement</code>
     * or an argument is supplied to this method
     * @see RegisteredEntityTable
     */
    public boolean insertRecords(RegisteredEntityTable regEntity) throws SQLException {
        return insertOrReplaceRecordsHelper("INSERT", regEntity);
    }

    public boolean insertRecordsOrUpdateIfExists(RegisteredEntityTable regEntity) throws SQLException {
        return insertOrReplaceRecordsHelper("INSERT OR REPLACE", regEntity);
    }

    /**
     * Insert records related to the TrustedAuthTable
     *
     * @param auth the records registered as to be used as trusted authentication server
     * @return <code>true</code> if the insertion has been successful
     *         <code>false</code> if the insertion has failed
     * @throws SQLException  if a database access error occurs;
     * this method is called on a closed <code>PreparedStatement</code>
     * or an argument is supplied to this method
     * @throws CertificateEncodingException If there is a problem in certificate encoding.
     * @see TrustedAuthTable
     */
    public boolean insertRecords(TrustedAuthTable auth) throws SQLException, CertificateEncodingException {
        String sql = "INSERT INTO " + TrustedAuthTable.T_TRUSTED_AUTH + "(";
        sql += TrustedAuthTable.c.ID.name() + ",";
        sql += TrustedAuthTable.c.Host.name() + ",";
        sql += TrustedAuthTable.c.EntityHost.name() + ",";
        sql += TrustedAuthTable.c.Port.name() + ",";
        sql += TrustedAuthTable.c.HeartbeatPeriod.name() + ",";
        sql += TrustedAuthTable.c.FailureThreshold.name() + ",";
        sql += TrustedAuthTable.c.InternetCertificateValue.name() + ",";
        sql += TrustedAuthTable.c.EntityCertificateValue.name() + ",";
        sql += TrustedAuthTable.c.BackupCertificateValue.name() + ")";
        sql += " VALUES(?,?,?,?,?,?,?,?,?)";
        PreparedStatement preparedStatement = connection.prepareStatement(sql);
        int index = 1;
        preparedStatement.setInt(index++,auth.getId());
        preparedStatement.setString(index++,auth.getHost());
        preparedStatement.setString(index++,auth.getEntityHost());
        preparedStatement.setInt(index++,auth.getPort());
        preparedStatement.setInt(index++,auth.getHeartbeatPeriod());
        preparedStatement.setInt(index++,auth.getFailureThreshold());
        preparedStatement.setBytes(index++,auth.getInternetCertificate().getEncoded());
        preparedStatement.setBytes(index++,auth.getEntityCertificate().getEncoded());
        X509Certificate backupCertificate = auth.getBackupCertificate();
        if (backupCertificate != null) {
            preparedStatement.setBytes(index++,backupCertificate.getEncoded());
        }
        else {
            preparedStatement.setNull(index++, Types.BLOB);
        }
        if (DEBUG) logger.info("{}",preparedStatement);
        boolean result = preparedStatement.execute();
        preparedStatement.close();
        closeConnection();
        return result;
    }


    public CachedSessionKeyTable encryptRecords(CachedSessionKeyTable cachedSessionKey) {
        if (!encryptCredentials) {
            return cachedSessionKey;
        }
        cachedSessionKey.setKeyVal(encryptAuthDBData(new Buffer(cachedSessionKey.getKeyVal())).getRawBytes());
        return cachedSessionKey;
    }
    public CachedSessionKeyTable decryptRecords(CachedSessionKeyTable cachedSessionKey) {
        if (!encryptCredentials) {
            return cachedSessionKey;
        }
        cachedSessionKey.setKeyVal(decryptAuthDBData(new Buffer(cachedSessionKey.getKeyVal())).getRawBytes());
        return cachedSessionKey;
    }
    /**
     * Insert records related to the cached session keys
     *
     * @param cachedSessionKey the information of records related cached as session keys
     * @return <code>true</code> if the insertion has been successful
     *         <code>false</code> if the insertion has failed
     * @throws SQLException  if a database access error occurs;
     * this method is called on a closed <code>PreparedStatement</code>
     * or an argument is supplied to this method
     * @see CachedSessionKeyTable
     */
    public boolean insertRecords(CachedSessionKeyTable cachedSessionKey) throws SQLException {
        encryptRecords(cachedSessionKey);
        String sql = "INSERT INTO " + CachedSessionKeyTable.T_CACHED_SESSION_KEY + "(";
        sql += CachedSessionKeyTable.c.ID.name() + ",";
        sql += CachedSessionKeyTable.c.Owners.name() + ",";
        sql += CachedSessionKeyTable.c.MaxNumOwners.name() + ",";
        sql += CachedSessionKeyTable.c.Purpose.name() + ",";
        sql += CachedSessionKeyTable.c.ExpirationTime.name() + ",";
        sql += CachedSessionKeyTable.c.RelValidity.name() + ",";
        sql += CachedSessionKeyTable.c.CryptoSpec.name() + ",";
        sql += CachedSessionKeyTable.c.KeyVal.name() + ")";
        sql += " VALUES(?,?,?,?,?,?,?,?)";
        PreparedStatement preparedStatement = connection.prepareStatement(sql);
        int index = 1;
        preparedStatement.setLong(index++,cachedSessionKey.getID());
        preparedStatement.setString(index++,cachedSessionKey.getOwner());
        preparedStatement.setInt(index++,cachedSessionKey.getMaxNumOwners());
        preparedStatement.setString(index++,cachedSessionKey.getPurpose());
        preparedStatement.setLong(index++,cachedSessionKey.getAbsValidity());
        preparedStatement.setLong(index++,cachedSessionKey.getRelValidity());
        preparedStatement.setString(index++,cachedSessionKey.getSessionCryptoSpec());
        preparedStatement.setBytes(index++,cachedSessionKey.getKeyVal());
        if (DEBUG) logger.info("{}",preparedStatement);
        boolean result = preparedStatement.execute();
        preparedStatement.close();
        closeConnection();
        return result;
    }

    /**
     * Inserts the meta data information into the table meta data.
     *
     * @param metaData the object container of the information in meta data table
     * @return <code>true</code> if the insertion has been successful
     *         <code>false</code> if the insertion has failed
     * @throws SQLException  if a database access error occurs;
     * this method is called on a closed <code>PreparedStatement</code>
     * or an argument is supplied to this method
     * @see MetaDataTable
     */
    public boolean insertRecords(MetaDataTable metaData) throws SQLException {

        String sql = "INSERT INTO " + MetaDataTable.T_META_DATA + "(";
        sql += MetaDataTable.c.Key.name() + ",";
        sql += MetaDataTable.c.Value.name() + ")";
        sql += " VALUES(?,?)";
        PreparedStatement preparedStatement = connection.prepareStatement(sql);
        int index = 1;
        preparedStatement.setString(index++, metaData.getKey());
        preparedStatement.setString(index++, metaData.getValue());
        if (DEBUG) logger.info("{}",preparedStatement);
        boolean result = preparedStatement.execute();
        preparedStatement.close();
        closeConnection();
        return result;
    }

    /**
     * Inserts the file-sharing information into the file-sharing table.
     *
     * @param fileSharing the object container of the information in file-sharing table
     * @return <code>true</code> if the insertion has been successful
     *         <code>false</code> if the insertion has failed
     * @throws SQLException  if a database access error occurs;
     * this method is called on a closed <code>PreparedStatement</code>
     * or an argument is supplied to this method
     * @see FileSharingTable
     */
    public boolean insertRecords(FileSharingTable fileSharing) throws SQLException {
        String sql = "INSERT INTO " + FileSharingTable.T_File_Sharing + "(";
        sql += FileSharingTable.c.Owner.name() + ",";
        sql += FileSharingTable.c.ReaderType.name() + ",";
        sql += FileSharingTable.c.Reader.name() + ")";
        sql += " VALUES (?,?,?)";
        PreparedStatement preparedStatement = connection.prepareStatement(sql);
        int index = 1;
        preparedStatement.setString(index++,fileSharing.getOwner());
        preparedStatement.setString(index++,fileSharing.getReaderType());
        preparedStatement.setString(index++,fileSharing.getReader());
        logger.info("{} {} {}", fileSharing.getOwner(), fileSharing.getReaderType(), fileSharing.getReader() );
        if (DEBUG) logger.info("{}",preparedStatement);
        boolean result = preparedStatement.execute();
        preparedStatement.close();
        closeConnection();
        return result;
    }

    /**
     * Selects all policies record from the table communication policy.
     * @return a list of all policies stored in the database
     * @throws SQLException  if a database access error occurs;
     * this method is called on a closed <code>PreparedStatement</code>
     * or an argument is supplied to this method
     */
    public List<CommunicationPolicyTable> selectAllPolicies() throws SQLException {
        statement = connection.createStatement();
        String sql = "SELECT * FROM " + CommunicationPolicyTable.T_COMMUNICATION_POLICY;
        if (DEBUG) logger.info(sql);
        ResultSet resultSet = statement.executeQuery(sql);
        List<CommunicationPolicyTable> policies = new LinkedList<>();
        while(resultSet.next()){
            CommunicationPolicyTable policy = CommunicationPolicyTable.createRecord(resultSet);
            policies.add(policy);
            if (DEBUG) logger.info(policy.toJSONObject().toJSONString());
        }
        closeStatement();
        closeConnection();
        return policies;
    }

    /**
     * Select all records stored in the table registered entity.
     * @return a list of all registered entities in the
     * @throws SQLException  if a database access error occurs;
     * this method is called on a closed <code>PreparedStatement</code>
     * or an argument is supplied to this method
     */
    public List<RegisteredEntityTable> selectAllRegEntities() throws SQLException {
        statement = connection.createStatement();
        String sql = "SELECT * FROM " + RegisteredEntityTable.T_REGISTERED_ENTITY;
        if (DEBUG) logger.info(sql);
        ResultSet resultSet = statement.executeQuery(sql);
        List<RegisteredEntityTable> entities = new LinkedList<>();
        while(resultSet.next()) {
            RegisteredEntityTable entity = RegisteredEntityTable.createRecord(resultSet);
            entities.add(decryptRecords(entity));
            if (DEBUG) logger.info(entity.toJSONObject().toJSONString());
        }
        return entities;
    }

    /**
     * Updates the registered entity distribution key values.
     * @param regEntityName registered entity name
     * @param distKeyExpirationTime distribution key expiration time
     * @param distKeyVal the actual binary representation of the distribute key
     * @return <code>true</code> if the update success otherwise, <code>false</code>
     * @throws SQLException  if a database access error occurs;
     * this method is called on a closed <code>PreparedStatement</code>
     * or an argument is supplied to this method
     */
    public boolean updateRegEntityDistKey(String regEntityName, long distKeyExpirationTime, Buffer distKeyVal)
            throws SQLException
    {
        if (encryptCredentials) {
            distKeyVal = encryptAuthDBData(distKeyVal);
        }
        String sql = "UPDATE " + RegisteredEntityTable.T_REGISTERED_ENTITY;
        sql += " SET " + RegisteredEntityTable.c.DistKeyExpirationTime.name() + " = " + distKeyExpirationTime;
        sql += ", " + RegisteredEntityTable.c.DistKeyValue.name() + " = :DistKeyValue";
        sql += " WHERE " + RegisteredEntityTable.c.Name.name() + " = '" + regEntityName + "'";
        if (DEBUG) logger.info(sql);
        PreparedStatement preparedStatement  = connection.prepareStatement(sql);
        preparedStatement.setBytes(1, distKeyVal.getRawBytes());
        return preparedStatement.execute();
    }

    /**
     * Selects all Trusted Auth records.
     *
     * @return a list of all trusted auth records.
     * @throws SQLException if a database access error occurs;
     * this method is called on a closed <code>PreparedStatement</code>
     * or an argument is supplied to this method
     * @throws CertificateEncodingException If there is a problem in certificate encoding.
     */
    public List<TrustedAuthTable> selectAllTrustedAuth() throws SQLException, CertificateEncodingException {
        statement = connection.createStatement();
        String sql = "SELECT * FROM " + TrustedAuthTable.T_TRUSTED_AUTH;
        if (DEBUG) logger.info(sql);
        ResultSet resultSet = statement.executeQuery(sql);
        List<TrustedAuthTable> authList = new LinkedList<>();
        while (resultSet.next()) {
            TrustedAuthTable auth = TrustedAuthTable.createRecord(resultSet);
            if (DEBUG) logger.info(auth.toJSONObject().toJSONString());
            authList.add(auth);
        }
        return authList;
    }

    /**
     * Selects all cached session keys.
     *
     * @return a list of all cached session keys
     * @throws SQLException  if a database access error occurs;
     * this method is called on a closed <code>PreparedStatement</code>
     * or an argument is supplied to this method
     */
    public List<CachedSessionKeyTable> selectAllCachedSessionKey() throws SQLException {
        statement = connection.createStatement();
        String sql = "SELECT * FROM " + CachedSessionKeyTable.T_CACHED_SESSION_KEY;
        if (DEBUG) logger.info(sql);
        ResultSet resultSet = statement.executeQuery(sql);
        List<CachedSessionKeyTable> cachedSessionKeyList = new LinkedList<>();
        while (resultSet.next()) {
            CachedSessionKeyTable cachedSessionKey = CachedSessionKeyTable.createRecord(resultSet);
            if (DEBUG) logger.info(cachedSessionKey.toJSONObject().toJSONString());
            cachedSessionKeyList.add(decryptRecords(cachedSessionKey));
        }
        return cachedSessionKeyList;
    }

    /**
     * Select a specific cached key by its ID
     * @param id the id used to store this cached session key.
     * @return returns the Object container ${@link CachedSessionKeyTable}
     * @throws SQLException  if a database access error occurs;
     * this method is called on a closed <code>PreparedStatement</code>
     * or an argument is supplied to this method
     */
    public CachedSessionKeyTable selectCachedSessionKeyByID(long id) throws SQLException {
        statement = connection.createStatement();
        String sql = "SELECT * FROM " + CachedSessionKeyTable.T_CACHED_SESSION_KEY;
        sql += " WHERE " + CachedSessionKeyTable.c.ID.name() + " = " + id;
        if (DEBUG) logger.info(sql);
        ResultSet resultSet = statement.executeQuery(sql);
        CachedSessionKeyTable cachedSessionKey = null;
        while (resultSet.next()) {
            cachedSessionKey = CachedSessionKeyTable.createRecord(resultSet);
            if (DEBUG) logger.info(cachedSessionKey.toJSONObject().toJSONString());
        }
        return decryptRecords(cachedSessionKey);
    }

    /**
     * Select session keys with the same purpose and that is not expired yet.
     * @param requestingEntityName the name of the requesting entity for cached session keys.
     *                             to be used for adding the entity as an owner of the session keys.
     * @param purpose the given purpose of the session key
     * @return returns the list of session keys with the given session key
     * @throws SQLException if a database access error occurs;
     * this method is called on a closed <code>PreparedStatement</code>
     * or an argument is supplied to this method
     */
    public List<CachedSessionKeyTable> selectCachedSessionKeysByPurpose(String requestingEntityName, String purpose)
            throws SQLException {
        statement = connection.createStatement();
        String sql = "SELECT * FROM " + CachedSessionKeyTable.T_CACHED_SESSION_KEY;
        sql += " WHERE " + CachedSessionKeyTable.c.Purpose.name() + " = " + "'" + purpose + "'";
        sql += " AND " + CachedSessionKeyTable.c.Owners.name() + " NOT LIKE " + "'%" + requestingEntityName + "%'";
        long currentTime = new java.util.Date().getTime();
        sql += " AND " + CachedSessionKeyTable.c.ExpirationTime.name() + " > " + currentTime;
        if (DEBUG) logger.info(sql);
        ResultSet resultSet = statement.executeQuery(sql);
        List<CachedSessionKeyTable> result = new LinkedList<>();
        while (resultSet.next()) {
            CachedSessionKeyTable cachedSessionKey = CachedSessionKeyTable.createRecord(resultSet);
            if (DEBUG) logger.info(cachedSessionKey.toJSONObject().toJSONString());
            result.add(decryptRecords(cachedSessionKey));
        }
        return result;
    }

    /**
     * Select a group of readers who can download files from file owner.
     * @param fileOwner the owner of the file.
     * @return returns the group of readers
     * this method is called on a closed <code>PreparedStatement</code>
     * or an argument is supplied to this method
     */
    public ArrayList <String> selectFileSharingInfoByOwner(String fileOwner){
        String sql = "SELECT Reader FROM " + FileSharingTable.T_File_Sharing;
        sql += " WHERE " + FileSharingTable.c.Owner.name() + " = " + "'" + fileOwner + "'";
        if (DEBUG) logger.info(sql);
        ResultSet resultSet = null;
        try {
            statement = connection.createStatement();
            resultSet = statement.executeQuery(sql);
        }
        catch (Exception e){
            e.printStackTrace();
        }
        ArrayList <String>  result = new ArrayList <String>();
        try{
            while(resultSet.next()){
            result.add(resultSet.getString("Reader"));
            }
        }
        catch (Exception e)
        {
            e.printStackTrace();
        }
        return result;
    }

    /**
     * Deletes expired cached session keys from the database.
     * @return <code>true</code> if the deletion is successful; otherwise, <code>false</code>
     * @throws SQLException  if a database access error occurs;
     * this method is called on a closed <code>PreparedStatement</code>
     * or an argument is supplied to this method
     */
    public boolean deleteExpiredCahcedSessionKeys() throws SQLException {
        String sql = "DELETE FROM " + CachedSessionKeyTable.T_CACHED_SESSION_KEY;
        long currentTime = new java.util.Date().getTime();
        sql += " WHERE " + CachedSessionKeyTable.c.ExpirationTime.name() + " < " + currentTime;
        if (DEBUG) logger.info(sql);
        PreparedStatement preparedStatement  = connection.prepareStatement(sql);
        boolean result = preparedStatement.execute();
        // It's in auto-commit mode no need for explicit commit
        //_commit();
        return result;
    }

    /**
     * Delete all cached session keys from the database.
     * @return <code>true</code> if the deletion is successful; otherwise, <code>false</code>
     * @throws SQLException if a database access error occurs;
     */
    public boolean deleteAllCachedSessionKeys() throws SQLException {
        String sql = "DELETE FROM " + CachedSessionKeyTable.T_CACHED_SESSION_KEY;
        if (DEBUG) logger.info(sql);
        PreparedStatement preparedStatement  = connection.prepareStatement(sql);
        return preparedStatement.execute();
    }

    /**
     * Append an owner to a session key.
     * @param keyID the id of the session key
     * @param newOwner the owner to the session key
     * @return <code>true</code> if the appending is successful; otherwise, <code>false</code>
     * @throws SQLException  if a database access error occurs;
     * this method is called on a closed <code>PreparedStatement</code>
     * or an argument is supplied to this method
     */
    public boolean appendSessionKeyOwner(long keyID, String newOwner) throws SQLException {
        String sql = "UPDATE " + CachedSessionKeyTable.T_CACHED_SESSION_KEY;
        sql += " SET " + CachedSessionKeyTable.c.Owners.name() + " = ";
        sql += CachedSessionKeyTable.c.Owners.name() + "|| ',' || " + "'" + newOwner + "'";
        sql += " WHERE " + CachedSessionKeyTable.c.ID.name() + " = " + keyID;
        if (DEBUG) logger.info(sql);
        PreparedStatement preparedStatement  = connection.prepareStatement(sql);
        return preparedStatement.execute();
    }

    /**
     * Append a file reader in database.
     * @param owner owner of the file.
     * @param fileReader reader of the file.
     * @return <code>true</code> if the appending is successful; otherwise, <code>false</code>
     * @throws SQLException  if a database access error occurs;
     * this method is called on a closed <code>PreparedStatement</code>
     * or an argument is supplied to this method
     */
    public boolean appendFileReader(String owner, String fileReader) throws SQLException {
        statement = connection.createStatement();
        String sql_deduplication = "SELECT * FROM " + FileSharingTable.T_File_Sharing;
        sql_deduplication += " WHERE " + FileSharingTable.c.Owner + "='";
        sql_deduplication += owner + "' AND " + FileSharingTable.c.ReaderType + "='entity' AND ";
        sql_deduplication += FileSharingTable.c.Reader + "='" + fileReader + "'";
        ResultSet resultSet = statement.executeQuery(sql_deduplication);
        if (resultSet.getString("Reader") != null) {
            logger.info("Already registered reader information!");
            return true;
        }
        else {
            String sql = "INSERT INTO " + FileSharingTable.T_File_Sharing + "(";
            sql += FileSharingTable.c.Owner.name() + ",";
            sql += FileSharingTable.c.ReaderType.name() + ",";
            sql += FileSharingTable.c.Reader.name() + ")";
            sql += " VALUES ('" + owner + "', 'entity', '" + fileReader + "')";
            if (DEBUG) logger.info(sql);
            PreparedStatement preparedStatement  = connection.prepareStatement(sql);
            return preparedStatement.execute();
        }
    }

    /**
     * Select the value of a meta data by its key
     * @param key the key to be selected
     * @return the string representation of the metadata's value
     * @throws SQLException  if a database access error occurs;
     * this method is called on a closed <code>PreparedStatement</code>
     * or an argument is supplied to this method
     */
    public String selectMetaDataValue(String key) throws SQLException {
        statement = connection.createStatement();
        String sql = "SELECT * FROM " + MetaDataTable.T_META_DATA;
        sql += " WHERE " + MetaDataTable.c.Key.name() + " = '" + key + "'";
        if (DEBUG) logger.info(sql);
        ResultSet resultSet = statement.executeQuery(sql);
        MetaDataTable metaData = null;
        while (resultSet.next()) {
            metaData = MetaDataTable.createRecord(resultSet);
            if (DEBUG) logger.info(metaData.toJSONObject().toJSONString());
        }
        closeStatement();
        return metaData.getValue();
    }

    /**
     * Updates the metadata value on the given key
     * @param key the key value of the metadata to update
     * @param value the value to update
     * @return <code>true</code> if the update is successful; otherwise <code>false</code>
     * @throws SQLException If a database access error occurs;
     * this method is called on a closed <code>PreparedStatement</code>
     * or an argument is supplied to this method
     */
    public boolean updateMetaData(String key, String value) throws SQLException
    {
        String sql = "UPDATE " + MetaDataTable.T_META_DATA;
        sql += " SET " + MetaDataTable.c.Value.name() + " = '" + value + "'";
        sql += " WHERE " + MetaDataTable.c.Key.name() + " = '" + key + "'";
        if (DEBUG) logger.info(sql);
        PreparedStatement preparedStatement  = connection.prepareStatement(sql);
        boolean result = preparedStatement.execute();
        // It's in auto-commit mode no need for explicit commit
        //_commit();
        preparedStatement.close();
        return result;

    }

    /**
     * Close the ${@link PreparedStatement}.
     * <pre>
     *     Recomended to be used after execute the sql through the ${@link Connection}
     * </pre>
     * @throws SQLException If a database access error occurs
     */
    public void closeStatement() throws SQLException {
        statement.close();
    }

    /**
     * Close the connection to the database.
     * @throws SQLException If a database access error occurs
     */
    public void closeConnection() throws SQLException {
        //connection.close();
    }


    /**
     * Delete registered entities except for those originally its own.
     * @return <code>true</code> if the deleting is successful; otherwise, <code>false</code>
     * @throws SQLException If a database access error occurs
     */
    public boolean deleteBackedUpRegisteredEntities() throws SQLException {
        String sql = "DELETE FROM " + RegisteredEntityTable.T_REGISTERED_ENTITY;
        sql += " WHERE " + RegisteredEntityTable.c.BackupFromAuthID.name() + " >= 0";
        if (DEBUG) logger.info(sql);
        PreparedStatement preparedStatement  = connection.prepareStatement(sql);
        boolean result = preparedStatement.execute();
        return result;
    }

    public boolean deleteRegisteredEntities(List<String> registeredEntityNameList) throws SQLException {
        if (registeredEntityNameList.isEmpty()) {
            throw new RuntimeException("The list of names of registered entities to be removed is empty!");
        }
        String sql = "DELETE FROM " + RegisteredEntityTable.T_REGISTERED_ENTITY;
        sql += " WHERE " + RegisteredEntityTable.c.Name.name() + " = '" + registeredEntityNameList.get(0) + "'";
        for (int i = 1; i < registeredEntityNameList.size(); i++) {
            sql += " OR " + RegisteredEntityTable.c.Name.name() + " = '" + registeredEntityNameList.get(i) + "'";
        }
        if (DEBUG) logger.info(sql);
        PreparedStatement preparedStatement  = connection.prepareStatement(sql);
        return preparedStatement.execute();
    }

    public boolean updateBackupCertificate(int backupFromAuthID, X509Certificate backupCertificate)
            throws SQLException, CertificateEncodingException
    {
        String sql = "UPDATE " + TrustedAuthTable.T_TRUSTED_AUTH;
        sql += " SET " + TrustedAuthTable.c.BackupCertificateValue.name() + " = :BackupCertificateValue";
        sql += " WHERE " + TrustedAuthTable.c.ID.name() + " = '" + backupFromAuthID + "'";
        if (DEBUG) logger.info(sql);
        PreparedStatement preparedStatement  = connection.prepareStatement(sql);
        preparedStatement.setBytes(1, backupCertificate.getEncoded());
        boolean result = preparedStatement.execute();
        ResultSet resultSet = preparedStatement.getResultSet();
        preparedStatement.close();
        return result;
    }
}
