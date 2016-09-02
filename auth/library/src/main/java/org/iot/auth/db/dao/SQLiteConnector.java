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

import org.iot.auth.db.bean.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.sql.*;
import java.util.*;

/**
 * A class for the SQLite connector for Auth database tables.
 * @author Salomon Lee
 */
public class SQLiteConnector {
    public boolean DEBUG;
    private static final Logger logger = LoggerFactory.getLogger(SQLiteConnector.class);
    private Connection connection;
    private Statement statement;
    private String dbPath;

    private void init() throws SQLException, ClassNotFoundException {
        logger.info("DB auth.db opened");
    }

    private void setConnection() throws ClassNotFoundException, SQLException {
        Class.forName("org.sqlite.JDBC");
        if (connection == null || connection.isClosed())
            connection = DriverManager.getConnection("jdbc:sqlite:" + dbPath);
    }

    public void createTablesIfNotExists() throws SQLException, ClassNotFoundException {
        setConnection();
        String sql = "CREATE TABLE IF NOT EXISTS " + CommunicationPolicyTable.T_COMMUNICATION_POLICY + "(";
        sql += CommunicationPolicyTable.c.RequestingGroup.name() + " TEXT NOT NULL,";
        sql += CommunicationPolicyTable.c.TargetType.name() + " TEXT NOT NULL,";
        sql += CommunicationPolicyTable.c.Target.name() + " TEXT NOT NULL,";
        sql += CommunicationPolicyTable.c.CipherAlgorithm.name() + " TEXT NOT NULL,";
        sql += CommunicationPolicyTable.c.HashAlgorithm.name() + " TEXT NOT NULL,";
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
        sql += RegisteredEntityTable.c.PublKeyFile.name() + " TEXT NOT NULL,";
        sql += RegisteredEntityTable.c.DistValidityPeriod.name() + " TEXT NOT NULL,";
        sql += RegisteredEntityTable.c.DistCipherAlgo.name() + " TEXT NOT NULL,";
        sql += RegisteredEntityTable.c.DistHashAlgo.name() + " TEXT NOT NULL,";
        sql += RegisteredEntityTable.c.DistKeyExpirationTime.name() + " INT,";
        sql += RegisteredEntityTable.c.DistKeyVal.name() + " BLOB)";
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
        sql += TrustedAuthTable.c.Port.name() + " INT NOT NULL,";
        sql += TrustedAuthTable.c.CertificatePath.name() + " TEXT NOT NULL)";
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
        sql += CachedSessionKeyTable.c.AbsValidity.name() + " INT NOT NULL,";
        sql += CachedSessionKeyTable.c.RelValidity.name() + " INT NOT NULL,";
        sql += CachedSessionKeyTable.c.CipherAlgo.name() + " TEXT NOT NULL,";
        sql += CachedSessionKeyTable.c.HashAlgo.name() + " TEXT NOT NULL,";
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

        closeConnection();
    }

    public boolean insertRecords(CommunicationPolicyTable policy) throws SQLException, ClassNotFoundException {
        setConnection();
        String sql = "INSERT INTO " + CommunicationPolicyTable.T_COMMUNICATION_POLICY + "(";
        sql += CommunicationPolicyTable.c.RequestingGroup.name() + ",";
        sql += CommunicationPolicyTable.c.TargetType.name() + ",";
        sql += CommunicationPolicyTable.c.Target.name() + ",";
        sql += CommunicationPolicyTable.c.CipherAlgorithm.name() + ",";
        sql += CommunicationPolicyTable.c.HashAlgorithm.name() + ",";
        sql += CommunicationPolicyTable.c.AbsoluteValidity.name() + ",";
        sql += CommunicationPolicyTable.c.RelativeValidity.name() + ")";
        sql += " VALUES (?,?,?,?,?,?,?)";
        PreparedStatement preparedStatement = connection.prepareStatement(sql);
        preparedStatement.setString(1,policy.getReqGroup());
        preparedStatement.setString(2,policy.getTargetTypeVal());
        preparedStatement.setString(3,policy.getTarget());
        preparedStatement.setString(4,policy.getCipherAlgo());
        preparedStatement.setString(5,policy.getHashAlgo());
        preparedStatement.setString(6,policy.getAbsValidityStr());
        preparedStatement.setString(7,policy.getRelValidityStr());
        if (DEBUG) logger.info(preparedStatement.toString());
        boolean result = preparedStatement.execute();
        preparedStatement.close();
        closeConnection();
        return result;
    }

    public boolean insertRecords(RegisteredEntityTable regEntity) throws SQLException, ClassNotFoundException {
        setConnection();
        String sql = "INSERT INTO " + RegisteredEntityTable.T_REGISTERED_ENTITY + "(";
        sql += RegisteredEntityTable.c.Name.name() + ",";
        sql += "'"+ RegisteredEntityTable.c.Group.name() + "',";
        sql += RegisteredEntityTable.c.PublKeyFile.name() + ",";
        sql += RegisteredEntityTable.c.DistValidityPeriod.name() + ",";
        sql += RegisteredEntityTable.c.DistCipherAlgo.name() + ",";
        sql += RegisteredEntityTable.c.DistHashAlgo.name() + ",";
        sql += RegisteredEntityTable.c.DistKeyExpirationTime.name() + ",";
        sql += RegisteredEntityTable.c.DistKeyVal.name() + ")";
        sql += " VALUES (?,?,?,?,?,?,?,?)";
        PreparedStatement preparedStatement = connection.prepareStatement(sql);
        preparedStatement.setString(1,regEntity.getName());
        preparedStatement.setString(2,regEntity.getGroup());
        preparedStatement.setString(3,regEntity.getPublicKeyFile());
        preparedStatement.setString(4,regEntity.getDistValidityPeriod());
        preparedStatement.setString(5,regEntity.getDistCipherAlgo());
        preparedStatement.setString(6,regEntity.getDistHashAlgo());
        byte[] distKeyVal = regEntity.getDistKeyVal();
        if (distKeyVal != null) {
            preparedStatement.setLong(7, regEntity.getDistKeyExpirationTime());
            preparedStatement.setBytes(8,distKeyVal);
        }
        else {
            preparedStatement.setNull(7, Types.INTEGER);
            preparedStatement.setNull(8, Types.BLOB);
        }

        preparedStatement.toString();
        if (DEBUG) logger.info("{}",preparedStatement);
        boolean result = preparedStatement.execute();
        preparedStatement.close();
        closeConnection();
        return result;
    }

    public boolean insertRecords(TrustedAuthTable auth)  throws SQLException, ClassNotFoundException {
        setConnection();
        String sql = "INSERT INTO " + TrustedAuthTable.T_TRUSTED_AUTH + "(";
        sql += TrustedAuthTable.c.ID.name() + ",";
        sql += TrustedAuthTable.c.Host.name() + ",";
        sql += TrustedAuthTable.c.Port.name() + ",";
        sql += TrustedAuthTable.c.CertificatePath.name() + ")";
        sql += " VALUES(?,?,?,?)";
        PreparedStatement preparedStatement = connection.prepareStatement(sql);
        preparedStatement.setInt(1,auth.getId());
        preparedStatement.setString(2,auth.getHost());
        preparedStatement.setInt(3,auth.getPort());
        preparedStatement.setString(4,auth.getCertificatePath());
        if (DEBUG) logger.info("{}",preparedStatement);
        boolean result = preparedStatement.execute();
        preparedStatement.close();
        closeConnection();
        return result;
    }

    public boolean insertRecords(CachedSessionKeyTable cachedSessionKey) throws SQLException, ClassNotFoundException {
        setConnection();
        String sql = "INSERT INTO " + CachedSessionKeyTable.T_CACHED_SESSION_KEY + "(";
        sql += CachedSessionKeyTable.c.ID.name() + ",";
        sql += CachedSessionKeyTable.c.Owners.name() + ",";
        sql += CachedSessionKeyTable.c.AbsValidity.name() + ",";
        sql += CachedSessionKeyTable.c.RelValidity.name() + ",";
        sql += CachedSessionKeyTable.c.CipherAlgo.name() + ",";
        sql += CachedSessionKeyTable.c.HashAlgo.name() + ",";
        sql += CachedSessionKeyTable.c.KeyVal.name() + ")";
        sql += " VALUES(?,?,?,?,?,?,?)";
        PreparedStatement preparedStatement = connection.prepareStatement(sql);
        preparedStatement.setLong(1,cachedSessionKey.getID());
        preparedStatement.setString(2,cachedSessionKey.getOwner());
        preparedStatement.setLong(3,cachedSessionKey.getAbsValidity());
        preparedStatement.setLong(4,cachedSessionKey.getRelValidity());
        preparedStatement.setString(5,cachedSessionKey.getCipherAlgo());
        preparedStatement.setString(6,cachedSessionKey.getHashAlgo());
        preparedStatement.setBytes(7,cachedSessionKey.getKeyVal());
        if (DEBUG) logger.info("{}",preparedStatement);
        boolean result = preparedStatement.execute();
        preparedStatement.close();
        closeConnection();
        return result;
    }

    public boolean insertRecords(MetaDataTable metaData) throws SQLException, ClassNotFoundException {
        setConnection();

        String sql = "INSERT INTO " + MetaDataTable.T_META_DATA + "(";
        sql += MetaDataTable.c.Key.name() + ",";
        sql += MetaDataTable.c.Value.name() + ")";
        sql += " VALUES(?,?)";
        PreparedStatement preparedStatement = connection.prepareStatement(sql);
        preparedStatement.setString(1, metaData.getKey());
        preparedStatement.setString(2, metaData.getValue());
        if (DEBUG) logger.info("{}",preparedStatement);
        boolean result = preparedStatement.execute();
        preparedStatement.close();
        closeConnection();
        return result;
    }

    public List<CommunicationPolicyTable> selectAllPolicies() throws SQLException, ClassNotFoundException {
        setConnection();
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

    public List<RegisteredEntityTable> selectAllRegEntities(String authDatabaseDir) throws SQLException, ClassNotFoundException {
        setConnection();
        statement = connection.createStatement();
        String sql = "SELECT * FROM " + RegisteredEntityTable.T_REGISTERED_ENTITY;
        if (DEBUG) logger.info(sql);
        ResultSet resultSet = statement.executeQuery(sql);
        List<RegisteredEntityTable> entities = new LinkedList<>();
        while(resultSet.next()) {
            RegisteredEntityTable entity = RegisteredEntityTable.createRecord(authDatabaseDir, resultSet);
            entities.add(entity);
            if (DEBUG) logger.info(entity.toJSONObject().toJSONString());
        }
        return entities;
    }

    public boolean updateRegEntityDistKey(String regEntityName, long distKeyExpirationTime, byte[] distKeyVal)
            throws SQLException, ClassNotFoundException
    {
        setConnection();
        String sql = "UPDATE " + RegisteredEntityTable.T_REGISTERED_ENTITY;
        sql += " SET " + RegisteredEntityTable.c.DistKeyExpirationTime.name() + " = " + distKeyExpirationTime;
        sql += ", " + RegisteredEntityTable.c.DistKeyVal.name() + " = :DistKeyVal";
        sql += " WHERE " + RegisteredEntityTable.c.Name.name() + " = '" + regEntityName + "'";
        if (DEBUG) logger.info(sql);
        PreparedStatement preparedStatement  = connection.prepareStatement(sql);
        preparedStatement.setBytes(1, distKeyVal);
        boolean result = preparedStatement.execute();
        // It's in auto-commit mode no need for explicit commit
        //_commit();
        return result;

    }

    public List<TrustedAuthTable> selectAllTrustedAuth() throws SQLException, ClassNotFoundException {
        setConnection();
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

    public List<CachedSessionKeyTable> selectAllCachedSessionKey() throws SQLException, ClassNotFoundException {
        setConnection();
        statement = connection.createStatement();
        String sql = "SELECT * FROM " + CachedSessionKeyTable.T_CACHED_SESSION_KEY;
        if (DEBUG) logger.info(sql);
        ResultSet resultSet = statement.executeQuery(sql);
        List<CachedSessionKeyTable> cachedSessionKeyList = new LinkedList<>();
        while (resultSet.next()) {
            CachedSessionKeyTable cachedSessionKey = CachedSessionKeyTable.createRecord(resultSet);
            if (DEBUG) logger.info(cachedSessionKey.toJSONObject().toJSONString());
            cachedSessionKeyList.add(cachedSessionKey);
        }
        return cachedSessionKeyList;
    }

    public CachedSessionKeyTable selectCachedSessionKeyByID(long id) throws SQLException, ClassNotFoundException {
        setConnection();
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
        return cachedSessionKey;
    }

    public boolean deleteExpiredCahcedSessionKeys() throws SQLException, ClassNotFoundException {
        setConnection();
        String sql = "DELETE FROM " + CachedSessionKeyTable.T_CACHED_SESSION_KEY;
        long currentTime = new java.util.Date().getTime();
        sql += " WHERE " + CachedSessionKeyTable.c.AbsValidity.name() + " < " + currentTime;
        if (DEBUG) logger.info(sql);
        PreparedStatement preparedStatement  = connection.prepareStatement(sql);
        boolean result = preparedStatement.execute();
        // It's in auto-commit mode no need for explicit commit
        //_commit();
        return result;
    }

    public boolean appendSessionKeyOwner(long keyID, String newOwner) throws SQLException, ClassNotFoundException {
        setConnection();
        String sql = "UPDATE " + CachedSessionKeyTable.T_CACHED_SESSION_KEY;
        sql += " SET " + CachedSessionKeyTable.c.Owners.name() + " = ";
        sql += CachedSessionKeyTable.c.Owners.name() + "|| ',' || " + "'" + newOwner + "'";
        sql += " WHERE " + CachedSessionKeyTable.c.ID.name() + " = " + keyID;
        if (DEBUG) logger.info(sql);
        PreparedStatement preparedStatement  = connection.prepareStatement(sql);
        boolean result = preparedStatement.execute();
        // It's in auto-commit mode no need for explicit commit
        //_commit();
        return result;
    }

    public String selectMetaDataValue(String key) throws SQLException, ClassNotFoundException {
        setConnection();
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
        return metaData.getValue();
    }

    public boolean updateMetaData(String key, String value) throws SQLException, ClassNotFoundException
    {
        setConnection();
        String sql = "UPDATE " + MetaDataTable.T_META_DATA;
        sql += " SET " + MetaDataTable.c.Value.name() + " = '" + value + "'";
        sql += " WHERE " + MetaDataTable.c.Key.name() + " = '" + key + "'";
        if (DEBUG) logger.info(sql);
        PreparedStatement preparedStatement  = connection.prepareStatement(sql);
        boolean result = preparedStatement.execute();
        // It's in auto-commit mode no need for explicit commit
        //_commit();
        return result;

    }

    public void closeStatement() throws SQLException {
        statement.close();
    }

    public void closeConnection() throws SQLException {
        connection.close();
    }

    public SQLiteConnector(String dbPath) {
        this.dbPath = dbPath;
        try {
            init();
        } catch (ClassNotFoundException e) {
            e.printStackTrace();
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }
}
