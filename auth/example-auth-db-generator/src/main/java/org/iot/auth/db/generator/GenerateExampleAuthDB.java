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
import org.omg.SendingContext.RunTime;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.FileInputStream;
import java.io.FileReader;
import java.io.IOException;
import java.security.PublicKey;
import java.sql.SQLException;
import java.util.Date;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.Options;
//import org.apache.commons.cli.ParseException;

/**
 * A program to generate example Auth databases for two example Auths with ID 101 and ID 102.
 * @author Hokeun Kim
 */
public class GenerateExampleAuthDB {
    public static void main(String[] args) throws Exception {
        // parsing command line arguments
        Options options = new Options();

        Option properties = new Option("n", "num_auths", true, "number of example Auths to be generated.");
        properties.setRequired(false);
        options.addOption(properties);

        CommandLineParser parser = new DefaultParser();
        HelpFormatter formatter = new HelpFormatter();
        CommandLine cmd;

        try {
            cmd = parser.parse(options, args);
        } catch (org.apache.commons.cli.ParseException e) {
            System.out.println(e.getMessage());
            formatter.printHelp("utility-name", options);

            System.exit(1);
            return;
        }
        String strNumAuths = cmd.getOptionValue("num_auths");
        if (strNumAuths == null) {
            logger.error("Number of Auths not specified! (Use option -n to specify the number of Auths to be generated.)");
            System.exit(1);
            return;
        }
        int numAuths = Integer.parseInt(strNumAuths);
        logger.info("Number of AUths to be generated: {}", numAuths);
        if (numAuths > 10 || numAuths < 1) {
            logger.error("Error: Illegal number of Auths to be generated!");
            System.exit(1);
            return;
        }

        for (int netID = 1; netID <= numAuths; netID++) {
            generateAuthDatabase(netID + 100);
        }
    }

    private static void generateAuthDatabase(int authID) throws Exception {
        String authDatabaseDir = "databases/auth" + authID + "/";
        String databasePublicKeyPath = authDatabaseDir + "my_certs/Auth" + authID + "DatabaseCert.pem";
        SQLiteConnector sqLiteConnector = new SQLiteConnector(authDatabaseDir + "auth.db");
        sqLiteConnector.createTablesIfNotExists();

        SymmetricKey databaseKey = new SymmetricKey(
                AuthDB.AUTH_DB_CRYPTO_SPEC,
                new Date().getTime() + DateHelper.parseTimePeriod(AuthDB.AUTH_DB_KEY_ABSOLUTE_VALIDITY)
        );
        initMetaDataTable(sqLiteConnector, databasePublicKeyPath, databaseKey);
        initRegisteredEntityTable(sqLiteConnector, authID, databaseKey,
                authDatabaseDir + "configs/Auth" + authID + "RegisteredEntityTable.config");
        initCommPolicyTable(sqLiteConnector,
                authDatabaseDir + "configs/Auth" + authID + "CommunicationPolicyTable.config");
        initTrustedAuthTable(sqLiteConnector,
                authDatabaseDir + "configs/Auth" + authID + "TrustedAuthTable.config");
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

    private static long convertObjectToLong(Object obj) throws InvalidDBDataTypeException {
        if (obj.getClass() == Integer.class) {
            return (Integer)obj;
        }
        else if (obj.getClass() == Long.class) {
            return (Long)obj;
        }
        else {
            throw new InvalidDBDataTypeException("Wrong class type object for Long!");
        }
    }

    private static int convertObjectToInteger(Object obj) throws InvalidDBDataTypeException {
        if (obj.getClass() == Integer.class) {
            return (Integer)obj;
        }
        else if (obj.getClass() == Long.class) {
            return ((Long)obj).intValue();
        }
        else {
            throw new InvalidDBDataTypeException("Wrong class type object for Integer!");
        }
    }

    private static void initRegisteredEntityTable(SQLiteConnector sqLiteConnector, int authID,
                                                  SymmetricKey databaseKey, String tableConfigFilePath)
            throws ClassNotFoundException, SQLException, IOException, UseOfExpiredKeyException
    {
        JSONParser parser = new JSONParser();

        String authDatabaseDir = "databases/auth" + authID;
        try {
            JSONArray jsonArray = (JSONArray)parser.parse(new FileReader(tableConfigFilePath));

            for (Object objElement : jsonArray) {
                RegisteredEntityTable registeredEntity = new RegisteredEntityTable();
                JSONObject jsonObject =  (JSONObject)objElement;

                registeredEntity.setName((String)jsonObject.get(RegisteredEntityTable.c.Name.name()));
                registeredEntity.setGroup((String)jsonObject.get(RegisteredEntityTable.c.Group.name()));
                registeredEntity.setDistProtocol((String)jsonObject.get(RegisteredEntityTable.c.DistProtocol.name()));
                boolean usePermanentDistKey = (Boolean)jsonObject.get(RegisteredEntityTable.c.UsePermanentDistKey.name());
                registeredEntity.setUsePermanentDistKey(usePermanentDistKey);
                registeredEntity.setMaxSessionKeysPerRequest(
                        convertObjectToInteger(jsonObject.get(RegisteredEntityTable.c.MaxSessionKeysPerRequest.name())));
                String distKeyValidityPeriod = (String)jsonObject.get(RegisteredEntityTable.c.DistKeyValidityPeriod.name());
                registeredEntity.setDistKeyValidityPeriod(distKeyValidityPeriod);
                registeredEntity.setDistCryptoSpec((String)jsonObject.get(RegisteredEntityTable.c.DistCryptoSpec.name()));
                if (usePermanentDistKey) {
                    registeredEntity.setDistKeyVal(loadEncryptDistributionKey(databaseKey,
                            authDatabaseDir + "/" + (String)jsonObject.get("DistCipherKeyFilePath"),
                            authDatabaseDir + "/" + (String)jsonObject.get("DistMacKeyFilePath")));
                    registeredEntity.setDistKeyExpirationTime(new Date().getTime() + DateHelper.parseTimePeriod(distKeyValidityPeriod));
                }
                else {
                    registeredEntity.setPublicKeyCryptoSpec((String)jsonObject.get(RegisteredEntityTable.c.PublicKeyCryptoSpec.name()));
                    registeredEntity.setPublicKeyFile((String)jsonObject.get(RegisteredEntityTable.c.PublKeyFile.name()));
                }
                registeredEntity.setActive((Boolean)jsonObject.get(RegisteredEntityTable.c.Active.name()));
                if (jsonObject.containsKey(RegisteredEntityTable.c.BackupToAuthID.name())) {
                    registeredEntity.setBackupToAuthID(
                            convertObjectToInteger(jsonObject.get(RegisteredEntityTable.c.BackupToAuthID.name())));
                }
                if (jsonObject.containsKey(RegisteredEntityTable.c.BackupFromAuthID.name())) {
                    registeredEntity.setBackupFromAuthID(
                            convertObjectToInteger(jsonObject.get(RegisteredEntityTable.c.BackupFromAuthID.name())));
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
    }

    private static void initCommPolicyTable(SQLiteConnector sqLiteConnector,
                                            String tableConfigFilePath)
            throws ClassNotFoundException, SQLException, IOException
    {
        JSONParser parser = new JSONParser();
        try {
            JSONArray jsonArray = (JSONArray)parser.parse(new FileReader(tableConfigFilePath));

            for (Object objElement : jsonArray) {
                JSONObject jsonObject =  (JSONObject)objElement;
                CommunicationPolicyTable communicationPolicyTable = new CommunicationPolicyTable();

                communicationPolicyTable.setReqGroup((String)jsonObject.get(CommunicationPolicyTable.c.RequestingGroup.name()));
                communicationPolicyTable.setTargetTypeVal((String)jsonObject.get(CommunicationPolicyTable.c.TargetType.name()));
                communicationPolicyTable.setTarget((String)jsonObject.get(CommunicationPolicyTable.c.Target.name()));
                communicationPolicyTable.setMaxNumSessionKeyOwners(
                        convertObjectToInteger(jsonObject.get(CommunicationPolicyTable.c.MaxNumSessionKeyOwners.name())));
                communicationPolicyTable.setSessionCryptoSpec((String)jsonObject.get(CommunicationPolicyTable.c.SessionCryptoSpec.name()));
                communicationPolicyTable.setAbsValidityStr((String)jsonObject.get(CommunicationPolicyTable.c.AbsoluteValidity.name()));
                communicationPolicyTable.setRelValidityStr((String)jsonObject.get(CommunicationPolicyTable.c.RelativeValidity.name()));
                sqLiteConnector.insertRecords(communicationPolicyTable);
            }
        }
        catch (ParseException e) {
            logger.error("ParseException {}", ExceptionToString.convertExceptionToStackTrace(e));
        }
        catch (InvalidDBDataTypeException e) {
            logger.error("InvalidDBDataTypeException {}", ExceptionToString.convertExceptionToStackTrace(e));
        }
    }

    private static void initTrustedAuthTable(SQLiteConnector sqLiteConnector, String tableConfigFilePath)
            throws ClassNotFoundException, SQLException, IOException
    {
        JSONParser parser = new JSONParser();
        try {
            JSONArray jsonArray = (JSONArray)parser.parse(new FileReader(tableConfigFilePath));

            for (Object objElement : jsonArray) {
                JSONObject jsonObject =  (JSONObject)objElement;
                TrustedAuthTable trustedAuth = new TrustedAuthTable();

                trustedAuth.setId(convertObjectToInteger(jsonObject.get(TrustedAuthTable.c.ID.name())));
                trustedAuth.setHost((String)jsonObject.get(TrustedAuthTable.c.Host.name()));
                trustedAuth.setPort(convertObjectToInteger(jsonObject.get(TrustedAuthTable.c.Port.name())));
                trustedAuth.setCertificatePath((String)jsonObject.get(TrustedAuthTable.c.CertificatePath.name()));
                sqLiteConnector.insertRecords(trustedAuth);
            }
        }
        catch (ParseException e) {
            logger.error("ParseException {}", ExceptionToString.convertExceptionToStackTrace(e));
        }
        catch (InvalidDBDataTypeException e) {
            logger.error("InvalidDBDataTypeException {}", ExceptionToString.convertExceptionToStackTrace(e));
        }
    }

    private static Buffer readSymmetricKey(String filePath) throws IOException {
        final int MAX_SYMMETRIC_KEY_SIZE = 64;  // Max symmetric key size: 256 bits
        FileInputStream inStream = new FileInputStream(filePath);
        byte[] byteArray = new byte[MAX_SYMMETRIC_KEY_SIZE];
        int numBytes = inStream.read(byteArray);
        return new Buffer(byteArray, numBytes);
    }

    private static byte[] encryptDataWithDatabaseKey(SymmetricKey databaseKey, byte[] data)
            throws UseOfExpiredKeyException {
        return databaseKey.encryptAuthenticate(new Buffer(data)).getRawBytes();
    }

    private static byte[] loadEncryptDistributionKey(SymmetricKey databaseKey,
                                                     String cipherKeyPath,
                                                     String macKeyPath) throws IOException, UseOfExpiredKeyException {
        Buffer rawCipherKeyVal = readSymmetricKey(cipherKeyPath);
        Buffer rawMackeyVal = readSymmetricKey(macKeyPath);
        Buffer serializedKeyVal = SymmetricKey.getSerializedKeyVal(rawCipherKeyVal, rawMackeyVal);
        return encryptDataWithDatabaseKey(databaseKey, serializedKeyVal.getRawBytes());
    }

    private static final Logger logger = LoggerFactory.getLogger(GenerateExampleAuthDB.class);
}
