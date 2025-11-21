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
import org.iot.auth.db.AuthDBProtectionMethod;
import org.iot.auth.db.bean.CommunicationPolicyTable;
import org.iot.auth.db.bean.MetaDataTable;
import org.iot.auth.db.bean.RegisteredEntityTable;
import org.iot.auth.db.bean.TrustedAuthTable;
import org.iot.auth.db.bean.FileSharingTable;
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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.security.PublicKey;
import java.security.cert.CertificateEncodingException;
import java.sql.SQLException;
import java.util.Date;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.Options;

/**
 * A program to generate example Auth databases for example Auths starting from ID 101
 * The number of Auths is specified as an argument.
 * @author Hokeun Kim
 */
public class GenerateExampleAuthDB {
    public static void main(String[] args) throws Exception {
        // parsing command line arguments
        Options options = new Options();

        Option option = new Option("i", "auth_id", true, "ID of Auth to be generated.");
        option.setRequired(true);
        options.addOption(option);
        option = new Option("d", "auth_db_protection_method", true, "protection method for Auth DB.");
        option.setRequired(true);
        options.addOption(option);

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
        int authID = Integer.parseInt(cmd.getOptionValue("auth_id"));
        AuthDBProtectionMethod authDBProtectionMethod = AuthDBProtectionMethod.fromValue(
                Integer.parseInt(cmd.getOptionValue("auth_db_protection_method")));

        logger.info("ID of Auths to be generated: {}", authID);
        logger.info("Specified protection method for Auth DB: {}", authDBProtectionMethod.name());

        generateAuthDatabase(authID, authDBProtectionMethod);
    }

    private static void generateAuthDatabase(int authID, AuthDBProtectionMethod authDBProtectionMethod) throws Exception {
        String authDatabaseDir = "databases/auth" + authID + "/";
        // TODO: These paths must be given rather than hard-coded?
        String databasePublicKeyPath = authDatabaseDir + "my_certs/Auth" + authID + "DatabaseCert.pem";
        String databaseEncryptionKeyPath = authDatabaseDir + "my_keystores/Auth" + authID + "Database.bin";

        SQLiteConnector sqLiteConnector = new SQLiteConnector(authDatabaseDir + "auth.db", authDBProtectionMethod);
        SymmetricKey databaseKey = new SymmetricKey(
                SQLiteConnector.AUTH_DB_CRYPTO_SPEC,
                new Date().getTime() + DateHelper.parseTimePeriod(SQLiteConnector.AUTH_DB_KEY_ABSOLUTE_VALIDITY)
            );
        sqLiteConnector.initialize(databaseKey);
        sqLiteConnector.createTablesIfNotExists();

        initMetaDataTable(sqLiteConnector, databasePublicKeyPath, databaseKey, databaseEncryptionKeyPath);
        initRegisteredEntityTable(sqLiteConnector, authID,
                authDatabaseDir + "configs/Auth" + authID + "RegisteredEntityTable.config");
        initCommPolicyTable(sqLiteConnector,
                authDatabaseDir + "configs/Auth" + authID + "CommunicationPolicyTable.config");
        initTrustedAuthTable(sqLiteConnector, authDatabaseDir,
                authDatabaseDir + "configs/Auth" + authID + "TrustedAuthTable.config");
        initFileSharingInfoTable(sqLiteConnector, 
                authDatabaseDir + "configs/Auth" + authID + "FileSharingInfoTable.config");
        sqLiteConnector.close();
    }

    private static void initMetaDataTable(SQLiteConnector sqLiteConnector,
                                          String databasePublicKeyPath, SymmetricKey databaseKey, String databaseEncryptionKeyPath)
            throws ClassNotFoundException, SQLException, IOException
    {
        MetaDataTable metaData;

        metaData = new MetaDataTable();
        metaData.setKey(MetaDataTable.key.SessionKeyCount.name());
        metaData.setValue(Long.toString(0));
        sqLiteConnector.insertRecords(metaData);

        PublicKey databasePublicKey = AuthCrypto.loadPublicKeyFromFile(databasePublicKeyPath);
        Buffer encryptedDatabaseKey = AuthCrypto.publicEncrypt(databaseKey.getSerializedKeyVal(), databasePublicKey,
                SQLiteConnector.AUTH_DB_PUBLIC_CIPHER);

        FileOutputStream fileOutputStream = new FileOutputStream(databaseEncryptionKeyPath);
        fileOutputStream.write(encryptedDatabaseKey.getRawBytes());
        fileOutputStream.close();
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

    private static String convertJSONArrayToString(JSONArray jsonArray) throws InvalidDBDataTypeException {
        String ret = "";
        for (int i = 0; i < jsonArray.size(); i++) {
            if (i != 0) {
                ret += ",";
            }
            Object obj = jsonArray.get(i);
            if (obj.getClass() == Integer.class) {
                ret += (Integer)obj;
            }
            else if (obj.getClass() == Long.class) {
                ret += (Long)obj;
            }
            else {
                throw new InvalidDBDataTypeException("Wrong class type object for Integer!");
            }
        }
        return ret;
    }

    private static void initRegisteredEntityTable(SQLiteConnector sqLiteConnector, int authID,
                                                  String tableConfigFilePath)
            throws ClassNotFoundException, SQLException, IOException, UseOfExpiredKeyException
    {
        JSONParser parser = new JSONParser();

        String authDatabaseDir = "databases/auth" + authID;
        try {
            JSONArray jsonArray = (JSONArray)parser.parse(new FileReader(tableConfigFilePath));

            for (Object objElement : jsonArray) {
                RegisteredEntityTable registeredEntity = new RegisteredEntityTable();
                JSONObject jsonObject;
                jsonObject = (JSONObject)objElement;

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
                    registeredEntity.setDistKeyVal(loadDistributionKey(
                            authDatabaseDir + "/" + jsonObject.get("DistCipherKeyFilePath"),
                            authDatabaseDir + "/" + jsonObject.get("DistMacKeyFilePath")));
                    registeredEntity.setDistKeyExpirationTime(new Date().getTime() + DateHelper.parseTimePeriod(distKeyValidityPeriod));
                }
                else {
                    registeredEntity.setPublicKeyCryptoSpec((String)jsonObject.get(RegisteredEntityTable.c.PublicKeyCryptoSpec.name()));
                    registeredEntity.setPublicKey(AuthCrypto.loadPublicKeyFromFile(
                            authDatabaseDir + "/" + jsonObject.get(RegisteredEntityTable.c.PublicKeyFile.name())));
                }
                registeredEntity.setActive((Boolean)jsonObject.get(RegisteredEntityTable.c.Active.name()));
                if (jsonObject.containsKey(RegisteredEntityTable.c.BackupToAuthIDs.name())) {
                    registeredEntity.setBackupToAuthIDs(
                            convertJSONArrayToString((JSONArray)jsonObject.get(RegisteredEntityTable.c.BackupToAuthIDs.name())));
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

    private static void initFileSharingInfoTable(SQLiteConnector sqLiteConnector,
                                            String tableConfigFilePath)
            throws ClassNotFoundException, SQLException, IOException
    {
        JSONParser parser = new JSONParser();
        try {
            JSONArray jsonArray = (JSONArray)parser.parse(new FileReader(tableConfigFilePath));

            for (Object objElement : jsonArray) {
                JSONObject jsonObject =  (JSONObject)objElement;
                FileSharingTable FileSharing = new FileSharingTable();
                
                FileSharing.setOwner((String)jsonObject.get(FileSharingTable.c.Owner.name()));
                FileSharing.setReader((String)jsonObject.get(FileSharingTable.c.Reader.name()));
                FileSharing.setReaderType((String)jsonObject.get(FileSharingTable.c.ReaderType.name()));
                sqLiteConnector.insertRecords(FileSharing);
            }
        }
        catch (ParseException e) {
            logger.error("ParseException {}", ExceptionToString.convertExceptionToStackTrace(e));
        }
    }

    private static void initTrustedAuthTable(SQLiteConnector sqLiteConnector, String authDatabaseDir, String tableConfigFilePath)
            throws ClassNotFoundException, SQLException, IOException, CertificateEncodingException {
        JSONParser parser = new JSONParser();
        try {
            JSONArray jsonArray = (JSONArray)parser.parse(new FileReader(tableConfigFilePath));

            for (Object objElement : jsonArray) {
                JSONObject jsonObject =  (JSONObject)objElement;
                TrustedAuthTable trustedAuth = new TrustedAuthTable();

                trustedAuth.setId(convertObjectToInteger(jsonObject.get(TrustedAuthTable.c.ID.name())));
                trustedAuth.setHost((String)jsonObject.get(TrustedAuthTable.c.Host.name()));
                trustedAuth.setEntityHost((String)jsonObject.get(TrustedAuthTable.c.EntityHost.name()));
                trustedAuth.setPort(convertObjectToInteger(jsonObject.get(TrustedAuthTable.c.Port.name())));
                trustedAuth.setHeartbeatPeriod(convertObjectToInteger(jsonObject.get(TrustedAuthTable.c.HeartbeatPeriod.name())));
                trustedAuth.setFailureThreshold(convertObjectToInteger(jsonObject.get(TrustedAuthTable.c.FailureThreshold.name())));
                trustedAuth.setInternetCertificate(
                        AuthCrypto.loadCertificateFromFile(
                        authDatabaseDir + "/" + jsonObject.get(TrustedAuthTable.c.InternetCertificatePath.name())));
                trustedAuth.setEntityCertificate(
                        AuthCrypto.loadCertificateFromFile(
                                authDatabaseDir + "/" + jsonObject.get(TrustedAuthTable.c.EntityCertificatePath.name())));
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

    private static byte[] loadDistributionKey(String cipherKeyPath, String macKeyPath)
            throws IOException, UseOfExpiredKeyException
    {
        Buffer rawCipherKeyVal = readSymmetricKey(cipherKeyPath);
        Buffer rawMackeyVal = readSymmetricKey(macKeyPath);
        Buffer serializedKeyVal = SymmetricKey.getSerializedKeyVal(rawCipherKeyVal, rawMackeyVal);
        return serializedKeyVal.getRawBytes();
    }

    private static final Logger logger = LoggerFactory.getLogger(GenerateExampleAuthDB.class);
}
