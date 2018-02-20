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

package org.iot.auth;
import org.iot.auth.crypto.AuthCrypto;
import org.iot.auth.db.CommunicationPolicy;
import org.iot.auth.db.CommunicationTargetType;
import org.iot.auth.db.RegisteredEntity;
import org.iot.auth.db.bean.CommunicationPolicyTable;
import org.iot.auth.db.bean.RegisteredEntityTable;
import org.iot.auth.util.ExceptionToString;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.sql.SQLException;
import java.util.List;

/**
 * A thread for processing command line interface.
 * @author Hokeun Kim
 */
public class AuthCommandLine extends Thread  {
    /**
     * Constructor for AuthCommandLine object
     * @param server Auth server object that this command line object works for
     */
    public AuthCommandLine(AuthServer server) {
        this.server = server;
    }

    public void run() {
        Runtime.getRuntime().addShutdownHook(new Thread() {
            public void run() {
                try {
                    server.end();
                    logger.info("Shutting down Auth " + server.getAuthID() + " ...");
                    //some cleaning up code...

                } catch (SQLException | IOException | InterruptedException e) {
                    // TODO Auto-generated catch block
                    e.printStackTrace();
                }
            }
        });
        BufferedReader br = new BufferedReader(new InputStreamReader(System.in));
        for (;;) {
            try {
                logger.info("\nEnter command (e.g., help, show re/cp/ta/sk/maps, clean sk, reset re/sk, issue cert [ic], backup ): ");
                String command = br.readLine();
                if (command == null) {
                    break;
                }
                command = command.trim();
                if (command.length() == 0) {
                    continue;
                }
                if (command.equals("help")) {
                    logger.info(getHelp());
                }
                else if (command.equals("show re")) {
                    logger.info("\nShow registered entities command\n{}", server.registeredEntitiesToString());
                }
                else if (command.equals("show cp")) {
                    logger.info("\nShow communication policies command\n{}", server.communicationPoliciesToString());
                }
                else if (command.equals("show ta")) {
                    logger.info("\nShow trusted Auths command\n{}", server.trustedAuthsToString());
                }
                else if (command.equals("show sk")) {
                    // show sk (show session keys)
                    try {
                        logger.info("\nShow session keys command\n{}", server.sessionKeysToString());
                    }
                    catch (SQLException | ClassNotFoundException e) {
                        logger.error("SQLException | ClassNotFoundException {}", ExceptionToString.convertExceptionToStackTrace(e));
                        throw new RuntimeException("Exception occurred while loading session keys!");
                    }
                }
                else if (command.equals("show maps")) {
                    logger.info("\nShow maps for UDP listener port command\n{}", server.showAllUdpPortListenerMaps());
                }
                else if (command.equals("clean sk")) {
                    logger.info("\nClean expired session keys command\n");
                    try {
                        server.cleanExpiredSessionKeys();
                    }
                    catch (SQLException | ClassNotFoundException e) {
                        logger.error("SQLException | ClassNotFoundException {}", ExceptionToString.convertExceptionToStackTrace(e));
                        throw new RuntimeException("Exception occurred while cleaning session keys!");
                    }
                }
                else if (command.equals("reset sk")) {
                    logger.info("\nReset cached session key table (Delete all session keys) command\n");
                    try {
                        server.deleteAllSessionKeys();
                    }
                    catch (SQLException | ClassNotFoundException e) {
                        logger.error("SQLException | ClassNotFoundException {}", ExceptionToString.convertExceptionToStackTrace(e));
                        throw new RuntimeException("Exception occurred while deleting all session keys!");
                    }
                }
                else if (command.equals("reset re")) {
                    logger.info("\nReset registered entities (delete all entities backed up from other Auths)\n");
                    try {
                        server.deleteBackedUpRegisteredEntities();
                        server.reloadRegEntityDB();
                    }
                    catch (SQLException | ClassNotFoundException e) {
                        logger.error("SQLException {}", ExceptionToString.convertExceptionToStackTrace(e));
                        throw new RuntimeException("Exception occurred while deleting all session keys!");
                    }
                }
                else if (command.equals("issue cert") || command.equals("ic")) {
                    logger.info("\nIssue certificate command\n");
                    List<X509Certificate> backupCertificates = server.issueBackupCertificate();
                    for (X509Certificate backupCertificate: backupCertificates) {
                        logger.info(backupCertificate.toString());
                    }
                }
                else if (command.equals("backup")) {
                    logger.info("\nBackup command\n");
                    server.backup();
                }
                else if (command.equals("add re")) {
                    logger.info("\n Add new registered entity command");
                    RegisteredEntity newRegisteredEntity = getRegisteredEntityInformation(br);
                    if (newRegisteredEntity == null) {
                        logger.info("\n Information of new registered entity was not entered correctly.");
                        continue;
                    }
                    logger.info("Entered new entity information");
                    logger.info(newRegisteredEntity.toString());
                    if (server.addRegisteredEntity(newRegisteredEntity)) {
                        logger.info("New registered entity has been added successfully.");
                    }
                    else {
                        logger.error("New registered entity has NOT been added due to errors.");
                    }
                }
                else if (command.equals("remove re")) {
                    logger.info("\n Remove existing registered entity command");
                    logger.info("\nEnter registered entity name:");
                    String entityName = br.readLine();
                    if (entityName.isEmpty()) {
                        logger.info("\n Name of the registered entity to be removed was not entered correctly.");
                    }
                    if (server.removeRegisteredEntity(entityName)) {
                        logger.info("Existing registered entity has been removed successfully.");
                    }
                    else {
                        logger.error("Existing registered entity has NOT been removed due to errors.");
                    }
                }
                else if (command.equals("add cp")) {
                    logger.info("\n Add new communication policy command");
                    CommunicationPolicyTable newCommunicationPolicy = getCommunicationPolicyInformation(br);
                    if (newCommunicationPolicy == null) {
                        logger.info("\n Information of new communication policy was not entered correctly.");
                        continue;
                    }
                    logger.info("Entered new entity information");
                    logger.info(newCommunicationPolicy.toString());
                    if (server.addCommunicationPolicy(newCommunicationPolicy)) {
                        logger.info("New communication policy has been added successfully.");
                    }
                    else {
                        logger.error("New communication policy has NOT been added due to errors.");
                    }
                }
                else {
                    logger.info("Unrecognized command: {}", command);
                }
            }
            catch (Exception e) {
                logger.error("Exception {}", ExceptionToString.convertExceptionToStackTrace(e));
            }
        }
    }

    private String getHelp() {
        return "\n" +
                "show re            : Show registered entities\n" +
                "show cp            : Show communication policies\n" +
                "show ta            : Show trusted Auths\n" +
                "show maps          : Show maps for UDP listener port\n" +
                "clean sk           : Clean expired session keys\n" +
                "reset sk           : Reset cached session key table (Delete all session keys)\n" +
                "reset re           : Reset registered entities (delete all entities backed up from other Auths)\n" +
                "issue cert [or ic] : Issue certificate\n" +
                "backup             : Backup registered entities to a trusted Auth\n" +
                "add re             : Add new registered entity\n" +
                "remove re          : Remove registered entity\n" +
                "add cp             : Add new communication policy\n" +
                "remove cp          : Remove communication policy\n";
    }

    private RegisteredEntity getRegisteredEntityInformation(BufferedReader br) throws IOException {
        logger.info("\nEnter registered entity name:");
            String entityName = br.readLine();
            if (entityName.isEmpty()) {
                return null;
        }
        logger.info("\nEnter registered entity group:");
        String group = br.readLine();
        if (group.isEmpty()) {
            return null;
        }

        logger.info("\nEnter registered entity distribution protocol [Default: TCP]:");
        String distributionProtocol = br.readLine();
        if (distributionProtocol.isEmpty()) {
            distributionProtocol = "TCP";
        }

        logger.info("\nWill new entity use permanent distribution key (y/n)?: [Default: n]");
        String usePermanentDistributionKeyString = br.readLine();
        boolean usePermanentDistributionKey = false;
        if (!usePermanentDistributionKeyString.isEmpty()) {
            if (usePermanentDistributionKeyString.equalsIgnoreCase("y")) {
                usePermanentDistributionKey = true;
            }
        }

        logger.info("\nEnter registered entity max session keys per request [Default: 1]:");
        String maxSessionKeysPerRequestString = br.readLine();
        if (maxSessionKeysPerRequestString.isEmpty()) {
            maxSessionKeysPerRequestString = "1";
        }
        int maxSessionKeysPerRequest = Integer.parseInt(maxSessionKeysPerRequestString);

        PublicKey publicKey = null;
        String publicKeyCryptoSpec = null;
        if (!usePermanentDistributionKey) {
            logger.info("\nEnter registered entity's public key path:");
            String publicKeyPath = br.readLine();
            publicKey = AuthCrypto.loadPublicKeyFromFile(publicKeyPath);

            logger.info("\nEnter registered entity's public key crypto spec [Default: RSA-SHA256]:");
            publicKeyCryptoSpec = br.readLine();
            if (publicKeyCryptoSpec.isEmpty()) {
                publicKeyCryptoSpec = "RSA-SHA256";
            }
        }

        logger.info("\nEnter registered entity distribution key crypto spec [Default: AES-128-CBC:SHA256]:");
        String distributionCryptoSpec = br.readLine();
        if (distributionCryptoSpec.isEmpty()) {
            distributionCryptoSpec = "AES-128-CBC:SHA256";
        }

        logger.info("\nEnter registered entity distribution key validity period [Default: 1*day] (use day, hour, min, sec):");
        String distributionKeyValidityPeriod = br.readLine();
        if (distributionKeyValidityPeriod.isEmpty()) {
            distributionKeyValidityPeriod = "1*day";
        }

        RegisteredEntityTable registeredEntityTable = new RegisteredEntityTable().setName(entityName)
                .setGroup(group)
                .setDistProtocol(distributionProtocol)
                .setUsePermanentDistKey(usePermanentDistributionKey)
                .setMaxSessionKeysPerRequest(maxSessionKeysPerRequest)
                .setPublicKey(publicKey)
                .setPublicKeyCryptoSpec(publicKeyCryptoSpec)
                .setDistCryptoSpec(distributionCryptoSpec)
                .setDistKeyValidityPeriod(distributionKeyValidityPeriod)
                .setActive(true);

        return new RegisteredEntity(registeredEntityTable, null);
    }

    private CommunicationPolicyTable getCommunicationPolicyInformation(BufferedReader br) throws IOException {
        logger.info("\nEnter requesting group:");
        String requestingGroup = br.readLine();
        if (requestingGroup.isEmpty()) {
            return null;
        }

        logger.info("\nEnter target (target group or target topic):");
        String target = br.readLine();
        if (target.isEmpty()) {
            return null;
        }

        logger.info("\nEnter target type [Default: Group] (other options: PubTopic, SubTopic):");
        String targetType = br.readLine();
        if (targetType.isEmpty()) {
            targetType = "Group";
        }

        logger.info("\nEnter max number of session key owners [Default: 2] (Must be >= 2:");
        String maxNumSessionKeyOwnersString = br.readLine();
        if (maxNumSessionKeyOwnersString.isEmpty()) {
            maxNumSessionKeyOwnersString = "2";
        }
        int maxNumSessionKeyOwners = Integer.parseInt(maxNumSessionKeyOwnersString);

        logger.info("\nEnter session crypto spec [Default: AES-128-CBC:SHA256]:");
        String sessionCryptoSpec = br.readLine();
        if (sessionCryptoSpec.isEmpty()) {
            sessionCryptoSpec = "AES-128-CBC:SHA256";
        }

        logger.info("\nEnter absolute validity period of session keys [Default: 1*day] (use day, hour, min, sec):");
        String absoluteValidityString = br.readLine();
        if (absoluteValidityString.isEmpty()) {
            absoluteValidityString = "1*day";
        }


        logger.info("\nEnter absolute validity period of session keys [Default: 1*hour] (use day, hour, min, sec):");
        String relativeValidityString = br.readLine();
        if (relativeValidityString.isEmpty()) {
            relativeValidityString = "1*hour";
        }

        return new CommunicationPolicyTable().setReqGroup(requestingGroup)
                .setTarget(target)
                .setTargetTypeVal(targetType)
                .setTargetType(CommunicationTargetType.fromStringValue(targetType))
                .setMaxNumSessionKeyOwners(maxNumSessionKeyOwners)
                .setSessionCryptoSpec(sessionCryptoSpec)
                .setAbsValidityStr(absoluteValidityString)
                .setRelValidityStr(relativeValidityString);
    }

    private AuthServer server;
    private static final Logger logger = LoggerFactory.getLogger(AuthCommandLine.class);
}
