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
import org.iot.auth.util.ExceptionToString;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

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
                "backup             : Backup registered entities to a trusted Auth";
    }
    private AuthServer server;
    private static final Logger logger = LoggerFactory.getLogger(AuthCommandLine.class);
}
