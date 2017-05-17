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
import org.iot.auth.AuthServer;
import org.iot.auth.exception.InvalidNonceException;
import org.iot.auth.message.AuthBackupReqMessage;
import org.iot.auth.message.AuthHeartbeatReqMessage;
import org.iot.auth.message.AuthHeartbeatRespMessage;
import org.iot.auth.util.ExceptionToString;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.http.HttpServletResponse;
import java.util.LinkedList;
import java.util.List;
import java.util.concurrent.*;

/**
 * Class for creating threads that send heartbeat requests to other trusted Auths
 * @author Hokeun Kim
 */
public class BackupRequester {
    private AuthServer server;
    private final ScheduledExecutorService scheduler;
    private static final Logger logger = LoggerFactory.getLogger(BackupRequester.class);
    private int backupRequestingPeriod = 2;

    public BackupRequester(AuthServer server) {
        this.server = server;
        scheduler = Executors.newScheduledThreadPool(1);
    }
    public void start() {
        List<AuthBackupReqMessage> backupReqMessages = server.getBackupReqMessages();
        final Runnable requester = new Runnable() {
            private int failureCount = 0;
            private boolean isTrustedAuthAlive = false;
            public void run() {
                try {
                    for (AuthBackupReqMessage backupReqMessage: backupReqMessages) {
                        ContentResponse contentResponse = server.sendBackupReqMessage(backupReqMessage);
                        logger.info("Response code: " + contentResponse.getStatus());
                        if (contentResponse.getStatus() == HttpServletResponse.SC_OK) {
                            logger.info("The request was successfully handled by the trusted Auth, removing the request");
                            backupReqMessages.remove(backupReqMessage);
                        }
                    }
                } catch (TimeoutException | ExecutionException | InterruptedException e) {
                    logger.error("Exception occurred during backup() {}", e.getMessage());
                    //throw new RuntimeException();
                }
                finally {
                    if (!backupReqMessages.isEmpty()) {
                        scheduler.schedule(this, backupRequestingPeriod, TimeUnit.SECONDS);
                    }
                }
            }
        };
        if (backupRequestingPeriod <= 0) {
            logger.info("Not scheduling backup requester since the period is not set.");
            return;
        }
        logger.info("scheduling a task of sending backup requests every " + backupRequestingPeriod + "second(s).");
        final ScheduledFuture<?> beeperHandle =
                scheduler.schedule(requester, backupRequestingPeriod, TimeUnit.SECONDS);
    }
}
