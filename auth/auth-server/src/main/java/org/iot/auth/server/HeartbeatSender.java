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
import org.iot.auth.db.TrustedAuth;
import org.iot.auth.message.AuthHeartbeatReqMessage;
import org.iot.auth.util.ExceptionToString;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.concurrent.*;

/**
 * Class for creating threads that send heartbeat requests to other trusted Auths
 * @author Hokeun Kim
 */
public class HeartbeatSender {
    private final int[] trustedAuthIDs;
    private AuthServer server;
    private final ScheduledExecutorService scheduler;
    private static final Logger logger = LoggerFactory.getLogger(HeartbeatSender.class);

    public HeartbeatSender(AuthServer server, int[] trustedAuthIDs) {
        this.server = server;
        this.trustedAuthIDs = trustedAuthIDs;
        scheduler = Executors.newScheduledThreadPool(trustedAuthIDs.length);
    }
    public void start() {
        for (int i = 0; i < trustedAuthIDs.length; i++) {
            TrustedAuth trustedAuth = server.getTrustedAuthInfo(trustedAuthIDs[i]);
            final Runnable beeper = new Runnable() {
                private int failureCount = 0;
                public void run() {
                    AuthHeartbeatReqMessage heartbeatReqMessage = new AuthHeartbeatReqMessage();
                    try {
                        ContentResponse response = server.performPostRequestToTrustedAuth(trustedAuth.getID(), heartbeatReqMessage);
                        failureCount = 0;
                        logger.info(trustedAuth.getID() + " is up!" +
                                " Failure Count: " + failureCount);
                        //        " Response content: " + response.getContentAsString());
                    } catch (TimeoutException | ExecutionException | InterruptedException e) {
                        failureCount++;
                        logger.info(trustedAuth.getID() + " is down..." +
                                " Failure Count: " + failureCount +
                                " The reason is: " + e.getLocalizedMessage()
                        );
                    }
                }
            };
            final int currentHeartbeatPeriod = trustedAuth.getHeartbeatPeriod();
            if (currentHeartbeatPeriod <= 0) {
                logger.info("Not scheduling heartbeat to Auth" + trustedAuth.getID() +
                        " since the period is set.");
                continue;
            }
            logger.info("scheduling a task of sending heartbeat to Auth" + trustedAuth.getID() +
                    " every " + currentHeartbeatPeriod + "second(s).");
            final ScheduledFuture<?> beeperHandle =
                    scheduler.scheduleWithFixedDelay(beeper, currentHeartbeatPeriod, currentHeartbeatPeriod, TimeUnit.SECONDS);
            // use the following code to remove the handler
                /*
                scheduler.schedule(new Runnable() {
                    public void run() { beeperHandle.cancel(true); }
                }, 1000*10, TimeUnit.MILLISECONDS);
                */
        }
    }
}