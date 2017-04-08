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

import org.iot.auth.AuthServer;
import org.iot.auth.crypto.AuthCrypto;
import org.iot.auth.io.Buffer;
import org.iot.auth.message.AuthHelloMessage;
import org.iot.auth.util.ExceptionToString;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.InputStream;
import java.net.Socket;
import java.util.Date;

/**
 * A handler class for TCP connections from each entity that requests Auth service (e.g., session key requests)
 * @author Hokeun Kim
 */
public class EntityTcpConnectionHandler extends EntityConnectionHandler implements Runnable {
    /**
     * Constructor for the entity connection handler, to process a connected entity
     * @param server Auth server that this handler is for
     * @param entitySocket TCP socket of the connection with the entity
     * @param timeout A timeout for the connection with the entity
     */
    public EntityTcpConnectionHandler(AuthServer server, Socket entitySocket, long timeout) {
        super(server);
        this.socket = entitySocket;
        this.timeOut = timeout;
    }

    /**
     * Run method from the parent class, Thread
     */
    public void run() {
        try {
            Buffer authNonce = AuthCrypto.getRandomBytes(AuthHelloMessage.AUTH_NONCE_SIZE);
            sendAuthHello(authNonce);

            long waitStartedTime = new Date().getTime();

            while (!socket.isClosed()) {
                InputStream is = socket.getInputStream();
                int availableLength = is.available();
                if (availableLength > 0) {
                    byte[] buf = new byte[availableLength];
                    int length = is.read(buf);

                    getLogger().debug("Received bytes ({}): {}", length, Buffer.toHexString(buf, 0, length));

                    // Process session key request
                    handleEntityReq(buf, authNonce);
                    close();
                    return;
                }

                long currentTime = new Date().getTime();
                long elapsedTime = currentTime - waitStartedTime;
                if (timeOut < elapsedTime) {
                    getLogger().info("Timed out at " + new Date(currentTime) +
                            ", elapsed: " + elapsedTime +
                            ", started at " +  new Date(waitStartedTime));
                    close();
                    return;
                }
            }
        }
        catch (Exception e) {
            getLogger().error("Exception occurred while handling Auth service!\n {}",
                    ExceptionToString.convertExceptionToStackTrace(e));
            close();
            return;
        }
        close();
    }
    /**
     * Close TCP connection with the entity.
     */
    protected void close() {
        try {
            if (!socket.isClosed()) {
                getLogger().info("Closing connection with socket at {}", getRemoteAddress());
                socket.close();
            }
        }
        catch (IOException e) {
            getLogger().error("Exception occurred while closing socket!\n {}",
                    ExceptionToString.convertExceptionToStackTrace(e));
        }
    }

    protected Logger getLogger() {
        return logger;
    }

    protected String getRemoteAddress() {
        return socket.getRemoteSocketAddress().toString();
    }

    protected void writeToSocket(byte[] bytes) throws IOException {
        socket.getOutputStream().write(bytes);
    }

    private static final Logger logger = LoggerFactory.getLogger(EntityTcpConnectionHandler.class);
    private Socket socket;
    private long timeOut;
}
