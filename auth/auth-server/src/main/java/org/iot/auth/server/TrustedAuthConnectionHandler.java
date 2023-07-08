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

import org.eclipse.jetty.server.Request;
import org.eclipse.jetty.server.handler.AbstractHandler;
import org.iot.auth.AuthServer;
import org.iot.auth.db.CommunicationTargetType;
import org.iot.auth.db.RegisteredEntity;
import org.iot.auth.crypto.SessionKey;
import org.iot.auth.db.SessionKeyPurpose;
import org.iot.auth.db.TrustedAuth;
import org.iot.auth.message.*;
import org.iot.auth.util.ExceptionToString;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;

/**
 * A handler class for connections from other trusted Auths
 * @author Hokeun Kim
 */
public class TrustedAuthConnectionHandler extends AbstractHandler {

    /**
     * Constructor for the trusted connection handler
     * @param server Auth server that this handler works for
     */
    public TrustedAuthConnectionHandler(AuthServer server) {
        this.server = server;
    }


    /**
     * This method implements the handle method of AbstractHandler interface, for handling a HTTP request.
     * @param target The target of HTTP request (url or name), NOT used in this handler.
     * @param baseRequest The original unwrapped request object, mainly used in this handler.
     * @param request Request of the wrapper, only used for getting the certificate of the requester (a trusted Auth) in
     *                this handler.
     * @param response The response to be sent to the requester (trusted Auth).
     * @throws IOException If any IO fails.
     * @throws ServletException If the serverlet fails.
     */
    public void handle( String target, Request baseRequest, HttpServletRequest request,
                        HttpServletResponse response) throws IOException, ServletException
    {
        logger.debug("Received request from Trusted Auth at: {}:{}",
                baseRequest.getRemoteHost(), baseRequest.getRemotePort());

        X509Certificate[] certs = (X509Certificate[])request.getAttribute("javax.servlet.request.X509Certificate");
        int requestingAuthID = server.getTrustedAuthIDByCertificate(certs[0]);

        // TODO: Check client (trusted Auth) identity before sending response
        TrustedAuth requestingAuthInfo = server.getTrustedAuthInfo(requestingAuthID);

        if (requestingAuthInfo == null) {
            throw new RuntimeException("Unrecognized Auth, Alias: " + requestingAuthID);
        }

        logger.debug("Information of Trusted Auth which sent the request: " + requestingAuthInfo.toBriefString());

        String authReqType = baseRequest.getParameter(TrustedAuthReqMessasge.TYPE);
        if (authReqType.equals(TrustedAuthReqMessasge.type.AUTH_SESSION_KEY_REQ.name())) {
            logger.info("Received " + authReqType + " from Auth"
                            + requestingAuthInfo.getID() + " at " + baseRequest.getRemoteHost() + ":" + baseRequest.getRemotePort());
            handleAuthSessionKeyReq(baseRequest, response);
            logger.info("The request {} was successfully handled!", authReqType);
        }
        else if(authReqType.equals(TrustedAuthReqMessasge.type.BACKUP_REQ.name())) {
            logger.info("Received " + authReqType + " from Auth"
                    + requestingAuthInfo.getID() + " at " + baseRequest.getRemoteHost() + ":" + baseRequest.getRemotePort());
            try {
                handleBackupReq(requestingAuthInfo, baseRequest, response);
                logger.info("The request {} was successfully handled!", authReqType);
            } catch (Exception e) {
                logger.error("Exception while handling Auth backup request\n{}",
                        ExceptionToString.convertExceptionToStackTrace(e));
                throw new RuntimeException("Exception while handling Auth backup request\n"
                        + ExceptionToString.convertExceptionToStackTrace(e));
            }
        }
        else if(authReqType.equals(TrustedAuthReqMessasge.type.HEARTBEAT_REQ.name())) {
            // to keep heartbeat req silent
            logger.debug("Received " + authReqType + " from Auth"
                    + requestingAuthInfo.getID() + " at " + baseRequest.getRemoteHost() + ":" + baseRequest.getRemotePort());
            try {
                AuthHeartbeatReqMessage heartbeatReqMessage = AuthHeartbeatReqMessage.fromHttpRequest(baseRequest);
                AuthHeartbeatRespMessage.fromAuthHeartbeatReq(heartbeatReqMessage).sendAsHttpResponse(response);
                baseRequest.setHandled(true);
            } catch (InvalidKeySpecException e) {
                e.printStackTrace();
            } catch (NoSuchAlgorithmException e) {
                e.printStackTrace();
            }
        }
        else {
            logger.info("Unknown request! " + authReqType);

        }
    }

    private void handleAuthSessionKeyReq(Request baseRequest, HttpServletResponse response) throws IOException {
        AuthSessionKeyReqMessage authSessionKeyReqMessage = AuthSessionKeyReqMessage.fromHttpRequest(baseRequest);
        logger.info("Received AuthSessionKeyReqMessage: {}", authSessionKeyReqMessage.toString());

        List<SessionKey> sessionKeyList = null;
        if (authSessionKeyReqMessage.getCachedKeyAuthID() > 0) {
            if (server.getAuthID() != authSessionKeyReqMessage.getCachedKeyAuthID()) {
                throw new RuntimeException("Auth ID is not my ID!");
            }
            SessionKeyPurpose purpose = new SessionKeyPurpose(CommunicationTargetType.TARGET_GROUP, authSessionKeyReqMessage.getRequestingEntityGroup());
            try {
                sessionKeyList = server.getSessionKeysByPurpose(authSessionKeyReqMessage.getRequestingEntityName(), purpose);
            } catch (SQLException | ClassNotFoundException e) {
                logger.error("SQLException | ClassNotFoundException {}", ExceptionToString.convertExceptionToStackTrace(e));
                throw new RuntimeException("Exception occurred while finding cached session keys.");
            }
            try {
                for (SessionKey sessionKey : sessionKeyList) {
                    server.addSessionKeyOwner(sessionKey.getID(), authSessionKeyReqMessage.getRequestingEntityName());
                }
            } catch (SQLException | ClassNotFoundException e) {
                logger.error("SQLException | ClassNotFoundException {}", ExceptionToString.convertExceptionToStackTrace(e));
                throw new RuntimeException("Exception occurred while adding session key owner for cached session keys.");
            }
        }
        else {
            SessionKey sessionKey;
            try {
                sessionKey = server.getSessionKeyByID(authSessionKeyReqMessage.getSessionKeyID());
            } catch (SQLException | ClassNotFoundException e) {
                logger.error("SQLException | ClassNotFoundException {}", ExceptionToString.convertExceptionToStackTrace(e));
                throw new RuntimeException("Session key for ID " + authSessionKeyReqMessage.getSessionKeyID() + " cannot be found!");
            }
            if (!CommunicationPolicyChecker.checkSessionKeyCommunicationPolicy(server,
                    authSessionKeyReqMessage.getRequestingEntityGroup(),
                    authSessionKeyReqMessage.getRequestingEntityName(), sessionKey)) {
                throw new RuntimeException("Session key communication policy check failed.");
            }

            try {
                server.addSessionKeyOwner(authSessionKeyReqMessage.getSessionKeyID(), authSessionKeyReqMessage.getRequestingEntityName());
            } catch (SQLException | ClassNotFoundException e) {
                logger.error("SQLException | ClassNotFoundException {}", ExceptionToString.convertExceptionToStackTrace(e));
                throw new RuntimeException("Exception occurred while adding session key owner.");
            }
            // TODO: Check group requirement
            sessionKeyList = new ArrayList<>();
            sessionKeyList.add(sessionKey);
        }

        AuthSessionKeyRespMessage authSessionKeyRespMessage = new AuthSessionKeyRespMessage(sessionKeyList);
        authSessionKeyRespMessage.sendAsHttpResponse(response);

        // Inform jetty that this request has now been handled
        baseRequest.setHandled(true);
    }

    private void handleBackupReq(TrustedAuth requestingAuthInfo, Request baseRequest, HttpServletResponse response)
            throws InvalidKeySpecException, NoSuchAlgorithmException, IOException, ClassNotFoundException,
            SQLException, CertificateEncodingException
    {
        AuthBackupReqMessage authBackupReqMessage = AuthBackupReqMessage.fromHttpRequest(baseRequest);
        List<RegisteredEntity> registeredEntities = authBackupReqMessage.getRegisteredEntityList();
        for (RegisteredEntity registeredEntity: registeredEntities) {
            registeredEntity.setActive(false);
            registeredEntity.setBackupToAuthIDs(new int[0]);
            registeredEntity.setBackupFromAuthID(requestingAuthInfo.getID());
        }
        // insert!
        server.updateBackupCertificate(requestingAuthInfo.getID(), authBackupReqMessage.getBackupCertificate());
        server.insertRegisteredEntitiesOrUpdateIfExist(authBackupReqMessage.getRegisteredEntityList());
        server.reloadRegEntityDB();

        AuthBackupRespMessage backupRespMessage = new AuthBackupRespMessage();
        backupRespMessage.sendAsHttpResponse(response);
        baseRequest.setHandled(true);
    }

    private AuthServer server;
    private static final Logger logger = LoggerFactory.getLogger(TrustedAuthConnectionHandler.class);
}
