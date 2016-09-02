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

import org.apache.commons.cli.*;
import org.eclipse.jetty.client.HttpClient;
import org.eclipse.jetty.client.api.ContentResponse;
import org.eclipse.jetty.server.*;
import org.eclipse.jetty.util.Fields;
import org.eclipse.jetty.util.ssl.SslContextFactory;
import org.iot.auth.config.AuthServerProperties;
import org.iot.auth.db.*;
import org.iot.auth.server.CommunicationTargetType;
import org.iot.auth.server.EntityConnectionHandler;
import org.iot.auth.server.TrustedAuthConnectionHandler;
import org.iot.auth.util.ExceptionToString;
import org.json.simple.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.*;
import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeoutException;

/**
 * A main class for Auth, a local authentication/authorization entity for locally
 * registered entities.
 * @author Hokeun Kim, Salomon Lee
 */
public class AuthServer {
    public static AuthServerProperties PROPERTIES;
    public boolean isRunning() {
        return isRunning;
    }

    public void setRunning(boolean running) {
        this.isRunning = running;
    }

    public AuthServer(AuthServerProperties properties) throws Exception {
        this.db = new AuthDB(properties.getAuthDatabaseDir());

        // TODO: replace this with password input
        String authKeyStorePassword = "asdf";

        db.initialize(authKeyStorePassword);
        logger.info("Finished initializing Auth DB.");

        authID =  properties.getAuthID();

        crypto = new AuthCrypto(properties.getEntityKeyStorePath(), authKeyStorePassword);

        entityPortTimeout = properties.getEntityPortTimeout();

        // suppress default logging by jetty
        org.eclipse.jetty.util.log.Log.setLog(new NoLogging());

        // TODO: get Port for this
        entityPortServerSocket = new ServerSocket(properties.getEntityPort());

        serverForTrustedAuths = initServerForTrustedAuths(properties, authKeyStorePassword);
        clientForTrustedAuths = initClientForTrustedAuths(properties, authKeyStorePassword);

        logger.info("Auth server information. Auth ID: {}, Entity Port: {}, Trusted auth Port: {}, Host name: {}",
                properties.getAuthID(), entityPortServerSocket.getLocalPort(),
                ((ServerConnector) serverForTrustedAuths.getConnectors()[0]).getPort(),
                properties.getHostName());

        setRunning(true);
    }

    public int getAuthID() {
        return authID;
    }

    public AuthCrypto getCrypto() {
        return crypto;
    }

    public RegisteredEntity getRegEntity(String entityName) {
        return db.getRegEntity(entityName);
    }

    public CommunicationPolicy getCommPolicy(String reqGroup, CommunicationTargetType targetType, String target) {
        return db.getCommPolicy(reqGroup, targetType, target);
    }

    public void updateDistributionKey(String entityName, DistributionKey distributionKey)
            throws SQLException, ClassNotFoundException {
        db.updateDistributionKey(entityName, distributionKey);
    }

    public List<SessionKey> generateSessionKeys(String owner, int numKeys, CommunicationPolicy communicationPolicy)
            throws IOException, SQLException, ClassNotFoundException {
        return db.generateSessionKeys(authID, owner, numKeys, communicationPolicy);
    }

    public SessionKey getSessionKeyByID(long keyID) throws SQLException, ClassNotFoundException {
        return db.getSessionKeyByID(keyID);
    }

    public String sessionKeysToString() throws SQLException, ClassNotFoundException {
        return db.sessionKeysToString();
    }
    public String regEntitiesToString() {
        return db.regEntitiesToString();
    }
    public String commPoliciesToString() {
        return db.commPoliciesToString();
    }

    public String trustedAuthsToString() { return db.trustedAuthsToString(); }

    public static void main(String[] args) throws Exception {
        // parsing command line arguments
        Options options = new Options();

        Option properties = new Option("p", "properties", true, "properties file path");
        properties.setRequired(false);
        options.addOption(properties);

        CommandLineParser parser = new DefaultParser();
        HelpFormatter formatter = new HelpFormatter();
        CommandLine cmd;

        try {
            cmd = parser.parse(options, args);
        } catch (ParseException e) {
            System.out.println(e.getMessage());
            formatter.printHelp("utility-name", options);

            System.exit(1);
            return;
        }
        String propertiesFilePath = cmd.getOptionValue("properties");
        if (propertiesFilePath == null) {
            logger.info("No properties file specified! (Use option -p to specify the properties file.)");
            System.exit(1);
            return;
        }
        logger.info("Properties file specified: {}", propertiesFilePath);

        PROPERTIES = new AuthServerProperties(propertiesFilePath);
        logger.info("Finished loading Auth Server properties.");

        AuthServer authServer = new AuthServer(PROPERTIES);
        authServer.begin();
    }

    public void begin() throws Exception {
        EntityPortListener entityPortListener = new EntityPortListener(this);
        entityPortListener.start();

        AuthCommandLine authCommandLine = new AuthCommandLine(this);
        authCommandLine.start();

        clientForTrustedAuths.start();

        serverForTrustedAuths.start();
        serverForTrustedAuths.join();
    }

    public int getTrustedAuthIDByCert(X509Certificate cert) {
        return db.getTrustedAuthIDByCert(cert);
    }

    public TrustedAuth getTrustedAuthInfo(int authID) {
        return db.getTrustedAuthInfo(authID);
    }

    public boolean addSessionKeyOwner(long keyID, String newOwner) throws SQLException, ClassNotFoundException {
        return db.addSessionKeyOwner(keyID, newOwner);
    }

    public ContentResponse performPostRequest(String uri, Fields fields, JSONObject keyVals) throws TimeoutException,
            ExecutionException, InterruptedException
    {
        org.eclipse.jetty.client.api.Request postRequest = clientForTrustedAuths.POST(uri);
        keyVals.forEach((k, v) -> {
            postRequest.param(k.toString(), v.toString());
        });
        return postRequest.send();
    }

    public void cleanExpiredSessionKeys() throws SQLException, ClassNotFoundException {
        db.cleanExpiredSessionKeys();
    }

    private Server initServerForTrustedAuths(AuthServerProperties properties, String authKeyStorePassword)
            throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException
    {
        TrustedAuthConnectionHandler trustedAuthConnectionHandler = new TrustedAuthConnectionHandler(this);

        Server serverForTrustedAuths = new Server();
        serverForTrustedAuths.setHandler(trustedAuthConnectionHandler);

        SslContextFactory sslContextFactory = new SslContextFactory();
        sslContextFactory.setTrustAll(false);
        sslContextFactory.setKeyStore(AuthCrypto.loadKeyStore(properties.getInternetKeyStorePath(), authKeyStorePassword));
        sslContextFactory.setKeyStorePassword(authKeyStorePassword);

        KeyStore serverTrustStore = KeyStore.getInstance(KeyStore.getDefaultType());
        serverTrustStore.load(null, authKeyStorePassword.toCharArray());
        String[] trustedCACertPaths = properties.getTrustedCACertPaths();
        for (int i = 0; i < trustedCACertPaths.length; i++) {
            serverTrustStore.setCertificateEntry("" + i, AuthCrypto.loadCertificate(trustedCACertPaths[i]));
        }
        sslContextFactory.setTrustStore(serverTrustStore);
        sslContextFactory.setNeedClientAuth(true);

        HttpConfiguration httpConfig = new HttpConfiguration();
        httpConfig.setPersistentConnectionsEnabled(true);
        httpConfig.setSecureScheme("https");
        // time out with out keep alive messages?
        //httpConfig.setBlockingTimeout();

        httpConfig.addCustomizer(new SecureRequestCustomizer());
        //new SSL
        ServerConnector connector = new ServerConnector(serverForTrustedAuths,
                new SslConnectionFactory(sslContextFactory, "http/1.1"), new HttpConnectionFactory(httpConfig));

        connector.setPort(properties.getTrustedAuthPort());

        // Idle time out for keep alive connections
        // time out with out requests?
        connector.setIdleTimeout(properties.getTrustedAuthPortIdleTimeout());

        serverForTrustedAuths.setConnectors(new Connector[]{connector});

        return serverForTrustedAuths;
    }

    private HttpClient initClientForTrustedAuths(AuthServerProperties properties, String authKeyStorePassword)
            throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException
    {
        SslContextFactory sslContextFactory = new SslContextFactory();

        sslContextFactory.setTrustAll(false);
        sslContextFactory.setNeedClientAuth(true);
        sslContextFactory.setKeyStore(AuthCrypto.loadKeyStore(properties.getInternetKeyStorePath(), authKeyStorePassword));
        sslContextFactory.setKeyStorePassword(authKeyStorePassword);

        KeyStore clientTrustStore = KeyStore.getInstance(KeyStore.getDefaultType());
        clientTrustStore.load(null, authKeyStorePassword.toCharArray());
        String[] trustedCACertPaths = properties.getTrustedCACertPaths();
        for (int i = 0; i < trustedCACertPaths.length; i++) {
            clientTrustStore.setCertificateEntry("" + i, AuthCrypto.loadCertificate(trustedCACertPaths[i]));
        }

        sslContextFactory.setTrustStore(clientTrustStore);

        sslContextFactory.setKeyManagerPassword(authKeyStorePassword);
        sslContextFactory.setEndpointIdentificationAlgorithm("HTTPS");
        try {
            sslContextFactory.start();
        } catch (Exception e) {
            e.printStackTrace();
        }

        SSLEngine sslEngine = null;
        try {
            sslEngine = SSLContext.getDefault().createSSLEngine();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }

        SSLParameters sslParams = new SSLParameters();
        List<SNIServerName> list = new ArrayList<>();
        list.add(new SNIHostName("localhost"));
        sslParams.setServerNames(list);
        sslEngine.setSSLParameters(sslParams);

        sslContextFactory.customize(sslEngine);

        HttpClient clientForTrustedAuths = new HttpClient(sslContextFactory);

        return clientForTrustedAuths;
    }

    private class EntityPortListener extends Thread {
        public EntityPortListener(AuthServer server) {
            this.server = server;
        }
        public void run() {

            while(isRunning()) {
                try {
                    while (isRunning) {
                        Socket entitySocket = entityPortServerSocket.accept();
                        logger.info("An entity connected from: {} ", entitySocket.getRemoteSocketAddress());

                        EntityConnectionHandler entityConnectionHandler =
                                new EntityConnectionHandler(server, entitySocket, entityPortTimeout);
                        entityConnectionHandler.start();
                    }
                } catch (IOException e) {
                    logger.error("IOException {}", ExceptionToString.convertExceptionToStackTrace(e));
                }
            }
        }
        private AuthServer server;
    }

    private class NoLogging implements org.eclipse.jetty.util.log.Logger {
        @Override public String getName() { return "no"; }
        @Override public void warn(String msg, Object... args) { }
        @Override public void warn(Throwable thrown) { }
        @Override public void warn(String msg, Throwable thrown) { }
        @Override public void info(String msg, Object... args) { }
        @Override public void info(Throwable thrown) { }
        @Override public void info(String msg, Throwable thrown) { }
        @Override public boolean isDebugEnabled() { return false; }
        @Override public void setDebugEnabled(boolean enabled) { }
        @Override public void debug(String msg, long value) { }
        @Override public void debug(String msg, Object... args) { }
        @Override public void debug(Throwable thrown) { }
        @Override public void debug(String msg, Throwable thrown) { }
        @Override public org.eclipse.jetty.util.log.Logger getLogger(String name) { return this; }
        @Override public void ignore(Throwable ignored) { }
    }

    private static final Logger logger = LoggerFactory.getLogger(AuthServer.class);

    private int authID;
    private long entityPortTimeout;

    private ServerSocket entityPortServerSocket;

    private boolean isRunning;
    private AuthDB db;
    private AuthCrypto crypto;

    private Server serverForTrustedAuths;
    private HttpClient clientForTrustedAuths;
}
