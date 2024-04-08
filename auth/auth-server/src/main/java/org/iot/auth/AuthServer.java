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

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;
import org.bouncycastle.cert.CertIOException;
import org.eclipse.jetty.client.HttpClient;
import org.eclipse.jetty.client.api.ContentResponse;
import org.eclipse.jetty.client.dynamic.HttpClientTransportDynamic;
import org.eclipse.jetty.io.ClientConnector;
import org.eclipse.jetty.server.HttpConfiguration;
import org.eclipse.jetty.server.HttpConnectionFactory;
import org.eclipse.jetty.server.SecureRequestCustomizer;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.ServerConnector;
import org.eclipse.jetty.server.SslConnectionFactory;
import org.eclipse.jetty.util.ssl.SslContextFactory;
import org.iot.auth.config.AuthServerProperties;
import org.iot.auth.config.constants.C;
import org.iot.auth.crypto.AuthCrypto;
import org.iot.auth.crypto.DistributionKey;
import org.iot.auth.crypto.SessionKey;
import org.iot.auth.db.*;
import org.iot.auth.db.bean.CommunicationPolicyTable;
import org.iot.auth.io.Buffer;
import org.iot.auth.message.*;
import org.iot.auth.db.CommunicationTargetType;
import org.iot.auth.server.*;
import org.iot.auth.util.ExceptionToString;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.bluetooth.DiscoveryAgent;
import javax.microedition.io.StreamConnection;
import javax.microedition.io.StreamConnectionNotifier;
import javax.net.ssl.SNIHostName;
import javax.net.ssl.SNIServerName;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLParameters;
import java.awt.*;
import java.awt.event.ComponentAdapter;
import java.awt.event.ComponentEvent;
import java.io.*;
import java.math.BigInteger;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.sql.SQLException;
import java.util.*;
import java.util.List;
import java.util.Timer;
import java.util.concurrent.*;
import javax.bluetooth.LocalDevice;
import javax.bluetooth.BluetoothStateException;
import javax.swing.*;


/**
 * A main class for Auth, a local authentication/authorization entity for locally
 * registered entities.
 * @author Hokeun Kim, Salomon Lee
 */
public class AuthServer {
    private boolean isRunning() {
        return isRunning;
    }

    private void setRunning(boolean running) {
        this.isRunning = running;
    }

    public AuthServer(AuthServerProperties properties, String givenAuthPassword) throws Exception {
        String authKeyStorePassword;
        if (givenAuthPassword == null) {
            authKeyStorePassword = readPassword();
        }
        else {
            logger.warn("WARNING! Auth's password is given as a program argument!");
            logger.warn("WARNING! DO NOT give password using a program argument unless you are running experiments or debugging.");
            authKeyStorePassword = givenAuthPassword;
        }

        authID =  properties.getAuthID();

        crypto = new AuthCrypto(properties.getEntityKeyStorePath(), authKeyStorePassword);
        this.db = new AuthDB(properties.getAuthDatabaseDir());
        db.initialize(properties.getDatabaseKeyStorePath(), authKeyStorePassword,
                properties.getDatabaseEncryptionKeyPath(),
                AuthDBProtectionMethod.fromValue(properties.getAuthDBProtectionMethod()));
        logger.info("Finished initializing Auth DB.");

        entityTcpPortTimeout = properties.getEntityTcpPortTimeout();
        entityUdpPortTimeout = properties.getEntityUdpPortTimeout();

        // suppress default logging by jetty
        org.eclipse.jetty.util.log.Log.setLog(new NoLogging());

        // Init tcp server socket
        entityTcpPortServerSocket = new ServerSocket(properties.getEntityTcpPort());
        entityUdpPortServerSocket = new DatagramSocket(properties.getEntityUdpPort());

        serverForTrustedAuths = initServerForTrustedAuths(properties, authKeyStorePassword);
        clientForTrustedAuths = initClientForTrustedAuths(properties, authKeyStorePassword);
        serverForContextualCallbacks = initServerForContextualCallbacks(properties);

        backupEnabled = properties.getBackupEnabled();
        bluetoothEnabled = properties.getBluetoothEnabled();

        if (properties.getQpsThrottlingEnabled()) {
            qpsCalculator = new QPSCalculator(properties.getQpsLimit(), properties.getQpsCalculationBucketSizeInSec());
        }

        logger.info("Auth server information. Auth ID: " + properties.getAuthID() +
                ", Entity Ports TCP: " + entityTcpPortServerSocket.getLocalPort() +
                " UDP: " + entityUdpPortServerSocket.getLocalPort() +
                ", Trusted auth Port: " + ((ServerConnector) serverForTrustedAuths.getConnectors()[0]).getPort() +
                ", Host name: " + properties.getHostName());
    }

    /**
     * Let the user enter a password. If connected to a console, get the
     * password from the commandline. Else, assuming that the server is
     * running inside an IDE, either raise a dialog, or get the password
     * from the IDE console (password will show in plain text). Note that
     * if no password is entered, this method terminates the entire program!
     * @return Password entered by user.
     * @throws IOException If the input stream throws an exception.
     */
    private String readPassword() throws IOException {
        Console console = System.console();
        String authKeyStorePassword;
        if (console == null) {
            if (GraphicsEnvironment.isHeadless()) {
                // Assuming we are running in IDE, password will show.
                logger.warn("WARNING! Console is not available, password will appear on screen. Are you sure to continue(y/n)?");
                BufferedReader br = new BufferedReader(new InputStreamReader(System.in));
                String yesOrNo = br.readLine();
                if (yesOrNo == null || !yesOrNo.equalsIgnoreCase("y")) {
                    logger.info("Aborting... please run Auth with a console.");
                    System.exit(1);
                }
                logger.info("Warning! This can be insecure! - Please enter Auth password: ");
                authKeyStorePassword = br.readLine();
            } else {

                JPasswordField passwordField = new JPasswordField();
                JPanel panel = new JPanel();
                panel.setLayout(new GridLayout(2, 1));
                panel.add(new JLabel("Please enter your password."));
                panel.add(passwordField);
                JOptionPane jop = new JOptionPane(panel, JOptionPane.QUESTION_MESSAGE, JOptionPane.OK_CANCEL_OPTION);
                JDialog dialog = jop.createDialog("Enter Password");
                dialog.addComponentListener(new ComponentAdapter() {
                    @Override
                    public void componentShown(ComponentEvent e) {
                        SwingUtilities.invokeLater(new Runnable() {
                            @Override
                            public void run() {
                                passwordField.requestFocusInWindow();
                            }
                        });
                        super.componentShown(e);
                    }
                });
                dialog.setVisible(true);
                int result = (Integer) jop.getValue();
                dialog.dispose();
                char[] password = null;
                if (result == JOptionPane.OK_OPTION) {
                    password = passwordField.getPassword();
                } else {
                    logger.info("Aborting... no password given..");
                    System.exit(1);
                }
                authKeyStorePassword = new String(password);
            }
        }
        else {
            logger.info("Please enter Auth password: ");
            authKeyStorePassword = new String(console.readPassword());
        }
        return authKeyStorePassword;
    }

    /**
     * Getter for Auth's unique identifier
     * @return Auth's ID
     */
    public int getAuthID() {
        return authID;
    }

    /**
     * Getter for AuthCrypto object of Auth
     * @return Auth's AuthCrypto object
     */
    public AuthCrypto getCrypto() {
        return crypto;
    }

    /**
     * Main method of Auth server, which is executed at the very beginning
     * @param args Command line arguments
     * @throws Exception When any exception occurs
     */
    public static void main(String[] args) throws Exception {
        // parsing command line arguments
        Options options = new Options();

        Option propertiesOption = new Option("p", "properties", true, "properties file path");
        propertiesOption.setRequired(true);
        options.addOption(propertiesOption);

        Option basePathOption = new Option("b", "base_path", true, "base directory path to read files specified in properties");
        basePathOption.setRequired(false);
        options.addOption(basePathOption);

        Option passwordOption = new Option("s", "password", true,
                "password for Auth, DO NOT USE THIS OPTION in actual deployment, use only for experiments or debugging");
        passwordOption.setRequired(false);
        options.addOption(passwordOption);

        Option debugOption = new Option("d", "debug", false,
                "enable logging debug messages");
        debugOption.setRequired(false);
        options.addOption(debugOption);

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
            logger.error("No properties file specified! (Use option -p to specify the properties file.)");
            System.exit(1);
            return;
        }
        logger.info("Properties file specified: {}", propertiesFilePath);

        String basePath = cmd.getOptionValue("base_path");
        C.PROPERTIES = new AuthServerProperties(propertiesFilePath, basePath);
        logger.info("Finished loading Auth Server properties.");

        // enable debug logging
        if(cmd.hasOption("debug")) {
            ch.qos.logback.classic.Logger root =
                    (ch.qos.logback.classic.Logger) LoggerFactory.getLogger(ch.qos.logback.classic.Logger.ROOT_LOGGER_NAME);
            root.setLevel(ch.qos.logback.classic.Level.DEBUG);
        }

        String authPassword = cmd.getOptionValue("password");

        AuthServer authServer = new AuthServer(C.PROPERTIES, authPassword);

        authServer.begin();
    }

    /**
     * Starts Auth server
     * @throws Exception When any exception occurs
     */
    private void begin() throws Exception {
        setRunning(true);

        logger.info("Bluetooth entities - {}", this.bluetoothEnabled ? "ENABLED" : "DISABLED");
        if (bluetoothEnabled) {
            EntityBluetoothListener entityBluetoothListener = new EntityBluetoothListener(this);
            entityBluetoothListener.start();
        }

        EntityTcpPortListener entityTcpPortListener = new EntityTcpPortListener(this);
        entityTcpPortListener.start();

        EntityUdpPortListener entityUdpPortListener = new EntityUdpPortListener(this);
        entityUdpPortListener.start();

        AuthCommandLine authCommandLine = new AuthCommandLine(this);
        authCommandLine.start();

        HeartbeatSender heartbeatSender = new HeartbeatSender(this, db.getAllTrustedAuthIDs());
        heartbeatSender.start();

        if (backupEnabled) {
            BackupRequester backupRequester = new BackupRequester(this);
            backupRequester.start();
        }

        clientForTrustedAuths.start();

        serverForTrustedAuths.start();
        serverForTrustedAuths.join();
    }

    /**
     * Ends Auth server
     * @throws SQLException When an SQLException occurs
     * @throws IOException When an IOException occurs
     * @throws InterruptedException When an InterruptedException occurs
     */
    public void end() throws SQLException, IOException, InterruptedException {
        db.close();
    }

    /**
     * Send POST request to the trusted Auth, using HTTPS client, clientForTrustedAuths, this is why this method is
     * within AuthServer, not TrustedAuthConnectionHandler.
     * @param trustedAuthID ID of the trusted Auth.
     * @param trustedAuthReqMessasge Message to be sent to the trusted Auth.
     * @return HTTP response from the trusted Auth
     * @throws TimeoutException When timeout occurs.
     * @throws ExecutionException When an execution error occurs.
     * @throws InterruptedException When the request is interrupted.
     */
    public ContentResponse performPostRequestToTrustedAuth(int trustedAuthID, TrustedAuthReqMessasge trustedAuthReqMessasge)
            throws TimeoutException, ExecutionException, InterruptedException
    {
        TrustedAuth trustedAuth = getTrustedAuthInfo(trustedAuthID);
        if (trustedAuth == null) {
            throw new RuntimeException("Cannot find trusted Auth ID, " + trustedAuthID);
        }
        String uri = "https://" + trustedAuth.getHost() + ":" + trustedAuth.getPort();
        return trustedAuthReqMessasge.sendAsHttpRequest(clientForTrustedAuths.POST(uri));
    }

    //////////////////////////////////////////////////
    ///
    /// Below are methods for exposing AuthDB operations, rather than exposing AuthDB object itself
    ///
    //////////////////////////////////////////////////
    /**
     * Method to view database information for all registered entities
     * @return String with information of all registered entities
     */
    public String registeredEntitiesToString() {
        return db.registeredEntitiesToString();
    }

    /**
     * Method to view database information for all communication policies
     * @return String with information of all communication policies
     */
    public String communicationPoliciesToString() {
        return db.communicationPoliciesToString();
    }

    /**
     * Method to view database information for all trusted Auths
     * @return String with information of all trusted Auths
     */
    public String trustedAuthsToString() { return db.trustedAuthsToString(); }

    /**
     * Method for exposing an AuthDB operation, addSessionKeyOwner
     * @param keyID ID for specifying the session key to be updated.
     * @param newOwner A new owner (entity) of the session key specified.
     * @return Whether the operation succeeded.
     * @throws SQLException if database error occurs.
     * @throws ClassNotFoundException if the class cannot be located.
     */
    public boolean addSessionKeyOwner(long keyID, String newOwner) throws SQLException, ClassNotFoundException {
        return db.addSessionKeyOwner(keyID, newOwner);
    }

    /**
     * Method for exposing an AuthDB operation, addFileReader
     * @param owner Owner of the file.
     * @param reader Reader of the file.
     * @return Whether the operation succeeded.
     * @throws SQLException if database error occurs.
     * @throws ClassNotFoundException if the class cannot be located.
     */
    public boolean addFileReader(String owner, String reader) throws SQLException, ClassNotFoundException {
        return db.addFileReader(owner, reader);
    }

    public boolean addCommunicationPolicy(CommunicationPolicyTable newCommunicationPolicyTable) {
        try {
            db.insertCommunicationPolicy(newCommunicationPolicyTable);
            db.reloadCommunicationPolicyDB();
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
        return true;
    }

    /**
     * Method for exposing an AuthDB operation, getCommunicationPolicy
     * @param reqGroup The requesting group's name in communication policy.
     * @param targetType The type of the target for communication.
     * @param target The target's name - can be a group's name or publish-subscribe topic.
     * @return Communication policy found, or {@code null} if the specified communication policy does not exist.
     */
    public CommunicationPolicy getCommunicationPolicy(String reqGroup, CommunicationTargetType targetType, String target) {
        return db.getCommunicationPolicy(reqGroup, targetType, target);
    }

    /**
     * Method for exposing an AuthDB operation, updateDistributionKey
     * @param entityName The name of entity whose distribution key will be updated.
     * @param distributionKey New distribution key to be updated with.
     * @throws SQLException if database error occurs.
     * @throws ClassNotFoundException if the class cannot be located.
     */
    public void updateDistributionKey(String entityName, DistributionKey distributionKey)
            throws SQLException, ClassNotFoundException {
        db.updateDistributionKey(entityName, distributionKey);
    }

    /**
     * Method for exposing an AuthDB operation, generateSessionKeys.
     * This method is protected using the "synchronized" keyword to ensure the atomicity of the process creating session
     * keys when there are multiple threads trying to create session keys at the same time.
     * @param owner The owner who will own the generated session keys.
     * @param numKeys The number of keys specified.
     * @param communicationPolicy The communication policy specified.
     * @param sessionKeyPurpose The purpose Auth generates session keys for.
     * @return A list of session keys.
     * @throws IOException If an error occurs in IO.
     * @throws SQLException if database error occurs.
     * @throws ClassNotFoundException if the class cannot be located.
     */
    public synchronized List<SessionKey> generateSessionKeys(String owner, int numKeys, CommunicationPolicy communicationPolicy,
                                                SessionKeyPurpose sessionKeyPurpose)
            throws IOException, SQLException, ClassNotFoundException {
        return db.generateSessionKeys(authID, owner, numKeys, communicationPolicy, sessionKeyPurpose);
    }

    /**
     * Method for exposing an AuthDB operation, getSessionKeyByID
     * @param keyID ID of the session key to be found.
     * @return Session key specified by keyID, or {@code null} if there is no such session.
     * @throws SQLException if database error occurs.
     * @throws ClassNotFoundException if the class cannot be located.
     */
    public SessionKey getSessionKeyByID(long keyID) throws SQLException, ClassNotFoundException {
        return db.getSessionKeyByID(keyID);
    }

    /**
     * Method for exposing an AuthDB operation, getSessionKeysByPurpose
     * @param requestingEntityName The name of the requester entity.
     * @param sessionKeyPurpose Session key purpose specified for finding session keys.
     * @return A list of session keys.
     * @throws SQLException if database error occurs.
     * @throws ClassNotFoundException if the class cannot be located.
     */
    public List<SessionKey> getSessionKeysByPurpose(String requestingEntityName, SessionKeyPurpose sessionKeyPurpose)
            throws SQLException, ClassNotFoundException {
        return db.getSessionKeysByPurpose(requestingEntityName, sessionKeyPurpose);
    }

    /**
     * Method for exposing an AuthDB operation, sessionKeysToString
     * @return Session keys in string with newline separators.
     * @throws SQLException if database error occurs.
     * @throws ClassNotFoundException if the class cannot be located.
     */
    public String sessionKeysToString() throws SQLException, ClassNotFoundException {
        return db.sessionKeysToString();
    }

    /**
     * Method for exposing an AuthDB operation, getTrustedAuthIDByCertificate
     * @param cert The certificate of Auth that we search for.
     * @return ID of the trusted Auth specified by the certificate.
     */
    public int getTrustedAuthIDByCertificate(X509Certificate cert) {
        return db.getTrustedAuthIDByCertificate(cert);
    }

    /**
     * Method for exposing an AuthDB operation, getFileSharingInfoByOwner
     * @param fileOwner The owner of file that we search for.
     * @return List of name registered by fileOwner
     */
    public ArrayList <String> getFileSharingInfo(String fileOwner) {
        return db.getFileSharingInfoByOwner(fileOwner);
    }

    /**
     * Method for exposing an AuthDB operation, getRegisteredEntity
     * @param entityName The name of entity to be found.
     * @return RegisteredEntity object specified the entityName, or
     *         {@code null} if TrustedAuth cannot be found.
     */
    public RegisteredEntity getRegisteredEntity(String entityName) {
        return db.getRegisteredEntity(entityName);
    }

    /**
     *  Method for exposing an AuthDB operation, getTrustedAuthInfo
     * @param authID ID of the trusted Auth to be found.
     * @return TrustedAuth object specified by ID, or
     *         {@code null} if TrustedAuth cannot be found.
     */
    public TrustedAuth getTrustedAuthInfo(int authID) {
        return db.getTrustedAuthInfo(authID);
    }

    /**
     * Method for exposing an AuthDB operation, cleanExpiredSessionKeys
     * @throws SQLException If an error occurs in SQL processing.
     * @throws ClassNotFoundException If the class is not found.
     */
    public void cleanExpiredSessionKeys() throws SQLException, ClassNotFoundException {
        db.cleanExpiredSessionKeys();
    }

    /**
     * Method for exposing an AuthDB operation, deleteAllSessionKeys
     * @throws SQLException If an error occurs in SQL processing.
     * @throws ClassNotFoundException If the class is not found.
     */
    public void deleteAllSessionKeys() throws SQLException, ClassNotFoundException {
        db.deleteAllSessionKeys();
    }

    public void insertRegisteredEntitiesOrUpdateIfExist(List<RegisteredEntity> registeredEntities)
            throws SQLException, IOException, ClassNotFoundException
    {
        db.insertRegisteredEntitiesOrUpdateIfExist(registeredEntities);
        db.reloadRegEntityDB();
    }

    public void deleteBackedUpRegisteredEntities() throws SQLException, ClassNotFoundException {
        db.deleteBackedUpRegisteredEntities();
        db.reloadRegEntityDB();
    }

    public void reloadRegEntityDB()
            throws SQLException, IOException, ClassNotFoundException
    {
        db.reloadRegEntityDB();
    }
    //////////////////////////////////////////////////
    ///
    /// Above are methods for exposing AuthDB operations, rather than exposing AuthDB object itself
    ///
    //////////////////////////////////////////////////

    /**
     * Initialize HTTPS server to which trusted Auths connect
     * @param properties Auth server's properties to get paths for key stores and certificates
     * @param authKeyStorePassword Password for Auth's key store that is used for communication with trusted Auths
     * @return HTTPS server object
     * @throws CertificateException When there is a problem with certificate.
     * @throws NoSuchAlgorithmException If the specified algorithm cannot be found.
     * @throws KeyStoreException When there is a problem with accessing key store.
     * @throws IOException If there is a problem in IO.
     */
    private Server initServerForTrustedAuths(AuthServerProperties properties, String authKeyStorePassword)
            throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException
    {
        TrustedAuthConnectionHandler trustedAuthConnectionHandler = new TrustedAuthConnectionHandler(this);

        Server serverForTrustedAuths = new Server();
        serverForTrustedAuths.setHandler(trustedAuthConnectionHandler);

        SslContextFactory.Server sslContextFactory = new SslContextFactory.Server();
        sslContextFactory.setTrustAll(false);
        sslContextFactory.setKeyStore(AuthCrypto.loadKeyStore(properties.getInternetKeyStorePath(), authKeyStorePassword));
        sslContextFactory.setKeyStorePassword(authKeyStorePassword);

        KeyStore serverTrustStore = KeyStore.getInstance(KeyStore.getDefaultType());
        serverTrustStore.load(null, authKeyStorePassword.toCharArray());
        String[] trustedCACertPaths = properties.getTrustedCACertPaths();
        for (int i = 0; i < trustedCACertPaths.length; i++) {
            serverTrustStore.setCertificateEntry("" + i, AuthCrypto.loadCertificateFromFile(trustedCACertPaths[i]));
        }
        sslContextFactory.setTrustStore(serverTrustStore);
        sslContextFactory.setNeedClientAuth(true);

        HttpConfiguration httpConfig = new HttpConfiguration();
        httpConfig.setPersistentConnectionsEnabled(true);
        httpConfig.setSecureScheme("https");
        // time out without keep alive messages?
        //httpConfig.setBlockingTimeout();

        httpConfig.addCustomizer(new SecureRequestCustomizer());
        //new SSL
        ServerConnector connector = new ServerConnector(serverForTrustedAuths,
                new SslConnectionFactory(sslContextFactory, "http/1.1"), new HttpConnectionFactory(httpConfig));

        connector.setPort(properties.getTrustedAuthPort());

        // Idle time out for keep alive connections
        // time out without requests?
        connector.setIdleTimeout(properties.getTrustedAuthPortIdleTimeout());

        serverForTrustedAuths.setConnectors(new org.eclipse.jetty.server.Connector[]{connector});

        return serverForTrustedAuths;
    }

    /**
     * Initialize HTTPS client for connecting to other trusted Auths and sending Auth session key requests
     * @param properties Auth server's properties to get paths for key stores and certificates
     * @param authKeyStorePassword Password for Auth's key store that is used for communication with trusted Auths
     * @return HTTPS client object
     * @throws CertificateException When there is a problem with certificate.
     * @throws NoSuchAlgorithmException If the specified algorithm cannot be found.
     * @throws KeyStoreException When there is a problem with accessing key store.
     * @throws IOException If there is a problem in IO.
     */
    private HttpClient initClientForTrustedAuths(AuthServerProperties properties, String authKeyStorePassword)
            throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException
    {
        SslContextFactory.Client sslContextFactory = new SslContextFactory.Client();

        sslContextFactory.setTrustAll(false);
        sslContextFactory.setKeyStore(AuthCrypto.loadKeyStore(properties.getInternetKeyStorePath(), authKeyStorePassword));
        sslContextFactory.setKeyStorePassword(authKeyStorePassword);

        KeyStore clientTrustStore = KeyStore.getInstance(KeyStore.getDefaultType());
        clientTrustStore.load(null, authKeyStorePassword.toCharArray());
        String[] trustedCACertPaths = properties.getTrustedCACertPaths();
        for (int i = 0; i < trustedCACertPaths.length; i++) {
            clientTrustStore.setCertificateEntry("" + i, AuthCrypto.loadCertificateFromFile(trustedCACertPaths[i]));
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

        ClientConnector clientConnector = new ClientConnector();
        clientConnector.setSslContextFactory(sslContextFactory);

        HttpClient clientForTrustedAuths = new HttpClient(new HttpClientTransportDynamic(clientConnector));

        return clientForTrustedAuths;
    }

    private Server initServerForContextualCallbacks(AuthServerProperties properties)
            throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException
    {
        ContextualCallbackHandler contextualCallbackHandler = new ContextualCallbackHandler(this);

        Server serverForContextualCallbacks = new Server();
        serverForContextualCallbacks.setHandler(contextualCallbackHandler);

        HttpConfiguration httpConfig = new HttpConfiguration();
        httpConfig.setPersistentConnectionsEnabled(true);
        httpConfig.setSecureScheme("https");
        // time out with out keep alive messages?
        //httpConfig.setBlockingTimeout();

        httpConfig.addCustomizer(new SecureRequestCustomizer());
        //new SSL
        ServerConnector connector = new ServerConnector(serverForContextualCallbacks, new HttpConnectionFactory(httpConfig));

        connector.setPort(properties.getTrustedAuthPort());

        // Idle time out for keep alive connections
        // time out with out requests?
        connector.setIdleTimeout(properties.getTrustedAuthPortIdleTimeout());

        serverForContextualCallbacks.setConnectors(new org.eclipse.jetty.server.Connector[]{connector});

        return serverForContextualCallbacks;
    }
    public List<AuthBackupReqMessage> getBackupReqMessages() {
        int[] trustedAuthIDs = db.getAllTrustedAuthIDs();
        List<RegisteredEntity> allRegisteredEntities = db.getAllRegisteredEntitiies();
        List<AuthBackupReqMessage> backupReqMessages = new LinkedList<>();
        if (allRegisteredEntities.size() == 0) {
            logger.error("No registered entities to be backed up.");
            return null;
        }

        for (int i = 0; i < trustedAuthIDs.length; i++) {
            int backupToAuthID = trustedAuthIDs[i];
            List<RegisteredEntity> registeredEntitiesToBeBackedUp = new LinkedList<>();
            for (RegisteredEntity registeredEntity: allRegisteredEntities) {
                for (int currentBackupToAuthID : registeredEntity.getBackupToAuthIDs()) {
                    if (currentBackupToAuthID == backupToAuthID) {
                        registeredEntitiesToBeBackedUp.add(registeredEntity);
                    }
                }
            }

            if (registeredEntitiesToBeBackedUp.size() == 0) {
                logger.info("no entities to be backed up to Auth " + backupToAuthID);
                continue;
            }
            logger.info("Trying to back up to Auth" + backupToAuthID);
            TrustedAuth backupToAuth = getTrustedAuthInfo(backupToAuthID);

            X509Certificate backupCertificate = null;
            try {
                backupCertificate = crypto.issueCertificate(backupToAuth.getEntityCertificate(),
                        authID, backupToAuthID, backupToAuth.getEntityHost());
            } catch (CertIOException e) {
                throw new RuntimeException("Problem with issuing a certificate" + "\n" + e.getMessage());
            }

            StringBuilder builder = new StringBuilder();
            for (RegisteredEntity registeredEntity: registeredEntitiesToBeBackedUp) {
                builder.append("\n" + registeredEntity.getName());
            }
            logger.info("List of entities to be backed up: " + builder.toString());
            AuthBackupReqMessage authBackupReqMessage = new AuthBackupReqMessage(backupToAuthID, backupCertificate, registeredEntitiesToBeBackedUp);
            backupReqMessages.add(authBackupReqMessage);
        }
        return backupReqMessages;
    }

    public ContentResponse sendBackupReqMessage(AuthBackupReqMessage backupReqMessage) throws InterruptedException,
            ExecutionException, TimeoutException
    {
        ContentResponse ret;
        ret = performPostRequestToTrustedAuth(backupReqMessage.getBackupToAuthID(), backupReqMessage);
        return ret;
    }

    public List<ContentResponse> backup() {
        List<ContentResponse> ret = new LinkedList<>();
        try {
            List<AuthBackupReqMessage> backupReqMessages = getBackupReqMessages();
            for (AuthBackupReqMessage backupReqMessage: backupReqMessages) {
                    ContentResponse contentResponse = sendBackupReqMessage(backupReqMessage);
                    ret.add(contentResponse);
            }
        } catch (TimeoutException | ExecutionException | InterruptedException e) {
            logger.error("Exception occurred during backup() {}", ExceptionToString.convertExceptionToStackTrace(e));
            throw new RuntimeException();
        }
        return ret;
    }

    public boolean updateBackupCertificate(int backupFromAuthID, X509Certificate backupCertificate)
            throws SQLException, CertificateEncodingException
    {
        return db.updateBackupCertificate(backupFromAuthID, backupCertificate);
    }

    private class EntityBluetoothListener extends Thread {
        public EntityBluetoothListener(AuthServer server) {
            this.server = server;
        }
        public void run() {
            StreamConnectionNotifier notifier;
            StreamConnection connection;
            try {
                if (!LocalDevice.isPowerOn()) {
                    logger.warn("Bluetooth device for Auth is not turned on, Bluetooth will be disabled.");
                    return;
                }

                final LocalDevice device = LocalDevice.getLocalDevice();
                device.setDiscoverable(DiscoveryAgent.GIAC); // General/Unlimited Inquiry Access Code (GIAC).
                String uuidString = "d0c722b07e1511e1b0c40800200c9a66";
                UUID uuid = new UUID(
                        new BigInteger(uuidString.substring(0, 16), 16).longValue(),
                        new BigInteger(uuidString.substring(16), 16).longValue());
                logger.info(uuid.toString());

                String url = "btspp://localhost:" + uuid.toString().replaceAll("-", "") + ";name=RemoteBluetooth";
                notifier = (StreamConnectionNotifier) javax.microedition.io.Connector.open(url);
            }
            catch (BluetoothStateException e)
            {
                logger.error("BluetoothStateException occurred while initializing Bluetooth.");
                throw new RuntimeException(e.getMessage());
            }
            catch (IOException e)
            {
                logger.error("IOException occurred while initializing Bluetooth.");
                throw new RuntimeException(e.getMessage());
            }
            catch (Error e)
            {
                logger.error("Error occurred while initializing Bluetooth.");
                throw new RuntimeException(e.getMessage());
            }

            while (isRunning()) {
                try {
                    System.out.println("waiting for connection...");
                    connection = notifier.acceptAndOpen();
                    System.out.println("After AcceptAndOpen...");

                    DataInputStream dis = connection.openDataInputStream();

                    byte buffer[] = new byte[4096];
                    int ret = dis.read(buffer, 0, 4095);
                    buffer[ret] = 0;
                    logger.info("buffer:" + new String(buffer).trim());
                    logger.info("ret: " + ret);

                    //Thread processThread = new Thread(new ProcessConnectionThread(connection));
                    //processThread.start();

                }
                catch (IOException e)
                {
                    throw new RuntimeException(e.getMessage());
                }
            }

        }
        private AuthServer server;
    }

    /**
     * Class for a thread that listens to TCP connections coming from entities, and creates another thread for processing
     * the connection from an entity, which is entityTcpConnectionHandler
     */
    private class EntityTcpPortListener extends Thread {
        public EntityTcpPortListener(AuthServer server) {
            this.server = server;
        }
        public void run() {

            while(isRunning()) {
                try {
                    while (isRunning) {
                        Socket entitySocket = entityTcpPortServerSocket.accept();
                        logger.info("An entity connected from: {} ", entitySocket.getRemoteSocketAddress());
                        if (qpsCalculator != null && qpsCalculator.checkQpsLimitExceededOtherwiseIncreaseRequestCounter()) {
                            logger.info("QPS limit is exceeded in TCP, discarding the request.");
                            continue;
                        }
                        new Thread(new EntityTcpConnectionHandler(server, entitySocket, entityTcpPortTimeout)).start();
                    }
                } catch (IOException e) {
                    logger.error("IOException in Entity TCP Port Listener {}", ExceptionToString.convertExceptionToStackTrace(e));
                }
            }
        }
        private AuthServer server;
    }

    /**
     * Class for a thread that listens to UDP connection coming from entities
     */
    private class EntityUdpPortListener extends Thread {
        public EntityUdpPortListener(AuthServer server) {
            this.server = server;
            nonceMapForUdpPortListener = new HashMap<>();
            responseMapForUdpPortListener = new HashMap<>();
        }
        public void run() {
            Timer timer = new Timer();
            while (isRunning()) {
                byte[] bufferBytes = new byte[4096];
                DatagramPacket receivedPacket = new DatagramPacket(bufferBytes, bufferBytes.length);
                try {
                    entityUdpPortServerSocket.receive(receivedPacket);
                    logger.info("Entity Address: " + receivedPacket.getAddress().toString() +
                            ", Port: " + receivedPacket.getPort() +
                            ", Length: " + receivedPacket.getLength());

                    if (qpsCalculator != null && qpsCalculator.checkQpsLimitExceededOtherwiseIncreaseRequestCounter()) {
                        logger.info("QPS limit is exceeded in UDP, discarding the request.");
                        continue;
                    }

                    String addressKey = receivedPacket.getAddress() + ":" + receivedPacket.getPort();
                    byte[] receivedBytes = receivedPacket.getData();
                    MessageType type = MessageType.fromByte(receivedBytes[0]);
                    if (type == MessageType.ENTITY_HELLO) {
                        if (responseMapForUdpPortListener.get(addressKey) != null) {
                            logger.error("Response for address key {} still exists", addressKey);
                            // send alert
                            continue;
                        }
                        Buffer authNonce = nonceMapForUdpPortListener.get(addressKey);
                        if (authNonce == null) {
                            authNonce = AuthCrypto.getRandomBytes(AuthHelloMessage.AUTH_NONCE_SIZE);
                            nonceMapForUdpPortListener.put(addressKey, authNonce);
                            timer.schedule(new TimerTask() {
                                @Override
                                public void run() {
                                    nonceMapForUdpPortListener.remove(addressKey);
                                }
                            }, entityUdpPortTimeout);
                        }
                        // send auth hello here
                        AuthHelloMessage authHello = new AuthHelloMessage(server.getAuthID(), authNonce);
                        byte[] bytes = authHello.serialize().getRawBytes();
                        DatagramPacket packetToSend = new DatagramPacket(bytes, bytes.length,
                                receivedPacket.getAddress(), receivedPacket.getPort());
                        entityUdpPortServerSocket.send(packetToSend);
                    }
                    else if (type == MessageType.SESSION_KEY_REQ || type == MessageType.SESSION_KEY_REQ_IN_PUB_ENC) {
                        Buffer response = responseMapForUdpPortListener.get(addressKey);
                        if (response != null) {
                            // send response
                            DatagramPacket packetToSend = new DatagramPacket(response.getRawBytes(), response.getRawBytes().length,
                                    receivedPacket.getAddress(), receivedPacket.getPort());
                            entityUdpPortServerSocket.send(packetToSend);
                            continue;
                        }
                        Buffer authNonce = nonceMapForUdpPortListener.get(addressKey);
                        if (authNonce != null) {
                            // handle this
                            // let it put to response map
                            // and send the response
                            Buffer receivedBuffer = new Buffer(receivedBytes, receivedPacket.getLength());
                            logger.info("Received data : {}", receivedBuffer.toHexString());
                            new EntityUdpConnectionHandler(server, entityUdpPortServerSocket,
                                    receivedPacket.getAddress(), receivedPacket.getPort(), entityUdpPortTimeout,
                                    responseMapForUdpPortListener, receivedBuffer, authNonce).run();
                        }
                    }
                    /*
                    Buffer receivedBuffer = new Buffer(receivedBytes, receivedPacket.getLength());
                    logger.info("Received data : {}", receivedBuffer.toHexString());
                    new Thread(new EntityUdpConnectionHandler(server,
                            receivedPacket.getAddress(), receivedPacket.getPort(), entityUdpPortTimeout)).start();
                    */
                } catch (IOException e) {
                    logger.error("IOException in Entity UDP Port Listener {}", ExceptionToString.convertExceptionToStackTrace(e));
                }
            }
        }
        private AuthServer server;
    }

    public String showAllUdpPortListenerMaps() {
        StringBuilder sb = new StringBuilder();
        sb.append("Nonce Map\n");
        nonceMapForUdpPortListener.forEach((k, v)->{
            sb.append(k + "->" + v.toHexString() + "\n");
        });
        sb.append("Response Map\n");
        responseMapForUdpPortListener.forEach((k, v)->{
            sb.append(k + "->" + v.length() + "\n");
        });
        return sb.toString();
    }
    private Map<String, Buffer> nonceMapForUdpPortListener;
    private Map<String, Buffer> responseMapForUdpPortListener;

    public List<X509Certificate> issueBackupCertificate() throws CertIOException {
        Set<Integer> backupAuthIDSet = new HashSet<>();
        for (RegisteredEntity registeredEntity: db.getAllRegisteredEntitiies()) {
            for (int backupToAuthID: registeredEntity.getBackupToAuthIDs()) {
                backupAuthIDSet.add(backupToAuthID);
            }
        }
        Iterator<Integer> itr = backupAuthIDSet.iterator();
        List<X509Certificate> ret = new LinkedList<>();
        while (itr.hasNext()) {
            int backupAuthID = itr.next();
            TrustedAuth trustedAuth = db.getTrustedAuthInfo(backupAuthID);
            X509Certificate cert = crypto.issueCertificate(
                    trustedAuth.getEntityCertificate(), getAuthID(), backupAuthID, trustedAuth.getEntityHost());
            ret.add(cert);
        }
        return ret;
        /*
        TrustedAuth trustedAuth = db.getTrustedAuthInfo(102);
        BASE64Encoder encoder = new BASE64Encoder();
        System.out.println(X509Factory.BEGIN_CERT);
        try {
            encoder.encodeBuffer(cert.getEncoded(), System.out);
        } catch (IOException e) {
            e.printStackTrace();
        } catch (CertificateEncodingException e) {
            e.printStackTrace();
        }
        System.out.println(X509Factory.END_CERT);
        */
    }

    /**
     * Add new registered entity to the Auth DB.
     * @param newRegisteredEntity The new entity to be registered with the Auth
     * @return Whether the registration succeeded.
     */
    public boolean addRegisteredEntity(RegisteredEntity newRegisteredEntity) {
        List<RegisteredEntity> newRegisteredEntityList = new ArrayList<>();
        newRegisteredEntityList.add(newRegisteredEntity);
        try {
            db.insertRegisteredEntities(newRegisteredEntityList);
            db.reloadRegEntityDB();
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
        return true;
    }

    public boolean removeRegisteredEntity(String registeredEntityName) {
        List<String> registeredEntityNameList = new ArrayList<>();
        registeredEntityNameList.add(registeredEntityName);
        registeredEntityNameList.add("net1.udpClient");
        try {
            db.deleteRegisteredEntities(registeredEntityNameList);
            db.reloadRegEntityDB();
            return true;
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }

    /**
     * Class for suppressing logging by jetty
     */
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
    private long entityTcpPortTimeout;
    private long entityUdpPortTimeout;

    private ServerSocket entityTcpPortServerSocket;
    private DatagramSocket entityUdpPortServerSocket;

    private boolean isRunning;
    private AuthDB db;
    private AuthCrypto crypto;

    private Server serverForTrustedAuths;
    private Server serverForContextualCallbacks;
    private HttpClient clientForTrustedAuths;
    private boolean backupEnabled;
    private boolean bluetoothEnabled;
    private QPSCalculator qpsCalculator = null;
}
