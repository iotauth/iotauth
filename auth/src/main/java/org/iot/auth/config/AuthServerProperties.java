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

package org.iot.auth.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.*;
import java.util.Properties;

/**
 * Authentication Server Configuration Properties are accessed and computed from this class.
 *
 * @author Salomon Lee
 */
public class AuthServerProperties {
    private static final Logger logger = LoggerFactory.getLogger(AuthServerProperties.class);
    private String _propertyFilePath;

    enum key {
        auth_id,

        host_name,

        entity_port,
        entity_port_timeout,

        trusted_auth_port,
        trusted_auth_port_idle_timeout,

        entity_key_store_path,
        internet_key_store_path,
        trusted_ca_cert_paths,

        auth_database_dir
    }

    private Properties prop;

    private int authID;

    private String hostName;

    private int entityPort;
    private long entityPortTimeout;

    private int trustedAuthPort;
    private long trustedAuthPortIdleTimeout;

    private String entityKeyStorePath;
    private String internetKeyStorePath;
    private String[] trustedCACertPaths;

    private String authDatabaseDir;

    public AuthServerProperties(String propertyFilePath) throws IOException {
        _propertyFilePath = propertyFilePath;

        prop = new Properties();
        File propertyFile = new File("../src/main/resources/" + _propertyFilePath);
        InputStream inputStream = new FileInputStream(propertyFile);
        if (inputStream != null) {
            prop.load(inputStream);

            authID = Integer.parseInt(prop.getProperty(key.auth_id.toString()));
            logger.info("key:value = {}:{}", key.auth_id.toString(), authID);


            hostName = prop.getProperty(key.host_name.toString());
            logger.info("key:value = {}:{}", key.host_name.toString(), hostName);


            entityPort = Integer.parseInt(prop.getProperty(key.entity_port.toString()));
            logger.info("key:value = {}:{}", key.entity_port.toString(), entityPort);

            entityPortTimeout = Long.parseLong(prop.getProperty(key.entity_port_timeout.toString()));
            logger.info("key:value = {}:{}", key.entity_port_timeout.toString(), entityPortTimeout);


            trustedAuthPort = Integer.parseInt(prop.getProperty(key.trusted_auth_port.toString()));
            logger.info("key:value = {}:{}", key.trusted_auth_port.toString(), trustedAuthPort);

            trustedAuthPortIdleTimeout = Long.parseLong(prop.getProperty(key.trusted_auth_port_idle_timeout.toString()));
            logger.info("key:value = {}:{}", key.trusted_auth_port_idle_timeout.toString(), trustedAuthPortIdleTimeout);


            entityKeyStorePath = prop.getProperty(key.entity_key_store_path.toString());
            logger.info("key:value = {}:{}", key.entity_key_store_path.toString(), entityKeyStorePath);

            internetKeyStorePath = prop.getProperty(key.internet_key_store_path.toString());
            logger.info("key:value = {}:{}", key.internet_key_store_path.toString(), internetKeyStorePath);

            trustedCACertPaths = prop.getProperty(key.trusted_ca_cert_paths.toString()).trim().split("\\s*(;|,|\\s+)\\s*");
            logger.info("key:value = {}:{}", key.trusted_ca_cert_paths.toString(), trustedCACertPaths);


            authDatabaseDir = prop.getProperty(key.auth_database_dir.toString());
            logger.info("key:value = {}:{}", key.auth_database_dir.toString(), authDatabaseDir);
        }
        else {
            throw new FileNotFoundException("property file (" + _propertyFilePath + ") not found in the classpath");
        }
    }

    public int getAuthID() {
        return authID;
    }

    public String getHostName() {
        return hostName;
    }

    public int getEntityPort() {
        return entityPort;
    }
    public long getEntityPortTimeout() {
        return entityPortTimeout;
    }

    public int getTrustedAuthPort() {
        return trustedAuthPort;
    }
    public long getTrustedAuthPortIdleTimeout() {
        return trustedAuthPortIdleTimeout;
    }

    public String getEntityKeyStorePath() {
        return entityKeyStorePath;
    }
    public String getInternetKeyStorePath() {
        return internetKeyStorePath;
    }
    public String[] getTrustedCACertPaths() { return trustedCACertPaths; }

    public String getAuthDatabaseDir() {
        return authDatabaseDir;
    }
}
