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
 * @author Salomon Lee, Hokeun Kim
 */
public class AuthServerProperties {
    private static final Logger logger = LoggerFactory.getLogger(AuthServerProperties.class);
    private String _propertyFilePath;

    enum key {
        auth_id,

        host_name,

        entity_tcp_port,
        entity_tcp_port_timeout,

        entity_udp_port,
        entity_udp_port_timeout,

        trusted_auth_port,
        trusted_auth_port_idle_timeout,

        contextual_callback_port,
        contextual_callback_port_idle_timeout,
        contextual_callback_enabled,

        entity_key_store_path,
        internet_key_store_path,
        database_key_store_path,
        database_encryption_key_path,

        trusted_ca_cert_paths,

        auth_database_dir,
        auth_db_protection_method,
        backup_enabled,
        bluetooth_enabled,

        qps_throttling_enabled,
        qps_limit,
        qps_calculation_bucket_size_in_sec
    }

    private Properties prop;

    private int authID;

    private String hostName;

    private int entityTcpPort;
    private long entityTcpPortTimeout;

    private int entityUdpPort;
    private long entityUdpPortTimeout;

    private int trustedAuthPort;
    private long trustedAuthPortIdleTimeout;

    private int contextualCallbackPort;
    private long contextualCallbackIdleTimeout;
    private boolean contextualCallbackEnabled;

    private String entityKeyStorePath;
    private String internetKeyStorePath;
    private String databaseKeyStorePath;
    private String databaseEncryptionKeyPath;

    private String[] trustedCACertPaths;

    private String authDatabaseDir;
    private int authDBProtectionMethod;
    private boolean backupEnabled;
    private boolean bluetoothEnabled;

    private boolean qpsThrottlingEnabled;
    private float qpsLimit;
    private int qpsCalculationBucketSizeInSec;

    public AuthServerProperties(String propertyFilePath, String basePath) throws IOException {
        _propertyFilePath = propertyFilePath;

        if (basePath == null) {
            basePath =  "";
        }

        prop = new Properties();
        File propertyFile = new File(_propertyFilePath);
        InputStream inputStream = new FileInputStream(propertyFile);
        if (inputStream != null) {
            prop.load(inputStream);

            authID = Integer.parseInt(prop.getProperty(key.auth_id.toString()));
            logger.info("key:value = {}:{}", key.auth_id.toString(), authID);


            hostName = prop.getProperty(key.host_name.toString());
            logger.info("key:value = {}:{}", key.host_name.toString(), hostName);


            entityTcpPort = Integer.parseInt(prop.getProperty(key.entity_tcp_port.toString()));
            logger.info("key:value = {}:{}", key.entity_tcp_port.toString(), entityTcpPort);

            entityTcpPortTimeout = Long.parseLong(prop.getProperty(key.entity_tcp_port_timeout.toString()));
            logger.info("key:value = {}:{}", key.entity_tcp_port_timeout.toString(), entityTcpPortTimeout);


            entityUdpPort = Integer.parseInt(prop.getProperty(key.entity_udp_port.toString()));
            logger.info("key:value = {}:{}", key.entity_udp_port.toString(), entityUdpPort);

            entityUdpPortTimeout = Long.parseLong(prop.getProperty(key.entity_udp_port_timeout.toString()));
            logger.info("key:value = {}:{}", key.entity_udp_port_timeout.toString(), entityUdpPortTimeout);


            trustedAuthPort = Integer.parseInt(prop.getProperty(key.trusted_auth_port.toString()));
            logger.info("key:value = {}:{}", key.trusted_auth_port.toString(), trustedAuthPort);

            trustedAuthPortIdleTimeout = Long.parseLong(prop.getProperty(key.trusted_auth_port_idle_timeout.toString()));
            logger.info("key:value = {}:{}", key.trusted_auth_port_idle_timeout.toString(), trustedAuthPortIdleTimeout);


            contextualCallbackPort = Integer.parseInt(prop.getProperty(key.contextual_callback_port.toString()));
            logger.info("key:value = {}:{}", key.contextual_callback_port.toString(), contextualCallbackPort);

            contextualCallbackIdleTimeout = Long.parseLong(prop.getProperty(key.contextual_callback_port_idle_timeout.toString()));
            logger.info("key:value = {}:{}", key.contextual_callback_port_idle_timeout.toString(), contextualCallbackIdleTimeout);

            contextualCallbackEnabled = Boolean.parseBoolean(prop.getProperty(key.contextual_callback_enabled.toString()));
            logger.info("key:value = {}:{}", key.contextual_callback_enabled.toString(), contextualCallbackEnabled);


            entityKeyStorePath = basePath + prop.getProperty(key.entity_key_store_path.toString());
            logger.info("key:value = {}:{}", key.entity_key_store_path.toString(), entityKeyStorePath);

            internetKeyStorePath = basePath + prop.getProperty(key.internet_key_store_path.toString());
            logger.info("key:value = {}:{}", key.internet_key_store_path.toString(), internetKeyStorePath);

            databaseKeyStorePath = basePath + prop.getProperty(key.database_key_store_path.toString());
            logger.info("key:value = {}:{}", key.database_key_store_path.toString(), databaseKeyStorePath);

            databaseEncryptionKeyPath = basePath + prop.getProperty(key.database_encryption_key_path.toString());
            logger.info("key:value = {}:{}", key.database_encryption_key_path.toString(), databaseEncryptionKeyPath);


            trustedCACertPaths = prop.getProperty(key.trusted_ca_cert_paths.toString()).trim().split("\\s*(;|,|\\s+)\\s*");
            for (int i = 0; i < trustedCACertPaths.length; i++) {
                trustedCACertPaths[i] = basePath + trustedCACertPaths[i];
            }
            logger.info("key:value = {}:{}", key.trusted_ca_cert_paths.toString(), trustedCACertPaths);


            authDatabaseDir = basePath + prop.getProperty(key.auth_database_dir.toString());
            logger.info("key:value = {}:{}", key.auth_database_dir.toString(), authDatabaseDir);

            authDBProtectionMethod = Integer.parseInt(prop.getProperty(key.auth_db_protection_method.toString()));
            logger.info("key:value = {}:{}", key.auth_db_protection_method.toString(), authDBProtectionMethod);

            backupEnabled = Boolean.parseBoolean(prop.getProperty(key.backup_enabled.toString()));
            logger.info("key:value = {}:{}", key.backup_enabled.toString(), backupEnabled);

            bluetoothEnabled = Boolean.parseBoolean(prop.getProperty(key.bluetooth_enabled.toString()));
            logger.info("key:value = {}:{}", key.bluetooth_enabled.toString(), bluetoothEnabled);

            qpsThrottlingEnabled = Boolean.parseBoolean(prop.getProperty(key.qps_throttling_enabled.toString()));
            logger.info("key:value = {}:{}", key.qps_throttling_enabled.toString(), qpsThrottlingEnabled);

            qpsLimit = Float.parseFloat(prop.getProperty(key.qps_limit.toString()));
            logger.info("key:value = {}:{}", key.qps_limit.toString(), qpsLimit);

            qpsCalculationBucketSizeInSec = Integer.parseInt(prop.getProperty(key.qps_calculation_bucket_size_in_sec.toString()));
            logger.info("key:value = {}:{}", key.qps_calculation_bucket_size_in_sec.toString(), qpsCalculationBucketSizeInSec);
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

    public int getEntityTcpPort() {
        return entityTcpPort;
    }
    public long getEntityTcpPortTimeout() {
        return entityTcpPortTimeout;
    }

    public int getEntityUdpPort() {
        return entityUdpPort;
    }
    public long getEntityUdpPortTimeout() {
        return entityUdpPortTimeout;
    }

    public int getTrustedAuthPort() {
        return trustedAuthPort;
    }
    public long getTrustedAuthPortIdleTimeout() {
        return trustedAuthPortIdleTimeout;
    }

    public int getContextualCallbackPort() {
        return contextualCallbackPort;
    }
    public long getContextualCallbackIdleTimeout() {
        return contextualCallbackIdleTimeout;
    }
    public boolean isContextualCallbackEnabled() {
        return contextualCallbackEnabled;
    }

    public String getEntityKeyStorePath() {
        return entityKeyStorePath;
    }
    public String getInternetKeyStorePath() {
        return internetKeyStorePath;
    }
    public String getDatabaseKeyStorePath() {
        return databaseKeyStorePath;
    }
    public String getDatabaseEncryptionKeyPath() {
        return databaseEncryptionKeyPath;
    }
    public String[] getTrustedCACertPaths() { return trustedCACertPaths; }

    public String getAuthDatabaseDir() {
        return authDatabaseDir;
    }
    public int getAuthDBProtectionMethod() { return authDBProtectionMethod; }
    public boolean getBackupEnabled() {
        return backupEnabled;
    }
    public boolean getBluetoothEnabled() {
        return bluetoothEnabled;
    }

    public boolean getQpsThrottlingEnabled() {
        return qpsThrottlingEnabled;
    }
    public float getQpsLimit() {
        return qpsLimit;
    }
    public int getQpsCalculationBucketSizeInSec() {
        return qpsCalculationBucketSizeInSec;
    }
}
