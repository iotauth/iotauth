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

package org.iot.auth.message;

import org.eclipse.jetty.client.api.ContentResponse;
import org.eclipse.jetty.client.util.BytesContentProvider;
import org.iot.auth.crypto.AuthCrypto;
import org.iot.auth.crypto.DistributionKey;
import org.iot.auth.crypto.MigrationToken;
import org.iot.auth.db.RegisteredEntity;
import org.iot.auth.exception.InvalidSymmetricKeyOperationException;
import org.iot.auth.exception.UseOfExpiredKeyException;
import org.iot.auth.io.Buffer;

import java.io.IOException;
import java.io.InputStream;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeoutException;

/**
 * A message to back up registered entities to another trusted Auth
 *
 * @author Hokeun Kim
 */
public class AuthBackupReqMessage extends TrustedAuthReqMessasge {
    private List<RegisteredEntity> registeredEntityList;
    private X509Certificate backupCertificate;
    private int backupToAuthID;
    public AuthBackupReqMessage(int backupToAuthID, X509Certificate backupCertificate, List<RegisteredEntity> registeredEntityList) {
        this.backupToAuthID = backupToAuthID;
        this.backupCertificate = backupCertificate;
        this.registeredEntityList = registeredEntityList;
    }

    public int getBackupToAuthID() {
        return backupToAuthID;
    }

    public List<RegisteredEntity> getRegisteredEntityList() {
        return registeredEntityList;
    }

    public X509Certificate getBackupCertificate() {
        return backupCertificate;
    }

    public RegisteredEntity prepareBackup(RegisteredEntity currentRegisteredEntity) throws UseOfExpiredKeyException,
            InvalidSymmetricKeyOperationException, InvalidKeySpecException, NoSuchAlgorithmException {
        if (!currentRegisteredEntity.getUsePermanentDistKey()) {
            return currentRegisteredEntity;
        }
        // prepare migration token
        //MigrationToken migrationToken = new MigrationToken
        RegisteredEntity newRegisteredEntity = new RegisteredEntity(currentRegisteredEntity.serialize());
        DistributionKey currentDistributionKey = newRegisteredEntity.getDistributionKey();
        DistributionKey newDistributionKey = new DistributionKey(newRegisteredEntity.getDistCryptoSpec(),
                newRegisteredEntity.getDistKeyValidityPeriod());
        Buffer encryptedNewDistributionKey = currentDistributionKey.encryptAuthenticate(newDistributionKey.serialize());
        MigrationToken migrationToken = new MigrationToken(currentDistributionKey.makeMacOnly(), encryptedNewDistributionKey);
        newRegisteredEntity.setDistributionKey(newDistributionKey);
        newRegisteredEntity.setMigrationToken(migrationToken);
        return newRegisteredEntity;
    }

    // Because of the class name conflict of Request (client's or server's)
    public ContentResponse sendAsHttpRequest(org.eclipse.jetty.client.api.Request postRequest)
            throws TimeoutException, ExecutionException, InterruptedException
    {
        postRequest.param(TrustedAuthReqMessasge.TYPE, type.BACKUP_REQ.name());
        byte[] bytesBackupCertificate;
        try {
            bytesBackupCertificate = backupCertificate.getEncoded();
        } catch (CertificateEncodingException e) {
            throw new RuntimeException("Error occurred while encoding backup certificate in AuthBackupReqMessage: " + e.getMessage());
        }
        postRequest.param("CertSize", "" + bytesBackupCertificate.length);
        postRequest.param("EntityCount", "" + registeredEntityList.size());

        Buffer totalBuffer = new Buffer(bytesBackupCertificate);
        int totalLength = 0;
        for (RegisteredEntity registeredEntity: registeredEntityList) {
            try {
                registeredEntity = prepareBackup(registeredEntity);
            } catch (UseOfExpiredKeyException | InvalidSymmetricKeyOperationException | InvalidKeySpecException | NoSuchAlgorithmException e) {
                throw new RuntimeException("Error occurred while preparing AuthBackupReqMessage: " + e.getMessage());
            }
            Buffer registeredEntityBuffer = registeredEntity.serialize();
            Buffer lengthBuffer = new Buffer(Buffer.INT_SIZE);
            lengthBuffer.putInt(registeredEntityBuffer.length(), 0);
            totalLength += registeredEntityBuffer.length();
            totalBuffer.concat(lengthBuffer);
            totalBuffer.concat(registeredEntityBuffer);
        }
        BytesContentProvider contentProvider = new BytesContentProvider(totalBuffer.getRawBytes());
        postRequest.content(contentProvider);
        return postRequest.send();
    }

    public static AuthBackupReqMessage fromHttpRequest(org.eclipse.jetty.server.Request baseRequest) throws IOException,
            InvalidKeySpecException, NoSuchAlgorithmException
    {
        int certiSize = Integer.parseInt(baseRequest.getParameter("CertSize"));
        int entityCount =  Integer.parseInt(baseRequest.getParameter("EntityCount"));
        InputStream inputStream = baseRequest.getInputStream();
        byte[] bytes = new byte[baseRequest.getContentLength()];
        int ret = inputStream.read(bytes);
        if (ret != baseRequest.getContentLength()) {
            throw new RuntimeException("Error occurred in reading content of AuthBackupReqMessage request, Expected: "
                + baseRequest.getContentLength() + " Actual: " + ret);
        }
        Buffer totalBuffer = new Buffer(bytes);
        X509Certificate backupCertificate = AuthCrypto.loadCertificateFromBytes(totalBuffer.slice(0, certiSize).getRawBytes());
        List<RegisteredEntity> registeredEntities = new ArrayList<>(entityCount);
        int curIndex = certiSize;
        for (int i = 0; i < entityCount; i++) {
            int length = totalBuffer.getInt(curIndex);
            curIndex += Buffer.INT_SIZE;
            RegisteredEntity registeredEntity = new RegisteredEntity(totalBuffer.slice(curIndex, curIndex + length));
            curIndex += length;
            registeredEntities.add(registeredEntity);
        }
        // -1 means that is it is a received back request
        return new AuthBackupReqMessage(-1, backupCertificate, registeredEntities);
    }
}
