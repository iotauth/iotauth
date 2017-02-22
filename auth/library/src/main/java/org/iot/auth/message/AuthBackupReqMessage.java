package org.iot.auth.message;

import org.eclipse.jetty.client.api.ContentResponse;
import org.eclipse.jetty.client.util.BytesContentProvider;
import org.iot.auth.db.RegisteredEntity;
import org.iot.auth.io.Buffer;

import java.io.IOException;
import java.io.InputStream;
import java.security.NoSuchAlgorithmException;
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
    public AuthBackupReqMessage(List<RegisteredEntity> registeredEntityList) {
        this.registeredEntityList = registeredEntityList;
    }

    public List<RegisteredEntity> getRegisteredEntityList() {
        return registeredEntityList;
    }

    // Because of the class name conflict of Request (client's or server's)
    public ContentResponse sendAsHttpRequest(org.eclipse.jetty.client.api.Request postRequest)
            throws TimeoutException, ExecutionException, InterruptedException
    {
        postRequest.param(TrustedAuthReqMessasge.TYPE, type.BACKUP_REQ.name());
        Buffer totalBuffer = new Buffer(0);
        int totalLength = 0;
        for (RegisteredEntity registeredEntity: registeredEntityList) {
            Buffer registeredEntityBuffer = registeredEntity.serialize();
            Buffer lengthBuffer = new Buffer(Buffer.INT_SIZE);
            lengthBuffer.putInt(registeredEntityBuffer.length(), 0);
            totalLength += registeredEntityBuffer.length();
            totalBuffer.concat(lengthBuffer);
            totalBuffer.concat(registeredEntityBuffer);
        }
        postRequest.param("EntityCount", "" + registeredEntityList.size());
        BytesContentProvider contentProvider = new BytesContentProvider(totalBuffer.getRawBytes());
        postRequest.content(contentProvider);
        return postRequest.send();
    }

    public static AuthBackupReqMessage fromHttpRequest(org.eclipse.jetty.server.Request baseRequest) throws IOException,
            InvalidKeySpecException, NoSuchAlgorithmException
    {
        int entityCount =  Integer.parseInt(baseRequest.getParameter("EntityCount"));
        InputStream inputStream = baseRequest.getInputStream();
        byte[] bytes = new byte[baseRequest.getContentLength()];
        if (inputStream.read(bytes) != baseRequest.getContentLength()) {
            throw new RuntimeException("Error occurred in reading content of HTTP request");
        }
        Buffer totalBuffer = new Buffer(bytes);
        List<RegisteredEntity> registeredEntities = new ArrayList<>(entityCount);
        int curIndex = 0;
        for (int i = 0; i < entityCount; i++) {
            int length = totalBuffer.getInt(curIndex);
            curIndex += Buffer.INT_SIZE;
            RegisteredEntity registeredEntity = new RegisteredEntity(totalBuffer.slice(curIndex, curIndex + length));
            curIndex += length;
            registeredEntities.add(registeredEntity);
        }
        return new AuthBackupReqMessage(registeredEntities);
    }
}
