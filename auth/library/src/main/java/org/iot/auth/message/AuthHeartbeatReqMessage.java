package org.iot.auth.message;

import org.eclipse.jetty.client.api.ContentResponse;
import org.eclipse.jetty.client.util.BytesContentProvider;
import org.iot.auth.crypto.AuthCrypto;
import org.iot.auth.io.Buffer;

import java.io.IOException;
import java.io.InputStream;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeoutException;

/**
 * Created by hokeunkim on 3/22/17.
 */
public class AuthHeartbeatReqMessage extends TrustedAuthReqMessasge  {
    private static final int HEARTBEAT_NONCE_SIZE = 8;
    Buffer heartbeatNonce;
    public AuthHeartbeatReqMessage() {
        heartbeatNonce = AuthCrypto.getRandomBytes(HEARTBEAT_NONCE_SIZE);
    }
    public AuthHeartbeatReqMessage(Buffer heartbeatNonce) {
        this.heartbeatNonce = new Buffer(heartbeatNonce.getRawBytes());
    }

    // Because of the class name conflict of Request (client's or server's)
    public ContentResponse sendAsHttpRequest(org.eclipse.jetty.client.api.Request postRequest)
            throws TimeoutException, ExecutionException, InterruptedException
    {
        postRequest.param(TrustedAuthReqMessasge.TYPE, type.HEARTBEAT_REQ.name());
        BytesContentProvider contentProvider = new BytesContentProvider(heartbeatNonce.getRawBytes());
        postRequest.content(contentProvider);
        return postRequest.send();
    }

    public static AuthHeartbeatReqMessage fromHttpRequest(org.eclipse.jetty.server.Request baseRequest) throws IOException,
            InvalidKeySpecException, NoSuchAlgorithmException
    {
        InputStream inputStream = baseRequest.getInputStream();
        byte[] bytes = new byte[baseRequest.getContentLength()];
        if (inputStream.read(bytes) != baseRequest.getContentLength()) {
            throw new RuntimeException("Error occurred in reading content of HTTP request");
        }
        Buffer buffer = new Buffer(bytes);
        if (buffer.length() != HEARTBEAT_NONCE_SIZE) {
            throw new RuntimeException("Hearbeat nonce size is not as expected!");

        }
        return new AuthHeartbeatReqMessage(buffer);
    }
}
