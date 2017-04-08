package org.iot.auth.message;

import org.iot.auth.crypto.AuthCrypto;
import org.iot.auth.io.Buffer;
import org.iot.auth.io.BufferedString;
import sun.security.provider.X509Factory;

import java.io.IOException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;

/**
 * A class for a migration response message from an entity.
 * MigrationResp Format
 * {
 *      authId: /UInt32/,
 *      entityNonce: /Nonce/,
 *      authCert: /String/,
 *      authSignature: /Buffer/
 *  }
 * @author Hokeun Kim
 */
public class MigrationRespMessage extends IoTSPMessage {
    public MigrationRespMessage(int authID, Buffer entityNonce, X509Certificate authCertificate) {
        super(MessageType.MIGRATION_RESP_WITH_SIGN);
        this.authID = authID;
        this.entityNonce = entityNonce;
        this.authCertificate = authCertificate;
    }

    public Buffer serializeAndSign(AuthCrypto authCrypto) throws CertificateEncodingException, IOException {
        Buffer payload = new Buffer(4);
        payload.putInt(authID, 0);
        payload.concat(entityNonce);

        String stringAuthCertificate = X509Factory.BEGIN_CERT + "\n"
                + new Buffer(authCertificate.getEncoded()).toBase64().replaceAll("(.{64})", "$1\n")
                + "\n" + X509Factory.END_CERT;

        BufferedString bufferedStringAuthCertificate = new BufferedString(stringAuthCertificate);
        payload.concat(bufferedStringAuthCertificate.serialize());

        Buffer signature = authCrypto.signWithPrivateKey(payload);
        payload.concat(signature);
        this.payload = payload;
        return super.serialize();
    }

    private int authID;
    private Buffer entityNonce;
    private X509Certificate authCertificate;
}
