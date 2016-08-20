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

/**
 * Common file for example client and server entities.
 * @author Hokeun Kim
 */

"use strict";

// local variables
var SESSION_CIPHER_ALGO = 'AES-128-CBC';

var HS_NONCE_SIZE = 8;            // handshake nonce size

var SESSION_HASH_ALGO = 'SHA256';
var SEQ_NUM_SIZE = 8;

var crypto = require('crypto');
var net = require('net');
var fs = require('fs');
var util = require('util');

var sleep =require('sleep');        // for testing

var common = require('../common/common');

exports.commState = {
    IDLE: 0,
    HANDSHAKE_1_SENT: 1,
    HANDSHAKE_2_SENT: 2,
    HANDSHAKE_3_SENT: 3,
    IN_COMM: 4                    // Session message
};

// encryption and decryption for session messages
exports.encryptSessionMessage = function(buf, sessionKeyVal) {
    return common.symmetricEncryptWithHash(buf, sessionKeyVal,
        SESSION_CIPHER_ALGO, SESSION_HASH_ALGO);
};

exports.decryptSessionMessage = function(buf, sessionKeyVal) {
    var ret = common.symmetricDecryptWithHash(buf, sessionKeyVal,
        SESSION_CIPHER_ALGO, SESSION_HASH_ALGO);

    if (!ret.hashOk) {
        console.log('Error: session message digest does not match!')
        return;
    }

    return ret.data;
};

/*
    SecureMqtt Format
    {
        keyId: /UIntBE/, // S_KEY_ID_SIZE Bytes - in plain text
        seqNum: /UIntBE/, SEQ_NUM_SIZE Bytes - encrypted
        data: /Buffer/, // data - encrypted
    }
*/
exports.encryptSerializeSecureqMqtt = function(obj, sessionKey) {
    if (obj.seqNum == undefined || obj.data == undefined) {
        console.log('Error: SecureMqtt seqNum or data is missing.');
        return;
    }
    var seqNumBuf = new Buffer(SEQ_NUM_SIZE);
    seqNumBuf.writeUIntBE(obj.seqNum, 0, SEQ_NUM_SIZE);
    var buf = Buffer.concat([seqNumBuf, obj.data]);
    var encBuf = exports.encryptSessionMessage(buf, sessionKey.val);
    var keyIdBuf = new Buffer(common.S_KEY_ID_SIZE);
    keyIdBuf.writeUIntBE(sessionKey.id, 0, common.S_KEY_ID_SIZE);

    return Buffer.concat([keyIdBuf, encBuf]);
}

exports.parseDecryptSecureMqtt = function(buf, sessionKeyList) {
    var keyId = buf.readUIntBE(0, common.S_KEY_ID_SIZE);
    // find id
    for (var i = 0; i < sessionKeyList.length; i++) {
        if (sessionKeyList[i].id == keyId) {
            var decBuf = exports.decryptSessionMessage(buf.slice(common.S_KEY_ID_SIZE),
                sessionKeyList[i].val);
            var seqNum = decBuf.readUIntBE(0, SEQ_NUM_SIZE);
            var data = decBuf.slice(SEQ_NUM_SIZE);
            return {seqNum: seqNum, data:data};
        }
    }
    console.log('cannot find the session key id: ' + keyId);
}

// generate handshake nonce
exports.generateHSNonce = function() {
    return crypto.randomBytes(HS_NONCE_SIZE);
};

/*
    Handshake Format
    {
        nonce: /Buffer/, // encrypted, may be undefined
        replyNonce: /Buffer/, // encrypted, may be undefined
    }
*/
exports.serializeHandshake = function(obj) {
    if (obj.nonce == undefined && obj.replyNonce == undefined) {
        console.log('Error: handshake should include at least on nonce.');
        return;
    }

    var buf = new Buffer(1 + HS_NONCE_SIZE * 2);

    // indicates existance of nonces
    var indicator = 0;
    if (obj.nonce != undefined) {
        indicator += 1;
        obj.nonce.copy(buf, 1);
    }
    if (obj.replyNonce != undefined) {
        indicator += 2;
        obj.replyNonce.copy(buf, 1 + HS_NONCE_SIZE);
    }

    buf.writeUInt8(indicator, 0);

    return buf;
};

// buf should be just the unencrypted part
exports.parseHandshake = function(buf) {
    var obj = {};
    var indicator = buf.readUInt8(0);
    if ((indicator & 1) != 0) {
        // nonce exists
        obj.nonce = buf.slice(1, 1 + HS_NONCE_SIZE);
    }
    if ((indicator & 2) != 0) {
        // replayNonce exists
        obj.replyNonce = buf.slice(1 + HS_NONCE_SIZE, 1 + HS_NONCE_SIZE * 2);
    }
    return obj;
};

/*
    SecureSessionMessage Format
    {
        SeqNum: /Buffer/, // UIntBE, SEQ_NUM_SIZE Bytes
        data: /Buffer/,
    }
*/
exports.serializeEncryptSessionMessage = function(obj, sessionKeyVal) {
    if (obj.seqNum == undefined || obj.data == undefined) {
        console.log('Error: Secure session message seqNum or data is missing.');
        return;
    }
    var seqNumBuf = new Buffer(SEQ_NUM_SIZE);
    seqNumBuf.writeUIntBE(obj.seqNum, 0, SEQ_NUM_SIZE);
    var buf = Buffer.concat([seqNumBuf, obj.data]);
    return exports.encryptSessionMessage(buf, sessionKeyVal);
};

exports.parseDecryptSessionMessage = function(buf, sessionKeyVal) {
        var decBuf = exports.decryptSessionMessage(buf, sessionKeyVal);
        var seqNum = decBuf.readUIntBE(0, SEQ_NUM_SIZE);
        var data = decBuf.slice(SEQ_NUM_SIZE);
        return {seqNum: seqNum, data: data};
};

exports.sendSessionKeyReq = function(senderName, purpose, numKeys, authInfo, privateKey,
    distributionKey, sessionKeyRespHandler) {
    var client = net.connect({host: authInfo.host,port: authInfo.port}, 
        function() {
            console.log('connected to auth! from local port ' + client.localPort);
    });
    var myNonce;
    var expectingMoreData = false;
    var obj;
    client.on('data', function(data) {
        if (!expectingMoreData) {
            obj = common.parseIoTSP(data);
            if (obj.payload.length < obj.payloadLen) {
                expectingMoreData = true;
                console.log('more data will come. current: ' + obj.payload.length
                    + ' expected: ' + obj.payloadLen);
            }
        }
        else {
            obj.payload = Buffer.concat([obj.payload, data]);
            if (obj.payload.length ==  obj.payloadLen) {
                expectingMoreData = false;
            }
            else {
                console.log('more data will come. current: ' + obj.payload.length
                    + ' expected: ' + obj.payloadLen);
            }
        }

        // Test code
        //sleep.sleep(1);

        if (expectingMoreData) {
            // do not process the packet yet
            return;
        }
        else if (obj.msgType == common.msgType.AUTH_HELLO) {
            console.log('received auth hello!');
            obj = common.parseAuthHello(obj.payload);
            console.log(obj);
            myNonce = common.generateAuthNonce();

            var sessionKeyReq = {
                nonce: myNonce,
                replyNonce: obj.nonce,
                numKeys: numKeys,
                sender: senderName,
                purpose: purpose
            };

            var msg;
            if (distributionKey == null || distributionKey.absValidity < new Date()) {
                if (distributionKey != null) {
                    console.log('current distribution key expired, '
                        + 'requesting new distribution key as well...');
                }
                var sessionKeyReqBuf = common.serializeSessionKeyReq(sessionKeyReq);
                msg = {
                    msgType: common.msgType.SESSION_KEY_REQ_IN_PUB_ENC,
                    payload: common.publicEncryptAndSign(
                        sessionKeyReqBuf, authInfo.publicKey, privateKey)
                };
                // TEST: generating error in signature
                //msg.payload.writeUInt8(12, msg.payload.length - 12);
            }
            else {
                msg = {
                    msgType: common.msgType.SESSION_KEY_REQ,
                    payload: common.serializeSessionKeyReqWithDistributionKey(senderName,
                        sessionKeyReq, distributionKey.val)
                };
            }
            
            var buf = common.serializeIoTSP(msg);
            client.write(buf);
        }
        else if (obj.msgType == common.msgType.SESSION_KEY_RESP_WITH_DIST_KEY) {
            console.log('received session key response with distribution key attached!');

            var distributionKeyBuf = obj.payload.slice(0, common.getPublicEncryptedAndSignedMessageSize());
            var sessionKeyBuf = obj.payload.slice(common.getPublicEncryptedAndSignedMessageSize());

            var ret = common.verifySignedData(distributionKeyBuf, authInfo.publicKey);
            if (!ret.verified) {
                console.log('auth signature NOT verified');
                return;
            }
            console.log('auth signature verified');
            var decBuf = common.privateDecrypt(ret.buf, privateKey);
            var receivedDistKey = common.parseDistributionKey(decBuf);

            decBuf = common.decryptDistributionMessage(sessionKeyBuf, receivedDistKey.val);

            var sessionKeyResp = common.parseSessionKeyResp(decBuf);
            console.log('replyNonce in sessionKeyResp: ' + util.inspect(sessionKeyResp.replyNonce));
            if (!myNonce.equals(sessionKeyResp.replyNonce)) {
                console.log('auth nonce NOT verified');
                return;
            }
            console.log('auth nonce verified');

            sessionKeyRespHandler(sessionKeyResp.sessionKeyList, receivedDistKey);
            client.end();
        }
        else if (obj.msgType == common.msgType.SESSION_KEY_RESP) {
			console.log('received session key response encrypted with distribution key');

            var decBuf = common.decryptDistributionMessage(obj.payload, distributionKey.val);

            var sessionKeyResp = common.parseSessionKeyResp(decBuf);
            console.log('replyNonce in sessionKeyResp: ' + util.inspect(sessionKeyResp.replyNonce));
            if (!myNonce.equals(sessionKeyResp.replyNonce)) {
                console.log('auth nonce NOT verified');
                return;
            }
            console.log('auth nonce verified');

            sessionKeyRespHandler(sessionKeyResp.sessionKeyList, null);
            client.end();
        }
    });
    client.on('end', function() {
        console.log('disconnected from auth');
    });
};

exports.loadEntityConfig = function(inputFileName) {
    console.log('loading from config file: ' + inputFileName);
    var entityInfo;
    var authInfo;
    var targetServerInfoList = [];
    var listeningServerInfo;
    var fileLines = fs.readFileSync(inputFileName, 'utf8').split('\n');
    for (var i = 0; i < fileLines.length; i++) {
        var line = fileLines[i].trim();
        if (line.startsWith('//') || line.length == 0) {
            continue;
        }
        var tokens = line.split(/[\s,]+/);
        if (tokens.length == 0) {
            continue;
        }
        if (tokens[0] == 'entityInfo') {
            if (tokens.length != 4) {
                throw 'error loading entityInfo: wrong number of properties!';
            }
            entityInfo = {
                name: tokens[1],
                group: tokens[2],
                privateKey: fs.readFileSync(tokens[3])
            };
        }
        else if (tokens[0] == 'authInfo') {
            if (tokens.length != 5) {
                throw 'error loading authInfo: wrong number of properties!';
            }
            authInfo = {
                id: parseInt(tokens[1]),
                host: tokens[2],
                port: parseInt(tokens[3]),
                publicKey: fs.readFileSync(tokens[4])
            };
        }
        else if (tokens[0] == 'targetServerInfo') {
            if (tokens.length != 4) {
                throw 'error loading targetServerInfo: wrong number of properties!';
            }
            targetServerInfoList.push({
                name: tokens[1],
                host: tokens[2],
                port: parseInt(tokens[3])
            });
        }
        else if (tokens[0] == 'listeningServerInfo') {
            if (tokens.length != 3) {
                throw 'error loading listeningServerInfo: wrong number of properties!';
            }
            listeningServerInfo = {
                host: tokens[1],
                port: parseInt(tokens[2])
            };
        }
        else {
            throw 'Configuration item is NOT recognized! ' + tokens[0];
        }
    }
    return {
        entityInfo: entityInfo,
        authInfo: authInfo,
        targetServerInfoList: targetServerInfoList,
        listeningServerInfo: listeningServerInfo
    };
};
