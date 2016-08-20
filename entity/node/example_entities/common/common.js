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
 * Global common file for example entities.
 * @author Hokeun Kim
 */

"use strict";

var crypto = require('crypto');
var net = require('net');
var constants = require('constants');

// global variables
exports.DIST_CIPHER_KEY_SIZE = 16;                // 256 bit key = 32 bytes
exports.SESSION_CIPHER_KEY_SIZE = 16;            // 128 bit key = 16 bytes
exports.S_KEY_ID_SIZE = 8;

// local variables

var AUTH_NONCE_SIZE = 8;        // auth nonce size

var SIGN_ALGO = 'RSA-SHA256';

// crypto for key distribution messages (SESSION_KEY_REQ, SESSION_KEY_RESP)
var DIST_CIPHER_ALGO = 'AES-128-CBC';
var DIST_HASH_ALGO = 'SHA256';

var RSA_KEY_SIZE = 256;         // 2048 bit
var RSA_PADDING = constants.RSA_PKCS1_PADDING;


var ABS_VALIDITY_SIZE = 6;
var REL_VALIDITY_SIZE = 6;

exports.msgType = {
    AUTH_HELLO: 0,
    AUTH_SESSION_KEY_REQ: 10,
    AUTH_SESSION_KEY_RESP: 11,
    SESSION_KEY_REQ_IN_PUB_ENC: 20,
    SESSION_KEY_RESP_WITH_DIST_KEY: 21,    // Includes distribution message (session keys)
    SESSION_KEY_REQ: 22,        // Distribution message
    SESSION_KEY_RESP: 23,        // Distribution message
    SKEY_HANDSHAKE_1: 30,
    SKEY_HANDSHAKE_2: 31,
    SKEY_HANDSHAKE_3: 32,
    SECURE_COMM_MSG: 33,
    FIN_SECURE_COMM: 34,
    SECURE_PUB: 40
};

// generate auth hello nonce
exports.generateAuthNonce = function() {
    return crypto.randomBytes(AUTH_NONCE_SIZE);
};

/*
    AuthHello Format
    {
        authId: /UInt32BE/,    // identifier of auth (when auths are replicated)
        nonce: /Buffer/
    }
*/
exports.serializeAuthHello = function(obj) {
    if (obj.authId == undefined || obj.nonce == undefined) {
        console.log('Error: AuthHello authId or nonce is missing.');
        return;
    }
    var buf = new Buffer(4 + AUTH_NONCE_SIZE);
    buf.writeUInt32BE(obj.authId, 0);
    obj.nonce.copy(buf, 4);
    return buf;
};
exports.parseAuthHello = function(buf) {
    var authId = buf.readUInt32BE(0);
    var nonce = buf.slice(4, 4 + AUTH_NONCE_SIZE);
    return {authId: authId, nonce: nonce};
};

function getCipherIvSize(cipherAlgorithm) {
    if (cipherAlgorithm.toUpperCase().startsWith('AES')) {
        return 16;
    }
    else if (cipherAlgorithm.toUpperCase().startsWith('DES')) {
        return 8;
    }
    else {
        console.log('Error: cipher NOT supported');
        return -1;
    }
};

function getHashSize(hashAlgorithm) {
    if (hashAlgorithm.toUpperCase() === 'SHA256') {
        return 32;
    }
    if (hashAlgorithm.toUpperCase() === 'SHA1') {
        return 20;
    }
};

exports.symmetricEncryptWithHash = function(buf, keyVal, cipherAlgorithm, hashAlgorithm) {
    var hash = crypto.createHash(hashAlgorithm);
    hash.update(buf);
    var digest = hash.digest();

    // TEST: generating error in encrypted data
    //digest.writeUInt8(4, digest.length - 4);

    // concat digest and buf
    buf = Buffer.concat([buf, digest]);

    var iv = new Buffer(crypto.randomBytes(getCipherIvSize(cipherAlgorithm)));
    var cipher = crypto.createCipheriv(cipherAlgorithm, keyVal, iv);

    var enc = cipher.update(buf);
    enc = Buffer.concat([enc, cipher.final()]);
    // it is ok to send iv in clear text
    return Buffer.concat([iv, enc]);
};

// returns {hashOk: bool, data: Buffer}
exports.symmetricDecryptWithHash = function(buf, keyVal, cipherAlgorithm, hashAlgorithm) {
    var ivSize = getCipherIvSize(cipherAlgorithm);
    var iv = buf.slice(0, ivSize);
    var decipher = crypto.createDecipheriv(cipherAlgorithm, keyVal, iv);

    var dec = decipher.update(buf.slice(ivSize));
    dec = Buffer.concat([dec, decipher.final()]);

    // separate digest from buf
    var hashSize = getHashSize(hashAlgorithm);
    var data = dec.slice(0, dec.length - hashSize);
    var digest = dec.slice(dec.length - hashSize);

    // verify digest
    var hash = crypto.createHash(hashAlgorithm);
    hash.update(data);
    var calculatedDigest = hash.digest();
    var hashOk = digest.equals(calculatedDigest);

    return {
        hashOk : hashOk,
        data : data
    };
};

exports.encryptDistributionMessage = function(buf, distributionKeyVal) {
    return exports.symmetricEncryptWithHash(buf, distributionKeyVal,
        DIST_CIPHER_ALGO, DIST_HASH_ALGO);
};

exports.decryptDistributionMessage = function(buf, distributionKeyVal) {
    var ret = exports.symmetricDecryptWithHash(buf, distributionKeyVal,
        DIST_CIPHER_ALGO, DIST_HASH_ALGO);
    if (!ret.hashOk) {
        console.log('Error: distribution message digest does not match!')
        return;
    }
    return ret.data;
};
/*
    SessionKeyReq Format
    {
        nonce: /Buffer/, (AUTH_NONCE_SIZE)
        replyNonce:    /Buffer/, (AUTH_NONCE_SIZE)
        numKeys: /UInt32BE/,
        sender: /string/, (senderLen UInt8)
        purpose: JSON
    }
*/
exports.serializeSessionKeyReq = function(obj) {
    if (obj.nonce == undefined || obj.replyNonce == undefined || obj.sender == undefined
        || obj.purpose == undefined || obj.numKeys == undefined) {
        console.log('Error: SessionKeyReq nonce or replyNonce '
            + 'or purpose or numKeys is missing.');
        return;
    }
    var buf = new Buffer(AUTH_NONCE_SIZE * 2 + 5);
    obj.nonce.copy(buf, 0);
    obj.replyNonce.copy(buf, AUTH_NONCE_SIZE);
    buf.writeUInt32BE(obj.numKeys, AUTH_NONCE_SIZE * 2);
    buf.writeUInt8(obj.sender.length, AUTH_NONCE_SIZE * 2 + 4);

    var senderBuf = new Buffer(obj.sender);
    var purposeBuf = new Buffer(JSON.stringify(obj.purpose));
    return Buffer.concat([buf, senderBuf, purposeBuf]);
};
exports.parseSessionKeyReq = function(buf) {
    var nonce = buf.slice(0, AUTH_NONCE_SIZE);
    var replyNonce = buf.slice(AUTH_NONCE_SIZE, AUTH_NONCE_SIZE * 2);
    var numKeys = buf.readUInt32BE(AUTH_NONCE_SIZE * 2);
    var senderLen = buf.readUInt8(AUTH_NONCE_SIZE * 2 + 4);

    var senderStartIdx = AUTH_NONCE_SIZE * 2 + 5;

    var sender = buf.toString('utf8', senderStartIdx, senderStartIdx + senderLen);
    var purpose = JSON.parse(buf.toString('utf8', senderStartIdx + senderLen));
    return {nonce: nonce, replyNonce: replyNonce, numKeys: numKeys, sender: sender, purpose: purpose};
};

/*
    DistributionKey Format
    {
        absValidity: /UIntBE, ABS_VALIDITY_SIZE Bytes, Date() format/, // for absolute validity period
        val: /Buffer/
    }
*/
exports.serializeDistributionKey = function(obj) {
    if (obj.absValidity == undefined || obj.val == undefined) {
        console.log('Error: distribution key val or validity is missing.');
        return;
    }
    var buf = new Buffer(ABS_VALIDITY_SIZE);
    buf.writeUIntBE(obj.absValidity.valueOf(), 0, ABS_VALIDITY_SIZE);
    return Buffer.concat([buf, obj.val]);
};

exports.parseDistributionKey = function(buf) {
    var absValidity = new Date(buf.readUIntBE(0, ABS_VALIDITY_SIZE));
    var keyVal = buf.slice(ABS_VALIDITY_SIZE, ABS_VALIDITY_SIZE + exports.DIST_CIPHER_KEY_SIZE);
    return {val: keyVal, absValidity: absValidity};
};

/*
    SessionKey Format
    {
        id: /UIntBE, S_KEY_ID_SIZE Bytes/,
        absValidity: /UIntBE, ABS_VALIDITY_SIZE Bytes, Date() format/, // for absolute validity period
        relValidity: /UIntBE, REL_VALIDITY_SIZE Bytes, integer in millisecons/, // for relative validity period
        val: /Buffer/
    }
*/
var SESSION_KEY_BUF_SIZE = exports.S_KEY_ID_SIZE + ABS_VALIDITY_SIZE + REL_VALIDITY_SIZE 
    + exports.SESSION_CIPHER_KEY_SIZE;

exports.serializeSessionKey = function(obj) {
    if (obj.id == undefined || obj.val == undefined
        || obj.absValidity == undefined || obj.relValidity == undefined) {
        console.log('Error: session key id or val or validity is missing.');
        return;
    }
    var buf = new Buffer(exports.S_KEY_ID_SIZE + ABS_VALIDITY_SIZE + REL_VALIDITY_SIZE);
    buf.writeUIntBE(obj.id, 0, exports.S_KEY_ID_SIZE);
    buf.writeUIntBE(obj.absValidity.valueOf(), exports.S_KEY_ID_SIZE, ABS_VALIDITY_SIZE);
    buf.writeUIntBE(obj.relValidity, exports.S_KEY_ID_SIZE + ABS_VALIDITY_SIZE, REL_VALIDITY_SIZE);
    return Buffer.concat([buf, obj.val]);
};

exports.parseSessionKey = function(buf) {
    var keyId = buf.readUIntBE(0, exports.S_KEY_ID_SIZE);
    var absValidity = new Date(buf.readUIntBE(exports.S_KEY_ID_SIZE, ABS_VALIDITY_SIZE));
    var relValidity = buf.readUIntBE(exports.S_KEY_ID_SIZE + ABS_VALIDITY_SIZE, REL_VALIDITY_SIZE);
    var curIndex =  exports.S_KEY_ID_SIZE + ABS_VALIDITY_SIZE + REL_VALIDITY_SIZE;
    var keyVal = buf.slice(curIndex, curIndex + exports.SESSION_CIPHER_KEY_SIZE);
    return {id: keyId, val: keyVal, absValidity: absValidity, relValidity: relValidity};
};

/*
    SessionKeyReq (encrypted with Distribution Key) Format
    {
    	sender: /string/, (senderLen UInt8) should be plain text so that Auth can find distribution key
		enBuf: /Buffer/ SessionKeyReq (nonce included) encrypted with distribution key
    }
*/
exports.serializeSessionKeyReqWithDistributionKey = function(senderName,
    sessionKeyReq, distributionKeyVal) {
    var sessionKeyReqBuf = exports.serializeSessionKeyReq(sessionKeyReq);
    var encBuf = exports.encryptDistributionMessage(sessionKeyReqBuf, distributionKeyVal);

    // TEST: generating error in encrypted data
    //encBuf.writeUInt8(12, encBuf.length - 12);

    var senderBuf = new Buffer(senderName);
    var lengthBuf = new Buffer(1);
    lengthBuf.writeUInt8(senderBuf.length);
    return Buffer.concat([lengthBuf, senderBuf, encBuf]);
};

exports.parseSessionKeyReqWithDistributionKey = function(buf) {
    var senderLength = buf.readUInt8(0);
    var sender = buf.slice(1, 1 + senderLength).toString();
    var encBuf = buf.slice(1 + senderLength);
    return {sender: sender, encBuf: encBuf};
}

function serializeStringParam(stringParam) {
    var result;
    if (stringParam == null) {
        result = new Buffer(1);
        result.writeUInt8(0);
    }
    else {
        result = new Buffer(stringParam.length + 1);
        result.writeUInt8(stringParam.length);
        result.write(stringParam, 1);
    }
    return result;
};

function parseStringParam(buf, offset) {
    var len = buf.readUInt8(offset);
    if (len == 0) {
        return {len: 1, str: null};
    }
    var str = buf.toString('utf8', offset + 1, offset + 1 + len);
    return {len: len + 1, str: str};
};

/*
    SessionKeyResp Format
    {
        replyNonce:    /Buffer/,
        cryptoSpec:    /JSON/ {cipher: 'AES-128-CBC', hash: 'SHA256'} stringified, 
        sessionKeyList: /UInt32BE for length and List of SessionKey's/
        // TODO: who you're talking to? if req included keyId=?
    }
*/
exports.serializeSessionKeyResp = function(obj) {
    if (obj.replyNonce == undefined || obj.cryptoSpec == undefined || obj.sessionKeyList == undefined) {
        console.log('Error: SessionKeyResp replyNonce, cryptoSpec or sessionKeyList is missing.');
        return;
    }
    var nonceBuf = new Buffer(AUTH_NONCE_SIZE);
    obj.replyNonce.copy(nonceBuf, 0);

    var cryptoSpecBuf = serializeStringParam(JSON.stringify(obj.cryptoSpec));

    var sessionKeyListLengthBuf = new Buffer(4);
    sessionKeyListLengthBuf.writeUInt32BE(obj.sessionKeyList.length, 0);

    var buf = Buffer.concat([nonceBuf, cryptoSpecBuf, sessionKeyListLengthBuf]);
    for (var i = 0; i < obj.sessionKeyList.length; i++) {
        buf = Buffer.concat([buf,
            exports.serializeSessionKey(obj.sessionKeyList[i])]);
    }
    return buf;
};

exports.parseSessionKeyResp = function(buf) {
    var replyNonce = buf.slice(0, AUTH_NONCE_SIZE);
    var bufIdx = AUTH_NONCE_SIZE;

    var ret = parseStringParam(buf, bufIdx);
    var cryptoSpec = JSON.parse(ret.str);
    bufIdx += ret.len;

    var sessionKeyListLength = buf.readUInt32BE(bufIdx);
    bufIdx += 4;

    var sessionKeyList = [];
    for (var i = 0; i < sessionKeyListLength; i++) {
        var sessionKey = exports.parseSessionKey(buf.slice(bufIdx));
        sessionKeyList.push(sessionKey);
        bufIdx += SESSION_KEY_BUF_SIZE;
    }
    return {replyNonce: replyNonce, cryptoSpec: cryptoSpec, sessionKeyList: sessionKeyList};
};

// verialbe length integer encoding
function numToVarLenInt(num) {
    var buf = new Buffer(0);
    while (num > 127) {
        var extraBuf = new Buffer(1);
        extraBuf.writeUInt8(128 | num & 127);
        buf = Buffer.concat([buf, extraBuf]);
        num >>= 7;
    }
    var extraBuf = new Buffer(1);
    extraBuf.writeUInt8(num);
    buf = Buffer.concat([buf, extraBuf]);
    return buf;
};

function varLenIntToNum(buf, offset) {
    var num = 0;
    for (var i = 0; i < buf.length && i < 5; i++) {
        num |= (buf[offset + i] & 127) << (7 * i);
        if ((buf[offset + i] & 128) == 0) {
            return {num: num, bufLen: i + 1};
            break;
        }
    }
    return null;
};

/*
    IoTSP (IoT Secure Protocol) Message
    {
        msgType: /UInt8/,
        payloadLen: /variable-length integer encoding/
        payload: /Buffer/
    }
*/
exports.serializeIoTSP = function(obj) {
    if (obj.msgType == undefined || obj.payload == undefined) {
        console.log('Error: IoTSP msgType or payload is missing.');
        return;
    }
    var msgTypeBuf = new Buffer(1);
    msgTypeBuf.writeUInt8(obj.msgType, 0);
    var payLoadLenBuf = numToVarLenInt(obj.payload.length);
    return Buffer.concat([msgTypeBuf, payLoadLenBuf, obj.payload]);
};

exports.parseIoTSP = function(buf) {
    var msgTypeVal = buf.readUInt8(0);
    var ret = varLenIntToNum(buf, 1);
    var payloadVal = buf.slice(1 + ret.bufLen);
    return {msgType: msgTypeVal, payloadLen: ret.num, payload: payloadVal};
};

/*
    SignedMsg Format
    {
        data: /Buffer/,
        signature: /Buffer/   RSA_KEY_SIZE
    }
*/
exports.signAndAttach = function(buf, privateKey) {
    var sign = crypto.createSign(SIGN_ALGO);
    sign.update(buf);
    var signature = sign.sign(privateKey);

    return Buffer.concat([buf, signature]);
};

// returns {signature: buffer, data: buffer}
exports.parseSignedData = function(buf) {
    var data = buf.slice(0, buf.length - RSA_KEY_SIZE);
    var signature = buf.slice(buf.length - RSA_KEY_SIZE);
    return {signature:signature, data: data};
};

// returns {verified: bool, buf: Buffer}
exports.verifySignedData = function(buf, publicKey) {
    var ret = exports.parseSignedData(buf);
    var verifier = crypto.createVerify(SIGN_ALGO);
    verifier.update(ret.data);
    if (!verifier.verify(publicKey, ret.signature, 'hex')) {
        return {verified: false};
    }
    return {verified: true, buf: ret.data};
};

//var MAX_PUB_ENC_BYTES = RSA_KEY_SIZE - 42; // 256 Bytes - 42 Bytes OAEP Padding = max 214 Bytes
var MAX_PUB_ENC_BYTES = RSA_KEY_SIZE - 11; // 256 Bytes - 11 Bytes PKCS#1 Padding = max 245 Bytes

exports.publicEncryptAndSign = function(buf, pubDest, privateKey) {
    if (buf.length <= MAX_PUB_ENC_BYTES) {
        var encBuf = crypto.publicEncrypt({key: pubDest, padding: RSA_PADDING}, buf);
        return exports.signAndAttach(encBuf, privateKey);
    }
    else {
        /*
        console.log('Error| public key encryption data must no be longer than '
            + MAX_PUB_ENC_BYTES + ' bytes.');
        return;
        */
        var symEncKey = new Buffer(exports.DIST_CIPHER_KEY_SIZE);
        var pubEncBytes = MAX_PUB_ENC_BYTES - symEncKey.length;
        var tempBuf = Buffer.concat([symEncKey, buf.slice(0, pubEncBytes)]);

        var pubEncBuf = crypto.publicEncrypt({key: pubDest, padding: RSA_PADDING}, tempBuf);

        var symEncBuf = exports.symmetricEncryptWithHash(buf.slice(pubEncBytes), symEncKey,
            DIST_CIPHER_ALGO, DIST_HASH_ALGO);
        return exports.signAndAttach(Buffer.concat([pubEncBuf, symEncBuf]), privateKey);
    }
};

exports.getPublicEncryptedAndSignedMessageSize = function() {
    return RSA_KEY_SIZE * 2;
}

exports.privateDecrypt = function(buf, privateKey) {
    if (buf.length <= RSA_KEY_SIZE) {
        return crypto.privateDecrypt({key: privateKey, padding: RSA_PADDING}, buf);
    }
    else {
        /*
        console.log('Error| data to be private decrypted must no be longer than '
            + RSA_KEY_SIZE + ' bytes.');
        return;
        */
        var tempBuf = crypto.privateDecrypt({key: privateKey, padding: RSA_PADDING},
            buf.slice(0, RSA_KEY_SIZE));
        var symDecKey = tempBuf.slice(0, exports.DIST_CIPHER_KEY_SIZE);
        var pubDecBuf = tempBuf.slice(symDecKey.length);

        var symDecBuf = exports.symmetricDecryptWithHash(buf.slice(RSA_KEY_SIZE), symDecKey,
            DIST_CIPHER_ALGO, DIST_HASH_ALGO);
        return Buffer.concat([pubDecBuf, symDecBuf.data]);
    }
};
/*
    AuthSessionKeyReq Format
    {
        requestingAuthId: /UInt32BE/,
        numKeys: /UInt32BE/,
        senderName: /string/, (senderLen UInt8 = 0 if N/A)
        senderGroup: /string/, (senderLen UInt8 = 0 if N/A)
        purpose: JSON (senderLen UInt8)
    }
*/
exports.serializeAuthSessionKeyReq = function(obj)
{
    var buf = new Buffer(4 + 4);
    buf.writeUInt32BE(obj.requestingAuthId);
    buf.writeUInt32BE(obj.numKeys, 4);

    return Buffer.concat([
        buf,
        serializeStringParam(obj.senderName),
        serializeStringParam(obj.senderGroup),
        serializeStringParam(JSON.stringify(obj.purpose))
    ]);
};

exports.parseAuthSessionKeyReq = function(buf)
{
    var idx = 0;
    var requestingAuthId = buf.readUInt32BE(idx);
    idx += 4;
    var numKeys = buf.readUInt32BE(idx);
    idx += 4;

    var ret = parseStringParam(buf, idx);
    var senderName = ret.str;
    idx += ret.len;

    ret = parseStringParam(buf, idx);
    var senderGroup = ret.str;
    idx += ret.len;

    ret = parseStringParam(buf, idx);
    var purpose = JSON.parse(ret.str);
    idx += ret.len;

    return {
        requestingAuthId: requestingAuthId,
        numKeys: numKeys,
        senderName: senderName,
        senderGroup: senderGroup,
        purpose: purpose
    };
};

/*
    AuthSessionKeyResp Format
    {
        cryptoSpec: JSON
        sessionKeyList: /UInt32BE for length and List of SessionKey's/
        // TODO: who you're talking to? if req included keyId=?
    }
*/
exports.serializeAuthSessionKeyResp = function(obj) {
    if (obj.cryptoSpec == undefined || obj.sessionKeyList == undefined) {
        console.log('Error: AuthSessionKeyResp replyNonce, cryptoSpec or sessionKeyList is missing.');
        return;
    }
    var cryptoSpecBuf = serializeStringParam(JSON.stringify(obj.cryptoSpec));

    var sessionKeyListLengthBuf = new Buffer(4);
    sessionKeyListLengthBuf.writeUInt32BE(obj.sessionKeyList.length, 0);
    var buf = Buffer.concat([cryptoSpecBuf, sessionKeyListLengthBuf]);
    for (var i = 0; i < obj.sessionKeyList.length; i++) {
        buf = Buffer.concat([buf,
            exports.serializeSessionKey(obj.sessionKeyList[i])]);
    }
    return buf;
};

exports.parseAuthSessionKeyResp = function(buf) {
    var ret = parseStringParam(buf, 0);
    var cryptoSpec = JSON.parse(ret.str);
    var bufIdx = ret.len;

    var sessionKeyListLength = buf.readUInt32BE(bufIdx);

    var sessionKeyList = [];
    bufIdx += 4;
    for (var i = 0; i < sessionKeyListLength; i++) {
        var sessionKey = exports.parseSessionKey(buf.slice(bufIdx));
        sessionKeyList.push(sessionKey);
        bufIdx += SESSION_KEY_BUF_SIZE;
    }
    return {cryptoSpec: cryptoSpec, sessionKeyList: sessionKeyList};
};
 
exports.parseTimePeriod = function(str) {
    str = str.replace(/sec/gi, '1000');
    str = str.replace(/min/gi, '1000*60');
    str = str.replace(/hour/gi, '1000*60*60');
    str = str.replace(/day/gi, '1000*60*60*24');
    str = str.replace(/week/gi, '1000*60*60*24*7');
    return eval(str);
};
