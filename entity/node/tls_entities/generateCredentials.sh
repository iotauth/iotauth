#!/bin/bash

mkdir credentials

#directory constants
CA_DIR="credentials"
CERTS_DIR="credentials"
KS_DIR="keystores"
VAL_DAYS=730
KS_DIR="credentials"
HOST_NAME="localhost"

mkdir -p $CA_DIR

openssl genrsa -out $CA_DIR/CAKey.pem 2048
openssl req -new -key $CA_DIR/CAKey.pem -sha256 -out $CA_DIR/CAReq.pem -subj "/C=US/ST=CA/L=Berkeley/O=EECS/OU=CertificateAuthority/CN=iotauth.org"
openssl x509 -req -in $CA_DIR/CAReq.pem -sha256 -extensions v3_ca -signkey $CA_DIR/CAKey.pem -out $CA_DIR/CACert.pem -days $VAL_DAYS

rm $CA_DIR/CAReq.pem

#$1 is credential type (Internet of Entity)
auth_cred_gen() {
	FILE_PREFIX=$1
	openssl genrsa -out $KS_DIR/$FILE_PREFIX"Key.pem" 2048
	openssl req -new -key $KS_DIR/$FILE_PREFIX"Key.pem" -sha256 -out $KS_DIR/$FILE_PREFIX"Req.pem" -subj "/C=US/ST=CA/L=Berkeley/O=EECS/OU=Auth"$AUTH_ID"/CN="$HOST_NAME
	openssl x509 -req -in $KS_DIR/$FILE_PREFIX"Req.pem" -sha256 -extensions usr_cert -CA $CA_DIR/CACert.pem -CAkey $CA_DIR/CAKey.pem -CAcreateserial \
		-out $KS_DIR/$FILE_PREFIX"Cert.pem" -days $VAL_DAYS

	rm $KS_DIR/$FILE_PREFIX"Req.pem"
	rm $CA_DIR/CACert.srl
}

auth_cred_gen "Server" 
auth_cred_gen "Client" 
