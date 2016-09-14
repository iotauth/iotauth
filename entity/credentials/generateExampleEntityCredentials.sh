#!/bin/bash

#directory constants
CA_DIR="../../auth/credentials/ca"
CERTS_DIR="certs"
KEYS_DIR="keys"
VAL_DAYS=730


entity_cred_gen() {
	NET_NAME=$1
	FILE_PREFIX=$2
	CERT_PATH_PREFIX=$CERTS_DIR/$NET_NAME/$FILE_PREFIX
	KEY_PATH_PREFIX=$KEYS_DIR/$NET_NAME/$FILE_PREFIX
	ENTITY_NAME=$NET_NAME"."$2

	openssl genrsa -out $KEY_PATH_PREFIX"Key.pem" 2048
	openssl req -new -key $KEY_PATH_PREFIX"Key.pem" -sha256 -out $KEY_PATH_PREFIX"Req.pem" -subj "/C=US/ST=CA/L=Berkeley/O=EECS/OU="$NET_NAME"/CN="$ENTITY_NAME
	openssl x509 -req -in $KEY_PATH_PREFIX"Req.pem" -sha256 -extensions usr_cert -CA $CA_DIR/CACert.pem -CAkey $CA_DIR/CAKey.pem -CAcreateserial \
		-out $CERT_PATH_PREFIX"Cert.pem" -days $VAL_DAYS
	rm $KEY_PATH_PREFIX"Req.pem"
	if [[ $FILE_PREFIX == Pt* ]]
	then
		openssl pkcs8 -topk8 -inform PEM -outform DER -in $KEY_PATH_PREFIX"Key.pem" -out $KEY_PATH_PREFIX"Key.der" -nocrypt
		rm $KEY_PATH_PREFIX"Key.pem"
	fi
}

mkdir -p $CERTS_DIR/"net1"
mkdir -p $KEYS_DIR/"net1"

mkdir -p $CERTS_DIR/"net2"
mkdir -p $KEYS_DIR/"net2"

entity_cred_gen "net1" "Client"
entity_cred_gen "net1" "Server"
entity_cred_gen "net1" "PtClient"
entity_cred_gen "net1" "PtServer"
entity_cred_gen "net1" "PtPublisher"
entity_cred_gen "net1" "PtSubscriber"

entity_cred_gen "net2" "Client"
entity_cred_gen "net2" "Server"
entity_cred_gen "net2" "PtClient"
entity_cred_gen "net2" "PtServer"
entity_cred_gen "net2" "PtPublisher"
entity_cred_gen "net2" "PtSubscriber"
