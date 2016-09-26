#!/bin/bash

#directory constants
CA_DIR="ca"
CERTS_DIR="certs"
KS_DIR="keystores"
VAL_DAYS=730

if [ $# != 4 ]
then
	echo 'please provide ID, host name, CA/AUTH passwords (e.g., ./generateExampleAuthCredentials.sh 101 localhost ca_password auth_password)'
	exit
fi

AUTH_ID=$1
HOST_NAME=$2
CA_PASSWORD=$3
AUTH_PASSWORD=$4

echo 'Generating credentials for ID:' $AUTH_ID', Host name:' $HOST_NAME

mkdir -p $CERTS_DIR
mkdir -p $KS_DIR

#$1 is credential type (Internet of Entity)
auth_cred_gen() {
	FILE_PREFIX="Auth"$AUTH_ID$1
	openssl genrsa -out $KS_DIR/$FILE_PREFIX"Key.pem" 2048
	openssl req -new -key $KS_DIR/$FILE_PREFIX"Key.pem" -sha256 -out $KS_DIR/$FILE_PREFIX"Req.pem" -subj "/C=US/ST=CA/L=Berkeley/O=EECS/OU=Auth"$AUTH_ID"/CN="$HOST_NAME
	openssl x509 -passin pass:$CA_PASSWORD -req -in $KS_DIR/$FILE_PREFIX"Req.pem" -sha256 -extensions usr_cert -CA $CA_DIR/CACert.pem -CAkey $CA_DIR/CAKey.pem -CAcreateserial \
		-out $KS_DIR/$FILE_PREFIX"Cert.pem" -days $VAL_DAYS

	openssl pkcs12 -export -out $KS_DIR/$FILE_PREFIX".pfx" -inkey $KS_DIR/$FILE_PREFIX"Key.pem" -in $KS_DIR/$FILE_PREFIX"Cert.pem" -password pass:$AUTH_PASSWORD

	mv $KS_DIR/$FILE_PREFIX"Cert.pem" $CERTS_DIR/$FILE_PREFIX"Cert.pem"
	rm $KS_DIR/$FILE_PREFIX"Cert.pem"
	rm $KS_DIR/$FILE_PREFIX"Key.pem"
	rm $KS_DIR/$FILE_PREFIX"Req.pem"
	rm $CA_DIR/CACert.srl
}

auth_cred_gen "Internet" 
auth_cred_gen "Entity" 
auth_cred_gen "Database" 
