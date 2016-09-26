#!/bin/bash

#directory constants
CA_DIR="ca"
CERTS_DIR="certs"
KS_DIR="keystores"
VAL_DAYS=730

if [ $# != 1 ]
then
	echo 'please provide CA password (e.g., ./generateCACredentials.sh ca_password)'
	exit
fi

CA_PASSWORD=$1

mkdir -p $CA_DIR

openssl genrsa -passout pass:$CA_PASSWORD -out $CA_DIR/CAKey.pem -aes128 2048
openssl req -passin pass:$CA_PASSWORD -passout pass:$CA_PASSWORD -new -key $CA_DIR/CAKey.pem -sha256 -out $CA_DIR/CAReq.pem -subj "/C=US/ST=CA/L=Berkeley/O=EECS/OU=CertificateAuthority/CN=iotauth.org"
openssl x509 -passin pass:$CA_PASSWORD -req -in $CA_DIR/CAReq.pem -sha256 -extensions v3_ca -signkey $CA_DIR/CAKey.pem -out $CA_DIR/CACert.pem -days $VAL_DAYS

rm $CA_DIR/CAReq.pem
