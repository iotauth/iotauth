#!/bin/bash

#directory constants
CA_DIR="ca"
CERTS_DIR="certs"
KS_DIR="keystores"
VAL_DAYS=730

mkdir -p $CA_DIR

openssl genrsa -out $CA_DIR/CAKey.pem 2048
openssl req -new -key $CA_DIR/CAKey.pem -sha256 -out $CA_DIR/CAReq.pem -subj "/C=US/ST=CA/L=Berkeley/O=EECS/OU=CertificateAuthority/CN=iotauth.org"
openssl x509 -req -in $CA_DIR/CAReq.pem -sha256 -extensions v3_ca -signkey $CA_DIR/CAKey.pem -out $CA_DIR/CACert.pem -days $VAL_DAYS

rm $CA_DIR/CAReq.pem
