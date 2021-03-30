#!/bin/bash

# Author: Hokeun Kim
# Script for generating credentials of example entities (public/private key pairs, symmetric crypto keys).

echo "*SCRIPT- generateExampleAuthCredentials.sh: For generating credentials for example entities (public/private key pairs, symmetric crypto keys)"

#directory constants
CA_DIR="../../auth/credentials/ca"
CERTS_DIR="certs"
KEYS_DIR="keys"
VAL_DAYS=730

if [ $# != 2 ]
then
	echo "Please provide required arguments (1. number of networks, 2. CA's password)"
	echo 'Usage: ./generateExampleAuthCredentials.sh num_nets ca_password'
	exit
fi

# number of networks (Auths)
NUM_NETS=$1
CA_PASSWORD=$2

entity_cred_gen() {
	NET_ID=$1
	NET_NAME="net"$NET_ID
	FILE_PREFIX="Net"$NET_ID"."$2
	COPY_TO=$3
	CERT_PATH_PREFIX=$CERTS_DIR/$NET_NAME/$FILE_PREFIX
	KEY_PATH_PREFIX=$KEYS_DIR/$NET_NAME/$FILE_PREFIX
	ENTITY_NAME=$NET_NAME"."$2

	openssl genrsa -out $KEY_PATH_PREFIX"Key.pem" 2048
	openssl req -new -key $KEY_PATH_PREFIX"Key.pem" -sha256 -out $KEY_PATH_PREFIX"Req.pem" -subj "/C=US/ST=CA/L=Berkeley/O=EECS/OU="$NET_NAME"/CN="$ENTITY_NAME
	openssl x509 -passin pass:$CA_PASSWORD -req -in $KEY_PATH_PREFIX"Req.pem" -sha256 -extensions usr_cert -CA $CA_DIR/CACert.pem -CAkey $CA_DIR/CAKey.pem -CAcreateserial \
		-out $CERT_PATH_PREFIX"Cert.pem" -days $VAL_DAYS
	rm $KEY_PATH_PREFIX"Req.pem"
	if [[ $FILE_PREFIX == Net*.Pt* ]]
	then
		openssl pkcs8 -topk8 -inform PEM -outform DER -in $KEY_PATH_PREFIX"Key.pem" -out $KEY_PATH_PREFIX"Key.der" -nocrypt
		rm $KEY_PATH_PREFIX"Key.pem"
	fi
	cp $CERT_PATH_PREFIX"Cert.pem" $COPY_TO
}

entity_dist_key_gen() {
	NET_ID=$1
	NET_NAME="net"$NET_ID
	FILE_PREFIX="Net"$NET_ID"."$2
	COPY_TO=$3
	CIPHER_KEY_SIZE=$4
	MAC_KEY_SIZE=$5
	KEY_PATH_PREFIX=$KEYS_DIR/$NET_NAME/$FILE_PREFIX
	ENTITY_NAME=$NET_NAME"."$2

	openssl rand $CIPHER_KEY_SIZE > $KEY_PATH_PREFIX"CipherKey.key"
	openssl rand $MAC_KEY_SIZE > $KEY_PATH_PREFIX"MacKey.key"

	cp $KEY_PATH_PREFIX"CipherKey.key" $COPY_TO
	cp $KEY_PATH_PREFIX"MacKey.key" $COPY_TO
}

entity_list=(
	"Client"
	"Server"
	"PtClient"
	"PtServer"
	"PtPublisher"
	"PtSubscriber"
	"UdpClient"
	"UdpServer"
	"SafetyCriticalClient"
	"SafetyCriticalServer"
)

rc_entity_list=(
	"RcClient"
	"RcServer"
	"RcUdpClient"
	"RcUdpServer"
)

net_id=1
while [ "$net_id" -le $NUM_NETS ]
do
	mkdir -p $CERTS_DIR/"net"$net_id
	mkdir -p $KEYS_DIR/"net"$net_id
	AUTH_DB_ENTITY_CERT_PATH="../../auth/databases/auth10"$net_id"/entity_certs/"
	AUTH_DB_ENTITY_KEY_PATH="../../auth/databases/auth10"$net_id"/entity_keys/"
	for entity in "${entity_list[@]}"
	do
		# "net"$net_id becomes a network id
		entity_cred_gen $net_id $entity $AUTH_DB_ENTITY_CERT_PATH
	done
	for rc_entity in "${rc_entity_list[@]}"
	do
		# "net"$net_id becomes a network id
		entity_dist_key_gen $net_id $rc_entity $AUTH_DB_ENTITY_KEY_PATH 16 32	# 16 bytes - 128 bits (AES-128-CBC), 32 bytes - 256 bits (SHA256)
	done
	let "net_id+=1"
done
