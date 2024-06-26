#!/bin/bash

# Script for cleaning example Auths and entities
# Author: Hokeun Kim

AUTH_CREDS_DIR=auth/credentials/
AUTH_DATABASES_DIR=auth/databases/
AUTH_PROPERTIES_DIR=auth/properties/
ENTITY_CREDS_DIR=entity/credentials/
NODE_EXAMPLE_ENTITY_DIR=entity/node/example_entities/

cd ..

cd $AUTH_CREDS_DIR
rm -rf ca certs keystores
cd ../../

cd $AUTH_DATABASES_DIR
rm -rf auth*
cd ../../

cd $AUTH_PROPERTIES_DIR
rm -f *.properties
cd ../../

cd $ENTITY_CREDS_DIR
rm -rf certs keys
cd ../../

rm -rf entity/auth_certs
rm -rf $NODE_EXAMPLE_ENTITY_DIR"configs"
