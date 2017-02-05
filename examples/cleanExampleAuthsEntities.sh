#!/bin/bash

# Script for cleaning example Auths and entities
# Author: Hokeun Kim

AUTH_CREDS_DIR=auth/credentials/
AUTH_DATABASES_DIR=auth/databases/
ENTITY_CREDS_DIR=entity/credentials/

cd ..

cd $AUTH_CREDS_DIR
rm -rf ca certs keystores
cd ../../

cd $AUTH_DATABASES_DIR
rm -rf auth101 auth102
cd ../../

cd $ENTITY_CREDS_DIR
rm -rf certs keys
cd ../../

rm -rf entity/auth_certs
