AUTH_CREDS_DIR=auth/credentials/
ENTITY_CREDS_DIR=entity/credentials/
AUTH_DATABASES_DIR=auth/databases/

# Move to Auth credentials
cd ../
cd $AUTH_CREDS_DIR

# Generate CA credentials
./generateCACredentials.sh

# Generate Auth credentials (with password asdf)
./generateExampleAuthCredentials.sh 101 localhost asdf
./generateExampleAuthCredentials.sh 102 localhost asdf

# Move to Entity credentials
cd ../../
cd $ENTITY_CREDS_DIR

# Generate Entity credentials
./generateExampleEntityCredentials.sh

# Move to repository root
cd ../../

# Copy Entity certificates to Auth databases
mkdir -p $AUTH_DATABASES_DIR/auth101/certs/
mkdir -p $AUTH_DATABASES_DIR/auth102/certs/

cp $ENTITY_CREDS_DIR/certs/net1/*.pem $AUTH_DATABASES_DIR/auth101/certs/
cp $ENTITY_CREDS_DIR/certs/net2/*.pem $AUTH_DATABASES_DIR/auth102/certs/

# Copy Auth certificates to Entity local directories
mkdir -p entity/auth_certs
cp $AUTH_CREDS_DIR/certs/*EntityCert.pem entity/auth_certs

# Create example databases for Auths
cd auth/example-auth-db-generator
./generateExampleAuthDB.sh
