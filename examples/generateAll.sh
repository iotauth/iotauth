#!/bin/bash

# Author: Hokeun Kim
# Script for generating example Auths and entities

echo "*SCRIPT- generateAll.sh: For generating example Auths and entities"

# number of networks (Auths)
NUM_NETS=2
# Protection method for Auth DB, see AuthDBProtectionMethod.java for supported methods
AUTH_DB_PROTECTION_METHOD=2
# file for host and port assignment of Auth and entities
HOST_PORT_ASSIGNMENT_FILE="configs/host_port_assignments/simple.txt"

# generate credentials and configs
./generateCredentialsAndConfigs.sh $NUM_NETS $AUTH_DB_PROTECTION_METHOD $HOST_PORT_ASSIGNMENT_FILE

# generate Auth DBs
./generateDB.sh $NUM_NETS $AUTH_DB_PROTECTION_METHOD

