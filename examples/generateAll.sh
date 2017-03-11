#!/bin/bash

# Script for generating example Auths and entities
# Author: Hokeun Kim

# number of networks (Auths)
NUM_NETS=2
# Protection method for Auth DB, see AuthDBProtectionMethod.java for supported methods
AUTH_DB_PROTECTION_METHOD=2

# generate credentials and configs
./generateCredentialsAndConfigs.sh $NUM_NETS $AUTH_DB_PROTECTION_METHOD "configs/host_port_assignments/simple.txt"

# generate Auth DBs
./generateDB.sh $NUM_NETS $AUTH_DB_PROTECTION_METHOD

