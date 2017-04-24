#!/bin/bash

# Author: Hokeun Kim
# Script for generating example Auths and entities

echo "*SCRIPT- generateAll.sh: For generating example Auths and entities"

# followings are default parameters
# file for host and port assignment of Auth and entities
GRAPH_FILE="default.graph"
# Whether to show help
SHOW_HELP=false
# Generate credentials and configs
GEN_CRED_CONFIG=true
# Generate Auth databases
GEN_AUTH_DB=true

# parsing command line arguments
# -n for number of nets, -d for DB protection method and -a for host port assignment
while [[ $# -gt 0 ]]
do
	key="$1"

	case $key in
		-g|--graph)
			HOST_PORT_ASSIGNMENT_FILE="$2"
			shift # past argument
		;;
		-gc|--gen-cred-config-only)
			GEN_AUTH_DB=false
		;;
		-gd|--gen-db-only)
			GEN_CRED_CONFIG=false
		;;
		-h|--help)
			SHOW_HELP=true
		;;
		*)
			# unknown option
		;;
	esac
	shift # past argument or value
done

if [ "$SHOW_HELP" = true ] ; then
	echo "Usage: ./generateAll.sh [options]"
	echo
	echo "Options:"
	echo "  -g,--graph <arg>                Path for host and port assignment file."
	echo "  -gc,--gen-cred-config-only      Generate credentials and configuration files only."
	echo "                                  (without generating Auth DBs.)"
	echo "  -gd,--gen-db-only               Generate Auth databases only."
	echo "                                  (Skip generation of credentials and configuration files.)"
	echo "  -h,--help                       Show this help."
	exit
fi

echo "Example generation options:"
echo GRAPH_FILE  = $GRAPH_FILE

echo "Installing required npm modules..."
./initConfigs.sh

# generate credentials and configs
if [ "$GEN_CRED_CONFIG" = true ] ; then
	echo "Generating credentials ..."
	node generateCredentials.js
	echo "Generating entity configuration files..."
	node generateEntityConfigs.js
	echo "Generating Auth configuration files..."
	node generateAuthConfigs.js
fi

if [ "$GEN_AUTH_DB" = true ] ; then
	echo "Generating auth databases..."
	# generate Auth DBs
	node generateDB.js
fi
