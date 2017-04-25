#!/bin/bash

if [ $# != 2 ]
then
	echo "Please provide required arguments (1. number of networks, 2. Auth DB protection method)"
	echo 'Usage: ./generateExampleAuthDB.sh NUM_NETS AUTH_DB_PROTECTION_METHOD'
	exit
fi

# number of networks (Auths)
NUM_NETS=$1
AUTH_DB_PROTECTION_METHOD=$2

echo `pwd`
if [ ! -d "../databases/auth101" ];
then
    echo "need to create databases"
else
	cd ../
	mvn -pl example-auth-db-generator -am install -DskipTests
	cd example-auth-db-generator
    cp target/init-example-auth-db-jar-with-dependencies.jar ../
    cd ../

	net_id=1
	while [ "$net_id" -le $NUM_NETS ]
	do
    	java -jar init-example-auth-db-jar-with-dependencies.jar -i 10$net_id -d $AUTH_DB_PROTECTION_METHOD
		let "net_id+=1"
	done
    rm init-example-auth-db-jar-with-dependencies.jar
fi