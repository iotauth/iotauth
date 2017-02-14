#!/bin/bash

if [ $# != 1 ]
then
	echo "Please provide required argument (1. number of networks)"
	echo 'Usage: ./generateExampleAuthDB.sh num_nets'
	exit
fi

# number of networks (Auths)
NUM_NETS=$1

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
    java -jar init-example-auth-db-jar-with-dependencies.jar -n $NUM_NETS
    rm init-example-auth-db-jar-with-dependencies.jar
fi