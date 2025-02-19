# Prerequisites
## Ubuntu 24.04
```
// openssl 3.0 or higher
$ apt-get install openssl 

// java 11 or higher
$ apt-get install openjdk-17-jdk

$ apt-get install nodejs
$ apt-get install npm
$ apt-get install maven

// cmake 3.19 or higher
$ apt-get install cmake

$ git clone https://github.com/iotauth/iotauth.git
$ cd iotauth
// Update submodule.
$ git submodule update --init
```

## Mac OS
```
// openssl 3.0 or higher
$ brew install openssl@3

// java 11 or higher
$ brew install openjdk

$ brew install node
$ brew install npm
$ brew install maven

// cmake 3.19 or higher
$ brew install cmake

$ git clone https://github.com/iotauth/iotauth.git
$ cd iotauth
// Update submodule.
$ git submodule update --init
```

# C Basic Server Client Example
## Generate Credentials, Build ***Auth***
```
$ cd examples
$ ./cleanAll.sh
$ ./generateAll.sh

$ cd ../auth/auth-server/
$ mvn clean install
```

## Build C examples
```
$ cd entity/c/examples/server_client_example/
$ mkdir build
$ cd build

// For full logs, add -DCMAKE_BUILD_TYPE=DEBUG
$ cmake ../
$ make
```
## Execute C examples
Turn on three terminals. Run each command on each terminal.
```
// Execute Auth in $ROOT/auth/auth-server
$ java -jar target/auth-server-jar-with-dependencies.jar -p ../properties/exampleAuth101.properties

// Execute server example in $ROOT/entity/c/examples/server_client_example/build
$ ./entity_server ../c_server.config

// Execute client example in $ROOT/entity/c/examples/server_client_example/build
$ ./entity_client ../c_client.config
```

# Further Details

For further details, see "How to run examples" in [README.md under *examples/*](https://github.com/iotauth/iotauth/blob/master/examples/README.md) for more details.

Also for more C examples, see https://github.com/iotauth/sst-c-api/tree/master/examples/ for more details.