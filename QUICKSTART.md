# Prerequisites
1. OpenSSL 3.0 or higher, for cryptographic key generation, and the C API.
2. Java 11 or higher, for *Auth*.
3. NodeJS, Npm, and Maven.
5. CMake 3.19 or higher, for C example compilation.
## Ubuntu 24.04
```
$ apt-get install openssl openjdk-17-jdk nodejs npm maven cmake
```

## Mac OS
```
$ brew install openssl@3 openjdk node npm maven cmake
```

## Clone repository & Update submodule
```
$ git clone https://github.com/iotauth/iotauth.git
$ cd iotauth
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
```

To see full logs, add `-DCMAKE_BUILD_TYPE=DEBUG` as cmake flags.
```
$ cmake ../
$ make
```
## Execute C examples
Turn on three terminals. Run each command on each terminal.
1. Execute Auth in `$ROOT/auth/auth-server`.
```
$ java -jar target/auth-server-jar-with-dependencies.jar -p ../properties/exampleAuth101.properties
```

2. Execute server example in `$ROOT/entity/c/examples/server_client_example/build`.
```
$ ./entity_server ../c_server.config
```

3. Execute client example in `$ROOT/entity/c/examples/server_client_example/build`.
```
$ ./entity_client ../c_client.config
```

# Further Details

For further details, see "How to run examples" in [README.md under *examples/*](https://github.com/iotauth/iotauth/blob/master/examples/README.md) for more details.

Also for more C examples, see https://github.com/iotauth/sst-c-api/tree/master/examples/ for more details.\
