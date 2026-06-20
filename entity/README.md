# Entity directory
---
This directory includes entities in the IoT, to be authenticated/authorized by Auth

# Directory structure
---

- **auth_certs**: Certificates of Auth, to be created after running the script for generating and copying example Auth/entity credentials.

- **c**: API in C language and example entities implemented using the C API. It is implemented in [this repository](https://github.com/iotauth/sst-c-api). For usage, initialize and update submodule as below.
	```
	git submodule init
	git submodule update
	``` 

- **cpp**: C++ API (work in progress).

- **credentials**: Directory for certificates and keys for entities (including example entities)

- **node**: API in JavaScript on Node.js and entities implemented using JavaScript on Node.js
	- **accessors**: Secure Communication Accessors to be used to build entities running on Node.js host. For more information, see [this website](https://accessors.org).
	- **data_examples**: Data files used by example entities
	- **example_entities**: Sample codes and configurations for example entities, client.js and server.js
		- **common**: Common JavaScript files imported by example entities.
		- **configs**: Configuration files for example entities
		- **experimentalConfigs**: Configuration files for entities used for experiments

	- **node_modules**: This directory will be generated after npm installation to store necessary node modules used by entities in JavaScript on Node.js
