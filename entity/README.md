# Entity directory
---
This directory includes entities in the IoT, to be authenticated/authorized by Auth

# Directory structure
---

- **auth_certs**: Certificates of Auth, to be created after running the script for generating and copying example Auth/entity credentials.

- **capecode**: Example entities in CapeCode (IoT Modeling environment, for details, see [[1]](https://chess.eecs.berkeley.edu/capecode/), [[2]](https://www.terraswarm.org/accessors/hosts/ptolemy/index.html)) (*Under development*)

- **credentials**: Directory for certificates and keys for entities (including example entities)

- **figures**: Directory for figures explaining example entities.

- **node**: Entities implemented using JavaScript on Node.js

	- **data_examples**: Data files used by example entities
	- **example_entities**: Sample codes and configurations for example entities, client.js and server.js
		- **common**: Common JavaScript files imported by example entities.
		- **configs**: Configuration files for example entities
		- **experimentalConfigs**: Configuration files for entities used for experiments

	- **node_modules**: Node modules used by entities in JavaScript on Node.js
	- **tls_entities**: Entities using SSL/TLS (*Only for performance evaluation against SSL/TLS*)
