# Overview
---
This directory includes scripts and descriptions for running example Auths and entities.
The scripts are used to clean and generate credentials (certificates and keystores) for example Auths and entities.

# Example details
---
![Image of Example Auths and entities]
(https://github.com/iotauth/iotauth/blob/master/entity/figures/example_description.pdf)

# Script details
---

### generateExampleAuthsEntities.sh

This script generates credentials for example Auths and example entities. And it copies certificates (public keys) of entities to Auths' databases, and copies certificates (public keys) of Auths to entities' local directories. This script uses following helper scripts.

- **auth/credentials/generateCACredentials.sh**: This helper script generates credentials (public key, private key) for certificate authority which signs certificates of example Auths and entities.

- **auth/credentials/generateExampleAuthCredentials.sh**: This helper script generates credentials for example Auths.

- **entity/credentials/generateExampleEntityCredentials.sh**: This helper script generates credentials for example entities.

- **auth/example-auth-db-generator/generateExampleAuthDB.sh**: This helper script generates databases for Example Auths

### cleanExampleAuthsEntities.sh

This scripts deletes all credentials of example Auths and entities, and deletes databases for example Auths
