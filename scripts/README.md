# Overview
---
Automated shell scripts for Auth.

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
