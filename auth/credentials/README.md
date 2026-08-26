# Directory structure
---
- **.**: Includes a shell script for generating credentials for a certificate authority (CA) and example Auths (generateCACredentials.sh, generateExampleAuthCredentials.sh)
- **ca**: Directory for credentials of a certificate authority (CA)
- **certs**: Directory for Certificates of example Auths
- **keystores**: Directory for keystore files (.pfx) of example Auths
# separate genrsa and req processes, no more need for password

# Certificate and key generation steps used in the shell script
---
- (1) Create RSA keys
- (2) Generate CSR (certificate signing request)
- (3) Create certificate by signing with CA(auth)'s private key
- (4) Check subject and issuer (CA)

(Separated genrsa and req processes, no more need for password)

### ⚠️ Note on CA certificate extensions
---
`-extensions v3_ca` alone doesn't guarantee `[v3_ca]` is defined — it depends on the system's default OpenSSL config, which varies by environment. If missing, `CACert.pem` lacks `BasicConstraints: CA:true`, causing Auth-to-Auth TLS handshakes to fail (Java's PKIX validator rejects non-CA trust anchors).

Fix: added `ca.cnf` defining `[v3_ca]` explicitly, and pass it via `-extfile` so the extension is always applied regardless of environment.

`generateCACredentials.sh` now explicitly passes `-extfile ca.cnf` to avoid this environment dependency:
`openssl x509 -req -in CAReq.pem -sha256 -extensions v3_ca -extfile ca.cnf -signkey CAKey.pem -out CACert.pem -days 730`

### To check subjet, issuer, validity period of a certificate
---
openssl x509 -noout -startdate -enddate -subject -issuer -in CACert.pem 

### When you create a request (certificate signing request)
---
* Country: US
* State: CA
* Locality: Berkeley
* Organization: UC Berkeley / Net1 / Net2
* Organizational Unit: EECS Ptolemy Project Group / Auth / Clients / Servers
* Common Name: CA / Auth(2) / localhost / localhost


### Self-signed certificate for CA
---
openssl genrsa -out CAKey.pem 2048 

openssl req -new -key CAKey.pem -sha256 -out CAReq.pem

openssl x509 -req -in CAReq.pem -sha256 -extensions v3_ca -signkey CAKey.pem -out CACert.pem -days 730

### Certificate for auth
---
openssl genrsa -out AuthKey.pem 2048

openssl req -new -key AuthKey.pem -sha256 -out AuthReq.pem

openssl x509 -req -in AuthReq.pem -sha256 -extensions usr_cert -CA CACert.pem -CAkey CAKey.pem -CAcreateserial -out AuthCert.pem -days 730


### certificate for server
---
openssl genrsa -out ServerKey.pem 2048

openssl req -new -key ServerKey.pem -sha256 -out ServerReq.pem

openssl x509 -req -in ServerReq.pem -sha256 -extensions usr_cert -CA CACert.pem -CAkey CAKey.pem -CAcreateserial -out ServerCert.pem -days 730

### Certificate for client
---
openssl genrsa -out ClientKey.pem 2048

openssl req -new -key ClientKey.pem -sha256 -out ClientReq.pem

openssl x509 -req -in ClientReq.pem -sha256 -extensions usr_cert -CA CACert.pem -CAkey CAKey.pem -CAcreateserial -out ClientCert.pem -days 730

### To convert .pem key to .der key
---
openssl pkcs8 -topk8 -inform PEM -outform DER -in AuthKey.pem -out AuthKey.der -nocrypt

openssl pkcs8 -topk8 -inform PEM -outform DER -in PtServerKey.pem -out PtServerKey.der -nocrypt

openssl pkcs8 -topk8 -inform PEM -outform DER -in PtClientKey.pem -out PtClientKey.der -nocrypt

### To convert pem files to pfx (keystores to be used in Java)
---
openssl pkcs12 -export -out Auth.pfx -inkey AuthKey.pem -in AuthCert.pem -password pass:asdf

openssl pkcs12 -in Auth.pfx

### Using shell scripts
---
./generateCACredentials.sh

./generateExampleAuthCredentials.sh 101 localhost asdf

./generateExampleAuthCredentials.sh 102 localhost asdf
