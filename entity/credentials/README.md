# Directory structure
---
- **.**: Includes a shell script for generating credentials for example entities (generateExampleEntityCredentials.sh)
- **certs**: Directory for Certificates of network 1 (net1) example entities (to be created by the script)
	- **net1**: Certificates for net1 example entities
	- **net2**: Certificates for net2 example entities
- **keys**: Directory for private keys of network 2 (net2) example entities (to be created by the script)
	- **net1**: Private keys for net1 example entities
	- **net2**: Private keys for net2 example entities

# Certificate and key generation steps used in the shell script
---
- (1) Create RSA keys
- (2) Generate CSR (certificate signing request)
- (3) Create certificate by signing with CA(auth)'s private key
- (4) Check subject and issuer (CA)

(Separated genrsa and req processes, no more need for password)

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



