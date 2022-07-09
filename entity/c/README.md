# Prerequisites

- OpenSSL (TODO: Elaborate why OpenSSL is needed).
  - On Max OS X, OpenSSL can be installed using `brew install openssl`.
  - Following environment variables need to be set before running `make`. The exact variable values can be found from the output of `brew install openssl`.
    - export LDFLAGS="-L/opt/homebrew/opt/openssl@3/lib"
    - export CPPFLAGS="-I/opt/homebrew/opt/openssl@3/include"

# Code Hiearchy
common -> crypto -> secure_comm -> c_api  -> test
                    load_config -----¡è

# writing function rules

void function(return_pointer, input ...)

every return and input buffers and lengths input with pointers

void function(unsigned char * ret, unsigned int * ret_length, unsigned char * input_buf, unsigned int * input_buf_length)

# C API

**void load_config()**

- load_config() is a function to load the config file.
- The reason for creating this function is that if you load a file within another function, problems of high computation and long running time occur.
- Input includes entity name, purpose, number of keys, public key path, private key path, auth ip address, port number, entity server ip, port number.
- Return struct config

**void get_session_key()**
- get_session_key() is a function to get secure session key from Auth.
- Input is the struct config returned from the load_config function. 
- Return struct session_key

**void secure_connection()**
- secure_connection() is a function that establishes a secure connection with the entity server in the struct config. 
- Input is the struct config returned from load_config() and session key received from get_session_key().
- Return secure socket

**void send_secure_message() **
- send secure message() is a function that enables secure communication with the server by encrypting it with the session key.
- Input includes session key, secure socket, message
- Return sequence number

**void wait_connection_message()**
- wait_connection_message() is a function that the server continues to wait for the entity client and, if the client tries to connect, proceeds with a secure connection.
- Input is the struct config
- Return struct session_key

#compile

$make
$./test
