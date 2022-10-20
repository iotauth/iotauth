# Prerequisites

-   OpenSSL:
    SST uses the APIs from OpenSSL for encryption and decryption. OpenSSL 3.0 above is required to run SST.
    -   On Max OS X, OpenSSL can be installed using `brew install openssl`.
    -   Following environment variables need to be set before running `make`. The exact variable values can be found from the output of `brew install openssl`.
    -   add two lines below by using `vi ~/.zshrc`
        -   `export LDFLAGS="-L/opt/homebrew/opt/openssl@3/lib"`
        -   `export CPPFLAGS="-I/opt/homebrew/opt/openssl@3/include"`

# Code Hiearchy

c_common -> c_crypto -> c_secure_comm -> c_api -> entity_client, entity_server

&emsp;&emsp;&emsp;&emsp;&emsp;&emsp;&emsp;&emsp;&emsp;&emsp;&emsp;&emsp;&emsp;&emsp;&emsp;&emsp;&emsp; load_config --&uarr;

# C API

**SST_ctx_t \* init_SST()**

-   `init_SST()` is a function to load the config file, public and private keys, and store the distribution key.
-   It initializes important settings, at once.
-   Returns struct SST_ctx_t

**session_key_list_t \* get_session_key()**

-   `get_session_key()` is a function to get secure session key from Auth.
-   Input is the struct config returned from the `init_SST()`, and the existing session key list. It can be NULL, if there were no list.
-   Returns struct session_key_list_t.

**SST_session_ctx_t secure_connect_to_server()**

-   `secure_connect_to_server()` is a function that establishes a secure connection with the entity server in the struct config.
-   Input is the session key received from `get_session_key()` and struct config returned from `load_config()`.
-   Returns struct SST_session_ctx_t

**SST_session_ctx_t \* server_secure_comm_setup()**

-   `server_secure_comm_setup()` is a function that the server continues to wait for the entity client and, if the client tries to connect, proceeds with a secure connection.
-   Input is the struct config.
-   Returns struct SST_session_ctx_t

**void \*receive_thread()**

-   Creates a receive_thread.
-   Usage:

```
pthread_t thread;
pthread_create(&thread, NULL, &receive_thread, (void \*)session_ctx);
```

**void receive_message()**

-   Enables receiving messages.

**void send_secure_message()**

-   `secure message()` is a function that send a message with secure communication to the server by encrypting it with the session key.
-   Input includes message, session_ctx struct.

**void free_session_key_list_t()**

-   `free_session_key_list_t()` is a function that frees the memory assigned to the config_t. It frees the memory assigned by the asymmetric key paths.

**void free_config_t()**

-   `free_config_t()` is a function that frees the memory assigned to the session_key_list. It recursively frees the memory assigned by the session keys.

**void free_SST_ctx()**

-   `free_SST_ctx()` is a function that frees the memory assigned to the loaded SST_ctx. It recursively frees the memory assigned by SST_ctx.

# Compile

`$cd ~/entity/c`
`$make`

# Example

-   Turn on two different terminals at `$~/entity/c`, and turn on Auth ont the third terminal.

Execute

`$./entity_client c_client.config`

`$./entity_server c_server.config`

on each terminal

# For Developers

-   For C language indentation, we use the Google style.
    -   To enable the Google style indentation in VSCode, follow the instructions below. ([Source](https://stackoverflow.com/questions/46111834/format-curly-braces-on-same-line-in-c-vscode))
        1. Go Preferences -> Settings
        2. Search for `C_Cpp.clang_format_fallbackStyle`
        3. Click Edit, Copy to Settings
        4. Change from `"Visual Studio"` to `"{ BasedOnStyle: Google, IndentWidth: 4 }"`
    -   To format the code, follow instructions in this [page](https://code.visualstudio.com/docs/editor/codebasics#_formatting).

# TODOs

-   Implement an additional API function for extracting session key from cached session keys.
