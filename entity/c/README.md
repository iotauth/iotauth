# Code Hiearchy
common -> crypto -> secure_server, secure_client -> main

# writing function rules

void function(return_pointer, input ...)

every return and input buffers and lengths input with pointers

void function(unsigned char * ret, unsigned int * ret_length, unsigned char * input_buf, unsigned int * input_buf_length)

# C API

**void load_config()**

- 다른 함수의 input으로 들어갈 내용인 sender, purpose, number of keys, crypto spec, pubkey path, privkey path 등의 내용을 config 파일로 불러오는 작업
- config 양식은 user가 사용할 수 있게 제공할 예정
- 다른 함수에서 load 하게되면 high computation, long running time이 발생하므로 따로 함수를 만듦
- return struct config

**void get_session_key()**
- entity client가 session key를 얻는 과정
- input으로는 struct config
- return struct session_key

**void secure_connection()**
- entity server에게 secure connection을 하기위한 과정
- input으로는 port, IP address, session key가 있음
- return secure socket

**void send_secure_message() **
- send secure message by encrypting with session key
- input으로는 session key, secure socket, message가 있음

**void wait_connection_message()**
- entity server가 client의 입력을 기다리는 과정
- input으로는 struct config
- return struct session_key
