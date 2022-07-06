# Prerequisites

- OpenSSL (TODO: Elaborate why OpenSSL is needed)

# Code Hiearchy
common -> crypto -> secure_comm -> c_api  -> test
                    load_config -----¡è

# writing function rules

void function(return_pointer, input ...)

every return and input buffers and lengths input with pointers

void function(unsigned char * ret, unsigned int * ret_length, unsigned char * input_buf, unsigned int * input_buf_length)

# C API

**void load_config()**

- ?‹¤ë¥? ?•¨?ˆ˜?˜ input?œ¼ë¡? ?“¤?–´ê°? ?‚´?š©?¸ sender, purpose, number of keys, crypto spec, pubkey path, privkey path ?“±?˜ ?‚´?š©?„ config ?ŒŒ?¼ë¡? ë¶ˆëŸ¬?˜¤?Š” ?ž‘?—…
- config ?–‘?‹??? userê°? ?‚¬?š©?•  ?ˆ˜ ?žˆê²? ? œê³µí•  ?˜ˆ? •
- ?‹¤ë¥? ?•¨?ˆ˜?—?„œ load ?•˜ê²Œë˜ë©? high computation, long running time?´ ë°œìƒ?•˜ë¯?ë¡? ?”°ë¡? ?•¨?ˆ˜ë¥? ë§Œë“¦
- return struct config

**void get_session_key()**
- entity clientê°? session keyë¥? ?–»?Š” ê³¼ì •
- input?œ¼ë¡œëŠ” struct config
- return struct session_key

**void secure_connection()**
- entity server?—ê²? secure connection?„ ?•˜ê¸°ìœ„?•œ ê³¼ì •
- input?œ¼ë¡œëŠ” port, IP address, session keyê°? ?žˆ?Œ
- return secure socket

**void send_secure_message() **
- send secure message by encrypting with session key
- input?œ¼ë¡œëŠ” session key, secure socket, messageê°? ?žˆ?Œ

**void wait_connection_message()**
- entity serverê°? client?˜ ?ž…? ¥?„ ê¸°ë‹¤ë¦¬ëŠ” ê³¼ì •
- input?œ¼ë¡œëŠ” struct config
- return struct session_key

#compile

$make
$./test
