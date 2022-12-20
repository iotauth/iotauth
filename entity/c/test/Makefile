all: client server test_client test_server

# cwd := $(shell pwd)
# cd $(cwd);
# $(info $$cwd is [${cwd}])

UNAME := $(shell uname)

ifeq ($(UNAME), Linux)
	LDFLAGS=-L/usr/local/lib64
	CPPFLAGS=-I/usr/local/include/openssl

endif
ifeq ($(UNAME), Darwin)
    LDFLAGS=-L/opt/homebrew/opt/openssl@3/lib
    CPPFLAGS=-I/opt/homebrew/opt/openssl@3/include
endif

client: 
	gcc -o client client.c

server: 
	gcc -o server server.c

test_client: ../c_common.o ../c_crypto.o ../c_secure_comm.o ../load_config.o ../c_api.o test_client.o
	gcc ${CPPFLAGS} ${LDFLAGS} -o test_client ../c_common.o ../c_crypto.o ../c_secure_comm.o ../load_config.o ../c_api.o test_client.o -lcrypto -pthread

test_client.o: test_client.c ../c_common.o ../c_crypto.o ../c_secure_comm.o ../load_config.o
	gcc ${CPPFLAGS} -c -o test_client.o test_client.c

test_server: ../c_common.o ../c_crypto.o ../c_secure_comm.o ../load_config.o ../c_api.o test_server.o
	gcc ${CPPFLAGS} ${LDFLAGS} -o test_server ../c_common.o ../c_crypto.o ../c_secure_comm.o ../load_config.o ../c_api.o test_server.o -lcrypto -pthread

test_server.o: test_server.c ../c_common.o ../c_crypto.o ../c_secure_comm.o ../load_config.o
	gcc ${CPPFLAGS} -c -o test_server.o test_server.c

c_common.o: ../c_common.h ../c_common.c
	gcc ${CPPFLAGS} -c -o ../c_common.o ../c_common.c

c_crypto.o: ../c_common.o ../c_crypto.h ../c_crypto.c
	gcc ${CPPFLAGS} -c -o ../c_crypto.o ../c_crypto.c

load_config.o: ../../load_config.h ../../load_config.c
	gcc ${CPPFLAGS} -c -o ../../load_config.o ../../load_config.c

c_secure_comm.o: ../c_crypto.o ../load_config.o ../c_secure_comm.h ../c_secure_comm.c
	gcc ${CPPFLAGS} -c -o ../c_secure_comm.o ../c_secure_comm.c

c_api.o: ../c_common.o ../c_crypto.o ../c_secure_comm.o ../load_config.o ../c_api.h ../c_api.c
	gcc ${CPPFLAGS} -c -o ../c_api.o ../c_api.c

clean:
	rm -f test_client test_server *.o client server
