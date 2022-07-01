all: test clean

test: c_common.o c_crypto.o c_secure_comm.o load_config.o c_api.o test.o
	gcc -o test c_common.o c_crypto.o c_secure_comm.o load_config.o c_api.o test.o -lcrypto -pthread

test.o: c_common.o c_crypto.o c_secure_comm.o load_config.o
	gcc -c -o test.o test.c

c_common.o: c_common.h c_common.c
	gcc -c -o c_common.o c_common.c

c_crypto.o: c_common.o c_crypto.h c_crypto.c
	gcc -c -o c_crypto.o c_crypto.c

c_secure_comm.o: c_crypto.o c_secure_comm.h c_secure_comm.c
	gcc -c -o c_secure_comm.o c_secure_comm.c

load_config.o: load_config.h load_config.c
	gcc -c -o load_config.o load_config.c

c_api.o: c_common.o c_crypto.o c_secure_comm.o load_config.o c_api.h c_api.c
	gcc -c -o c_api.o c_api.c

clean:
	rm -f *.o