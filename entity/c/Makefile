all: entity_client entity_server clean

entity_client: c_common.o c_crypto.o c_secure_comm.o load_config.o c_api.o entity_client.o
	gcc ${CPPFLAGS} ${LDFLAGS} -o entity_client c_common.o c_crypto.o c_secure_comm.o load_config.o c_api.o entity_client.o -lcrypto -pthread

entity_client.o: c_common.o c_crypto.o c_secure_comm.o load_config.o
	gcc ${CPPFLAGS} -c -o entity_client.o entity_client.c

entity_server: c_common.o c_crypto.o c_secure_comm.o load_config.o c_api.o entity_server.o
	gcc ${CPPFLAGS} ${LDFLAGS} -o entity_server c_common.o c_crypto.o c_secure_comm.o load_config.o c_api.o entity_server.o -lcrypto -pthread

entity_server.o: c_common.o c_crypto.o c_secure_comm.o load_config.o
	gcc ${CPPFLAGS} -c -o entity_server.o entity_server.c

c_common.o: c_common.h c_common.c
	gcc ${CPPFLAGS} -c -o c_common.o c_common.c

c_crypto.o: c_common.o c_crypto.h c_crypto.c
	gcc ${CPPFLAGS} -c -o c_crypto.o c_crypto.c

c_secure_comm.o: c_crypto.o c_secure_comm.h c_secure_comm.c
	gcc ${CPPFLAGS} -c -o c_secure_comm.o c_secure_comm.c

load_config.o: load_config.h load_config.c
	gcc -c -o load_config.o load_config.c

c_api.o: c_common.o c_crypto.o c_secure_comm.o load_config.o c_api.h c_api.c
	gcc ${CPPFLAGS} -c -o c_api.o c_api.c

clean:
	rm -f *.o