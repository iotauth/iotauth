#!/usr/bin/python

import os
import sys
import time

if len(sys.argv) < 3:
	print 'input parameter for number of clients and session key ID'
	sys.exit()

client_count = int(sys.argv[1])
keyId = sys.argv[2]

serverPort = 22100
if len(sys.argv) >= 3:
	serverPort = int(sys.argv[3])

for i in range(client_count):
	os.system('node clientWithAccessor configs/net1/client.config exp2 ' + keyId + ' ' + str(serverPort) + ' &')
	time.sleep(0.5)


