#!/usr/bin/python

import os
import sys
import time

if len(sys.argv) < 2:
	print 'input parameter for number of clients and session key ID'
	sys.exit()

client_count = int(sys.argv[1])
keyId = sys.argv[2]

for i in range(client_count):
	os.system('node client configs/net1/client.config exp2 ' + keyId + ' &')
	time.sleep(0.5)


