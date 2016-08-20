#!/usr/bin/python

num = 64
srcFileName = "../../configs/net1/server.config"
srcFile = open(srcFileName, "r")
srcFileContents = srcFile.read()

strPortNumber = str(21100)

for idx in range(0, num):
	destFileName = "server" + str(idx).zfill(3) + ".config"
	destFile = open(destFileName, "w")
	destFileContents = srcFileContents.replace(strPortNumber, str(21100 + idx))
	destFile.write(destFileContents)
	destFile.close()
