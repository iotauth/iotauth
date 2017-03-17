#!/usr/bin/python

# A Python script for removing features that are not supported in Android
# from AuthServer.java and AuthCommandLine.java.
# Author: Hokeun Kim

authServerFileName = "app/src/main/java/org/iot/auth/AuthServer.java"
authCommandFileName = "app/src/main/java/org/iot/auth/AuthCommandLine.java"

file = open(authServerFileName)

text = ""
for line in file:
	if "javax.bluetooth" in line:
		continue
	elif "javax.microedition" in line:
		continue
	elif "sun.security.provider.X509Factory" in line:
		continue
	elif "sun.misc.BASE64Encoder" in line:
		continue
	elif "entityBluetoothListener" in line:
		continue 
	text += line
file.close()

def removeElement(elementName, fileString):
	"Remove any element (method, class) with braces"
	methodStart = fileString.find(elementName)
	if methodStart < 0:
		return fileString
	braceStart = fileString.find("{", methodStart)
	currentPosition = braceStart + 1
	braceCount = 1
	while braceCount > 0:
		nextOpenBracePosition = fileString.find("{", currentPosition)
		nextCloseBracePosition = fileString.find("}", currentPosition)
		if nextOpenBracePosition < nextCloseBracePosition:
			currentPosition = nextOpenBracePosition + 1
			braceCount += 1
		else:
			currentPosition = nextCloseBracePosition + 1
			braceCount -= 1
	fileString = fileString[:methodStart - 1] + fileString[currentPosition:]
	return fileString

text = removeElement("private class EntityBluetoothListener", text)
text = removeElement("public void issueCertificate", text)

file = open(authServerFileName, 'w')
file.write(text)
file.close()


file = open(authCommandFileName)

text = ""
for line in file:
	if "issueCertificate" in line:
		continue
	text += line
file.close()

file = open(authCommandFileName, 'w')
file.write(text)
file.close()