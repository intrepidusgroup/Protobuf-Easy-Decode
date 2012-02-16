#!/usr/bin/python

import binascii
import sys

ifl = open(sys.argv[1])
ifl = ifl.read()
ifl = binascii.hexlify(ifl)
print ifl
