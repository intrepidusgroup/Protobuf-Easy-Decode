#!/usr/bin/python

#This will use a lot of code from the google protobuf project
#to generate decoders for the most general of cases.

#Once I learn a bit more about the proto and the src base
#I should be able to just use the protobuf code base to 
#accomplise this task.

"""
Author: Rajendra Umadas
"""

import sys
import binascii

class ProtobufEasyDecode:
    
    WIRETYPE_VARINT = 0
    WIRETYOE_FIXED_64 = 1
    WIRETYPE_LENGTHDELIM = 2
    WIRETYPE_STARTGROUP = 3
    WIRETYPE_ENDGROUP = 4
    WIRETYPE_FIXED_32 = 5

    raw_message = ""
    decoded_message = {}
    def __init__(self,new_message):
        self.raw_message = new_message 
    
    def decode_varint(self,buf,pos):
    #pass in buffer and starting position
    #return the int and the ending pos
        result = 0
        shifts = 0
        while True:
            current_byte = ord(buf[pos])
            result = result | ((current_byte & 0x7f) << shifts)
            pos = pos + 1
            if not (current_byte & 0x80):
                return (result,pos)
            shifts = shifts + 7
    
    def decode_tag_header(self, tag_header):
        #returns tag_id, and tag_type
        return (tag_header >> 3, tag_header & 0x07)

    def decode_lengthdelim (self, buf, pos):
    #pass in buffer and start pos
    #return bytes and ending pos
        length,pos = self.decode_varint(buf,pos)
        new_pos = pos + length
        return buf[pos:new_pos],new_pos

    def decode_raw_message(self,message):
        alls_good = True
        pos = 0
        temp_proto = {}
        while alls_good:
            current_tag_header,pos=self.decode_varint(message,pos)
            current_tag_id,current_tag_type = \
                           self.decode_tag_header(current_tag_header)
            if current_tag_type == self.WIRETYPE_LENGTHDELIM:
                data,pos = self.decode_lengthdelim(message,pos)
            elif current_tag_type == self.WIRETYPE_VARINT:
                data,pos = self.decode_varint(message,pos)
            else:
                data = "ERR"
                pos = len(message)
                alls_good = False
            temp_proto[current_tag_id] = (current_tag_type,data)
            if pos == len(message):
                alls_good = False
        return temp_proto
    
    def get_decoded_raw_message (self):
        if self.decoded_message == {}:
            self.decoded_message = self.decode_raw_message(self.raw_message)
            return self.decoded_message
        else:
            return self.decoded_message
    def decode_tag(self, tag_id):
        if self.decoded_message == {}:
            return
        if not (tag_id in self.decoded_message):
            return
        if self.decoded_message[tag_id][0] == self.WIRETYPE_LENGTHDELIM:
            self.decoded_message[tag_id] = \
                 (self.WIRETYPE_LENGTHDELIM,
                  self.decode_raw_message(self.decoded_message[tag_id][1]))
        else:
            return 
x = ProtobufEasyDecode(binascii.unhexlify(sys.argv[1]))
x.get_decoded_raw_message()
x.decode_tag(3)
x.decode_tag(5)
x.decode_tag(10)
print x.get_decoded_raw_message()
