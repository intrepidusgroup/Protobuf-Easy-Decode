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
import struct
import pprint

class WIRETYPE:
    
    VARINT = 0
    FIXED_64 = 1
    LENGTHDELIM = 2
    STARTGROUP = 3
    ENDGROUp = 4
    FIXED_32 = 5


class ProtobufEasyDecode:

    def __init__(self,new_message):
        self.raw_message = new_message 
        self.decoded_message = {}
        self.decoded_message_deep = {}
    
    def decode_fixed_64(self, buf, pos):
        newpos = pos + 8 
        data = buf[pos:newpos]
        data = struct.unpack('<Q',data)
        return (data,newpos)    
    
    def decode_fixed_32(self, buf, pos):
        newpos = pos + 4
        data = buf[pos:newpos]
        data = struct.unpack('<I',data)
        return (data,newpos)

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
    
    def decode_raw_message(self,message, deep = False):
        alls_good = True
        pos = 0
        temp_proto = {}
        while alls_good:
            try:
                current_tag_header,pos=self.decode_varint(message,pos)
                current_tag_id,current_tag_type = \
                           self.decode_tag_header(current_tag_header)
            except:
                #could not extract a correct tag header
                current_tag_type= -1
                pos = len(message)
            try:
                if current_tag_type == WIRETYPE.LENGTHDELIM:
                    data,pos = self.decode_lengthdelim(message,pos)
                    if deep:
                        old_data = data
                        data = (old_data,self.decode_raw_message(data,True))
                elif current_tag_type == WIRETYPE.VARINT:
                    data,pos = self.decode_varint(message,pos)
                elif current_tag_type == WIRETYPE.FIXED_64:
                    data,pos = self.decode_fixed_64(message,pos)
                elif current_tag_type == WIRETYPE.FIXED_32:
                    data,pos = self.decode_fixed_32(message,pos)
                else:
                    #did not get a valid tag_type
                    data = "ERR"
                    pos = len(message)
                    alls_good = False
            except:
                #got a valid tag_type but parsing failed
                data = "Err"
                pos = len(message)
                alls_good = False
            temp_proto[current_tag_id] = (current_tag_type,data)
            if pos == len(message):
                alls_good = False
        return temp_proto
    
    def get_decoded_raw_message (self):
        if self.decoded_message != {}:
            return self.decoded_message
        self.decoded_message = self.decode_raw_message(self.raw_message)
        return self.decoded_message
 
    def get_decoded_raw_message_deep(self):
        if self.decoded_message_deep != {}:
            return self.decoded_message_deep
        self.decoded_message_deep = self.decode_raw_message(self.raw_message,True)
        return self.decoded_message_deep
    
    def pretty_print_decoded_message_deep(self):
        pp = pprint.PrettyPrinter()
        pp.pprint(self.decoded_message_deep)
    
    def pretty_print_decoded_message(self):
        pp = pprint.PrettyPrinter()
        pp.pprint(self.decoded_message)

if __name__ == "__main__":
    x = ProtobufEasyDecode(binascii.unhexlify(sys.argv[1]))
    x.get_decoded_raw_message() 
    x.get_decoded_raw_message_deep()
    x.pretty_print_decoded_message_deep()
    x.pretty_print_decoded_message(

)
