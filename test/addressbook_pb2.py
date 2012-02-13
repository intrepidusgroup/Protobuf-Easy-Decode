# Generated by the protocol buffer compiler.  DO NOT EDIT!

from google.protobuf import descriptor
from google.protobuf import message
from google.protobuf import reflection
from google.protobuf import descriptor_pb2
# @@protoc_insertion_point(imports)



DESCRIPTOR = descriptor.FileDescriptor(
  name='addressbook.proto',
  package='test',
  serialized_pb='\n\x11\x61\x64\x64ressbook.proto\x12\x04test\"\xd2\x01\n\x06Person\x12\x0c\n\x04name\x18\x01 \x02(\t\x12\n\n\x02id\x18\x02 \x02(\x05\x12\r\n\x05\x65mail\x18\x03 \x01(\t\x12\'\n\x05phone\x18\x04 \x03(\x0b\x32\x18.test.Person.PhoneNumber\x1aI\n\x0bPhoneNumber\x12\x0e\n\x06number\x18\x01 \x02(\t\x12*\n\x04type\x18\x02 \x01(\x0e\x32\x16.test.Person.PhoneType:\x04HOME\"+\n\tPhoneType\x12\n\n\x06MOBILE\x10\x00\x12\x08\n\x04HOME\x10\x01\x12\x08\n\x04WORK\x10\x02\"+\n\x0b\x41\x64\x64ressBook\x12\x1c\n\x06person\x18\x01 \x03(\x0b\x32\x0c.test.Person')



_PERSON_PHONETYPE = descriptor.EnumDescriptor(
  name='PhoneType',
  full_name='test.Person.PhoneType',
  filename=None,
  file=DESCRIPTOR,
  values=[
    descriptor.EnumValueDescriptor(
      name='MOBILE', index=0, number=0,
      options=None,
      type=None),
    descriptor.EnumValueDescriptor(
      name='HOME', index=1, number=1,
      options=None,
      type=None),
    descriptor.EnumValueDescriptor(
      name='WORK', index=2, number=2,
      options=None,
      type=None),
  ],
  containing_type=None,
  options=None,
  serialized_start=195,
  serialized_end=238,
)


_PERSON_PHONENUMBER = descriptor.Descriptor(
  name='PhoneNumber',
  full_name='test.Person.PhoneNumber',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    descriptor.FieldDescriptor(
      name='number', full_name='test.Person.PhoneNumber.number', index=0,
      number=1, type=9, cpp_type=9, label=2,
      has_default_value=False, default_value=unicode("", "utf-8"),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    descriptor.FieldDescriptor(
      name='type', full_name='test.Person.PhoneNumber.type', index=1,
      number=2, type=14, cpp_type=8, label=1,
      has_default_value=True, default_value=1,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  options=None,
  is_extendable=False,
  extension_ranges=[],
  serialized_start=120,
  serialized_end=193,
)

_PERSON = descriptor.Descriptor(
  name='Person',
  full_name='test.Person',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    descriptor.FieldDescriptor(
      name='name', full_name='test.Person.name', index=0,
      number=1, type=9, cpp_type=9, label=2,
      has_default_value=False, default_value=unicode("", "utf-8"),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    descriptor.FieldDescriptor(
      name='id', full_name='test.Person.id', index=1,
      number=2, type=5, cpp_type=1, label=2,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    descriptor.FieldDescriptor(
      name='email', full_name='test.Person.email', index=2,
      number=3, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=unicode("", "utf-8"),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    descriptor.FieldDescriptor(
      name='phone', full_name='test.Person.phone', index=3,
      number=4, type=11, cpp_type=10, label=3,
      has_default_value=False, default_value=[],
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
  ],
  extensions=[
  ],
  nested_types=[_PERSON_PHONENUMBER, ],
  enum_types=[
    _PERSON_PHONETYPE,
  ],
  options=None,
  is_extendable=False,
  extension_ranges=[],
  serialized_start=28,
  serialized_end=238,
)


_ADDRESSBOOK = descriptor.Descriptor(
  name='AddressBook',
  full_name='test.AddressBook',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    descriptor.FieldDescriptor(
      name='person', full_name='test.AddressBook.person', index=0,
      number=1, type=11, cpp_type=10, label=3,
      has_default_value=False, default_value=[],
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  options=None,
  is_extendable=False,
  extension_ranges=[],
  serialized_start=240,
  serialized_end=283,
)

_PERSON_PHONENUMBER.fields_by_name['type'].enum_type = _PERSON_PHONETYPE
_PERSON_PHONENUMBER.containing_type = _PERSON;
_PERSON.fields_by_name['phone'].message_type = _PERSON_PHONENUMBER
_PERSON_PHONETYPE.containing_type = _PERSON;
_ADDRESSBOOK.fields_by_name['person'].message_type = _PERSON
DESCRIPTOR.message_types_by_name['Person'] = _PERSON
DESCRIPTOR.message_types_by_name['AddressBook'] = _ADDRESSBOOK

class Person(message.Message):
  __metaclass__ = reflection.GeneratedProtocolMessageType
  
  class PhoneNumber(message.Message):
    __metaclass__ = reflection.GeneratedProtocolMessageType
    DESCRIPTOR = _PERSON_PHONENUMBER
    
    # @@protoc_insertion_point(class_scope:test.Person.PhoneNumber)
  DESCRIPTOR = _PERSON
  
  # @@protoc_insertion_point(class_scope:test.Person)

class AddressBook(message.Message):
  __metaclass__ = reflection.GeneratedProtocolMessageType
  DESCRIPTOR = _ADDRESSBOOK
  
  # @@protoc_insertion_point(class_scope:test.AddressBook)

# @@protoc_insertion_point(module_scope)
