import enum
import math
from typing import Optional, Type, Any
import struct

# As a byte string to save space.
TAG_LENGTH = b"\x00\x01\x02\x04\x02\x04\x06\x08"
INT_SIZE = "BHIQ"

class ElementType(enum.IntEnum):
    STRUCTURE = 0b10101
    ARRAY = 0b10110
    LIST = 0b10111
    END_OF_CONTAINER = 0b11000

class TLVStructure:
    def __init__(self, buffer = None):
        self.buffer: memoryview = buffer
        # These three dicts are keyed by tag.
        self.tag_value_offset = {}
        self.tag_value_length = {}
        self.cached_values = {}
        self._offset = 0 # Stopped at the next control octet

    def __str__(self):
        members = []
        for field in vars(type(self)):
            descriptor_class = vars(type(self))[field]
            if field.startswith("_") or not isinstance(descriptor_class, Member):
                continue
            value = descriptor_class.print(self)
            if isinstance(descriptor_class, StructMember):
                value = value.replace("\n", "\n  ")
            members.append(f"{field} = {value}")
        return "{\n  " + ",\n  ".join(members) + "\n}"

    def scan_until(self, tag):
        if self.buffer is None:
            return
        print(bytes(self.buffer[self._offset:]))
        print(f"Looking for {tag}")
        while self._offset < len(self.buffer):
            control_octet = self.buffer[self._offset]
            tag_control = control_octet >> 5
            element_type = control_octet & 0x1F
            print(f"Control 0x{control_octet:x} tag_control {tag_control} element_type {element_type}")

            this_tag = None
            if tag_control == 0: # Anonymous
                this_tag = None
            elif tag_control == 1: # Context specific
                print("context specific tag")
                this_tag = self.buffer[self._offset + 1]
            else:
                vendor_id = None
                profile_number = None
                if tag_control >= 6: # Fully qualified
                    vendor_id, profile_number = struct.unpack_from("<HH", self.buffer, self._offset + 1)
                
                if tag_control in (0b010, 0b011):
                    raise NotImplementedError("Common profile tag")

                if tag_control == 7: # 4 octet tag number
                    tag_number = struct.unpack_from("<I", self.buffer, self._offset + 5)[0]
                else:
                    tag_number = struct.unpack_from("<H", self.buffer, self._offset + 5)[0]
                if vendor_id:
                    this_tag = (vendor_id, profile_number, tag_number)
                else:
                    this_tag = tag_number
            print(f"found tag {this_tag}")

            length_offset = self._offset + 1 + TAG_LENGTH[tag_control]
            element_category = element_type >> 2
            if element_category == 0 or element_category == 1: # ints
                value_offset = length_offset
                value_length = 1 << (element_type & 0x3)
            elif element_category == 2: # Bool or float
                if element_type & 0x3 <= 1:
                    value_offset = self._offset
                    value_length = 1
                else: # Float
                    value_offset = length_offset
                    print(value_offset)
                    value_length = 4 << (element_type & 0x1)
                    print(value_length)
            elif element_category == 3 or element_category == 4: # UTF-8 String or Octet String
                power_of_two = (element_type & 0x3)
                length_length = 1 << power_of_two
                value_offset = length_offset + length_length
                value_length = struct.unpack_from(INT_SIZE[power_of_two], self.buffer, length_offset)[0]
            elif element_type == 0b10100: # Null
                value_offset = self._offset
                value_length = 1
            else: # Container
                value_offset = length_offset
                value_length = 1
                nesting = 0
                print("in container")
                while self.buffer[value_offset + value_length] != ElementType.END_OF_CONTAINER or nesting > 0:
                    octet = self.buffer[value_offset + value_length]
                    if octet == ElementType.END_OF_CONTAINER:
                        nesting -= 1
                        print(nesting)
                    elif (octet & 0x1f) in (ElementType.STRUCTURE, ElementType.ARRAY, ElementType.LIST):
                        nesting += 1
                        print(nesting)
                    value_length += 1
                    print(f"new length {value_length} {self.buffer[value_offset + value_length]:02x}")
                print(f"container length {value_length}")

            self.tag_value_offset[this_tag] = value_offset
            self.tag_value_length[this_tag] = value_length

            # A few values are encoded in the control byte. Move our offset past
            # the tag where the length would be in that case.
            if self._offset == value_offset:
                self._offset = length_offset
            else:
                self._offset = value_offset + value_length

            if tag == this_tag:
                break

class Member:
    def __init__(self, tag, optional=False):
        self.tag = tag
        self.optional = optional

    def __get__(
        self,
        obj: Optional[TLVStructure],
        objtype: Optional[Type[TLVStructure]] = None,
    ) -> Any:
        if self.tag in obj.cached_values:
            return obj.cached_values[self.tag]
        if self.tag not in obj.tag_value_offset:
            obj.scan_until(self.tag)
        if self.tag not in obj.tag_value_offset:
            return None

        value = self.decode(obj.buffer, obj.tag_value_length[self.tag], offset=obj.tag_value_offset[self.tag])
        obj.cached_values[self.tag] = value
        return value

    def __set__(self, obj: TLVStructure, value: Any) -> None:
        obj.cached_values[self.tag] = value

class IntegerMember(Member):
    def __init__(self, tag, _format, optional=False):
        self.format = _format
        self.integer = _format[-1] in INT_SIZE
        super().__init__(tag, optional)

    def decode(self, buffer, length, offset=0):
        if self.integer:
            encoded_format = INT_SIZE[int(math.log(length, 2))]
            if self.format.islower():
                encoded_format = encoded_format.lower()
        else:
            encoded_format = self.format
        return struct.unpack_from(encoded_format, buffer, offset=offset)[0]

    def print(self, obj):
        value = self.__get__(obj)
        unsigned = "U" if self.format.isupper() else ""
        return f"{value}{unsigned}"

class FloatMember(Member):
    def decode(self, buffer, length, offset=0):
        if length == 4:
            encoded_format = "<f"
        else:
            encoded_format = "<d"
        return struct.unpack_from(encoded_format, buffer, offset=offset)[0]

    def print(self, obj):
        value = self.__get__(obj)
        return f"{value}"

class BoolMember(Member):
    def decode(self, buffer, length, offset=0) -> bool:
        octet = buffer[offset]
        return octet & 1 == 1

    def print(self, obj):
        if self.__get__(obj):
            return "true"
        return "false"

class OctetStringMember(Member):
    def __init__(self, tag, max_length, optional=False):
        self.max_length = max_length
        super().__init__(tag, optional)

    def decode(self, buffer, length, offset=0):
        return buffer[offset:offset + length]

    def print(self, obj):
        value = self.__get__(obj)
        return " ".join((f"{byte:02x}" for byte in value))


class UTF8StringMember(Member):
    def __init__(self, tag, max_length, optional=False):
        self.max_length = max_length
        super().__init__(tag, optional)

    def decode(self, buffer, length, offset=0):
        return buffer[offset:offset + length].decode("utf-8")

    def print(self, obj):
        value = self.__get__(obj)
        return f"\"{value}\""

class StructMember(Member):
    def __init__(self, tag, substruct_class, optional=False):
        self.substruct_class = substruct_class
        super().__init__(tag, optional)

    def decode(self, buffer, length, offset=0) -> TLVStructure:
        return self.substruct_class(buffer[offset:offset + length])

    def print(self, obj):
        value = self.__get__(obj)
        if value is None:
            return "null"
        return str(value)
