import enum
import math
from typing import Optional, Type, Any
import struct

# As a byte string to save space.
TAG_LENGTH = b"\x00\x01\x02\x04\x02\x04\x06\x08"
INT_SIZE = "BHIQ"


class ElementType(enum.IntEnum):
    SIGNED_INT = 0b00000
    UNSIGNED_INT = 0b00100
    BOOL = 0b01000
    NULL = 0b10100
    STRUCTURE = 0b10101
    ARRAY = 0b10110
    LIST = 0b10111
    END_OF_CONTAINER = 0b11000


class TLVStructure:
    _max_length = None

    def __init__(self, buffer=None):
        self.buffer: memoryview = buffer
        # These three dicts are keyed by tag.
        self.tag_value_offset = {}
        self.null_tags = set()
        self.tag_value_length = {}
        self.cached_values = {}
        self._offset = 0  # Stopped at the next control octet

    @classmethod
    def max_length(cls):
        if cls._max_length is None:
            cls._max_length = 0
            for field in vars(cls):
                descriptor_class = vars(cls)[field]
                if field.startswith("_") or not isinstance(descriptor_class, Member):
                    continue
                cls._max_length += descriptor_class.max_length
        return cls._max_length

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

    def __bytes__(self):
        buffer = bytearray(self.max_length())
        offset = 0
        for field in vars(type(self)):
            descriptor_class = vars(type(self))[field]
            if field.startswith("_") or not isinstance(descriptor_class, Member):
                continue
            offset += descriptor_class.encode_into(self, buffer, offset)

    def scan_until(self, tag):
        if self.buffer is None:
            return
        print(bytes(self.buffer[self._offset :]))
        print(f"Looking for {tag}")
        while self._offset < len(self.buffer):
            control_octet = self.buffer[self._offset]
            tag_control = control_octet >> 5
            element_type = control_octet & 0x1F
            print(
                f"Control 0x{control_octet:x} tag_control {tag_control} element_type {element_type:x}"
            )

            this_tag = None
            if tag_control == 0:  # Anonymous
                this_tag = None
            elif tag_control == 1:  # Context specific
                print("context specific tag")
                this_tag = self.buffer[self._offset + 1]
            else:
                vendor_id = None
                profile_number = None
                if tag_control >= 6:  # Fully qualified
                    vendor_id, profile_number = struct.unpack_from(
                        "<HH", self.buffer, self._offset + 1
                    )

                if tag_control in (0b010, 0b011):
                    raise NotImplementedError("Common profile tag")

                if tag_control == 7:  # 4 octet tag number
                    tag_number = struct.unpack_from(
                        "<I", self.buffer, self._offset + 5
                    )[0]
                else:
                    tag_number = struct.unpack_from(
                        "<H", self.buffer, self._offset + 5
                    )[0]
                if vendor_id:
                    this_tag = (vendor_id, profile_number, tag_number)
                else:
                    this_tag = tag_number
            print(f"found tag {this_tag}")

            length_offset = self._offset + 1 + TAG_LENGTH[tag_control]
            element_category = element_type >> 2
            print(f"element_category {element_category}")
            if element_category == 0 or element_category == 1:  # ints
                value_offset = length_offset
                value_length = 1 << (element_type & 0x3)
            elif element_category == 2:  # Bool or float
                if element_type & 0x3 <= 1:
                    value_offset = self._offset
                    value_length = 1
                else:  # Float
                    value_offset = length_offset
                    print(value_offset)
                    value_length = 4 << (element_type & 0x1)
                    print(value_length)
            elif (
                element_category == 3 or element_category == 4
            ):  # UTF-8 String or Octet String
                print(f"element_type {element_type:x}", bin(element_type))
                power_of_two = element_type & 0x3
                print(f"power_of_two {power_of_two}")
                length_length = 1 << power_of_two
                print(f"length_length {length_length}")
                value_offset = length_offset + length_length
                value_length = struct.unpack_from(
                    INT_SIZE[power_of_two], self.buffer, length_offset
                )[0]
            elif element_type == 0b10100:  # Null
                value_offset = self._offset
                value_length = 1
                self.null_tags.add(this_tag)
            else:  # Container
                value_offset = length_offset
                value_length = 0
                nesting = 0
                while (
                    self.buffer[value_offset + value_length]
                    != ElementType.END_OF_CONTAINER
                    or nesting > 0
                ):
                    octet = self.buffer[value_offset + value_length]
                    if octet == ElementType.END_OF_CONTAINER:
                        nesting -= 1
                    elif (octet & 0x1F) in (
                        ElementType.STRUCTURE,
                        ElementType.ARRAY,
                        ElementType.LIST,
                    ):
                        nesting += 1
                    value_length += 1

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
        self.tag_length = 0
        if isinstance(tag, int):
            self.tag_length = 1
        elif isinstance(tag, tuple):
            self.tag_length = 8
        self._max_length = None

    @property
    def max_length(self):
        return self.tag_length + self.max_value_length

    def __get__(
        self,
        obj: Optional[TLVStructure],
        objtype: Optional[Type[TLVStructure]] = None,
    ) -> Any:
        if self.tag in obj.cached_values:
            return obj.cached_values[self.tag]
        if self.tag not in obj.tag_value_offset:
            obj.scan_until(self.tag)
        if self.tag not in obj.tag_value_offset or self.tag in obj.null_tags:
            return None

        value = self.decode(
            obj.buffer,
            obj.tag_value_length[self.tag],
            offset=obj.tag_value_offset[self.tag],
        )
        obj.cached_values[self.tag] = value
        return value

    def __set__(self, obj: TLVStructure, value: Any) -> None:
        obj.cached_values[self.tag] = value

    def encode_into(self, obj: TLVStructure, buffer: bytearray, offset: int) -> int:
        value = self.__get__(obj)
        element_type = ElementType.NULL
        if value is not None:
            element_type = self.encode_element_type(value)
        buffer[offset] = 0x00 | element_type
        offset += 1
        if self.tag:
            buffer[offset] = self.tag
            offset += 1
        if value is not None:
            return self.encode_value_into(value, buffer, offset)
        return offset

    def print(self, obj):
        value = self.__get__(obj)
        if value is None:
            return "null"
        return self._print(value)


class NumberMember(Member):
    def __init__(self, tag, _format, optional=False):
        self.format = _format
        self.integer = _format[-1].upper() in INT_SIZE
        self.max_value_length = struct.calcsize(self.format)
        super().__init__(tag, optional)

    def decode(self, buffer, length, offset=0):
        if self.integer:
            encoded_format = INT_SIZE[int(math.log(length, 2))]
            if self.format.islower():
                encoded_format = encoded_format.lower()
        else:
            if length == 4:
                encoded_format = "<f"
            else:
                encoded_format = "<d"
        return struct.unpack_from(encoded_format, buffer, offset=offset)[0]

    def _print(self, value):
        unsigned = "U" if self.format.isupper() else ""
        return f"{value}{unsigned}"


class BoolMember(Member):
    max_value_length = 0

    def decode(self, buffer, length, offset=0) -> bool:
        octet = buffer[offset]
        return octet & 1 == 1

    def _print(self, value):
        if value:
            return "true"
        return "false"

    @property
    def element_type(self, value):
        return ElementType.BOOL | (1 if value else 0)

    def encode_value_into(self, value, buffer, offset) -> int:
        return offset


class OctetStringMember(Member):
    def __init__(self, tag, max_length, optional=False):
        self.max_value_length = max_length
        super().__init__(tag, optional)

    def decode(self, buffer, length, offset=0):
        return buffer[offset : offset + length]

    def _print(self, value):
        return " ".join((f"{byte:02x}" for byte in value))


class UTF8StringMember(Member):
    def __init__(self, tag, max_length, optional=False):
        self.max_value_length = max_length
        super().__init__(tag, optional)

    def decode(self, buffer, length, offset=0):
        return buffer[offset : offset + length].decode("utf-8")

    def _print(self, value):
        return f'"{value}"'


class StructMember(Member):
    def __init__(self, tag, substruct_class, optional=False):
        self.substruct_class = substruct_class
        self.max_value_length = substruct_class.max_length()
        super().__init__(tag, optional)

    def decode(self, buffer, length, offset=0) -> TLVStructure:
        return self.substruct_class(buffer[offset : offset + length])

    def _print(self, value):
        return str(value)
