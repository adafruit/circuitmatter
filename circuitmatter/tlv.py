from __future__ import annotations

import enum
import math
import struct
from abc import ABC, abstractmethod
from typing import AnyStr, Generic, Iterable, Literal, Optional, Type, TypeVar, overload

# As a byte string to save space.
TAG_LENGTH = b"\x00\x01\x02\x04\x02\x04\x06\x08"
INT_SIZE = "BHIQ"


class ElementType(enum.IntEnum):
    SIGNED_INT = 0b00000
    UNSIGNED_INT = 0b00100
    BOOL = 0b01000
    FLOAT = 0b01010
    UTF8_STRING = 0b01100
    OCTET_STRING = 0b10000
    NULL = 0b10100
    STRUCTURE = 0b10101
    ARRAY = 0b10110
    LIST = 0b10111
    END_OF_CONTAINER = 0b11000


class TLVStructure:
    _max_length = None

    def __init__(self, buffer: Optional[bytes] = None):
        self.buffer = buffer
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
            for _field, descriptor_class in cls._members(cls):
                cls._max_length += descriptor_class.max_length
        return cls._max_length

    def __str__(self):
        members = []
        for field, descriptor_class in self._members(type(self)):
            value = descriptor_class.print(self)
            if isinstance(descriptor_class, StructMember):
                value = value.replace("\n", "\n  ")
            members.append(f"{field} = {value}")
        return "{\n  " + ",\n  ".join(members) + "\n}"

    def encode(self) -> memoryview:
        buffer = bytearray(self.max_length())
        end = self.encode_into(buffer)
        return memoryview(buffer)[:end]

    def encode_into(self, buffer, offset: int = 0):
        for _, descriptor_class in self._members(type(self)):
            offset = descriptor_class.encode_into(self, buffer, offset)
        return offset

    @staticmethod
    def _members(class_: Type) -> Iterable[tuple[str, Member]]:
        for field_name, descriptor in vars(class_).items():
            if not field_name.startswith("_") and isinstance(descriptor, Member):
                yield field_name, descriptor

    def scan_until(self, tag):
        if self.buffer is None:
            return
        while self._offset < len(self.buffer):
            control_octet = self.buffer[self._offset]
            tag_control = control_octet >> 5
            element_type = control_octet & 0x1F

            this_tag = None
            if tag_control == 0:  # Anonymous
                this_tag = None
            elif tag_control == 1:  # Context specific
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

            length_offset = self._offset + 1 + TAG_LENGTH[tag_control]
            element_category = element_type >> 2
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
                power_of_two = element_type & 0x3
                length_length = 1 << power_of_two
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


_T = TypeVar("_T")
_NULLABLE = TypeVar("_NULLABLE", Literal[True], Literal[False])


class Member(ABC, Generic[_T, _NULLABLE]):
    max_value_length: int = 0

    def __init__(self, tag, *, optional: bool = False, nullable: _NULLABLE = False):
        self.tag = tag
        self.optional = optional
        self.nullable = nullable
        self.tag_length = 0
        if isinstance(tag, int):
            self.tag_length = 1
        elif isinstance(tag, tuple):
            self.tag_length = 8
        self._max_length = None

    @property
    def max_length(self):
        return 1 + self.tag_length + self.max_value_length

    @overload
    def __get__(
        self: Member[_T, Literal[True]],
        obj: TLVStructure,
        objtype: Optional[Type[TLVStructure]] = None,
    ) -> Optional[_T]: ...

    @overload
    def __get__(
        self: Member[_T, Literal[False]],
        obj: TLVStructure,
        objtype: Optional[Type[TLVStructure]] = None,
    ) -> _T: ...

    def __get__(self, obj, objtype=None):
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

    @overload
    def __set__(
        self: Member[_T, Literal[True]], obj: TLVStructure, value: Optional[_T]
    ) -> None: ...
    @overload
    def __set__(
        self: Member[_T, Literal[False]], obj: TLVStructure, value: _T
    ) -> None: ...
    def __set__(self, obj, value):
        if value is None and not self.nullable:
            raise ValueError("Not nullable")
        obj.cached_values[self.tag] = value

    def encode_into(self, obj: TLVStructure, buffer: bytearray, offset: int) -> int:
        value = self.__get__(obj)  # type: ignore  # self inference issues
        element_type = ElementType.NULL
        if value is not None:
            element_type = self.encode_element_type(value)
        elif self.optional:
            # Value is None and the field is optional so skip it.
            return offset
        elif not self.nullable:
            raise ValueError("Required field isn't set")

        buffer[offset] = 0x00 | element_type
        offset += 1
        if self.tag:
            buffer[offset] = self.tag
            offset += 1
        if value is not None:
            new_offset = self.encode_value_into(  # type: ignore  # self inference issues
                value,
                buffer,
                offset,
            )
            return new_offset
        return offset

    def print(self, obj):
        value = self.__get__(obj)  # type: ignore  # self inference issues
        if value is None:
            return "null"
        return self._print(value)

    @abstractmethod
    def decode(self, buffer, length: int, offset: int = 0) -> _T:
        "Return the decoded value at `offset` in `buffer`"
        ...

    @abstractmethod
    def encode_element_type(self, value: _T) -> int:
        "Return Element Type Field as defined in Appendix A in the spec"
        ...

    @overload
    @abstractmethod
    def encode_value_into(
        self: Member[_T, Literal[True]], value: Optional[_T], buffer, offset: int
    ) -> int: ...
    @overload
    @abstractmethod
    def encode_value_into(
        self: Member[_T, Literal[False]], value: _T, buffer, offset: int
    ) -> int: ...
    @abstractmethod
    def encode_value_into(self, value, buffer, offset: int) -> int:
        "Encode `value` into `buffer` and return the new offset"
        ...

    @abstractmethod
    def _print(self, value: _T) -> str:
        "Return string representation of `value`"
        ...


# number type
_NT = TypeVar("_NT", float, int)


class NumberMember(Member[_NT, _NULLABLE], Generic[_NT, _NULLABLE]):
    def __init__(self, tag, _format: str, nullable: _NULLABLE = False, **kwargs):
        self.format = _format
        self.integer = _format[-1].upper() in INT_SIZE
        self.signed = self.format.islower()
        self.max_value_length = struct.calcsize(self.format)
        if self.integer:
            self._element_type = (
                ElementType.SIGNED_INT if self.signed else ElementType.UNSIGNED_INT
            )
            self._element_type |= int(math.log(self.max_value_length, 2))
        else:
            self._element_type = ElementType.FLOAT
            if self.max_value_length == 8:
                self._element_type |= 1
        super().__init__(tag, nullable=nullable, **kwargs)

    def __set__(self, obj, value):
        if value is not None and self.integer:
            octets = 2 ** INT_SIZE.index(self.format.upper()[-1])
            bits = 8 * octets
            max_size: int = (2 ** (bits - 1) if self.signed else 2**bits) - 1
            min_size: int = -max_size - 1 if self.signed else 0
            if not min_size <= value <= max_size:
                raise ValueError(
                    f"Out of bounds for {octets} octet {'' if self.signed else 'un'}signed int"
                )

        super().__set__(obj, value)  # type: ignore  # self inference issues

    def decode(self, buffer, length, offset=0) -> _NT:
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
        unsigned = "" if self.signed else "U"
        return f"{value}{unsigned}"

    def encode_element_type(self, value):
        # We don't adjust our encoding based on value size. We always use the bytes needed for the
        # format.
        return self._element_type

    def encode_value_into(self, value, buffer, offset) -> int:
        struct.pack_into(self.format, buffer, offset, value)
        return offset + self.max_value_length


class IntMember(NumberMember[int, _NULLABLE]):
    def __init__(
        self,
        tag,
        *,
        signed: bool = True,
        octets: Literal[1, 2, 4, 8] = 1,
        nullable: _NULLABLE = False,
        **kwargs,
    ):
        uformat = INT_SIZE[int(math.log2(octets))]
        # little-endian
        self.format = f"<{uformat.lower() if signed else uformat}"
        super().__init__(tag, _format=self.format, nullable=nullable, **kwargs)


class BoolMember(Member[bool, _NULLABLE]):
    max_value_length = 0

    def decode(self, buffer, length, offset=0):
        octet = buffer[offset]
        return octet & 1 == 1

    def _print(self, value):
        if value:
            return "true"
        return "false"

    def encode_element_type(self, value):
        return ElementType.BOOL | (1 if value else 0)

    def encode_value_into(self, value, buffer, offset) -> int:
        return offset


class StringMember(Member[AnyStr, _NULLABLE], Generic[AnyStr, _NULLABLE]):
    _base_element_type: ElementType

    def __init__(
        self, tag, max_length, *, optional=False, nullable: _NULLABLE = False, **kwargs
    ):
        self.max_value_length = max_length
        length_encoding = int(math.log(max_length, 256))
        self._element_type = self._base_element_type | length_encoding
        self.length_format = INT_SIZE[length_encoding]
        self.length_length = struct.calcsize(self.length_format)
        super().__init__(tag, optional=optional, nullable=nullable, **kwargs)

    def decode(self, buffer, length, offset=0):
        return buffer[offset : offset + length]

    def _print(self, value):
        return " ".join((f"{byte:02x}" for byte in value))

    def encode_element_type(self, value):
        return self._element_type

    def encode_value_into(self, value, buffer, offset) -> int:
        struct.pack_into(self.length_format, buffer, offset, len(value))
        offset += self.length_length
        buffer[offset : offset + len(value)] = value
        return offset + len(value)


class OctetStringMember(StringMember[bytes, _NULLABLE]):
    _base_element_type: ElementType = ElementType.OCTET_STRING


class UTF8StringMember(StringMember[str, _NULLABLE]):
    _base_element_type = ElementType.UTF8_STRING

    def decode(self, buffer, length, offset=0):
        return super().decode(buffer, length, offset).decode("utf-8")

    def encode_value_into(self, value, buffer, offset) -> int:
        return super().encode_value_into(value.encode("utf-8"), buffer, offset)

    def _print(self, value):
        return f'"{value}"'


class StructMember(Member):
    def __init__(self, tag, substruct_class, optional=False):
        self.substruct_class = substruct_class
        self.max_value_length = substruct_class.max_length() + 1
        super().__init__(tag, optional=optional)

    def decode(self, buffer, length, offset=0) -> TLVStructure:
        return self.substruct_class(buffer[offset : offset + length])

    def _print(self, value):
        return str(value)

    def encode_element_type(self, value):
        return ElementType.STRUCTURE

    def encode_value_into(self, value, buffer, offset) -> int:
        offset = value.encode_into(buffer, offset)
        buffer[offset] = ElementType.END_OF_CONTAINER
        return offset + 1
