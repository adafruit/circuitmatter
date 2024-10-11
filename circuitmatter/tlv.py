from __future__ import annotations

import enum
import math
import struct
from abc import ABC, abstractmethod
from typing import (
    AnyStr,
    Generic,
    Iterable,
    Literal,
    Optional,
    Type,
    TypeVar,
    Union,
    overload,
)


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


def decode_tag(control_octet, buffer, offset=0):
    tag_control = control_octet >> 5

    this_tag = None
    if tag_control == 0:  # Anonymous
        this_tag = None
    elif tag_control == 1:  # Context specific
        this_tag = buffer[offset]
    else:
        vendor_id = None
        profile_number = None
        if tag_control >= 6:  # Fully qualified
            vendor_id, profile_number = struct.unpack_from("<HH", buffer, offset)

        if tag_control in (0b010, 0b011):
            raise NotImplementedError("Common profile tag")

        if tag_control == 7:  # 4 octet tag number
            tag_number = struct.unpack_from("<I", buffer, offset + 4)[0]
        else:
            tag_number = struct.unpack_from("<H", buffer, offset + 4)[0]
        if vendor_id:
            this_tag = (vendor_id, profile_number, tag_number)
        else:
            this_tag = tag_number
    return this_tag, offset + TAG_LENGTH[tag_control]


def decode_element(control_octet, buffer, offset, depth):
    element_type = control_octet & 0x1F
    element_category = element_type >> 2
    if element_category == 0 or element_category == 1:  # ints
        member_class = NumberMember
    elif element_category == 2:  # Bool or float
        if element_type & 0x3 <= 1:
            member_class = BoolMember
        else:  # Float
            member_class = NumberMember
    elif element_type == 0b10100:  # Null
        member_class = None
    elif element_category == (ElementType.UTF8_STRING >> 2):
        member_class = UTF8StringMember
    elif element_category == (ElementType.OCTET_STRING >> 2):
        member_class = OctetStringMember
    elif element_type == ElementType.STRUCTURE:
        member_class = StructMember
    elif element_type == ElementType.ARRAY:
        member_class = ArrayMember
    elif element_type == ElementType.LIST:
        member_class = ListMember
    else:
        raise ValueError(f"Unknown element type {element_type:b}")

    if member_class is None:
        value = None
        offset = offset
    else:
        result = member_class.decode(control_octet, buffer, offset, depth)
        value, offset = result
    return value, offset


class Container:
    _max_length = None

    def __init__(self):
        self.values = {}

    @classmethod
    def max_length(cls):
        if cls._max_length is None:
            cls._max_length = sum(member.max_length for _, member in cls._members())
        return cls._max_length + 2

    @classmethod
    def _members(cls) -> Iterable[tuple[str, Member]]:
        for superclass in cls.__mro__:
            for field_name, descriptor in vars(superclass).items():
                if not field_name.startswith("_") and isinstance(descriptor, Member):
                    yield field_name, descriptor

    @classmethod
    def _members_by_tag(cls) -> dict[int, tuple[str, Member]]:
        if hasattr(cls, "_members_by_tag_cache"):
            return cls._members_by_tag_cache
        members = {}
        for field_name, descriptor in vars(cls).items():
            if not field_name.startswith("_") and isinstance(descriptor, Member):
                members[descriptor.tag] = (field_name, descriptor)
        cls._members_by_tag_cache = members
        return members

    def set_value(self, tag, value):
        self.values[tag] = value

    def delete_value(self, tag):
        if tag in self.values:
            del self.values[tag]


class Structure(Container):
    def __str__(self):
        members = []
        for field, descriptor_class in self._members():
            value = getattr(self, field)  # type: ignore  # self inference issues
            if value is None:
                if descriptor_class.optional:
                    continue
                value = "null"
            else:
                value = descriptor_class.print(value)
            if isinstance(descriptor_class, StructMember):
                value = value.replace("\n", "\n  ")
            members.append(f"{field} = {value}")
        return "{\n  " + ",\n  ".join(members) + "\n}"

    def encode(self) -> memoryview:
        buffer = bytearray(self.max_length())
        buffer[0] = ElementType.STRUCTURE
        end = self.encode_into(buffer, offset=1)
        return memoryview(buffer)[:end]

    def encode_into(self, buffer: bytearray, offset: int = 0) -> int:
        for _, descriptor_class in self._members():
            offset = descriptor_class.encode_into(self, buffer, offset)
        buffer[offset] = ElementType.END_OF_CONTAINER
        return offset + 1

    @classmethod
    def decode(cls, control_octet, buffer, offset=0, depth=0) -> tuple[dict, int]:
        values = {}
        buffer = memoryview(buffer)
        while offset < len(buffer) and buffer[offset] != ElementType.END_OF_CONTAINER:
            control_octet = buffer[offset]
            this_tag, offset = decode_tag(control_octet, buffer, offset + 1)
            value, offset = decode_element(control_octet, buffer, offset, depth + 1)
            values[this_tag] = value

        if cls == Structure:
            return values, offset

        return cls.from_value(values), offset

    def construct_containers(self):
        tags = set(self.values.keys())
        for name, member_class in self._members():
            tag = member_class.tag
            if tag not in self.values:
                continue
            tags.remove(tag)
            self.values[tag] = member_class.from_value(self.values[tag])
        if tags:
            raise RuntimeError(f"Unknown tags {tags} in {type(self)}")

    @classmethod
    def from_value(cls, value):
        instance = cls()
        instance.values = value
        instance.construct_containers()
        return instance


_T = TypeVar("_T")
_NULLABLE = TypeVar("_NULLABLE", Literal[True], Literal[False])
_OPT = TypeVar("_OPT", Literal[True], Literal[False])


class Member(ABC, Generic[_T, _OPT, _NULLABLE]):
    max_value_length: int = 0

    def __init__(
        self, tag, *, optional: _OPT = False, nullable: _NULLABLE = False, default=None
    ) -> None:
        """
        :param optional: Indicates whether the value MAY be omitted from the encoding.
                         Can be used for deprecation.
        :param nullable: Indicates whether a TLV Null MAY be encoded in place of a value.
        """
        self.tag = tag
        self.optional = optional
        self.nullable = nullable
        self.tag_length = 0
        if isinstance(tag, int):
            self.tag_length = 1
            if tag >= 256:
                raise ValueError("Context specific tag too large")
        elif isinstance(tag, tuple):
            if tag[2] < 65536:
                self.tag_length = 6
            else:
                self.tag_length = 8
        self._max_length = None
        self._default = default
        self._name = None

    def __set_name__(self, owner, name):
        self._name = name

    @property
    def max_length(self):
        return 1 + self.tag_length + self.max_value_length

    @overload
    def __get__(
        self: Union[
            Member[_T, Literal[True], _NULLABLE], Member[_T, _OPT, Literal[True]]
        ],
        obj: Structure,
        objtype: Optional[Type[Structure]] = None,
    ) -> Optional[_T]: ...

    @overload
    def __get__(
        self: Member[_T, Literal[False], Literal[False]],
        obj: Structure,
        objtype: Optional[Type[Structure]] = None,
    ) -> _T: ...

    def __get__(self, obj, objtype=None):
        if obj is None:
            return self.tag
        if self.tag in obj.values:
            return obj.values[self.tag]
        return self._default

    @overload
    def __set__(
        self: Union[
            Member[_T, Literal[True], _NULLABLE], Member[_T, _OPT, Literal[True]]
        ],
        obj: Structure,
        value: Optional[_T],
    ) -> None: ...
    @overload
    def __set__(
        self: Member[_T, Literal[False], Literal[False]], obj: Structure, value: _T
    ) -> None: ...
    def __set__(self, obj, value):
        if value is None and not self.nullable:
            raise ValueError("Not nullable")
        obj.set_value(self.tag, value)

    def __delete__(self, obj):
        if not self.optional:
            raise ValueError("Not optional")
        obj.delete_value(self.tag)

    def encode(self, value):
        buffer = memoryview(bytearray(self.max_length))
        end = self._encode_value_into(value, buffer, 0, anonymous_ok=True)
        return buffer[:end]

    def encode_into(
        self,
        obj: Container,
        buffer: Union[bytearray, memoryview],
        offset: int,
        anonymous_ok=False,
    ) -> int:
        value = self.__get__(obj)  # type: ignore  # self inference issues
        return self._encode_value_into(value, buffer, offset, anonymous_ok)

    def _encode_value_into(
        self,
        value,
        buffer: Union[bytearray, memoryview],
        offset: int,
        anonymous_ok=False,
    ):
        element_type = ElementType.NULL
        if value is not None:
            element_type = self.encode_element_type(value)
        elif self.optional:
            # Value is None and the field is optional so skip it.
            return offset
        elif not self.nullable:
            raise ValueError(
                f"{self._name} ({type(self).__name__}) isn't set and not nullable or optional"
            )

        tag_control = 0
        if self.tag is not None:
            tag_control = 1
            if isinstance(self.tag, tuple):
                tag_control = 0b110
                if self.tag[2] >= 65536:
                    tag_control = 0b111
        elif not anonymous_ok:
            raise ValueError("Anonymous tag not allowed")

        buffer[offset] = tag_control << 5 | element_type
        offset += 1
        if self.tag is not None:
            if isinstance(self.tag, int):
                buffer[offset] = self.tag
                offset += 1
            else:
                vendor_id, profile_number, tag_number = self.tag
                struct.pack_into("<HH", buffer, offset, vendor_id, profile_number)
                offset += 4
                if tag_number >= 65536:
                    struct.pack_into("<I", buffer, offset, tag_number)
                    offset += 4
                else:
                    struct.pack_into("<H", buffer, offset, tag_number)
                    offset += 2
        if value is not None:
            new_offset = self.encode_value_into(  # type: ignore  # self inference issues
                value,
                buffer,
                offset,
            )
            return new_offset
        return offset

    @abstractmethod
    def decode(
        self, control_octet: int, buffer: memoryview, offset: int = 0
    ) -> (_T, int):
        "Return the decoded value at `offset` in `buffer`. `offset` is after the tag (but before any length)"
        ...

    @abstractmethod
    def encode_element_type(self, value: _T) -> int:
        "Return Element Type Field as defined in Appendix A in the spec"
        ...

    @overload
    @abstractmethod
    def encode_value_into(
        self: Union[
            Member[_T, Literal[True], _NULLABLE], Member[_T, _OPT, Literal[True]]
        ],
        value: Optional[_T],
        buffer: bytearray,
        offset: int,
    ) -> int: ...
    @overload
    @abstractmethod
    def encode_value_into(
        self: Member[_T, Literal[False], Literal[False]],
        value: _T,
        buffer: bytearray,
        offset: int,
    ) -> int: ...
    @abstractmethod
    def encode_value_into(
        self, value: Optional[_T], buffer: bytearray, offset: int
    ) -> int:
        "Encode `value` into `buffer` and return the new offset"
        ...

    @abstractmethod
    def print(self, value: _T) -> str:
        "Return string representation of `value`"
        ...

    def from_value(self, value):
        if value is None:
            if not self.nullable:
                raise ValueError("Member not nullable")
            return None
        return self._from_value(value)

    def _from_value(self, value):
        return value


# number type
_NT = TypeVar("_NT", float, int)


class NumberMember(Member[_NT, _OPT, _NULLABLE], Generic[_NT, _OPT, _NULLABLE]):
    def __init__(
        self,
        tag,
        _format: str,
        optional: _OPT = False,
        nullable: _NULLABLE = False,
        minimum: Optional[int] = None,
        maximum: Optional[int] = None,
        **kwargs,
    ):
        self.format = _format
        self.integer = _format[-1].upper() in INT_SIZE
        self.signed = self.format.islower()
        self.max_value_length = struct.calcsize(self.format)
        self._minimum = minimum
        self._maximum = maximum
        if self.integer:
            self._element_type = (
                ElementType.SIGNED_INT if self.signed else ElementType.UNSIGNED_INT
            )
            self._element_type |= int(math.log(self.max_value_length, 2))
        else:
            self._element_type = ElementType.FLOAT
            if self.max_value_length == 8:
                self._element_type |= 1
        super().__init__(tag, optional=optional, nullable=nullable, **kwargs)

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
        if self._minimum is not None and value < self._minimum:
            raise ValueError(f"Value is less than minimum of {self._minimum}")

        if self._maximum is not None and value > self._maximum:
            raise ValueError(f"Value is greater than maximum of {self._maximum}")

        super().__set__(obj, value)  # type: ignore  # self inference issues

    @staticmethod
    def decode(control_octet, buffer, offset=0, depth=0) -> tuple[_NT, int]:
        element_type = control_octet & 0x1F
        element_category = element_type >> 2
        if element_category == 0 or element_category == 1:
            length = 1 << (control_octet & 0x3)
            encoded_format = INT_SIZE[int(math.log(length, 2))]
            if element_category == 0:
                encoded_format = encoded_format.lower()
        else:
            length = 4 << (control_octet & 0x1)
            if length == 4:
                encoded_format = "<f"
            else:
                encoded_format = "<d"
        return (
            struct.unpack_from(encoded_format, buffer, offset=offset)[0],
            offset + struct.calcsize(encoded_format),
        )

    def print(self, value):
        unsigned = "" if self.signed else "U"
        return f"{value}{unsigned}"

    def encode_element_type(self, value):
        if self.integer:
            bit_length = value.bit_length()
            if self.signed:
                type = ElementType.SIGNED_INT
            else:
                type = ElementType.UNSIGNED_INT
            length = 0  # in power of two
            if bit_length <= 8:
                length = 0
            elif bit_length <= 16:
                length = 1
            elif bit_length <= 32:
                length = 2
            else:
                length = 3
            return type | length
        return self._element_type

    def encode_value_into(self, value, buffer, offset) -> int:
        print("encode value", value, f"{buffer}@{offset}")
        if self.integer:
            bit_length = value.bit_length()
            format_string = None
            if bit_length <= 8:
                format_string = "<b" if self.signed else "<B"
                length = 1
            elif bit_length <= 16:
                format_string = "<h" if self.signed else "<H"
                length = 2
            elif bit_length <= 32:
                format_string = "<i" if self.signed else "<I"
                length = 4
            else:
                format_string = "<q" if self.signed else "<Q"
                length = 8
            print(format_string)
            struct.pack_into(format_string, buffer, offset, value)
            return offset + length
        # Float
        struct.pack_into(self.format, buffer, offset, value)
        return offset + self.max_value_length


class IntMember(NumberMember[int, _OPT, _NULLABLE]):
    def __init__(
        self,
        tag,
        *,
        signed: bool = True,
        octets: Literal[1, 2, 4, 8] = 1,
        optional: _OPT = False,
        nullable: _NULLABLE = False,
        **kwargs,
    ):
        """
        :param octets: Number of octests to use for encoding.
                       1, 2, 4, 8 are 8, 16, 32, and 64 bits respectively
        :param optional: Indicates whether the value MAY be omitted from the encoding.
                         Can be used for deprecation.
        :param nullable: Indicates whether a TLV Null MAY be encoded in place of a value.
        """
        # TODO 7.18.1 mentions other bit lengths (that are not a power of 2) than the TLV Appendix
        uformat = INT_SIZE[int(math.log2(octets))]
        # < = little-endian
        self.format = f"<{uformat.lower() if signed else uformat}"
        super().__init__(
            tag, _format=self.format, optional=optional, nullable=nullable, **kwargs
        )


class EnumMember(IntMember):
    def __init__(self, tag, enum_class, **kwargs):
        self.enum_class = enum_class
        super().__init__(tag, octets=2, signed=False, **kwargs)

    def __set__(self, obj, value):
        if not isinstance(value, self.enum_class):
            raise ValueError(f"Value must be a {self.enum_class}")
        super().__set__(obj, value.value)

    def __get__(self, obj, objtype=None) -> Optional[enum.Enum]:
        value = super().__get__(obj, objtype)
        if value is not None:
            return self.enum_class(value)
        return

    def print(self, value):
        return self.enum_class(value).name


class FloatMember(NumberMember[float, _OPT, _NULLABLE]):
    def __init__(
        self,
        tag,
        *,
        octets: Literal[4, 8] = 4,
        optional: _OPT = False,
        nullable: _NULLABLE = False,
        **kwargs,
    ):
        """
        :param octets: Number of octests to use for encoding.
                       4, 8 are single and double precision floats respectively.
        :param optional: Indicates whether the value MAY be omitted from the encoding.
                         Can be used for deprecation.
        :param nullable: Indicates whether a TLV Null MAY be encoded in place of a value.
        """
        # < = little-endian
        self.format = f"<{'f' if octets == 4 else 'd'}"
        super().__init__(
            tag, _format=self.format, optional=optional, nullable=nullable, **kwargs
        )


class BoolMember(Member[bool, _OPT, _NULLABLE]):
    max_value_length = 0

    @staticmethod
    def decode(control_octet, buffer, offset=0, depth=0):
        return (control_octet & 1 == 1, offset)

    def print(self, value):
        if value:
            return "true"
        return "false"

    def encode_element_type(self, value):
        return ElementType.BOOL | (1 if value else 0)

    def encode_value_into(self, value, buffer, offset) -> int:
        return offset


class StringMember(Member[AnyStr, _OPT, _NULLABLE], Generic[AnyStr, _OPT, _NULLABLE]):
    _base_element_type: ElementType

    def __init__(
        self,
        tag,
        max_length: int,
        *,
        optional: _OPT = False,
        nullable: _NULLABLE = False,
        min_length: int = 0,
        **kwargs,
    ):
        self._element_type = self._base_element_type

        max_length_encoding = int(math.log(max_length, 256))
        max_length_format = INT_SIZE[max_length_encoding]
        self.length_length = struct.calcsize(max_length_format)
        self.min_length = min_length
        if max_length is None:
            raise ValueError("max_length is required")
        self._max_string_length = max_length if max_length is not None else 1280
        self.max_value_length = max_length + self.length_length
        super().__init__(tag, optional=optional, nullable=nullable, **kwargs)

    def print(self, value):
        return " ".join((f"{byte:02x}" for byte in value))

    def __set__(self, obj, value):
        if len(value) > self._max_string_length:
            raise ValueError(
                f"Value too long. {len(value)} > {self._max_string_length} bytes"
            )
        if len(value) < self.min_length:
            raise ValueError(f"Value too short. {len(value)} < {self.min_length} bytes")

        super().__set__(obj, value)  # type: ignore  # self inference issues

    def encode_element_type(self, value):
        # Log only works for 1+ so make 0 1 for length encoding.
        value_length = len(value)
        if value_length <= 0:
            value_length = 1
        length_encoding = int(math.log(value_length, 256))
        return self._element_type | length_encoding

    def encode_value_into(self, value, buffer: bytearray, offset: int) -> int:
        # Log only works for 1+ so make 0 1 for length encoding.
        value_length = len(value)
        if value_length <= 0:
            value_length = 1
        length_encoding = int(math.log(value_length, 256))
        length_format = INT_SIZE[length_encoding]
        length_length = struct.calcsize(length_format)
        struct.pack_into(length_format, buffer, offset, len(value))
        offset += length_length
        buffer[offset : offset + len(value)] = value
        return offset + len(value)

    @staticmethod
    def parse_length(control_octet, buffer, offset=0):
        element_type = control_octet & 0x1F
        power_of_two = element_type & 0x3
        length_length = 1 << power_of_two
        value_length = struct.unpack_from(INT_SIZE[power_of_two], buffer, offset)[0]
        return value_length, offset + length_length


class OctetStringMember(StringMember[bytes, _OPT, _NULLABLE]):
    _base_element_type: ElementType = ElementType.OCTET_STRING

    @staticmethod
    def decode(control_octet, buffer, offset=0, depth=0):
        length, offset = StringMember.parse_length(control_octet, buffer, offset)
        return (buffer[offset : offset + length].tobytes(), offset + length)


class UTF8StringMember(StringMember[str, _OPT, _NULLABLE]):
    _base_element_type = ElementType.UTF8_STRING

    @staticmethod
    def decode(control_octet, buffer, offset=0, depth=0):
        length, offset = StringMember.parse_length(control_octet, buffer, offset)
        return (
            buffer[offset : offset + length].tobytes().decode("utf-8"),
            offset + length,
        )

    def encode_value_into(self, value: str, buffer, offset) -> int:
        return super().encode_value_into(value.encode("utf-8"), buffer, offset)

    def print(self, value):
        return f'"{value}"'


_TLVStruct = TypeVar("_TLVStruct", bound=Structure)


class StructMember(Member[_TLVStruct, _OPT, _NULLABLE]):
    def __init__(
        self,
        tag,
        substruct_class: Type[_TLVStruct],
        *,
        optional: _OPT = False,
        nullable: _NULLABLE = False,
        **kwargs,
    ):
        self.substruct_class = substruct_class
        self.max_value_length = substruct_class.max_length() + 1
        super().__init__(tag, optional=optional, nullable=nullable, **kwargs)

    @staticmethod
    def decode(control_octet, buffer, offset=0, depth=0):
        value, offset = Structure.decode(control_octet, buffer, offset, depth)
        return value, offset + 1

    def print(self, value):
        return str(value)

    def encode_element_type(self, value):
        return ElementType.STRUCTURE

    def encode_value_into(self, value, buffer: bytearray, offset: int) -> int:
        offset = value.encode_into(buffer, offset)
        return offset

    def _from_value(self, value):
        return self.substruct_class.from_value(value)


class ArrayEncodingError(Exception):
    def __init__(self, index, offset):
        self.index = index
        """First index not encoded"""
        self.offset = offset


class ArrayMember(Member[_TLVStruct, _OPT, _NULLABLE]):
    def __init__(
        self,
        tag,
        substruct_class: Type[_TLVStruct, Member],
        *,
        max_length: Optional[int] = None,
        optional: _OPT = False,
        nullable: _NULLABLE = False,
        **kwargs,
    ):
        self.substruct_class = substruct_class
        self.max_value_length = 1280
        self.max_items = max_length
        super().__init__(tag, optional=optional, nullable=nullable, **kwargs)

    @staticmethod
    def decode(control_octet, buffer, offset=0, depth=0):
        entries = []
        while buffer[offset] != ElementType.END_OF_CONTAINER:
            control_octet = buffer[offset]
            value, offset = decode_element(control_octet, buffer, offset + 1, depth + 1)
            entries.append(value)
        return (entries, offset + 1)

    def print(self, value):
        s = ["["]
        items = []
        for v in value:
            items.append(str(v))
        s.append(", ".join(items))
        s.append("]")
        return "".join(s)

    def encode_element_type(self, value):
        return ElementType.ARRAY

    def encode_value_into(self, value, buffer: memoryview, offset: int) -> int:
        subbuffer = memoryview(buffer)[:-1]
        print(self.print(value))
        last_offset = offset
        for i, v in enumerate(value):
            if offset >= len(buffer) - 1:
                # If we run out of room, mark our end and raise an exception.
                buffer[offset] = ElementType.END_OF_CONTAINER
                raise ArrayEncodingError(i, offset + 1)
            try:
                if isinstance(self.substruct_class, Member):
                    buffer[offset] = self.substruct_class.encode_element_type(v)
                    offset = self.substruct_class.encode_value_into(
                        v, subbuffer, offset + 1
                    )
                else:
                    if isinstance(v, Structure):
                        buffer[offset] = ElementType.STRUCTURE
                    elif isinstance(v, List):
                        buffer[offset] = ElementType.LIST
                    offset = v.encode_into(subbuffer, offset + 1)
            except (ValueError, IndexError, struct.error):
                # If we run out of room, mark our end and raise an exception.
                buffer[offset] = ElementType.END_OF_CONTAINER
                raise ArrayEncodingError(i, last_offset + 1)
            last_offset = offset
        buffer[offset] = ElementType.END_OF_CONTAINER
        return offset + 1

    def _from_value(self, value):
        for i in range(len(value)):
            value[i] = self.substruct_class.from_value(value[i])
        return value


class List(Container):
    def __init__(self):
        self.items = []
        # items by tag. First occurence wins.
        self.values = {}

    def __iter__(self):
        return iter(self.items)

    def __str__(self):
        members = []
        member_by_tag = self._members_by_tag()
        for item in self.items:
            if isinstance(item, tuple):
                tag, value = item
                if tag in member_by_tag:
                    name, member = member_by_tag[tag]
                else:
                    name = tag
            else:
                name = None
                value = item

            if member:
                value = member.print(value)
                if not value:
                    continue
                if isinstance(member, StructMember):
                    value = value.replace("\n", "\n  ")
            if name:
                members.append(f"{name} = {value}")
            else:
                members.append(value)
        return "[[ " + ", ".join(members) + "]]"

    def encode(self) -> memoryview:
        buffer = bytearray(self.max_length())
        buffer[0] = ElementType.LIST
        end = self.encode_into(buffer, offset=1)
        return memoryview(buffer)[:end]

    def encode_into(self, buffer: bytearray, offset: int = 0) -> int:
        member_by_tag = self._members_by_tag()
        for item in self.items:
            if isinstance(item, tuple):
                tag, value = item
                if tag in member_by_tag:
                    name, member = member_by_tag[tag]
                else:
                    raise NotImplementedError("Unknown tag")
                offset = member.encode_into(self, buffer, offset, anonymous_ok=True)
            else:
                raise NotImplementedError("Anonymous list member")
        buffer[offset] = ElementType.END_OF_CONTAINER
        return offset + 1

    @classmethod
    def from_value(cls, value):
        instance = cls()
        instance.items = value
        instance.values = {}
        members_by_tag = cls._members_by_tag()
        for i, item in enumerate(value):
            if isinstance(item, tuple):
                tag, value = item
                if tag in members_by_tag:
                    value = members_by_tag[tag][1].from_value(value)
                    instance.items[i] = (tag, value)
                if tag in instance.values:
                    continue
                instance.values[tag] = value
        return instance

    def set_value(self, tag, value):
        if tag in self.values:
            i = self.items.index((tag, self.values[tag]))
            self.items[i] = (tag, value)
        else:
            self.items.append((tag, value))
        self.values[tag] = value

    def delete_value(self, tag):
        for item in self.items:
            if item[0] == tag:
                self.items.remove(item)
        del self.values[tag]

    def copy(self):
        new = type(self)()
        new.items.extend(self.items)
        new.values.update(self.values)
        return new


_TLVList = TypeVar("_TLVList", bound=List)


class ListMember(Member):
    def __init__(
        self,
        tag,
        substruct_class: Type[_TLVList],
        *,
        optional: _OPT = False,
        nullable: _NULLABLE = False,
        **kwargs,
    ):
        self.substruct_class = substruct_class
        self.max_value_length = substruct_class.max_length() + 1
        super().__init__(tag, optional=optional, nullable=nullable, **kwargs)

    @staticmethod
    def decode(control_octet, buffer, offset=0, depth=0):
        raw_list = []
        while buffer[offset] != ElementType.END_OF_CONTAINER:
            control_octet = buffer[offset]

            this_tag, offset = decode_tag(control_octet, buffer, offset + 1)
            value, offset = decode_element(control_octet, buffer, offset, depth + 1)

            if this_tag is None:
                raw_list.append(value)
            else:
                raw_list.append((this_tag, value))
        return raw_list, offset + 1

    def print(self, value):
        return str(value)

    def encode_element_type(self, value):
        return ElementType.LIST

    def encode_value_into(self, value, buffer: bytearray, offset: int) -> int:
        offset = value.encode_into(buffer, offset)
        return offset

    def _from_value(self, value):
        return self.substruct_class.from_value(value)


class AnythingMember(Member):
    """Stores a TLV encoded value."""

    def decode(self, control_octet, buffer, offset=0):
        return None

    def print(self, value):
        if isinstance(value, bytes):
            return value.hex(" ")
        if isinstance(value, memoryview):
            return value.hex(" ")
        return str(value)

    def encode_element_type(self, value):
        return value[0]

    def encode_value_into(self, value, buffer: bytearray, offset: int) -> int:
        value_length = len(value) - 1
        buffer[offset : offset + value_length] = memoryview(value)[1:]
        return offset + value_length
