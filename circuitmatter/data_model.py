import binascii
import enum
import inspect
import random
import struct
import traceback
import typing
from typing import Iterable, Union

from . import interaction_model
from . import tlv

ATTRIBUTES_KEY = "a"


class Enum8(enum.IntEnum):
    pass


class Enum16(enum.IntEnum):
    pass


class Map8(enum.IntFlag):
    pass


class Map16(enum.IntFlag):
    pass


class Uint16(tlv.IntMember):
    def __init__(self, _id=None, minimum=0, **kwargs):
        super().__init__(_id, signed=False, octets=2, minimum=minimum, **kwargs)


class Uint32(tlv.IntMember):
    def __init__(self, _id=None, minimum=0, **kwargs):
        super().__init__(_id, signed=False, octets=4, minimum=minimum, **kwargs)


class Uint64(tlv.IntMember):
    def __init__(self, _id=None, minimum=0, **kwargs):
        super().__init__(_id, signed=False, octets=8, minimum=minimum, **kwargs)


class NodeId(Uint64):
    pass


class GroupId(Uint16):
    def __init__(self, _id=None, **kwargs):
        super().__init__(_id, minimum=1, **kwargs)


class ClusterId(Uint16):
    pass


class DeviceTypeId(Uint32):
    pass


class EndpointNumber(Uint16):
    def __init__(self, _id=None, **kwargs):
        super().__init__(_id, minimum=1, **kwargs)


# Data model "lists" are encoded as tlv arrays. 🙄
class List(tlv.ArrayMember):
    pass


class Attribute:
    def __init__(
        self,
        _id,
        default=None,
        optional=False,
        feature=0,
        C_changes_omitted=False,
        F_fixed=False,
        N_nonvolatile=False,
        P_reportable=False,
        Q_quieter_reporting=False,
        S_scene=False,
        X_nullable=False,
    ):
        self.id = _id
        self.default = default
        self.optional = optional
        self.feature = feature
        self.nullable = X_nullable
        self.nonvolatile = N_nonvolatile

    def __get__(self, instance, cls):
        v = instance._attribute_values.get(self.id, None)
        if v is None:
            if callable(self.default):
                return self.default(instance.feature_map)
            return self.default
        return v

    def __set__(self, instance, value):
        old_value = instance._attribute_values.get(self.id, None)
        if old_value == value:
            return
        instance._attribute_values[self.id] = value
        if self.nonvolatile:
            instance._nonvolatile[ATTRIBUTES_KEY][hex(self.id)] = self.to_json(value)
        instance.data_version += 1

    def to_json(self, value):
        return value

    def from_json(self, value):
        return value

    def encode(self, value) -> bytes:
        if value is None and self.nullable:
            return b"\x14"  # No tag, NULL
        return self._encode(value)

    def _encode(self, value):
        raise NotImplementedError()


class NumberAttribute(Attribute):
    def __init__(self, _id, *, signed, bits, **kwargs):
        self.signed = signed
        self.bits = bits
        self.id = _id
        super().__init__(_id, **kwargs)

    @staticmethod
    def encode_number(value, *, signed=True) -> bytes:
        bit_length = value.bit_length()
        format_string = None
        if signed:
            type = tlv.ElementType.SIGNED_INT
        else:
            type = tlv.ElementType.UNSIGNED_INT
        length = 0  # in power of two
        if bit_length <= 8:
            format_string = "<Bb" if signed else "<BB"
            length = 0
        elif bit_length <= 16:
            format_string = "<Bh" if signed else "<BH"
            length = 1
        elif bit_length <= 32:
            format_string = "<Bi" if signed else "<BI"
            length = 2
        else:
            format_string = "<Bq" if signed else "<BQ"
            length = 3

        return struct.pack(format_string, type | length, value)

    def _encode(self, value) -> bytes:
        return NumberAttribute.encode_number(value, signed=self.signed)


class EnumAttribute(NumberAttribute):
    def __init__(self, _id, enum_type, **kwargs):
        self.enum_type = enum_type
        bits = 8 if issubclass(enum_type, Enum8) else 16
        super().__init__(_id, signed=False, bits=bits, **kwargs)


class _PersistentList:
    def __init__(self, wrapped_list, attribute, instance):
        self._list = wrapped_list
        self._instance = instance
        self._attribute = attribute

    def append(self, value):
        self._list.append(value)
        self._instance._nonvolatile[ATTRIBUTES_KEY][hex(self._attribute.id)] = (
            self._attribute.to_json(self._list)
        )

    def __getitem__(self, index):
        return self._list[index]

    def __setitem__(self, index, value):
        self._list[index] = value
        self._dirty = True

    def __iter__(self):
        return iter(self._list)

    def __len__(self):
        return len(self._list)

    def __str__(self):
        return "persistent" + str(self._list)


class ListAttribute(Attribute):
    def __init__(self, _id, element_type, **kwargs):
        if inspect.isclass(element_type) and issubclass(element_type, enum.Enum):
            element_type = tlv.EnumMember(None, element_type)
        self.tlv_type = tlv.ArrayMember(None, element_type)
        self._element_type = element_type
        # Copy the default list so we don't accidentally share it with another
        # cluster of the same type.
        if "default" in kwargs and isinstance(kwargs["default"], list):
            kwargs["default"] = list(kwargs["default"])
        super().__init__(_id, **kwargs)

    def __get__(self, instance, cls):
        v = super().__get__(instance, cls)
        if self.nonvolatile and v is not None and not isinstance(v, _PersistentList):
            # Wrap the list in an object that tracks changes and writes them to nonvolatile.
            p = _PersistentList(v, self, instance)
            instance._attribute_values[self.id] = p
            return p
        return v

    def to_json(self, value):
        return [
            binascii.b2a_base64(self._element_type.encode(v), newline=False).decode(
                "utf-8"
            )
            for v in value
        ]

    def from_json(self, value):
        return [
            self._element_type.decode(memoryview(binascii.a2b_base64(v))) for v in value
        ]

    def _encode(self, value) -> bytes:
        return self.tlv_type.encode(value)

    def element_from_value(self, value):
        if issubclass(self._element_type, tlv.Container):
            return self._element_type.from_value(value)
        if issubclass(self._element_type, enum.Enum):
            return self._element_type(value)
        return value


class BoolAttribute(Attribute):
    def encode(self, value) -> bytes:
        return struct.pack("B", tlv.ElementType.BOOL | (1 if value else 0))


class StructAttribute(Attribute):
    def __init__(self, _id, struct_type, default=None):
        self.struct_type = struct_type
        super().__init__(_id, default=default)

    def encode(self, value) -> memoryview:
        buffer = memoryview(bytearray(value.max_length() + 2))
        buffer[0] = tlv.ElementType.STRUCTURE
        end = value.encode_into(buffer, 1)
        return buffer[:end]


class OctetStringAttribute(Attribute):
    def __init__(self, _id, min_length, max_length, **kwargs):
        self.min_length = min_length
        self.max_length = max_length
        self.member = tlv.OctetStringMember(None, max_length=max_length)
        super().__init__(_id, **kwargs)

    def encode(self, value):
        return self.member.encode(value)


class UTF8StringAttribute(Attribute):
    def __init__(self, _id, min_length=0, max_length=1200, **kwargs):
        self.min_length = min_length
        self.max_length = max_length
        self.member = tlv.UTF8StringMember(None, max_length=max_length)
        super().__init__(_id, **kwargs)

    def encode(self, value):
        return self.member.encode(value)


class BitmapAttribute(NumberAttribute):
    def __init__(self, _id, enum_type, **kwargs):
        self.enum_type = enum_type
        bits = 8 if issubclass(enum_type, Map8) else 16
        super().__init__(_id, signed=False, bits=bits, **kwargs)


class Command:
    def __init__(
        self,
        command_id,
        request_type,
        response_id=None,
        response_type=interaction_model.StatusCode,
    ):
        self.command_id = command_id
        self.request_type = request_type
        self.response_id = response_id
        self.response_type = response_type


class Cluster:
    feature_map = NumberAttribute(0xFFFC, signed=False, bits=32, default=0)

    def __init__(self):
        self._attribute_values = {}
        # Use random since this isn't for security or replayability.
        self.data_version = random.randint(0, 0xFFFFFFFF)

    def __contains__(self, descriptor_id):
        return descriptor_id in self._attribute_values

    @classmethod
    def _attributes(cls) -> Iterable[tuple[str, Attribute]]:
        for superclass in cls.__mro__:
            for field_name, descriptor in vars(superclass).items():
                if not field_name.startswith("_") and isinstance(descriptor, Attribute):
                    yield field_name, descriptor

    def restore(self, nonvolatile):
        self._nonvolatile = nonvolatile

        if ATTRIBUTES_KEY not in nonvolatile:
            nonvolatile[ATTRIBUTES_KEY] = {}
        for field_name, descriptor in self._attributes():
            if descriptor.nonvolatile:
                if hex(descriptor.id) in nonvolatile[ATTRIBUTES_KEY]:
                    # Update our live value
                    self._attribute_values[descriptor.id] = descriptor.from_json(
                        nonvolatile[ATTRIBUTES_KEY][hex(descriptor.id)]
                    )
                else:
                    # Store the default
                    nonvolatile[ATTRIBUTES_KEY][hex(descriptor.id)] = descriptor.default

    def get_attribute_data(
        self, session, path
    ) -> typing.List[interaction_model.AttributeDataIB]:
        replies = []
        for field_name, descriptor in self._attributes():
            if path.Attribute is not None and descriptor.id != path.Attribute:
                continue
            if descriptor.feature and not (self.feature_map & descriptor.feature):
                continue
            self.current_fabric_index = session.local_fabric_index
            value = getattr(self, field_name)
            self.current_fabric_index = None
            print(
                "reading",
                f"EP{path.Endpoint}",
                type(self).__name__,
                field_name,
                "->",
                value,
            )
            if value is None and descriptor.optional:
                continue
            data = interaction_model.AttributeDataIB()
            data.DataVersion = 0
            attribute_path = interaction_model.AttributePathIB()
            attribute_path.Endpoint = path.Endpoint
            attribute_path.Cluster = path.Cluster
            attribute_path.Attribute = descriptor.id
            data.Path = attribute_path
            data.Data = descriptor.encode(value)
            print(
                f"{path.Endpoint}/{path.Cluster:x}/{descriptor.id:x} -> {data.Data.hex(' ')}"
            )
            replies.append(data)
            if path.Attribute is not None:
                break
        if not replies:
            print("not found", path.Attribute)
        return replies

    def set_attribute(
        self, context, attribute_data
    ) -> interaction_model.AttributeStatusIB:
        status_code = interaction_model.StatusCode.SUCCESS
        for field_name, descriptor in self._attributes():
            path = attribute_data.Path
            if path.Attribute is not None and descriptor.id != path.Attribute:
                continue
            has_list_index = False
            for entry in path:
                if (
                    isinstance(entry, tuple)
                    and entry[0] == interaction_model.AttributePathIB.ListIndex
                ):
                    has_list_index = True
                    break
            # value =
            value = attribute_data.Data
            print("writing", self, field_name, "->", value, "?", has_list_index)

            if has_list_index:
                if not isinstance(descriptor, ListAttribute):
                    status_code = interaction_model.StatusCode.UNSUPPORTED_WRITE
                    break
                list_ = getattr(self, field_name)
                if not isinstance(list_, list):
                    status_code = interaction_model.StatusCode.UNSUPPORTED_WRITE
                    break
                list_.append(descriptor.element_from_value(value))
            else:
                setattr(self, field_name, value)
        astatus = interaction_model.AttributeStatusIB()
        astatus.Path = attribute_data.Path
        status = interaction_model.StatusIB()
        status.Status = status_code
        status.ClusterStatus = 0
        astatus.Status = status
        return astatus

    @classmethod
    def _commands(cls) -> Iterable[tuple[str, Command]]:
        for superclass in cls.__mro__:
            for field_name, descriptor in vars(superclass).items():
                if not field_name.startswith("_") and isinstance(descriptor, Command):
                    yield field_name, descriptor

    def invoke(
        self, session, path, fields
    ) -> Union[interaction_model.CommandDataIB, interaction_model.StatusCode, None]:
        found = False
        for field_name, descriptor in self._commands():
            if descriptor.command_id != path.Command:
                continue

            print("invoke", type(self).__name__, field_name)
            command = getattr(self, field_name)
            if callable(command):
                if descriptor.request_type is not None:
                    try:
                        arg = descriptor.request_type.from_value(fields)
                    except ValueError:
                        return interaction_model.StatusCode.INVALID_COMMAND
                    try:
                        print(arg)
                        result = command(session, arg)
                    except Exception as e:
                        traceback.print_exception(e)
                        return interaction_model.StatusCode.FAILURE
                else:
                    try:
                        result = command(session)
                    except Exception as e:
                        print(e)
                        return interaction_model.StatusCode.FAILURE
            else:
                return interaction_model.StatusCode.UNSUPPORTED_COMMAND
            if descriptor.response_type is interaction_model.StatusCode:
                if result is None:
                    return interaction_model.StatusCode.SUCCESS
                return result
            elif descriptor.response_type is not None:
                cdata = interaction_model.CommandDataIB()
                response_path = interaction_model.CommandPathIB()
                response_path.Endpoint = path.Endpoint
                response_path.Cluster = path.Cluster
                response_path.Command = descriptor.response_id
                cdata.CommandPath = response_path
                if result:
                    cdata.CommandFields = descriptor.response_type.encode(result)
                return cdata
            return result
        if not found:
            print("not found", path.Command)
        return None
