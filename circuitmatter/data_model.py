import enum
import random
import struct
from typing import Iterable

from . import interaction_model
from . import tlv


class Enum8(enum.IntEnum):
    pass


class Enum16(enum.IntEnum):
    pass


class Attribute:
    def __init__(self, _id, default=None):
        self.id = _id
        self.default = default

    def __get__(self, instance, cls):
        v = instance._attribute_values.get(self.id, None)
        if v is None:
            return self.default
        return v

    def __set__(self, instance, value):
        old_value = instance._attribute_values.get(self.id, None)
        if old_value == value:
            return
        instance._attribute_values[self.id] = value
        instance.data_version += 1

    def encode(self, value):
        raise NotImplementedError()


class NumberAttribute(Attribute):
    def __init__(self, _id, *, signed, bits, default=None):
        self.signed = signed
        self.bits = bits
        self.id = _id
        self.default = default
        super().__init__(_id, default=default)

    @staticmethod
    def encode_number(value, *, signed=True):
        bit_length = value.bit_length()
        format_string = None
        if signed:
            type = tlv.ElementType.SIGNED_INT
        else:
            type = tlv.ElementType.UNSIGNED_INT
        length = 0  # in power of two
        if bit_length <= 8:
            format_string = "Bb" if signed else "BB"
            length = 0
        elif bit_length <= 16:
            format_string = "Bh" if signed else "BH"
            length = 1
        elif bit_length <= 32:
            format_string = "Bi" if signed else "BI"
            length = 2
        else:
            format_string = "Bq" if signed else "BQ"
            length = 3

        return struct.pack(format_string, type | length, value)

    def encode(self, value):
        return NumberAttribute.encode_number(value, signed=self.signed)


class FeatureMap(NumberAttribute):
    def __init__(self):
        super().__init__(0xFFFC, signed=False, bits=32, default=0)


class EnumAttribute(NumberAttribute):
    def __init__(self, _id, enum_type, default=None):
        self.enum_type = enum_type
        bits = 8 if issubclass(enum_type, Enum8) else 16
        super().__init__(_id, signed=False, bits=bits, default=default)


class ListAttribute(Attribute):
    pass


class BoolAttribute(Attribute):
    pass


class StructAttribute(Attribute):
    def __init__(self, _id, struct_type):
        self.struct_type = struct_type
        super().__init__(_id)

    def encode(self, value) -> memoryview:
        buffer = memoryview(bytearray(value.max_length() + 2))
        buffer[0] = tlv.ElementType.STRUCTURE
        end = value.encode_into(buffer, 1)
        buffer[end] = tlv.ElementType.END_OF_CONTAINER
        return buffer[: end + 1]


class OctetStringAttribute(Attribute):
    def __init__(self, _id, min_length, max_length):
        self.min_length = min_length
        self.max_length = max_length
        super().__init__(_id)


class UTF8StringAttribute(Attribute):
    def __init__(self, _id, min_length=0, max_length=1200, default=None):
        self.min_length = min_length
        self.max_length = max_length
        super().__init__(_id, default=default)


class BitmapAttribute(Attribute):
    pass


class Cluster:
    feature_map = FeatureMap()

    def __init__(self):
        self._attribute_values = {}
        # Use random since this isn't for security or replayability.
        self.data_version = random.randint(0, 0xFFFFFFFF)

    @classmethod
    def _attributes(cls) -> Iterable[tuple[str, Attribute]]:
        for field_name, descriptor in vars(cls).items():
            if not field_name.startswith("_") and isinstance(descriptor, Attribute):
                yield field_name, descriptor
        for field_name, descriptor in vars(Cluster).items():
            if not field_name.startswith("_") and isinstance(descriptor, Attribute):
                yield field_name, descriptor

    def get_attribute_data(self, path) -> interaction_model.AttributeDataIB:
        print("get_attribute_data", path.Attribute)
        data = interaction_model.AttributeDataIB()
        data.DataVersion = 0
        data.Path = path
        found = False
        for field_name, descriptor in self._attributes():
            if descriptor.id != path.Attribute:
                continue
            print("read", field_name, descriptor)
            data.Data = descriptor.encode(getattr(self, field_name))
            found = True
            break
        if not found:
            print("not found", path.Attribute)
        return data


class ProductFinish(enum.IntEnum):
    OTHER = 0
    MATTE = 1
    SATIN = 2
    POLISHED = 3
    RUGGED = 4
    FABRIC = 5


class Color(enum.IntEnum):
    BLACK = 0
    NAVY = 1
    GREEN = 2
    TEAL = 3
    MAROON = 4
    PURPLE = 5
    OLIVE = 6
    GRAY = 7
    BLUE = 8
    LIME = 9
    AQUA = 10
    RED = 11
    FUCHSIA = 12
    YELLOW = 13
    WHITE = 14
    NICKEL = 15
    CHROME = 16
    BRASS = 17
    COPPER = 18
    SILVER = 19
    GOLD = 20


class BasicInformationCluster(Cluster):
    CLUSTER_ID = 0x0028

    class CapabilityMinima(tlv.TLVStructure):
        CaseSessionsPerFabric = tlv.IntMember(
            0, signed=False, octets=2, minimum=3, default=3
        )
        SubscriptionsPerFabric = tlv.IntMember(
            1, signed=False, octets=2, minimum=3, default=3
        )

    class ProductAppearance(tlv.TLVStructure):
        Finish = tlv.EnumMember(0, ProductFinish)
        PrimaryColor = tlv.EnumMember(1, Color)

    data_model_revision = NumberAttribute(0x00, signed=False, bits=16)
    vendor_name = UTF8StringAttribute(0x01, max_length=32)
    vendor_id = NumberAttribute(0x02, signed=False, bits=16)
    product_name = UTF8StringAttribute(0x03, max_length=32)
    product_id = NumberAttribute(0x04, signed=False, bits=16)
    node_label = UTF8StringAttribute(0x05, max_length=32, default="")
    location = UTF8StringAttribute(0x06, max_length=2, default="XX")
    hardware_version = NumberAttribute(0x07, signed=False, bits=16)
    hardware_version_string = UTF8StringAttribute(0x08, min_length=1, max_length=64)
    software_version = NumberAttribute(0x09, signed=False, bits=32)
    software_version_string = UTF8StringAttribute(0x0A, min_length=1, max_length=64)
    manufacturing_date = UTF8StringAttribute(0x0B, min_length=8, max_length=16)
    part_number = UTF8StringAttribute(0x0C, max_length=32)
    product_url = UTF8StringAttribute(0x0D, max_length=256)
    product_label = UTF8StringAttribute(0x0E, max_length=64)
    serial_number = UTF8StringAttribute(0x0F, max_length=32)
    local_config_disabled = BoolAttribute(0x10, default=False)
    reachable = BoolAttribute(0x11, default=True)
    unique_id = UTF8StringAttribute(0x12, max_length=32)
    capability_minima = StructAttribute(0x13, CapabilityMinima)
    product_appearance = StructAttribute(0x14, ProductAppearance)
    specification_version = NumberAttribute(0x15, signed=False, bits=32, default=0)
    max_paths_per_invoke = NumberAttribute(0x16, signed=False, bits=16, default=1)


class GeneralCommissioningCluster(Cluster):
    CLUSTER_ID = 0x0030

    class BasicCommissioningInfo(tlv.TLVStructure):
        FailSafeExpiryLengthSeconds = tlv.IntMember(0, signed=False, octets=2)
        MaxCumulativeFailsafeSeconds = tlv.IntMember(1, signed=False, octets=2)

    class RegulatoryLocationType(enum.IntEnum):
        INDOOR = 0
        OUTDOOR = 1
        INDOOR_OUTDOOR = 2

        bits = 8

    breadcrumb = NumberAttribute(0, signed=False, bits=64, default=0)
    basic_commissioning_info = StructAttribute(1, BasicCommissioningInfo)
    regulatory_config = EnumAttribute(
        2, RegulatoryLocationType, default=RegulatoryLocationType.INDOOR_OUTDOOR
    )
    location_capability = EnumAttribute(
        3, RegulatoryLocationType, default=RegulatoryLocationType.INDOOR_OUTDOOR
    )
    support_concurrent_connection = BoolAttribute(4, default=True)


class NetworkCommissioningCluster(Cluster):
    CLUSTER_ID = 0x0031

    class FeatureBitmap(enum.IntFlag):
        WIFI_NETWORK_INTERFACE = 0b001
        THREAD_NETWORK_INTERFACE = 0b010
        ETHERNET_NETWORK_INTERFACE = 0b100

    class NetworkCommissioningStatus(Enum8):
        SUCCESS = 0
        """Ok, no error"""

        OUT_OF_RANGE = 1
        """Value Outside Range"""

        BOUNDS_EXCEEDED = 2
        """A collection would exceed its size limit"""

        NETWORK_ID_NOT_FOUND = 3
        """The NetworkID is not among the collection of added networks"""

        DUPLICATE_NETWORK_ID = 4
        """The NetworkID is already among the collection of added networks"""

        NETWORK_NOT_FOUND = 5
        """Cannot find AP: SSID Not found"""

        REGULATORY_ERROR = 6
        """Cannot find AP: Mismatch on band/channels/regulatory domain / 2.4GHz vs 5GHz"""

        AUTH_FAILURE = 7
        """Cannot associate due to authentication failure"""

        UNSUPPORTED_SECURITY = 8
        """Cannot associate due to unsupported security mode"""

        OTHER_CONNECTION_FAILURE = 9
        """Other association failure"""

        IPV6_FAILED = 10
        """Failure to generate an IPv6 address"""

        IP_BIND_FAILED = 11
        """Failure to bind Wi-Fi <-> IP interfaces"""

        UNKNOWN_ERROR = 12
        """Unknown error"""

    max_networks = NumberAttribute(0, signed=False, bits=8)
    networks = ListAttribute(1)
    scan_max_time_seconds = NumberAttribute(2, signed=False, bits=8)
    connect_max_time_seconds = NumberAttribute(3, signed=False, bits=8)
    interface_enabled = BoolAttribute(4)
    last_network_status = EnumAttribute(5, NetworkCommissioningStatus)
    last_network_id = OctetStringAttribute(6, min_length=1, max_length=32)
    last_connect_error_value = NumberAttribute(7, signed=True, bits=32)
    supported_wifi_bands = ListAttribute(8)
    supported_thread_features = BitmapAttribute(9)
    thread_version = NumberAttribute(10, signed=False, bits=16)
