import enum
import random
import struct
import typing
from typing import Iterable, Union

from . import interaction_model
from . import tlv


class Enum8(enum.IntEnum):
    pass


class Enum16(enum.IntEnum):
    pass


class Uint16(tlv.IntMember):
    def __init__(self, _id=None, minimum=0):
        super().__init__(_id, signed=False, octets=2, minimum=minimum)


class Uint32(tlv.IntMember):
    def __init__(self, _id=None, minimum=0):
        super().__init__(_id, signed=False, octets=4, minimum=minimum)


class Uint64(tlv.IntMember):
    def __init__(self, _id=None, minimum=0):
        super().__init__(_id, signed=False, octets=8, minimum=minimum)


class GroupId(Uint16):
    pass


class ClusterId(Uint16):
    pass


class DeviceTypeId(Uint32):
    pass


class EndpointNumber(Uint16):
    def __init__(self, _id=None):
        super().__init__(_id, minimum=1)


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

    def __get__(self, instance, cls):
        v = instance._attribute_values.get(self.id, None)
        if v is None:
            return self.default
        return v

    def __set__(self, instance, value):
        old_value = instance._attribute_values.get(self.id, None)
        print("set old_value", old_value)
        if old_value == value:
            return
        instance._attribute_values[self.id] = value
        instance.data_version += 1
        print("set new version", instance.data_version)

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


class ListAttribute(Attribute):
    def __init__(self, _id, element_type, **kwargs):
        self.tlv_type = tlv.ArrayMember(None, element_type)
        self._element_type = element_type
        # Copy the default list so we don't accidentally share it with another
        # cluster of the same type.
        if "default" in kwargs and isinstance(kwargs["default"], list):
            kwargs["default"] = list(kwargs["default"])
        super().__init__(_id, **kwargs)

    def _encode(self, value) -> bytes:
        return self.tlv_type.encode(value)

    def element_from_value(self, value):
        if issubclass(self._element_type, tlv.Container):
            return self._element_type.from_value(value)
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


class BitmapAttribute(Attribute):
    pass


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

    def get_attribute_data(
        self, path
    ) -> typing.List[interaction_model.AttributeDataIB]:
        replies = []
        for field_name, descriptor in self._attributes():
            if path.Attribute is not None and descriptor.id != path.Attribute:
                continue
            if descriptor.feature and not (self.feature_map & descriptor.feature):
                continue
            value = getattr(self, field_name)
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
            replies.append(data)
            if path.Attribute is not None:
                break
        if not replies:
            print("not found", path.Attribute)
        return replies

    def set_attribute(self, attribute_data) -> interaction_model.AttributeStatusIB:
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

            print("invoke", self, field_name, descriptor)
            command = getattr(self, field_name)
            if callable(command):
                if descriptor.request_type is not None:
                    try:
                        arg = descriptor.request_type.from_value(fields)
                    except ValueError:
                        return interaction_model.StatusCode.INVALID_COMMAND
                    try:
                        result = command(session, arg)
                    except Exception as e:
                        print(e)
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


class DescriptorCluster(Cluster):
    CLUSTER_ID = 0x001D

    class DeviceTypeStruct(tlv.Structure):
        DeviceType = DeviceTypeId(0)
        Revision = Uint16(1, minimum=1)

    DeviceTypeList = ListAttribute(0x0000, DeviceTypeStruct)
    ServerList = ListAttribute(0x0001, ClusterId())
    ClientList = ListAttribute(0x0002, ClusterId())
    PartsList = ListAttribute(0x0003, EndpointNumber())


class AccessControlEntryPrivilegeEnum(Enum8):
    VIEW = 1
    """Can read and observe all (except Access Control Cluster and as seen by a non-Proxy)"""
    PROXY_VIEW = 2
    """Can read and observe all (as seen by a Proxy)"""
    OPERATE = 3
    """View privileges, and can perform the primary function of this Node (except Access Control Cluster)"""
    MANAGE = 4
    """Operate privileges, and can modify persistent configuration of this Node (except Access Control Cluster)"""
    ADMINISTER = 5
    """Manage privileges, and can observe and modify the Access Control Cluster"""


class AccessControlEntryAuthModeEnum(Enum8):
    PASE = 1
    """Passcode authenticated session"""
    CASE = 2
    """Certificate authenticated session"""
    GROUP = 3
    """Group authenticated session"""


class AccessControlTargetStruct(tlv.Structure):
    Cluster = ClusterId(0)
    Endpoint = EndpointNumber(1)
    DeviceType = DeviceTypeId(2)


class AccessControlCluster(Cluster):
    CLUSTER_ID = 0x001F

    class AccessControlEntryStruct(tlv.Structure):
        Privilege = tlv.EnumMember(1, AccessControlEntryPrivilegeEnum)
        AuthMode = tlv.EnumMember(2, AccessControlEntryAuthModeEnum)
        Subjects = List(3, Uint64())
        Targets = List(4, AccessControlTargetStruct, nullable=True)

    class AccessControlExtensionStruct(tlv.Structure):
        Data = tlv.OctetStringMember(1, max_length=128)

    ACL = ListAttribute(0x0000, AccessControlEntryStruct)
    Extension = ListAttribute(0x0001, AccessControlExtensionStruct, optional=True)
    SubjectsPerAccessControlEntry = NumberAttribute(
        0x0002, signed=False, bits=16, default=4
    )
    TargetsPerAccessControlEntry = NumberAttribute(
        0x0003, signed=False, bits=16, default=3
    )
    AccessControlEntriesPerFabric = NumberAttribute(
        0x0004, signed=False, bits=16, default=4
    )


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

    class CapabilityMinima(tlv.Structure):
        CaseSessionsPerFabric = tlv.IntMember(
            0, signed=False, octets=2, minimum=3, default=3
        )
        SubscriptionsPerFabric = tlv.IntMember(
            1, signed=False, octets=2, minimum=3, default=3
        )

    class ProductAppearance(tlv.Structure):
        Finish = tlv.EnumMember(0, ProductFinish, default=ProductFinish.OTHER)
        PrimaryColor = tlv.EnumMember(1, Color, default=Color.BLACK)

    data_model_revision = NumberAttribute(0x00, signed=False, bits=16, default=16)
    vendor_name = UTF8StringAttribute(0x01, max_length=32, default="CircuitMatter")
    vendor_id = NumberAttribute(0x02, signed=False, bits=16)
    product_name = UTF8StringAttribute(0x03, max_length=32, default="Test Device")
    product_id = NumberAttribute(0x04, signed=False, bits=16)
    node_label = UTF8StringAttribute(0x05, max_length=32, default="")
    location = UTF8StringAttribute(0x06, max_length=2, default="XX")
    hardware_version = NumberAttribute(0x07, signed=False, bits=16, default=0)
    hardware_version_string = UTF8StringAttribute(
        0x08, min_length=1, max_length=64, default="Unknown"
    )
    software_version = NumberAttribute(0x09, signed=False, bits=32, default=0)
    software_version_string = UTF8StringAttribute(
        0x0A, min_length=1, max_length=64, default="Unknown"
    )
    manufacturing_date = UTF8StringAttribute(
        0x0B, min_length=8, max_length=16, default="Unknown"
    )
    part_number = UTF8StringAttribute(0x0C, max_length=32, default="")
    product_url = UTF8StringAttribute(
        0x0D, max_length=256, default="https://github.com/adafruit/circuitmatter"
    )
    product_label = UTF8StringAttribute(0x0E, max_length=64, default="")
    serial_number = UTF8StringAttribute(0x0F, max_length=32, default="")
    local_config_disabled = BoolAttribute(0x10, default=False)
    reachable = BoolAttribute(0x11, default=True)
    unique_id = UTF8StringAttribute(0x12, max_length=32, default="")
    capability_minima = StructAttribute(
        0x13, CapabilityMinima, default=CapabilityMinima()
    )
    product_appearance = StructAttribute(
        0x14, ProductAppearance, default=ProductAppearance()
    )
    specification_version = NumberAttribute(0x15, signed=False, bits=32, default=0)
    max_paths_per_invoke = NumberAttribute(0x16, signed=False, bits=16, default=1)


class GroupKeySetSecurityPolicyEnum(Enum8):
    TRUST_FIRST = 0
    CACHE_AND_SYNC = 1


class GroupKeyMulticastPolicyEnum(Enum8):
    PER_GROUP_ID = 0
    ALL_NODES = 1


class GroupKeySetStruct(tlv.Structure):
    GroupKeySetID = tlv.IntMember(0, signed=False, octets=2)
    GroupKeySecurityPolicy = tlv.EnumMember(1, GroupKeySetSecurityPolicyEnum)
    EpochKey0 = tlv.OctetStringMember(2, 16)
    EpochStartTime0 = tlv.IntMember(3, signed=False, octets=8)
    EpochKey1 = tlv.OctetStringMember(4, 16)
    EpochStartTime1 = tlv.IntMember(5, signed=False, octets=8)
    EpochKey2 = tlv.OctetStringMember(6, 16)
    EpochStartTime2 = tlv.IntMember(7, signed=False, octets=8)
    GroupKeyMulticastPolicy = tlv.EnumMember(8, GroupKeyMulticastPolicyEnum)


class GroupKeyManagementCluster(Cluster):
    CLUSTER_ID = 0x3F

    class GroupKeyMapStruct(tlv.Structure):
        GroupId = GroupId(1)
        GroupKeySetID = tlv.IntMember(2, signed=False, octets=2, minimum=1)

    class GroupInfoMapStruct(tlv.Structure):
        GroupId = GroupId(1)
        Endpoints = List(2, EndpointNumber())
        GroupName = tlv.UTF8StringMember(3, max_length=16)

    class KeySetWrite(tlv.Structure):
        GroupKeySet = tlv.StructMember(0, GroupKeySetStruct)

    group_key_map = ListAttribute(0, GroupKeyMapStruct, default=[])
    group_table = ListAttribute(1, GroupInfoMapStruct, default=[])
    max_groups_per_fabric = NumberAttribute(2, signed=False, bits=16, default=0)
    max_group_keys_per_fabric = NumberAttribute(3, signed=False, bits=16, default=1)

    key_set_write = Command(0, KeySetWrite, None, None)


class CommissioningErrorEnum(Enum8):
    OK = 0
    VALUE_OUTSIDE_RANGE = 1
    INVALID_AUTHENTICATION = 2
    NO_FAIL_SAFE = 3
    BUSY_WITH_OTHER_ADMIN = 4


class RegulatoryLocationType(Enum8):
    INDOOR = 0
    OUTDOOR = 1
    INDOOR_OUTDOOR = 2


class GeneralCommissioningCluster(Cluster):
    CLUSTER_ID = 0x0030

    class BasicCommissioningInfo(tlv.Structure):
        FailSafeExpiryLengthSeconds = tlv.IntMember(0, signed=False, octets=2)
        MaxCumulativeFailsafeSeconds = tlv.IntMember(1, signed=False, octets=2)

    breadcrumb = NumberAttribute(0, signed=False, bits=64, default=0)
    basic_commissioning_info = StructAttribute(1, BasicCommissioningInfo)
    regulatory_config = EnumAttribute(
        2, RegulatoryLocationType, default=RegulatoryLocationType.INDOOR_OUTDOOR
    )
    location_capability = EnumAttribute(
        3, RegulatoryLocationType, default=RegulatoryLocationType.INDOOR_OUTDOOR
    )
    support_concurrent_connection = BoolAttribute(4, default=True)

    class ArmFailSafe(tlv.Structure):
        ExpiryLengthSeconds = tlv.IntMember(0, signed=False, octets=2, default=900)
        Breadcrumb = tlv.IntMember(1, signed=False, octets=8)

    class CommissioningResponse(tlv.Structure):
        ErrorCode = tlv.EnumMember(
            0, CommissioningErrorEnum, default=CommissioningErrorEnum.OK
        )
        DebugText = tlv.UTF8StringMember(1, max_length=128, default="")

    ArmFailSafeResponse = CommissioningResponse

    arm_fail_safe = Command(0x00, ArmFailSafe, 0x01, ArmFailSafeResponse)

    class SetRegulatoryConfig(tlv.Structure):
        NewRegulatoryConfig = tlv.EnumMember(0, RegulatoryLocationType)
        CountryCode = tlv.UTF8StringMember(1, max_length=2)
        Breadcrumb = tlv.IntMember(2, signed=False, octets=8)

    SetRegulatoryConfigResponse = CommissioningResponse

    set_regulatory_config = Command(
        0x02, SetRegulatoryConfig, 0x03, SetRegulatoryConfigResponse
    )

    CommissioningCompleteResponse = CommissioningResponse

    commissioning_complete = Command(0x04, None, 0x05, CommissioningCompleteResponse)


class NetworkCommissioningCluster(Cluster):
    CLUSTER_ID = 0x0031

    class FeatureBitmap(enum.IntFlag):
        WIFI_NETWORK_INTERFACE = 0b001
        THREAD_NETWORK_INTERFACE = 0b010
        ETHERNET_NETWORK_INTERFACE = 0b100

    class WifiBandEnum(Enum8):
        BAND_2G4 = 0
        BAND_3G65 = 1
        BAND_5G = 2
        BAND_6G = 3
        BAND_60G = 4
        BAND_1G = 5

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

    class NetworkInfoStruct(tlv.Structure):
        NetworkID = tlv.OctetStringMember(0, min_length=1, max_length=32)
        Connected = tlv.BoolMember(1)

    max_networks = NumberAttribute(0, signed=False, bits=8, default=1, F_fixed=True)
    networks = ListAttribute(1, NetworkInfoStruct)
    scan_max_time_seconds = NumberAttribute(
        2,
        signed=False,
        bits=8,
        feature=FeatureBitmap.WIFI_NETWORK_INTERFACE
        | FeatureBitmap.THREAD_NETWORK_INTERFACE,
        F_fixed=True,
    )
    connect_max_time_seconds = NumberAttribute(
        3,
        signed=False,
        bits=8,
        feature=FeatureBitmap.WIFI_NETWORK_INTERFACE
        | FeatureBitmap.THREAD_NETWORK_INTERFACE,
        F_fixed=True,
    )
    interface_enabled = BoolAttribute(4, default=True, N_nonvolatile=True)
    last_network_status = EnumAttribute(5, NetworkCommissioningStatus, X_nullable=True)
    last_network_id = OctetStringAttribute(
        6, min_length=1, max_length=32, X_nullable=True
    )
    last_connect_error_value = NumberAttribute(7, signed=True, bits=32, X_nullable=True)
    supported_wifi_bands = ListAttribute(
        8, WifiBandEnum, feature=FeatureBitmap.WIFI_NETWORK_INTERFACE, F_fixed=True
    )
    supported_thread_features = BitmapAttribute(
        9, feature=FeatureBitmap.THREAD_NETWORK_INTERFACE, F_fixed=True
    )
    thread_version = NumberAttribute(
        10,
        signed=False,
        bits=16,
        feature=FeatureBitmap.THREAD_NETWORK_INTERFACE,
        F_fixed=True,
    )


class CertificateChainTypeEnum(Enum8):
    DAC = 1
    PAI = 2


class NodeOperationalCertStatusEnum(Enum8):
    OK = 0
    """OK, no error"""
    INVALID_PUBLIC_KEY = 1
    """Public Key in the NOC does not match the public key in the NOCSR"""
    INVALID_NODE_OP_ID = 2
    """The Node Operational ID in the NOC is not formatted correctly."""
    INVALID_NOC = 3
    """Any other validation error in NOC chain"""
    MISSING_CSR = 4
    """No record of prior CSR for which this NOC could match"""
    TABLE_FULL = 5
    """NOCs table full, cannot add another one"""
    INVALID_ADMIN_SUBJECT = 6
    """Invalid CaseAdminSubject field for an AddNOC command."""
    FABRIC_CONFLICT = 9
    """Trying to AddNOC instead of UpdateNOC against an existing Fabric."""
    LABEL_CONFLICT = 10
    """Label already exists on another Fabric."""
    INVALID_FABRIC_INDEX = 11
    """FabricIndex argument is invalid."""


RESP_MAX = 900


class NodeOperationalCredentialsCluster(Cluster):
    CLUSTER_ID = 0x003E

    class NOCStruct(tlv.Structure):
        NOC = tlv.OctetStringMember(0, 400)
        ICAC = tlv.OctetStringMember(1, 400)

    class FabricDescriptorStruct(tlv.Structure):
        RootPublicKey = tlv.OctetStringMember(1, 65)
        VendorID = tlv.IntMember(2, signed=False, octets=2)
        FabricID = tlv.IntMember(3, signed=False, octets=8)
        NodeID = tlv.IntMember(4, signed=False, octets=8)
        Label = tlv.UTF8StringMember(5, max_length=32, default="")

    class AttestationRequest(tlv.Structure):
        AttestationNonce = tlv.OctetStringMember(0, 32)

    class AttestationResponse(tlv.Structure):
        AttestationElements = tlv.OctetStringMember(0, RESP_MAX)
        AttestationSignature = tlv.OctetStringMember(1, 64)

    class CertificateChainRequest(tlv.Structure):
        CertificateType = tlv.EnumMember(0, CertificateChainTypeEnum)

    class CertificateChainResponse(tlv.Structure):
        Certificate = tlv.OctetStringMember(0, 600)

    class CSRRequest(tlv.Structure):
        CSRNonce = tlv.OctetStringMember(0, 32)
        IsForUpdateNOC = tlv.BoolMember(1, optional=True, default=False)

    class CSRResponse(tlv.Structure):
        NOCSRElements = tlv.OctetStringMember(0, RESP_MAX)
        AttestationSignature = tlv.OctetStringMember(1, 64)

    class AddNOC(tlv.Structure):
        NOCValue = tlv.OctetStringMember(0, 400)
        ICACValue = tlv.OctetStringMember(1, 400, optional=True)
        IPKValue = tlv.OctetStringMember(2, 16)
        CaseAdminSubject = tlv.IntMember(3, signed=False, octets=8)
        AdminVendorId = tlv.IntMember(4, signed=False, octets=2)

    class UpdateNOC(tlv.Structure):
        NOCValue = tlv.OctetStringMember(0, 400)
        ICACValue = tlv.OctetStringMember(1, 400, optional=True)

    class NOCResponse(tlv.Structure):
        StatusCode = tlv.EnumMember(0, NodeOperationalCertStatusEnum)
        FabricIndex = tlv.IntMember(1, signed=False, octets=1, optional=True)
        DebugText = tlv.UTF8StringMember(2, max_length=128, optional=True)

    class UpdateFabricLabel(tlv.Structure):
        Label = tlv.UTF8StringMember(0, max_length=32)

    class RemoveFabric(tlv.Structure):
        FabricIndex = tlv.IntMember(0, signed=False, octets=1)

    class AddTrustedRootCertificate(tlv.Structure):
        RootCACertificate = tlv.OctetStringMember(0, 400)

    nocs = ListAttribute(0, NOCStruct, N_nonvolatile=True, C_changes_omitted=True)
    fabrics = ListAttribute(1, FabricDescriptorStruct, N_nonvolatile=True)
    supported_fabrics = NumberAttribute(2, signed=False, bits=8, F_fixed=True)
    commissioned_fabrics = NumberAttribute(3, signed=False, bits=8, N_nonvolatile=True)
    trusted_root_certificates = ListAttribute(
        4, tlv.OctetStringMember(None, 400), N_nonvolatile=True, C_changes_omitted=True
    )
    current_fabric_index = NumberAttribute(5, signed=False, bits=8, default=0)

    attestation_request = Command(0x00, AttestationRequest, 0x01, AttestationResponse)

    certificate_chain_request = Command(
        0x02, CertificateChainRequest, 0x03, CertificateChainResponse
    )

    csr_request = Command(0x04, CSRRequest, 0x05, CSRResponse)

    add_noc = Command(0x06, AddNOC, 0x08, NOCResponse)

    update_noc = Command(0x07, UpdateNOC, 0x08, NOCResponse)

    update_fabric_label = Command(0x09, UpdateFabricLabel, 0x08, NOCResponse)

    remove_fabric = Command(0x0A, RemoveFabric, 0x08, NOCResponse)

    add_trusted_root_certificate = Command(0x0B, AddTrustedRootCertificate, None, None)
