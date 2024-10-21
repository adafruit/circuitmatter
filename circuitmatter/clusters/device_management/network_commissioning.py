import enum

from circuitmatter.data_model import (
    Cluster,
    Enum8,
    Map16,
    NumberAttribute,
    OctetStringAttribute,
    BoolAttribute,
    EnumAttribute,
    ListAttribute,
    BitmapAttribute,
)
from circuitmatter import tlv


class ThreadCapabilitiesBitmap(Map16):
    IS_BORDER_ROUTER_CAPABLE = 1 << 0
    IS_ROUTER_CAPABLE = 1 << 1
    IS_SLEEPY_END_DEVICE_CAPABLE = 1 << 2
    IS_FULL_THREAD_DEVICE = 1 << 3
    IS_SYNCHRONIZED_SLEEPY_END_DEVICE_CAPABLE = 1 << 4


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
        9,
        ThreadCapabilitiesBitmap,
        feature=FeatureBitmap.THREAD_NETWORK_INTERFACE,
        F_fixed=True,
    )
    thread_version = NumberAttribute(
        10,
        signed=False,
        bits=16,
        feature=FeatureBitmap.THREAD_NETWORK_INTERFACE,
        F_fixed=True,
    )
