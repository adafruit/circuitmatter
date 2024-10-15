from circuitmatter.data_model import (
    Cluster,
    Command,
    EndpointNumber,
    Enum8,
    GroupId,
    NumberAttribute,
    ListAttribute,
    List,
)
from circuitmatter import tlv


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
