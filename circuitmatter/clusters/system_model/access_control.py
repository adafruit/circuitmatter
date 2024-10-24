# SPDX-FileCopyrightText: Copyright (c) 2024 Scott Shawcroft for Adafruit Industries
#
# SPDX-License-Identifier: MIT

from circuitmatter import tlv
from circuitmatter.data_model import (
    Cluster,
    ClusterId,
    DeviceTypeId,
    EndpointNumber,
    Enum8,
    List,
    ListAttribute,
    NumberAttribute,
    Uint64,
)


class AccessControlEntryPrivilegeEnum(Enum8):
    VIEW = 1
    """Can read and observe all (except Access Control Cluster and as seen by a non-Proxy)"""
    PROXY_VIEW = 2
    """Can read and observe all (as seen by a Proxy)"""
    OPERATE = 3
    """View privileges, and can perform the primary function of this Node (except Access Control
    Cluster)"""
    MANAGE = 4
    """Operate privileges, and can modify persistent configuration of this Node (except Access
    Control Cluster)"""
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

    ACL = ListAttribute(0x0000, AccessControlEntryStruct, default=[])
    Extension = ListAttribute(0x0001, AccessControlExtensionStruct, optional=True)
    SubjectsPerAccessControlEntry = NumberAttribute(0x0002, signed=False, bits=16, default=4)
    TargetsPerAccessControlEntry = NumberAttribute(0x0003, signed=False, bits=16, default=3)
    AccessControlEntriesPerFabric = NumberAttribute(0x0004, signed=False, bits=16, default=4)
