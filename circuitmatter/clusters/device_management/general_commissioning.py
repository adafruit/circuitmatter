# SPDX-FileCopyrightText: Copyright (c) 2024 Scott Shawcroft for Adafruit Industries
#
# SPDX-License-Identifier: MIT

from circuitmatter import tlv
from circuitmatter.data_model import (
    BoolAttribute,
    Cluster,
    Command,
    Enum8,
    EnumAttribute,
    NumberAttribute,
    StructAttribute,
)


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
        ErrorCode = tlv.EnumMember(0, CommissioningErrorEnum, default=CommissioningErrorEnum.OK)
        DebugText = tlv.UTF8StringMember(1, max_length=128, default="")

    ArmFailSafeResponse = CommissioningResponse

    arm_fail_safe = Command(0x00, ArmFailSafe, 0x01, ArmFailSafeResponse)

    class SetRegulatoryConfig(tlv.Structure):
        NewRegulatoryConfig = tlv.EnumMember(0, RegulatoryLocationType)
        CountryCode = tlv.UTF8StringMember(1, max_length=2)
        Breadcrumb = tlv.IntMember(2, signed=False, octets=8)

    SetRegulatoryConfigResponse = CommissioningResponse

    set_regulatory_config = Command(0x02, SetRegulatoryConfig, 0x03, SetRegulatoryConfigResponse)

    CommissioningCompleteResponse = CommissioningResponse

    commissioning_complete = Command(0x04, None, 0x05, CommissioningCompleteResponse)
