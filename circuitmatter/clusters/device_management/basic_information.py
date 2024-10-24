# SPDX-FileCopyrightText: Copyright (c) 2024 Scott Shawcroft for Adafruit Industries
#
# SPDX-License-Identifier: MIT

import enum

from circuitmatter import tlv
from circuitmatter.data_model import (
    BoolAttribute,
    Cluster,
    NumberAttribute,
    StructAttribute,
    UTF8StringAttribute,
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
        CaseSessionsPerFabric = tlv.IntMember(0, signed=False, octets=2, minimum=3, default=3)
        SubscriptionsPerFabric = tlv.IntMember(1, signed=False, octets=2, minimum=3, default=3)

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
    manufacturing_date = UTF8StringAttribute(0x0B, min_length=8, max_length=16, default="Unknown")
    part_number = UTF8StringAttribute(0x0C, max_length=32, default="")
    product_url = UTF8StringAttribute(
        0x0D, max_length=256, default="https://github.com/adafruit/circuitmatter"
    )
    product_label = UTF8StringAttribute(0x0E, max_length=64, default="")
    serial_number = UTF8StringAttribute(0x0F, max_length=32, default="")
    local_config_disabled = BoolAttribute(0x10, default=False)
    reachable = BoolAttribute(0x11, default=True)
    unique_id = UTF8StringAttribute(0x12, max_length=32, default="")
    capability_minima = StructAttribute(0x13, CapabilityMinima, default=CapabilityMinima())
    product_appearance = StructAttribute(0x14, ProductAppearance, default=ProductAppearance())
    specification_version = NumberAttribute(0x15, signed=False, bits=32, default=0)
    max_paths_per_invoke = NumberAttribute(0x16, signed=False, bits=16, default=1)
