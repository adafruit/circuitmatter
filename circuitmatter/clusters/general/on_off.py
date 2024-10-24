# SPDX-FileCopyrightText: Copyright (c) 2024 Scott Shawcroft for Adafruit Industries
#
# SPDX-License-Identifier: MIT

import enum

from circuitmatter import data_model, tlv


class FeatureBitmap(enum.IntFlag):
    LIGHTING = 1 << 0
    DEAD_FRONT_BEHAVIOR = 1 << 1
    OFF_ONLY = 1 << 2


class StartUpOnOffEnum(data_model.Enum8):
    OFF = 0
    ON = 1
    TOGGLE = 2


class OnOff(data_model.Cluster):
    CLUSTER_ID = 0x0006

    OnOff = data_model.BoolAttribute(0x0000, default=False, N_nonvolatile=True)
    GlobalSceneControl = data_model.BoolAttribute(
        0x4000, default=True, feature=FeatureBitmap.LIGHTING
    )
    OnTime = data_model.NumberAttribute(
        0x4001, signed=False, bits=16, default=0, feature=FeatureBitmap.LIGHTING
    )
    OffWaitTime = data_model.NumberAttribute(
        0x4002, signed=False, bits=16, default=0, feature=FeatureBitmap.LIGHTING
    )
    StartUpOnOff = data_model.EnumAttribute(
        0x4003,
        StartUpOnOffEnum,
        N_nonvolatile=True,
        X_nullable=True,
        feature=FeatureBitmap.LIGHTING,
    )

    off = data_model.Command(0x00, None)
    on = data_model.Command(0x01, None)
    toggle = data_model.Command(0x02, None)

    class OffWithEffect(tlv.Structure):
        EffectIdentifier = tlv.EnumMember(0, 0)
        EffectVariant = tlv.EnumMember(1, 0, default=0)

    off_with_effect = data_model.Command(0x40, OffWithEffect)
    on_with_recall_global_scene = data_model.Command(0x41, None)
    on_with_timed_off = data_model.Command(0x42, None)
