# SPDX-FileCopyrightText: Copyright (c) 2024 Scott Shawcroft for Adafruit Industries
#
# SPDX-License-Identifier: MIT

import enum

from circuitmatter import data_model, tlv


class FeatureBitmap(enum.IntFlag):
    ON_OFF = 1 << 0
    LIGHTING = 1 << 1
    FREQUENCY = 1 << 2


class OptionsBitmap(data_model.Map8):
    ExecuteIfOff = 0
    CoupleColorTempToLevel = 1


class MoveModeEnum(data_model.Enum8):
    UP = 0
    DOWN = 1


class StepModeEnum(data_model.Enum8):
    UP = 0
    DOWN = 1


class LevelControl(data_model.Cluster):
    CLUSTER_ID = 0x0008

    CurrentLevel = data_model.NumberAttribute(
        0x0000, signed=False, bits=8, N_nonvolatile=True, X_nullable=True
    )
    RemainingTime = data_model.NumberAttribute(
        0x0001, signed=False, bits=16, default=0, feature=FeatureBitmap.LIGHTING
    )
    MinLevel = data_model.NumberAttribute(
        0x0002,
        signed=False,
        bits=8,
        default=lambda features: 1 if features & FeatureBitmap.LIGHTING else 0,
    )
    MaxLevel = data_model.NumberAttribute(0x0003, signed=False, bits=8, default=254)
    OnLevel = data_model.NumberAttribute(0x0011, signed=False, bits=8, X_nullable=True)
    Options = data_model.BitmapAttribute(0x000F, OptionsBitmap, default=0)
    StartUpCurrentLevel = data_model.NumberAttribute(
        0x4000,
        signed=False,
        bits=8,
        X_nullable=True,
        N_nonvolatile=True,
        feature=FeatureBitmap.LIGHTING,
    )

    class MoveToLevel(tlv.Structure):
        Level = tlv.IntMember(0, signed=False, octets=1)
        TransitionTime = tlv.IntMember(1, signed=False, octets=2, nullable=True)
        OptionsMask = tlv.BitmapMember(2, OptionsBitmap, default=0)
        OptionsOverride = tlv.BitmapMember(3, OptionsBitmap, default=0)

    move_to_level = data_model.Command(0x00, MoveToLevel)

    class Move(tlv.Structure):
        MoveMode = tlv.EnumMember(0, MoveModeEnum)
        Rate = tlv.IntMember(1, signed=True, octets=1, nullable=True)
        OptionsMask = tlv.BitmapMember(2, OptionsBitmap, default=0)
        OptionsOverride = tlv.BitmapMember(3, OptionsBitmap, default=0)

    move = data_model.Command(0x01, Move)

    class Step(tlv.Structure):
        StepMode = tlv.EnumMember(0, StepModeEnum)
        StepSize = tlv.IntMember(1, signed=True, octets=1)
        TransitionTime = tlv.IntMember(2, signed=False, octets=2, nullable=True)
        OptionsMask = tlv.BitmapMember(3, OptionsBitmap, default=0)
        OptionsOverride = tlv.BitmapMember(4, OptionsBitmap, default=0)

    step = data_model.Command(0x02, Step)

    class Stop(tlv.Structure):
        OptionsMask = tlv.BitmapMember(0, OptionsBitmap, default=0)
        OptionsOverride = tlv.BitmapMember(1, OptionsBitmap, default=0)

    stop = data_model.Command(0x03, Stop)

    move_to_level_with_on_off = data_model.Command(0x04, MoveToLevel)

    move_with_on_off = data_model.Command(0x05, Move)

    step_with_on_off = data_model.Command(0x06, Step)

    stop_with_on_off = data_model.Command(0x07, Stop)
