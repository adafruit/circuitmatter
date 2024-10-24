# SPDX-FileCopyrightText: Copyright (c) 2024 Scott Shawcroft for Adafruit Industries
#
# SPDX-License-Identifier: MIT

import enum

from circuitmatter import data_model, tlv


class FeatureBitmap(enum.IntFlag):
    HUE_SATURATION = 1 << 0
    ENHANCED_HUE = 1 << 1
    COLOR_LOOP = 1 << 2
    XY = 1 << 3
    COLOR_TEMPERATURE = 1 << 4


class OptionsBitmap(data_model.Map8):
    EXECUTE_IF_OFF = 1 << 0


class Direction(data_model.Enum8):
    SHORTEST_DISTANCE = 0
    LONGEST_DISTANCE = 1
    UP = 2
    DOWN = 3


class MoveMode(data_model.Enum8):
    STOP = 0
    UP = 1
    DOWN = 3


class StepMode(data_model.Enum8):
    UP = 1
    DOWN = 3


class ColorMode(data_model.Enum8):
    HUE_SATURATION = 0
    XY = 1
    COLOR_TEMPERATURE = 2


class ColorControl(data_model.Cluster):
    CLUSTER_ID = 0x0300
    cluster_revision = 6

    current_hue = data_model.NumberAttribute(0x0000, signed=False, bits=8, default=0)
    current_saturation = data_model.NumberAttribute(0x0001, signed=False, bits=8, default=0)
    remaining_time = data_model.NumberAttribute(0x0002, signed=False, bits=16, default=0)
    current_x = data_model.NumberAttribute(0x0003, signed=False, bits=16, default=0)
    current_y = data_model.NumberAttribute(0x0004, signed=False, bits=16, default=0)
    drift_compensation = data_model.NumberAttribute(0x0005, signed=False, bits=8, default=0)
    compensation_text = data_model.UTF8StringAttribute(0x0006, default="")
    color_temperature = data_model.NumberAttribute(0x0007, signed=False, bits=16, default=0)
    color_mode = data_model.EnumAttribute(0x0008, data_model.Enum8, default=0)
    options = data_model.BitmapAttribute(0x000F, OptionsBitmap, default=0)
    color_capabilities = data_model.BitmapAttribute(0x400A, FeatureBitmap, default=0)

    color_temp_physical_min_mireds = data_model.NumberAttribute(
        0x400B,
        signed=False,
        bits=16,
        default=0,
        feature=FeatureBitmap.COLOR_TEMPERATURE,
    )  # maximum=0xfeff
    color_temp_physical_max_mireds = data_model.NumberAttribute(
        0x400C,
        signed=False,
        bits=16,
        default=0xFEFF,
        feature=FeatureBitmap.COLOR_TEMPERATURE,
    )  # maximum=0xfeff

    class MoveToHue(tlv.Structure):
        Hue = tlv.IntMember(0, signed=False, octets=1, maximum=254)
        Direction = tlv.EnumMember(1, Direction)
        TransitionTime = tlv.IntMember(2, signed=False, octets=2, nullable=True)
        OptionsMask = tlv.BitmapMember(3, OptionsBitmap, default=0)
        OptionsOverride = tlv.BitmapMember(4, OptionsBitmap, default=0)

    move_to_hue = data_model.Command(0x00, MoveToHue)

    class MoveHue(tlv.Structure):
        MoveMode = tlv.EnumMember(0, Direction)
        Rate = tlv.IntMember(1, signed=True, octets=1, nullable=True)
        OptionsMask = tlv.BitmapMember(2, OptionsBitmap, default=0)
        OptionsOverride = tlv.BitmapMember(3, OptionsBitmap, default=0)

    move_hue = data_model.Command(0x01, MoveHue)

    class StepHue(tlv.Structure):
        StepMode = tlv.EnumMember(0, StepMode)
        StepSize = tlv.IntMember(1, signed=True, octets=1)
        TransitionTime = tlv.IntMember(2, signed=False, octets=1)
        OptionsMask = tlv.BitmapMember(3, OptionsBitmap, default=0)
        OptionsOverride = tlv.BitmapMember(4, OptionsBitmap, default=0)

    step_hue = data_model.Command(0x02, StepHue)

    class MoveToSaturation(tlv.Structure):
        Saturation = tlv.IntMember(0, signed=False, octets=1)
        TransitionTime = tlv.IntMember(1, signed=False, octets=2)
        OptionsMask = tlv.BitmapMember(2, OptionsBitmap, default=0)
        OptionsOverride = tlv.BitmapMember(3, OptionsBitmap, default=0)

    move_to_saturation = data_model.Command(0x03, MoveToSaturation)

    class MoveSaturation(tlv.Structure):
        MoveMode = tlv.EnumMember(0, MoveMode)
        Rate = tlv.IntMember(1, signed=True, octets=1, nullable=True)
        OptionsMask = tlv.BitmapMember(2, OptionsBitmap, default=0)
        OptionsOverride = tlv.BitmapMember(3, OptionsBitmap, default=0)

    move_saturation = data_model.Command(0x04, MoveSaturation)

    class StepSaturation(tlv.Structure):
        StepMode = tlv.EnumMember(0, StepMode)
        StepSize = tlv.IntMember(1, signed=True, octets=1)
        TransitionTime = tlv.IntMember(2, signed=False, octets=2, nullable=True)
        OptionsMask = tlv.BitmapMember(3, OptionsBitmap, default=0)
        OptionsOverride = tlv.BitmapMember(4, OptionsBitmap, default=0)

    step_saturation = data_model.Command(0x05, StepSaturation)

    class MoveToHueAndSaturation(tlv.Structure):
        Hue = tlv.IntMember(0, signed=False, octets=1)
        Saturation = tlv.IntMember(1, signed=False, octets=1)
        TransitionTime = tlv.IntMember(2, signed=False, octets=2, nullable=True)
        OptionsMask = tlv.BitmapMember(3, OptionsBitmap, default=0)
        OptionsOverride = tlv.BitmapMember(4, OptionsBitmap, default=0)

    move_to_hue_and_saturation = data_model.Command(0x06, MoveToHueAndSaturation)
