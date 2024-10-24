# SPDX-FileCopyrightText: Copyright (c) 2024 Scott Shawcroft for Adafruit Industries
#
# SPDX-License-Identifier: MIT

import abc

from circuitmatter.clusters.general import level_control

from .on_off import OnOffLight


class DimmableLight(OnOffLight):
    DEVICE_TYPE_ID = 0x0101
    REVISION = 3

    def __init__(self, name):
        super().__init__(name)

        self._level_control = level_control.LevelControl()
        self._level_control.feature_map |= level_control.FeatureBitmap.LIGHTING
        self._level_control.min_level = 1
        self._level_control.max_level = 254
        self.servers.append(self._level_control)

        self._level_control.move_to_level_with_on_off = self._move_to_level_with_on_off

    def _move_to_level_with_on_off(self, session, value):
        try:
            self.brightness = value.Level / self._level_control.max_level
        except Exception as e:
            print(f"Error setting brightness: {e}")
            return
        if self._level_control.min_level == value.Level:
            self._on_off.OnOff = False
        else:
            self._on_off.OnOff = True
        self._level_control.CurrentLevel = value.Level

    @property
    def brightness(self):
        """Set when the light is dimmed"""
        return self._level_control.CurrentLevel / self._level_control.max_level

    @brightness.setter
    @abstractmethod
    def brightness(self, value):
        raise NotImplementedError()
