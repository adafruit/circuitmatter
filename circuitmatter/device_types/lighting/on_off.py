# SPDX-FileCopyrightText: Copyright (c) 2024 Scott Shawcroft for Adafruit Industries
#
# SPDX-License-Identifier: MIT

from abc import abstractmethod

from circuitmatter.clusters.general import on_off
from circuitmatter.clusters.general.identify import Identify

from .. import simple_device


class OnOffLight(simple_device.SimpleDevice):
    """A light that can be turned `OnOffLight.on` and `OnOffLight.off`."""

    DEVICE_TYPE_ID = 0x0100
    REVISION = 3

    def __init__(self, name):
        super().__init__(name)

        self._identify = Identify()
        self.servers.append(self._identify)

        self._on_off = on_off.OnOff()
        self._on_off.on = self._on
        self._on_off.off = self._off
        self._on_off.feature_map |= on_off.FeatureBitmap.LIGHTING
        self.servers.append(self._on_off)

    def _on(self, session):
        try:
            self.on()
        except Exception as e:
            print(f"Error turning on light: {e}")
            return
        self._on_off.OnOff = True

    def _off(self, session):
        try:
            self.off()
        except Exception as e:
            print(f"Error turning off light: {e}")
            return
        self._on_off.OnOff = False

    @abstractmethod
    def on(self):
        """Called when the light is turned on"""
        pass

    @abstractmethod
    def off(self):
        """Called when the light is turned off"""
        pass
