# SPDX-FileCopyrightText: Copyright (c) 2024 Scott Shawcroft for Adafruit Industries
#
# SPDX-License-Identifier: MIT

"""Simple LED on and off as a light."""

import board
import digitalio

import circuitmatter as cm
from circuitmatter.device_types.lighting import on_off


class LED(on_off.OnOffLight):
    def __init__(self, name, led):
        super().__init__(name)
        self._led = led
        self._led.direction = digitalio.Direction.OUTPUT

    def on(self):
        self._led.value = True

    def off(self):
        self._led.value = False


matter = cm.CircuitMatter()
led = LED("led1", digitalio.DigitalInOut(board.D19))
matter.add_device(led)
led = LED("led2", digitalio.DigitalInOut(board.D20))
matter.add_device(led)
while True:
    matter.process_packets()
