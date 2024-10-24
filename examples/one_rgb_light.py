# SPDX-FileCopyrightText: Copyright (c) 2024 Scott Shawcroft for Adafruit Industries
#
# SPDX-License-Identifier: MIT

"""RGB LED strip as a full color light."""

import board
import neopixel

import circuitmatter as cm
from circuitmatter.device_types.lighting import extended_color


class RGBPixel(extended_color.ExtendedColorLight):
    def __init__(self, name, pixels):
        super().__init__(name)
        self._pixels = pixels
        self._brightness = 0.1

    @property
    def color_rgb(self):
        return self._color

    @color_rgb.setter
    def color_rgb(self, value):
        self._pixels.fill(value)
        print(f"new color 0x{value:06x}")

    @property
    def brightness(self):
        return self._brightness

    @brightness.setter
    def brightness(self, value):
        self._brightness = value
        self._pixels.brightness = value
        print(f"new brightness {value}")

    def on(self):
        self._pixels.brightness = self._brightness
        print("on!")

    def off(self):
        self._pixels.brightness = 0
        print("off!")


matter = cm.CircuitMatter()
# This is a 8mm NeoPixel breadboard LED. (https://www.adafruit.com/product/1734)
# Any pixelbuf compatible strip should work. The RGBPixel class will control the
# entire strip of pixels.
np = neopixel.NeoPixel(board.D12, 1, pixel_order="RGB")
led = RGBPixel("led1", np)
matter.add_device(led)
while True:
    matter.process_packets()
