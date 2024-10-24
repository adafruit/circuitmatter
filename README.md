# CircuitMatter

[![Documentation Status](https://readthedocs.org/projects/circuitmatter/badge/?version=latest)](https://docs.circuitpython.org/projects/matter/en/latest/)

[![Discord](https://raw.githubusercontent.com/adafruit/Adafruit_CircuitPython_Bundle/main/badges/adafruit_discord.svg)](https://adafru.it/discord)

[![Build Status](https://github.com/adafruit/CircuitMatter/workflows/Build%20CI/badge.svg)](https://github.com/adafruit/CircuitMatter/actions)

[![Code Style: Ruff](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/ruff/main/assets/badge/v2.json)](https://github.com/astral-sh/ruff)


CircuitMatter is a Python-only implementation of the Matter IOT specification. It is aimed at hobby use and hasn't been certified for commercial use.

The Matter spec originates out of the Connected Home over IP (CHIP) project and some resources still use this naming. Matter is the trademark associated with certification.

## Get the Matter Specification
The Matter specification is behind a contact info wall here: https://csa-iot.org/developer-resource/specifications-download-request/ CircuitMatter code is based on version 1.3 and references sections from that version.

You do not need to pay anything or be a member organization.

## Running CircuitMatter

CircuitMatter is currently developed in CPython 3.12, the de facto implementation written in C. It runs in Python 3.11 as well. It is designed with minimal dependencies so that it can also be used on CircuitPython on microcontrollers.

### Running on a Raspberry Pi SBC

CircuitMatter uses [avahi tools](https://avahi.org) to manage MDNS on Linux. It must therefore be installed for it to work properly.
```shell
sudo apt-get install avahi-utils
```

Now, install CircuitMatter:

```shell
pip install circuitmatter
```

The device demos use the `Blinka` library to interact with hardware via the CircuitPython API.
Follow [the instructions](https://learn.adafruit.com/circuitpython-on-raspberrypi-linux/installing-circuitpython-on-raspberry-pi) from the guide to install Blinka.

### Blink

The simplest example connects an LED to Matter as an OnOffLight.

```python
"""Simple LED on and off as a light."""

import circuitmatter as cm
from circuitmatter.device_types.lighting import on_off

import digitalio
import board


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
led = LED("led1", digitalio.DigitalInOut(board.D13))
matter.add_device(led)
while True:
    matter.process_packets()
```

To change the behavior of a device, you subclass the CircuitMatter device class
and implement the abstract methods and attributes it uses. These methods and
attributes are then used during the `process_packets()` call depending on
Matter interactions.

Save that as `code.py` (and on an SBC run it with):
```
python code.py
```

The first time this is run, it will generate all necessary pairing data and
certificates. They are stored in `matter-device-state.json` in the current
directory by default. They are loaded from that file on subsequent runs. Examples
may use a unique file name so that different "devices" are separate on to other
Matter devices.

The next step is to commission the device into your Matter Fabric from an app
such as Apple Home. CircuitMatter will print a QR code to the console that you
can scan to add the device. It also provides a setup code you can manually enter.
Here is an example (that won't work for your code):

```
QR code data: MT:MNOA5N1527ZM192KI10
                             
                             
    █▀▀▀▀▀█  ▀▄█▀ █▀▀▀▀▀█    
    █ ███ █ ▄ █▄▀ █ ███ █    
    █ ▀▀▀ █ ▀▀ █▀ █ ▀▀▀ █    
    ▀▀▀▀▀▀▀ ▀ ▀ █ ▀▀▀▀▀▀▀    
    ▀█▄▄ █▀█▄▀▄ ▀  ▄▀▀ ▄     
    ▄▄▀███▀█▄▀ █▀   ▀▀▄▄█    
     ▀▀   ▀ ▄▀▄▀██▀█▀▀▀▄▄    
    █▀▀▀▀▀█ █▀█  ▄█▀  █▄█    
    █ ███ █   ▄█▄  ▀▄▄▄      
    █ ▀▀▀ █ ▄███▀ █▄▀█ ▀█    
    ▀▀▀▀▀▀▀ ▀  ▀▀   ▀▀       
                             
                             
Manual code: 0418-824-2967
```

### NeoPixel

Setup is the same for the NeoPixel example.

```python
"""RGB LED strip as a full color light."""

import circuitmatter as cm
from circuitmatter.device_types.lighting import extended_color

import board
import neopixel


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
```

On Blinka, you'll need to run it as root to control the NeoPixel. This can be tricky when using a virtual environment because you'll need to call the specific Python in that case.

```shell
sudo .venv/bin/python code.py
```


## Developing CircuitMatter

### Requirements
Install the dependencies from "Running CircuitPython".

### Do a dev install

```shell
pip install -e .
```

### Running a CircuitMatter replay

CircuitMatter can capture and replay UDP packets and random numbers to ease development. You can test the start of the CircuitMatter process by using the replay file from the repo:

```shell
python examples/replay.py test_data/recorded_packets.jsonl
```

### Running for real

To run CircuitMatter against a live Matter commissioner run:

```shell
python examples/replay.py
```

This will start up MDNS via avahi for discovery by the commissioner and then reply to received UDP packets. CircuitMatter currently doesn't fully commission so it can't act as any specific type of device yet. When it can, there will be examples.

## Running a Matter commissioner

### chip-tool

The de facto standard implementation of Matter is open source as well. It is written in C++ and has many dependencies. It implements all of the different facets of the specification.

We use this implementation via [ESP Matter](https://github.com/espressif/esp-matter) (tested on commit 9350d9d5f948d3b7c61c8659c4d6990d0ff00ea4) to run an introspectable (aka debug printable) commissioner.

To setup esp-matter clone the repo and load submodules:

```shell
git clone -o espressif git@github.com:espressif/esp-matter.git
cd esp-matter
git submodule update --init --recursive .
```

This will pull down the ESP Matter wrapper code and the projectchip implementation into the `connectedhomeip/connectedhomeip/` sub-directory.

To build all of the command line tools run

```shell
bash install.sh
```

(Or source it directly if you use bash.)

Now setup the environment using `export.sh`. (This depends on what shell you use.)

Next, run `chip-tool` to initiate the commissioning process:

```shell
chip-tool pairing code 1 67202583
```

This will look up commissionable devices on the network via MDNS and then start that process. `67202583` is the manual pairing code that matches the device state in `test_data/device_state.json`.

Logs can be added into the chip sources to understand what is happening on the commissioner side. To rebuild, I've had to run `bash install.sh` again.

### Apple Home

The Apple Home app can also discover and (attempt to) commission the device. Tap Add Accessory.
* By default this will pull up the camera to scan a QR Code. CircuitMatter will print the qrcode to the console to scan.
* You can also use the passcode by clicking "More options" and the CircuitMatter device will show up as a nearby Matter Accessory. Tap it and then enter the setup code `67202583`. This will start the commissioning process from Apple Home.

### iOS Chip Tool

The `connectedhomeip` repo also has an iOS version of Chip Tool that can be helpful in debugging Apple Home. Installation instructions (requiring xcode) are here: https://github.com/project-chip/connectedhomeip/tree/master/src/darwin/CHIPTool

## Publish

To publish a new release, make a release through the GitHub CI. It'll push to PyPI.
