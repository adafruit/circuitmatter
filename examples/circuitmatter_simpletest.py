"""Simple LED on and off as a light."""

import circuitmatter as cm
from circuitmatter.device_types.lighting import on_off

import digitalio
import board


class LED(on_off.OnOffLight):
    def __init__(self, name, led):
        super().__init__(name)
        self._led = led

    def on(self, session):
        self._led.value = True

    def off(self, session):
        self._led.value = False


matter = cm.CircuitMatter(state_filename="test_data/device_state.json")
led = LED("led1", digitalio.DigitalInOut(board.D13))
matter.add_device(led)
while True:
    matter.process_packets()
