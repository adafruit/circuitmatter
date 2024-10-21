"""Pure Python implementation of the Matter IOT protocol."""

import json
import pathlib
import socket
import time

import circuitmatter as cm

from circuitmatter.device_types.lighting import extended_color

from circuitmatter.utility import random
from circuitmatter.utility.recording import RecordingSocketPool, RecordingRandom
from circuitmatter.utility.replay import ReplaySocketPool, ReplayRandom

from circuitmatter.utility.mdns import DummyMDNS
from circuitmatter.utility.mdns.avahi import Avahi


class NeoPixel(extended_color.ExtendedColorLight):
    @property
    def color_rgb(self):
        return self._color

    @color_rgb.setter
    def color_rgb(self, value):
        self._color = value
        print(f"new color 0x{value:06x}")

    @property
    def brightness(self):
        return self._brightness

    @brightness.setter
    def brightness(self, value):
        self._brightness = value
        print(f"new brightness {value}")

    def on(self):
        print("on!")

    def off(self):
        print("off!")


def run(replay_file=None):
    device_state = pathlib.Path("live-rgb-device-state.json")
    if replay_file:
        replay_lines = []
        with open(replay_file, "r") as f:
            device_state_fn = f.readline().strip()
            for line in f:
                replay_lines.append(json.loads(line))
        socketpool = ReplaySocketPool(replay_lines)
        mdns_server = DummyMDNS()
        random_source = ReplayRandom(replay_lines)
        # Reset device state to before the captured run
        if device_state_fn == "none":
            device_state.unlink(missing_ok=True)
        else:
            device_state.write_text(pathlib.Path(device_state_fn).read_text())
    else:
        timestamp = time.strftime("%Y%m%d-%H%M%S")
        record_file = open(f"test_data/recorded_packets-{timestamp}.jsonl", "w")
        device_state_fn = f"test_data/device_state-{timestamp}.json"
        replay_device_state = pathlib.Path(device_state_fn)
        if device_state.exists():
            record_file.write(f"{device_state_fn}\n")
            # Save device state before we run so replays can use it.
            replay_device_state.write_text(device_state.read_text())
        else:
            # No starting state.
            record_file.write("none\n")
        socketpool = RecordingSocketPool(record_file, socket)
        mdns_server = Avahi()
        random_source = RecordingRandom(record_file, random)

    matter = cm.CircuitMatter(socketpool, mdns_server, random_source, device_state)
    led = NeoPixel("neopixel1")
    matter.add_device(led)
    while True:
        matter.process_packets()


if __name__ == "__main__":
    import sys

    replay_file = None
    if len(sys.argv) > 1:
        replay_file = sys.argv[1]
    run(replay_file=replay_file)
