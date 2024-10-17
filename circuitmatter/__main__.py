"""Pure Python implementation of the Matter IOT protocol."""

import binascii
import json
import os
import pathlib
import secrets
import socket
import subprocess
import time

import circuitmatter as cm

from circuitmatter.device_types.lighting import on_off
from circuitmatter.device_types.measurement import temperature_sensor


class ReplaySocket:
    def __init__(self, replay_data):
        self.replay_data = replay_data

    def bind(self, address):
        print("bind to", address)

    def setblocking(self, value):
        print("setblocking", value)

    def recvfrom_into(self, buffer, nbytes=None):
        if nbytes is None:
            nbytes = len(buffer)
        direction = "send"
        while direction == "send":
            direction, _, address, data_b64 = self.replay_data.pop(0)
        decoded = binascii.a2b_base64(data_b64)
        if len(decoded) > nbytes:
            raise RuntimeError("Next replay packet is larger than buffer to read into")
        buffer[: len(decoded)] = decoded
        return len(decoded), address

    def sendto(self, data, address):
        if address is None:
            raise ValueError("Address must be set")
        # direction, _, address, data_b64 = self.replay_data.pop(0)
        # if direction == "send":
        #     decoded = binascii.a2b_base64(data_b64)
        # for i, b in enumerate(data):
        #     if b != decoded[i]:
        #         # print("sent", data.hex(" "))
        #         # print("old ", decoded.hex(" "))
        #         # print(i, hex(b), hex(decoded[i]))
        #         print("Next replay packet does not match sent data")
        return len(data)


class ReplayRandom:
    def __init__(self, replay_data):
        self.replay_data = replay_data

    def urandom(self, nbytes):
        direction = None
        while direction != "urandom":
            direction, _, recorded_nbytes, data_b64 = self.replay_data.pop(0)
            if recorded_nbytes != nbytes:
                raise RuntimeError("Next replay random data is not the expected length")
        decoded = binascii.a2b_base64(data_b64)
        return decoded

    def randbelow(self, n):
        direction = None
        while direction != "randbelow":
            direction, _, recorded_n, value = self.replay_data.pop(0)
            if recorded_n != n:
                raise RuntimeError("Next replay randbelow is not the expected length")
        return value


class ReplaySocketPool:
    AF_INET6 = 0
    SOCK_DGRAM = 1

    def __init__(self, replay_lines):
        self.replay_data = replay_lines
        self._socket_created = False

    def socket(self, *args, **kwargs):
        if self._socket_created:
            raise RuntimeError("Only one socket can be created")
        self._socket_created = True
        return ReplaySocket(self.replay_data)


class DummyMDNS:
    def advertise_service(
        self,
        service_type,
        protocol,
        port,
        txt_records=[],
        subtypes=[],
        instance_name="",
    ):
        print(f"Advertise service {service_type} {protocol} {port} {txt_records}")


class MDNSServer(DummyMDNS):
    def __init__(self):
        self.active_services = {}
        self.publish_address = None

    def advertise_service(
        self,
        service_type,
        protocol,
        port,
        txt_records={},
        subtypes=[],
        instance_name="",
    ):
        subtypes = [f"--subtype={subtype}" for subtype in subtypes]
        txt_records = [f"{key}={value}" for key, value in txt_records.items()]
        command = [
            "avahi-publish-service",
            *subtypes,
            instance_name,
            f"{service_type}.{protocol}",
            str(port),
            *txt_records,
        ]
        print("running avahi", command)
        self.active_services[service_type + instance_name] = subprocess.Popen(command)
        if self.publish_address is None:
            command = [
                "avahi-publish-address",
                "dalinar.local",
                "fd98:bbab:bd61:8040:642:1aff:fe0c:9f2a",  # "fe80::642:1aff:fe0c:9f2a",
            ]
            print("run", command)
            self.publish_address = subprocess.Popen(command)

    def __del__(self):
        for active_service in self.active_services.values():
            active_service.kill()
        if self.publish_address is not None:
            self.publish_address.kill()


class RecordingRandom:
    def __init__(self, record_file):
        self.record_file = record_file

    def urandom(self, nbytes):
        data = os.urandom(nbytes)
        entry = (
            "urandom",
            time.monotonic_ns(),
            nbytes,
            binascii.b2a_base64(data, newline=False).decode("utf-8"),
        )
        json.dump(entry, self.record_file)
        self.record_file.write("\n")
        return data

    def randbelow(self, n):
        value = secrets.randbelow(n)
        entry = ("randbelow", time.monotonic_ns(), n, value)
        json.dump(entry, self.record_file)
        self.record_file.write("\n")
        return value


class RecordingSocket:
    def __init__(self, record_file, socket):
        self.record_file = record_file
        self.socket = socket

    def bind(self, address):
        self.socket.bind(address)

    def setblocking(self, value):
        self.socket.setblocking(value)

    def recvfrom_into(self, buffer, nbytes=None):
        nbytes, addr = self.socket.recvfrom_into(buffer, nbytes)
        entry = (
            "receive",
            time.monotonic_ns(),
            addr,
            binascii.b2a_base64(buffer[:nbytes], newline=False).decode("utf-8"),
        )
        json.dump(entry, self.record_file)
        self.record_file.write("\n")
        return nbytes, addr

    def sendto(self, data, address):
        entry = (
            "send",
            time.monotonic_ns(),
            address,
            binascii.b2a_base64(data, newline=False).decode("utf-8"),
        )
        json.dump(entry, self.record_file)
        self.record_file.write("\n")
        return self.socket.sendto(data, address)


class RecordingSocketPool:
    AF_INET6 = socket.AF_INET6
    SOCK_DGRAM = socket.SOCK_DGRAM

    def __init__(self, record_file):
        self.record_file = record_file
        self._socket_created = False

    def socket(self, *args, **kwargs):
        if self._socket_created:
            raise RuntimeError("Only one socket can be created")
        self._socket_created = True
        return RecordingSocket(self.record_file, socket.socket(*args, **kwargs))


class NeoPixel(on_off.OnOffLight):
    pass


def run(replay_file=None):
    device_state = pathlib.Path("test_data/device_state.json")
    replay_device_state = pathlib.Path("test_data/replay_device_state.json")
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
        device_state.write_text(pathlib.Path(device_state_fn).read_text())
    else:
        timestamp = time.strftime("%Y%m%d-%H%M%S")
        record_file = open(f"test_data/recorded_packets-{timestamp}.jsonl", "w")
        device_state_fn = f"test_data/device_state-{timestamp}.json"
        record_file.write(f"{device_state_fn}\n")
        socketpool = RecordingSocketPool(record_file)
        mdns_server = MDNSServer()
        random_source = RecordingRandom(record_file)
        # Save device state before we run so replays can use it.
        replay_device_state = pathlib.Path(device_state_fn)
        replay_device_state.write_text(device_state.read_text())

    matter = cm.CircuitMatter(socketpool, mdns_server, random_source, device_state)
    led = NeoPixel("neopixel1")
    tempSensor = temperature_sensor()
    matter.add_device(led)
    matter.add_device(tempSensor)
    while True:
        matter.process_packets()


if __name__ == "__main__":
    import sys

    print(sys.argv)
    replay_file = None
    if len(sys.argv) > 1:
        replay_file = sys.argv[1]
    run(replay_file=replay_file)
