"""Pure Python implementation of the Matter IOT protocol."""

import binascii
import json
import os
import secrets
import socket
import subprocess
import time

import circuitmatter as cm


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
        if service_type in self.active_services:
            self.active_services[service_type].kill()
            del self.active_services[service_type]
        command = [
            "avahi-publish-service",
            *subtypes,
            instance_name,
            f"{service_type}.{protocol}",
            str(port),
            *txt_records,
        ]
        print("running avahi", command)
        self.active_services[service_type] = subprocess.Popen(command)

    def __del__(self):
        for active_service in self.active_services.values():
            active_service.kill()


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


def run(replay_file=None):
    if replay_file:
        replay_lines = []
        with open(replay_file, "r") as f:
            for line in f:
                replay_lines.append(json.loads(line))
        socketpool = ReplaySocketPool(replay_lines)
        mdns_server = DummyMDNS()
        random_source = ReplayRandom(replay_lines)
    else:
        record_file = open("test_data/recorded_packets.jsonl", "w")
        socketpool = RecordingSocketPool(record_file)
        mdns_server = MDNSServer()
        random_source = RecordingRandom(record_file)
    matter = cm.CircuitMatter(
        socketpool, mdns_server, random_source, "test_data/device_state.json"
    )
    while True:
        matter.process_packets()


if __name__ == "__main__":
    import sys

    print(sys.argv)
    replay_file = None
    if len(sys.argv) > 1:
        replay_file = sys.argv[1]
    run(replay_file=replay_file)
