"""Pure Python implementation of the Matter IOT protocol."""

import binascii
import json
import socket
import subprocess

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
        print("sendto", address, data.hex(" "))
        return len(data)


class ReplaySocketPool:
    AF_INET6 = 0
    SOCK_DGRAM = 1

    def __init__(self, replay_file):
        with open(replay_file, "r") as f:
            self.replay_data = json.load(f)
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


def run(replay_file=None):
    if replay_file:
        socketpool = ReplaySocketPool(replay_file)
        mdns_server = DummyMDNS()
        record_file = None
    else:
        socketpool = socket
        mdns_server = MDNSServer()
        record_file = "test_data/recorded_packets.json"
    matter = cm.CircuitMatter(
        socketpool, mdns_server, "test_data/device_state.json", record_file
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
