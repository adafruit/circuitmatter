# SPDX-FileCopyrightText: Copyright (c) 2024 Scott Shawcroft for Adafruit Industries
#
# SPDX-License-Identifier: MIT

import binascii
import json
import time


class RecordingRandom:
    def __init__(self, record_file, random):
        self.record_file = record_file
        self._random = random

    def urandom(self, nbytes):
        data = self._random.urandom(nbytes)
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
        value = self._random.randbelow(n)
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
    def __init__(self, record_file, socket):
        self.AF_INET6 = socket.AF_INET6
        self.SOCK_DGRAM = socket.SOCK_DGRAM
        self.record_file = record_file
        self._socket_created = False
        self._socket = socket

    def socket(self, *args, **kwargs):
        if self._socket_created:
            raise RuntimeError("Only one socket can be created")
        self._socket_created = True
        return RecordingSocket(self.record_file, self._socket.socket(*args, **kwargs))
