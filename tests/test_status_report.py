# SPDX-FileCopyrightText: Copyright (c) 2024 Scott Shawcroft for Adafruit Industries
#
# SPDX-License-Identifier: MIT

from circuitmatter.protocol import ProtocolId
from circuitmatter.session import GeneralCode, StatusReport


def test_example1():
    report = StatusReport()
    report.general_code = GeneralCode.FAILURE
    report.protocol_id = ProtocolId.BDX
    report.protocol_code = 0x52

    buffer = bytearray(10)
    assert report.encode_into(buffer) == 8
    assert buffer[:8] == bytes.fromhex("01 00 02 00 00 00 52 00")


def test_example1_decode():
    report = StatusReport()
    report.decode(bytes.fromhex("01 00 02 00 00 00 52 00"))

    assert report.general_code == GeneralCode.FAILURE
    assert report.protocol_id == ProtocolId.BDX
    assert report.protocol_code == 0x52


def test_example2():
    report = StatusReport()
    report.general_code = GeneralCode.SUCCESS
    report.protocol_id = 0xFFF1AABB
    report.protocol_code = 0

    buffer = bytearray(10)
    assert report.encode_into(buffer) == 8
    assert buffer[:8] == bytes.fromhex("00 00 BB AA F1 FF 00 00")


def test_example2_decode():
    report = StatusReport()
    report.decode(bytes.fromhex("00 00 BB AA F1 FF 00 00"))

    assert report.general_code == GeneralCode.SUCCESS
    assert report.protocol_id == 0xFFF1AABB
    assert report.protocol_code == 0


def test_protocol_data_example():
    report = StatusReport()
    report.general_code = GeneralCode.FAILURE
    report.protocol_id = 0xFFF1AABB
    report.protocol_code = 9921
    report.protocol_data = [0x55, 0x66, 0xEE, 0xFF]

    buffer = bytearray(20)
    assert report.encode_into(buffer) == 12
    assert buffer[:12] == bytes.fromhex("01 00 BB AA F1 FF C1 26 55 66 EE FF")


def test_protocol_data_example_decode():
    report = StatusReport()
    report.decode(bytes.fromhex("01 00 BB AA F1 FF C1 26 55 66 EE FF"))

    assert report.general_code == GeneralCode.FAILURE
    assert report.protocol_id == 0xFFF1AABB
    assert report.protocol_code == 9921
    assert report.protocol_data == b"\x55\x66\xee\xff"
