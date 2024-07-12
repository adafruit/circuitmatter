"""Pure Python implementation of the Matter IOT protocol."""

import enum
import math
import subprocess
import socket
import struct

from . import tlv
import circuitmatter as cm

from typing import Optional, Type, Any

# descriminator = 3840
# avahi = subprocess.Popen(["avahi-publish-service", "-v", f"--subtype=_L{descriminator}._sub._matterc._udp", "--subtype=_CM._sub._matterc._udp", "FA93546B21F5FB54", "_matterc._udp", "5540", "PI=", "PH=33", "CM=1", f"D={descriminator}", "CRI=3000", "CRA=4000", "T=1", "VP=65521+32769"])

# # Define the UDP IP address and port
# UDP_IP = "::"  # Listen on all available network interfaces
# UDP_PORT = 5540

# # Create the UDP socket
# sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)

# # Bind the socket to the IP and port
# sock.bind((UDP_IP, UDP_PORT))

# print(f"Listening on UDP port {UDP_PORT}")

unsecured_session_context = {
    
}

# while True:
#     # Receive data from the socket (1280 is the minimum ipv6 MTU and the max UDP matter packet size.)
#     data, addr = sock.recvfrom(1280)
data = b'\x04\x00\x00\x00\x0b\x06\xb7\t)\xad\x07\xd9\xae\xa1\xee\xa0\x05 j\x15\x00\x00\x150\x01 \x97\x064#\x1c\xd1E7H\x0b|\xc2G\xa7\xc38\xe9\xce3\x11\xb2@M\x86\xd7\xb5{)\xaa`\xddb%\x02\xc2\x86$\x03\x00(\x045\x05%\x01\xf4\x01%\x02,\x01%\x03\xa0\x0f$\x04\x11$\x05\x0b&\x06\x00\x00\x03\x01$\x07\x01\x18\x18'
addr = None

import pathlib

import json
# pathlib.Path("data.bin").write_bytes(data)

bookmarks = []

def add_bookmark(start, length, name, color=0x0000ff):
    bookmarks.append({
            "color": 0x4f000000 | color,
            "comment": "\n",
            "id": len(bookmarks),
            "locked": True,
            "name": name,
            "region": {
                "address": start,
                "size": length
            }
        })
    # Write every time in case we crash
    # pathlib.Path("parsed.hexbm").write_text(json.dumps({"bookmarks": bookmarks}))

def run():
    # Print the received data and the address of the sender
    print(f"Received packet from {addr}: {data}")
    print(f"Data length: {len(data)} bytes")
    flags, session_id, security_flags, message_counter = struct.unpack_from("<BHBI", data)
    add_bookmark(0, 8, "Header")
    print(f"Flags: {flags:x} Session ID: {session_id:x} Security Flags: {cm.SecurityFlags(security_flags)} Message Counter: {message_counter}")
    offset = 8
    if flags & (1 << 2):
        source_node_id = struct.unpack_from("<Q", data, 8)[0]
        add_bookmark(8, 8, "Source Node ID")
        print(source_node_id)
        offset += 8
    print(f"DSIZ {flags & (0x3)}")
    if (flags >> 4) != 0:
        print("Incorrect version")
        # continue
    secure_session = security_flags & 0x3 != 0 or session_id != 0

    if not secure_session:
        print("Unsecured session")
        print(data[offset:offset+8])
        decrypted_message = memoryview(data)[offset:]

        context = {"role": "responder", "node_id": source_node_id}
        unsecured_session_context[source_node_id] = context

    exchange_flags, protocol_opcode, exchange_id = struct.unpack_from("<BBH", decrypted_message)
    add_bookmark(offset, 4, "Protocol header")
    exchange_flags = cm.ExchangeFlags(exchange_flags)
    print(f"Exchange Flags: {exchange_flags} Exchange ID: {exchange_id}")
    decrypted_offset = 4
    protocol_vendor_id = 0
    if exchange_flags & cm.ExchangeFlags.V:
        protocol_vendor_id = struct.unpack_from("<H", decrypted_message, decrypted_offset)[0]
        add_bookmark(offset + decrypted_offset, 2, "Protocol Vendor ID")
        decrypted_offset += 2
    protocol_id = struct.unpack_from("<H", decrypted_message, decrypted_offset)[0]
    add_bookmark(offset + decrypted_offset, 2, "Protocol ID")
    decrypted_offset += 2
    protocol_id = cm.ProtocolId(protocol_id)
    protocol_opcode = cm.PROTOCOL_OPCODES[protocol_id](protocol_opcode)
    print(f"Protocol Vendor ID: {protocol_vendor_id} Protocol ID: {protocol_id} Protocol Opcode: {protocol_opcode}")

    acknowledged_message_counter = None
    if exchange_flags & cm.ExchangeFlags.A:
        acknowledged_message_counter = struct.unpack_from("<I", decrypted_message, decrypted_offset)[0]
        decrypted_offset += 4
    print(f"Acknowledged Message Counter: {acknowledged_message_counter}")

    if protocol_id == cm.ProtocolId.SECURE_CHANNEL:
        if protocol_opcode == cm.SecureProtocolOpcode.MSG_COUNTER_SYNC_REQ:
            print("Received Message Counter Synchronization Request")
            response = struct.pack("<BHBI", 0, 0, 0, 0)
            sock.sendto(response, addr)
            print(f"Sent Message Counter Synchronization Response to {addr}")
        elif protocol_opcode == cm.SecureProtocolOpcode.MSG_COUNTER_SYNC_RSP:
            print("Received Message Counter Synchronization Response")
        elif protocol_opcode == cm.SecureProtocolOpcode.PBKDF_PARAM_REQUEST:
            print("Received PBKDF Parameter Request")
            request = cm.PBKDFParamRequest(decrypted_message[decrypted_offset+1:])
            print(request)
            response = cm.PBKDFParamResponse()
            response.initiatorRandom = request.initiatorRandom
            response.responderRandom = b"\x00" * 32
            response.responderSessionId = 0
            params = cm.Crypto_PBKDFParameterSet()
            params.iterations = 1000
            params.salt = b"\x00" * 32
            response.pbkdf_parameters = params
            print(response)

        elif protocol_opcode == cm.SecureProtocolOpcode.PBKDF_PARAM_RESPONSE:
            print("Received PBKDF Parameter Response")
        elif protocol_opcode == cm.SecureProtocolOpcode.PASE_PAKE1:
            print("Received PASE PAKE1")
        elif protocol_opcode == cm.SecureProtocolOpcode.PASE_PAKE2:
            print("Received PASE PAKE2")
        elif protocol_opcode == cm.SecureProtocolOpcode.PASE_PAKE3:
            print("Received PASE PAKE3")
        elif protocol_opcode == cm.SecureProtocolOpcode.CASE_SIGMA1:
            print("Received CASE Sigma1")
        elif protocol_opcode == cm.SecureProtocolOpcode.CASE_SIGMA2:
            print("Received CASE Sigma2")
        elif protocol_opcode == cm.SecureProtocolOpcode.CASE_SIGMA3:
            print("Received CASE Sigma3")
        elif protocol_opcode == cm.SecureProtocolOpcode.CASE_SIGMA2_RESUME:
            print("Received CASE Sigma2 Resume")
        elif protocol_opcode == cm.SecureProtocolOpcode.STATUS_REPORT:
            print("Received Status Report")
        elif protocol_opcode == cm.SecureProtocolOpcode.ICD_CHECK_IN:
            print("Received ICD Check-in")

    # avahi.kill()

if __name__ == "__main__":
    run()
