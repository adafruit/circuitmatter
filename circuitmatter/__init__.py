"""Pure Python implementation of the Matter IOT protocol."""

import enum
import math
import subprocess
import socket
import struct

from . import tlv

from typing import Optional, Type, Any

__version__ = "0.0.0"

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

class ProtocolId(enum.Enum):
    SECURE_CHANNEL = 0
    INTERACTION_MODEL = 1
    BDX = 2
    USER_DIRECTED_COMMISSIONING = 3
    FOR_TESTING = 4

class SecurityFlags(enum.Flag):
    P = 1 << 7
    C = 1 << 6
    MX = 1 << 5

class ExchangeFlags(enum.Flag):
    V = 1 << 4
    SX = 1 << 3
    R = 1 << 2
    A = 1 << 1
    I = 1 << 0

class SecureProtocolOpcode(enum.Enum):
    MSG_COUNTER_SYNC_REQ = 0x00
    """The Message Counter Synchronization Request message queries the current message counter from a peer to bootstrap replay protection."""
    
    MSG_COUNTER_SYNC_RSP = 0x01
    """The Message Counter Synchronization Response message provides the current message counter from a peer to bootstrap replay protection."""
    
    MRP_STANDALONE_ACK = 0x10
    """This message is dedicated for the purpose of sending a stand-alone acknowledgement when there is no other data message available to piggyback an acknowledgement on top of."""
    
    PBKDF_PARAM_REQUEST = 0x20
    """The request for PBKDF parameters necessary to complete the PASE protocol."""
    
    PBKDF_PARAM_RESPONSE = 0x21
    """The PBKDF parameters sent in response to PBKDF-ParamRequest during the PASE protocol."""
    
    PASE_PAKE1 = 0x22
    """The first PAKE message of the PASE protocol."""
    
    PASE_PAKE2 = 0x23
    """The second PAKE message of the PASE protocol."""
    
    PASE_PAKE3 = 0x24
    """The third PAKE message of the PASE protocol."""
    
    CASE_SIGMA1 = 0x30
    """The first message of the CASE protocol."""
    
    CASE_SIGMA2 = 0x31
    """The second message of the CASE protocol."""
    
    CASE_SIGMA3 = 0x32
    """The third message of the CASE protocol."""
    
    CASE_SIGMA2_RESUME = 0x33
    """The second resumption message of the CASE protocol."""
    
    STATUS_REPORT = 0x40
    """The Status Report message encodes the result of an operation in the Secure Channel as well as other protocols."""
    
    ICD_CHECK_IN = 0x50
    """The Check-in message notifies a client that the ICD is available for communication."""

PROTOCOL_OPCODES = {
    ProtocolId.SECURE_CHANNEL: SecureProtocolOpcode,
}


# session-parameter-struct => STRUCTURE [ tag-order ]
# {
# SESSION_IDLE_INTERVAL
#  [1, optional] : UNSIGNED INTEGER [ range 32-bits ],
# SESSION_ACTIVE_INTERVAL
#  [2, optional] : UNSIGNED INTEGER [ range 32-bits ],
# SESSION_ACTIVE_THRESHOLD
#  [3, optional] : UNSIGNED INTEGER [ range 16-bits ],
# DATA_MODEL_REVISION
#  [4]
#  : UNSIGNED INTEGER [ range 16-bits ],
# INTERACTION_MODEL_REVISION [5]
#  : UNSIGNED INTEGER [ range 16-bits ],
# SPECIFICATION_VERSION
#  [6]
#  : UNSIGNED INTEGER [ range 32-bits ],
# MAX_PATHS_PER_INVOKE
#  [7]
#  : UNSIGNED INTEGER [ range 16-bits ],
# }
class SessionParameterStruct(tlv.TLVStructure):
    session_idle_interval = tlv.NumberMember(1, "<I", optional=True)
    session_active_interval = tlv.NumberMember(2, "<I", optional=True)
    session_active_threshold = tlv.NumberMember(3, "<H", optional=True)
    data_model_revision = tlv.NumberMember(4, "<H")
    interaction_model_revision = tlv.NumberMember(5, "<H")
    specification_version = tlv.NumberMember(6, "<I")
    max_paths_per_invoke = tlv.NumberMember(7, "<H")

# pbkdfparamreq-struct => STRUCTURE [ tag-order ]
# {
# initiatorRandom
#  [1] : OCTET STRING [ length 32 ],
# initiatorSessionId
#  [2] : UNSIGNED INTEGER [ range 16-bits ],
# passcodeId
#  [3] : UNSIGNED INTEGER [ length 16-bits ],
# hasPBKDFParameters
#  [4] : BOOLEAN,
# initiatorSessionParams [5, optional] : session-parameter-struct
# }
class PBKDFParamRequest(tlv.TLVStructure):
    initiatorRandom = tlv.OctetStringMember(1, 32)
    initiatorSessionId = tlv.NumberMember(2, "<H")
    passcodeId = tlv.NumberMember(3, "<H")
    hasPBKDFParameters = tlv.BoolMember(4)
    initiatorSessionParams = tlv.StructMember(5, SessionParameterStruct, optional=True)

# Crypto_PBKDFParameterSet => STRUCTURE [ tag-order ]
# {
# iterations [1] : UNSIGNED INTEGER [ range 32-bits ],
# salt [2] : OCTET STRING [ length 16..32 ],
# }
class Crypto_PBKDFParameterSet(tlv.TLVStructure):
    iterations = tlv.NumberMember(1, "<I")
    salt = tlv.OctetStringMember(2, 32)

# pbkdfparamresp-struct => STRUCTURE [ tag-order ]
# {
# initiatorRandom
#  [1] : OCTET STRING [ length 32 ],
# responderRandom
#  [2] : OCTET STRING [ length 32 ],
# responderSessionId
#  [3] : UNSIGNED INTEGER [ range 16-bits ],
# pbkdf_parameters
#  [4] : Crypto_PBKDFParameterSet,
# responderSessionParams [5, optional] : session-parameter-struct
# }
class PBKDFParamResponse(tlv.TLVStructure):
    initiatorRandom = tlv.OctetStringMember(1, 32)
    responderRandom = tlv.OctetStringMember(2, 32)
    responderSessionId = tlv.NumberMember(3, "<H")
    pbkdf_parameters = tlv.StructMember(4, Crypto_PBKDFParameterSet)
    responderSessionParams = tlv.StructMember(5, SessionParameterStruct, optional=True)

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
    pathlib.Path("parsed.hexbm").write_text(json.dumps({"bookmarks": bookmarks}))

def run():
    # Print the received data and the address of the sender
    print(f"Received packet from {addr}: {data}")
    print(f"Data length: {len(data)} bytes")
    flags, session_id, security_flags, message_counter = struct.unpack_from("<BHBI", data)
    add_bookmark(0, 8, "Header")
    print(f"Flags: {flags:x} Session ID: {session_id:x} Security Flags: {SecurityFlags(security_flags)} Message Counter: {message_counter}")
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
    exchange_flags = ExchangeFlags(exchange_flags)
    print(f"Exchange Flags: {exchange_flags} Exchange ID: {exchange_id}")
    decrypted_offset = 4
    protocol_vendor_id = 0
    if exchange_flags & ExchangeFlags.V:
        protocol_vendor_id = struct.unpack_from("<H", decrypted_message, decrypted_offset)[0]
        add_bookmark(offset + decrypted_offset, 2, "Protocol Vendor ID")
        decrypted_offset += 2
    protocol_id = struct.unpack_from("<H", decrypted_message, decrypted_offset)[0]
    add_bookmark(offset + decrypted_offset, 2, "Protocol ID")
    decrypted_offset += 2
    protocol_id = ProtocolId(protocol_id)
    protocol_opcode = PROTOCOL_OPCODES[protocol_id](protocol_opcode)
    print(f"Protocol Vendor ID: {protocol_vendor_id} Protocol ID: {protocol_id} Protocol Opcode: {protocol_opcode}")

    acknowledged_message_counter = None
    if exchange_flags & ExchangeFlags.A:
        acknowledged_message_counter = struct.unpack_from("<I", decrypted_message, decrypted_offset)[0]
        decrypted_offset += 4
    print(f"Acknowledged Message Counter: {acknowledged_message_counter}")

    if protocol_id == ProtocolId.SECURE_CHANNEL:
        if protocol_opcode == SecureProtocolOpcode.MSG_COUNTER_SYNC_REQ:
            print("Received Message Counter Synchronization Request")
            response = struct.pack("<BHBI", 0, 0, 0, 0)
            sock.sendto(response, addr)
            print(f"Sent Message Counter Synchronization Response to {addr}")
        elif protocol_opcode == SecureProtocolOpcode.MSG_COUNTER_SYNC_RSP:
            print("Received Message Counter Synchronization Response")
        elif protocol_opcode == SecureProtocolOpcode.PBKDF_PARAM_REQUEST:
            print("Received PBKDF Parameter Request")
            request = PBKDFParamRequest(decrypted_message[decrypted_offset+1:])
            response = PBKDFParamResponse()
            response.initiatorRandom = request.initiatorRandom
            response.responderRandom = b"\x00" * 32
            response.responderSessionId = 0
            params = response.pbkdf_parameters
            params.iterations = 1000
            params.salt = b"\x00" * 32
            print(response)

        elif protocol_opcode == SecureProtocolOpcode.PBKDF_PARAM_RESPONSE:
            print("Received PBKDF Parameter Response")
        elif protocol_opcode == SecureProtocolOpcode.PASE_PAKE1:
            print("Received PASE PAKE1")
        elif protocol_opcode == SecureProtocolOpcode.PASE_PAKE2:
            print("Received PASE PAKE2")
        elif protocol_opcode == SecureProtocolOpcode.PASE_PAKE3:
            print("Received PASE PAKE3")
        elif protocol_opcode == SecureProtocolOpcode.CASE_SIGMA1:
            print("Received CASE Sigma1")
        elif protocol_opcode == SecureProtocolOpcode.CASE_SIGMA2:
            print("Received CASE Sigma2")
        elif protocol_opcode == SecureProtocolOpcode.CASE_SIGMA3:
            print("Received CASE Sigma3")
        elif protocol_opcode == SecureProtocolOpcode.CASE_SIGMA2_RESUME:
            print("Received CASE Sigma2 Resume")
        elif protocol_opcode == SecureProtocolOpcode.STATUS_REPORT:
            print("Received Status Report")
        elif protocol_opcode == SecureProtocolOpcode.ICD_CHECK_IN:
            print("Received ICD Check-in")

    # avahi.kill()

if __name__ == "__main__":
    run()
