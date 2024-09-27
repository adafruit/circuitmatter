import enum
import struct

from . import tlv
from .protocol import ProtocolId

from typing import Optional


class ExchangeFlags(enum.IntFlag):
    V = 1 << 4
    SX = 1 << 3
    R = 1 << 2
    A = 1 << 1
    I = 1 << 0  # noqa: E741


class SecurityFlags(enum.IntFlag):
    P = 1 << 7
    C = 1 << 6
    MX = 1 << 5
    # This is actually 2 bits but the top bit is reserved and always zero.
    GROUP = 1 << 0


class Message:
    def __init__(self):
        self.clear()

    def clear(self):
        self.flags: int = 0
        self.session_id: int = 0
        self.security_flags: SecurityFlags = SecurityFlags(0)
        self.message_counter: Optional[int] = None
        self.source_node_id = 0
        self.destination_node_id = 0
        self.secure_session: Optional[bool] = None
        self.payload = None
        self.duplicate: Optional[bool] = None

        # Filled in after the message payload is decrypted.
        self.exchange_flags: ExchangeFlags = ExchangeFlags(0)
        self.exchange_id: Optional[int] = None

        self.protocol_vendor_id = 0
        self.protocol_id = ProtocolId(0)
        self.protocol_opcode: Optional[int] = None

        self.acknowledged_message_counter = None
        self.application_payload = None

        self.source_ipaddress = None

        self.header = None

    def parse_protocol_header(self):
        self.exchange_flags, self.protocol_opcode, self.exchange_id = (
            struct.unpack_from("<BBH", self.payload)
        )

        self.exchange_flags = ExchangeFlags(self.exchange_flags)
        decrypted_offset = 4
        self.protocol_vendor_id = 0
        if self.exchange_flags & ExchangeFlags.V:
            self.protocol_vendor_id = struct.unpack_from(
                "<H", self.payload, decrypted_offset
            )[0]
            decrypted_offset += 2
        protocol_id = struct.unpack_from("<H", self.payload, decrypted_offset)[0]
        decrypted_offset += 2
        self.protocol_id = ProtocolId(protocol_id)
        self.protocol_opcode = self.protocol_id.ProtocolOpcode(self.protocol_opcode)

        self.acknowledged_message_counter = None
        if self.exchange_flags & ExchangeFlags.A:
            self.acknowledged_message_counter = struct.unpack_from(
                "<I", self.payload, decrypted_offset
            )[0]
            decrypted_offset += 4

        self.application_payload = self.payload[decrypted_offset:]

    def decode(self, buffer):
        self.clear()
        self.buffer = buffer
        self.flags, self.session_id, self.security_flags, self.message_counter = (
            struct.unpack_from("<BHBI", buffer)
        )
        self.security_flags = SecurityFlags(self.security_flags)
        offset = 8
        if self.flags & (1 << 2):
            self.source_node_id = struct.unpack_from("<Q", buffer, 8)[0]
            offset += 8
        else:
            self.source_node_id = 0

        if (self.flags >> 4) != 0:
            raise RuntimeError("Incorrect version")
        self.secure_session = not (
            not (self.security_flags & SecurityFlags.GROUP) and self.session_id == 0
        )
        self.decrypted = not self.secure_session

        self.header = memoryview(buffer)[:offset]
        self.payload = memoryview(buffer)[offset:]
        self.duplicate = None

    def encode_into(self, buffer, cipher=None):
        offset = 0
        struct.pack_into(
            "<BHBI",
            buffer,
            offset,
            self.flags,
            self.session_id,
            self.security_flags,
            self.message_counter,
        )
        nonce_start = 3
        nonce_end = nonce_start + 1 + 4
        offset += 8
        if self.source_node_id > 0:
            struct.pack_into("<Q", buffer, offset, self.source_node_id)
            offset += 8
            nonce_end += 8
        if self.destination_node_id > 0:
            if self.destination_node_id > 0xFFFF_FFFF_FFFF_0000:
                struct.pack_into(
                    "<H", buffer, offset, self.destination_node_id & 0xFFFF
                )
                offset += 2
            else:
                struct.pack_into("<Q", buffer, offset, self.destination_node_id)
                offset += 8

        if cipher is not None:
            unencrypted_buffer = memoryview(bytearray(1280))
            unencrypted_offset = 0
        else:
            unencrypted_buffer = buffer
            unencrypted_offset = offset

        struct.pack_into(
            "BBHH",
            unencrypted_buffer,
            unencrypted_offset,
            self.exchange_flags,
            self.protocol_opcode,
            self.exchange_id,
            self.protocol_id,
        )
        unencrypted_offset += 6
        if self.acknowledged_message_counter is not None:
            struct.pack_into(
                "I",
                unencrypted_buffer,
                unencrypted_offset,
                self.acknowledged_message_counter,
            )
            unencrypted_offset += 4

        if self.application_payload is not None:
            if isinstance(self.application_payload, tlv.Structure):
                # Wrap the structure in an anonymous tag.
                unencrypted_buffer[unencrypted_offset] = 0x15
                unencrypted_offset += 1
                unencrypted_offset = self.application_payload.encode_into(
                    unencrypted_buffer, unencrypted_offset
                )
            elif hasattr(self.application_payload, "encode_into"):
                unencrypted_offset = self.application_payload.encode_into(
                    unencrypted_buffer, unencrypted_offset
                )
            else:
                # Skip a copy operation if we're using a separate unencrypted buffer
                if unencrypted_offset == 0:
                    unencrypted_buffer = self.application_payload
                else:
                    unencrypted_buffer[
                        unencrypted_offset : unencrypted_offset
                        + len(self.application_payload)
                    ] = self.application_payload
                unencrypted_offset += len(self.application_payload)

        # print("unencrypted", unencrypted_buffer[:unencrypted_offset].hex(" "))

        # Encrypt the payload
        if cipher is not None:
            # The message may not include the source_node_id so we encode the nonce separately.
            nonce = struct.pack(
                "<BIQ", self.security_flags, self.message_counter, self.source_node_id
            )
            additional = buffer[:offset]
            self.payload = cipher.encrypt(
                nonce, bytes(unencrypted_buffer[:unencrypted_offset]), bytes(additional)
            )
            buffer[offset : offset + len(self.payload)] = self.payload
            offset += len(self.payload)
        else:
            offset = unencrypted_offset

        return offset

    @property
    def source_node_id(self):
        return self._source_node_id

    @source_node_id.setter
    def source_node_id(self, value):
        self._source_node_id = value
        if value > 0:
            self.flags |= 1 << 2
        else:
            self.flags &= ~(1 << 2)

    @property
    def destination_node_id(self):
        return self._destination_node_id

    @destination_node_id.setter
    def destination_node_id(self, value):
        self._destination_node_id = value
        # Clear the field
        self.flags &= ~0x3
        if value == 0:
            pass
        elif value > 0xFFFF_FFFF_FFFF_0000:
            self.flags |= 2
        elif value > 0:
            self.flags |= 1

    def __str__(self):
        pieces = ["Message:"]
        pieces.append(f"Message Flags: {self.flags}")
        pieces.append(f"Session ID: {self.session_id}")
        pieces.append(f"Security Flags: {self.security_flags}")
        pieces.append(f"Message Counter: {self.message_counter}")
        if self.source_node_id is not None:
            pieces.append(f"Source Node ID: {self.source_node_id:x}")
        if self.destination_node_id is not None:
            pieces.append(f"Destination Node ID: {self.destination_node_id:x}")
        payload_info = ["Payload: "]
        payload_info.append(f"Exchange Flags: {self.exchange_flags!r}")
        payload_info.append(f"Protocol Opcode: {self.protocol_opcode!r}")
        payload_info.append(f"Exchange ID: {self.exchange_id}")
        if self.protocol_vendor_id:
            payload_info.append(f"Protocol Vendor ID: {self.protocol_vendor_id}")
        payload_info.append(f"Protocol ID: {self.protocol_id!r}")
        if self.acknowledged_message_counter is not None:
            payload_info.append(
                f"Acknowledged Message Counter: {self.acknowledged_message_counter}"
            )
        if self.application_payload is not None:
            application_payload = str(self.application_payload).replace("\n", "\n    ")
            payload_info.append(f"Application Payload: {application_payload}")
        pieces.append("\n    ".join(payload_info))
        return "\n  ".join(pieces)
