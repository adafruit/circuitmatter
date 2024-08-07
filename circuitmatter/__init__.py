"""Pure Python implementation of the Matter IOT protocol."""

import binascii
import enum
import hashlib
import hmac
import pathlib
import json
import os
import random
import struct
import time
from ecdsa.ellipticcurve import AbstractPoint, Point, PointJacobi
from ecdsa.curves import NIST256p

import cryptography
from cryptography.hazmat.primitives.ciphers.aead import AESCCM

from typing import Optional, Iterable

from . import tlv

__version__ = "0.0.0"

# Section 3.6

CRYPTO_SYMMETRIC_KEY_LENGTH_BITS = 128
CRYPTO_SYMMETRIC_KEY_LENGTH_BYTES = 16
CRYPTO_AEAD_MIC_LENGTH_BITS = 128
CRYPTO_AEAD_MIC_LENGTH_BYTES = 16
CRYPTO_AEAD_NONCE_LENGTH_BYTES = 13


# Section 4.11.2
MSG_COUNTER_WINDOW_SIZE = 32
MSG_COUNTER_SYNC_REQ_JITTER_MS = 500
MSG_COUNTER_SYNC_TIMEOUT_MS = 400

# Section 4.12.8
MRP_MAX_TRANSMISSIONS = 5
"""The maximum number of transmission attempts for a given reliable message. The sender MAY choose this value as it sees fit."""

MRP_BACKOFF_BASE = 1.6
"""The base number for the exponential backoff equation."""

MRP_BACKOFF_JITTER = 0.25
"""The scaler for random jitter in the backoff equation."""

MRP_BACKOFF_MARGIN = 1.1
"""The scaler margin increase to backoff over the peer idle interval."""

MRP_BACKOFF_THRESHOLD = 1
"""The number of retransmissions before transitioning from linear to exponential backoff."""

MRP_STANDALONE_ACK_TIMEOUT_MS = 200
"""Amount of time to wait for an opportunity to piggyback an acknowledgement on an outbound message before falling back to sending a standalone acknowledgement."""


class ProtocolId(enum.IntEnum):
    SECURE_CHANNEL = 0
    INTERACTION_MODEL = 1
    BDX = 2
    USER_DIRECTED_COMMISSIONING = 3
    FOR_TESTING = 4


class SecurityFlags(enum.IntFlag):
    P = 1 << 7
    C = 1 << 6
    MX = 1 << 5
    # This is actually 2 bits but the top bit is reserved and always zero.
    GROUP = 1 << 0


class ExchangeFlags(enum.IntFlag):
    V = 1 << 4
    SX = 1 << 3
    R = 1 << 2
    A = 1 << 1
    I = 1 << 0  # noqa: E741


class SecureProtocolOpcode(enum.IntEnum):
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


class InteractionModelOpcode(enum.IntEnum):
    STATUS_RESPONSE = 0x01
    READ_REQUEST = 0x02
    SUBSCRIBE_REQUEST = 0x03
    SUBSCRIBE_RESPONSE = 0x04
    REPORT_DATA = 0x05
    WRITE_REQUEST = 0x06
    WRITE_RESPONSE = 0x07
    INVOKE_REQUEST = 0x08
    INVOKE_RESPONSE = 0x09
    TIMED_REQUEST = 0x0A


PROTOCOL_OPCODES = {
    ProtocolId.SECURE_CHANNEL: SecureProtocolOpcode,
    ProtocolId.INTERACTION_MODEL: InteractionModelOpcode,
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
    session_idle_interval = tlv.IntMember(1, signed=False, octets=4, optional=True)
    session_active_interval = tlv.IntMember(2, signed=False, octets=4, optional=True)
    session_active_threshold = tlv.IntMember(3, signed=False, octets=2, optional=True)
    data_model_revision = tlv.IntMember(4, signed=False, octets=2)
    interaction_model_revision = tlv.IntMember(5, signed=False, octets=2)
    specification_version = tlv.IntMember(6, signed=False, octets=4)
    max_paths_per_invoke = tlv.IntMember(7, signed=False, octets=2)


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
    initiatorSessionId = tlv.IntMember(2, signed=False, octets=2)
    passcodeId = tlv.IntMember(3, signed=False, octets=2)
    hasPBKDFParameters = tlv.BoolMember(4)
    initiatorSessionParams = tlv.StructMember(5, SessionParameterStruct, optional=True)


# Crypto_PBKDFParameterSet => STRUCTURE [ tag-order ]
# {
# iterations [1] : UNSIGNED INTEGER [ range 32-bits ],
# salt [2] : OCTET STRING [ length 16..32 ],
# }
class Crypto_PBKDFParameterSet(tlv.TLVStructure):
    iterations = tlv.IntMember(1, signed=False, octets=4)
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
    responderSessionId = tlv.IntMember(3, signed=False, octets=2)
    pbkdf_parameters = tlv.StructMember(4, Crypto_PBKDFParameterSet)
    responderSessionParams = tlv.StructMember(5, SessionParameterStruct, optional=True)


CRYPTO_GROUP_SIZE_BITS = 256
CRYPTO_GROUP_SIZE_BYTES = 32
CRYPTO_PUBLIC_KEY_SIZE_BYTES = (2 * CRYPTO_GROUP_SIZE_BYTES) + 1

CRYPTO_HASH_LEN_BITS = 256
CRYPTO_HASH_LEN_BYTES = 32
CRYPTO_HASH_BLOCK_LEN_BYTES = 64


class PAKE1(tlv.TLVStructure):
    pA = tlv.OctetStringMember(1, CRYPTO_PUBLIC_KEY_SIZE_BYTES)


class PAKE2(tlv.TLVStructure):
    pB = tlv.OctetStringMember(1, CRYPTO_PUBLIC_KEY_SIZE_BYTES)
    cB = tlv.OctetStringMember(2, CRYPTO_HASH_LEN_BYTES)


class PAKE3(tlv.TLVStructure):
    cA = tlv.OctetStringMember(1, CRYPTO_HASH_LEN_BYTES)


class AttributePathIB(tlv.TLVStructure):
    """Section 10.6.2"""

    EnableTagCompression = tlv.BoolMember(0, optional=True)
    Node = tlv.IntMember(1, signed=False, octets=8, optional=True)
    Endpoint = tlv.IntMember(2, signed=False, octets=2, optional=True)
    Cluster = tlv.IntMember(3, signed=False, octets=4, optional=True)
    Attribute = tlv.IntMember(4, signed=False, octets=4, optional=True)
    ListIndex = tlv.IntMember(5, signed=False, octets=2, nullable=True, optional=True)
    WildcardPathFlags = tlv.IntMember(6, signed=False, octets=4, optional=True)


class EventPathIB(tlv.TLVStructure):
    """Section 10.6.8"""

    Node = tlv.IntMember(0, signed=False, octets=8)
    Endpoint = tlv.IntMember(1, signed=False, octets=2)
    Cluster = tlv.IntMember(2, signed=False, octets=4)
    Event = tlv.IntMember(3, signed=False, octets=4)
    IsUrgent = tlv.BoolMember(4)


class EventFilterIB(tlv.TLVStructure):
    """Section 10.6.6"""

    Node = tlv.IntMember(0, signed=False, octets=8)
    EventMinimumInterval = tlv.IntMember(1, signed=False, octets=8)


class ClusterPathIB(tlv.TLVStructure):
    Node = tlv.IntMember(0, signed=False, octets=8)
    Endpoint = tlv.IntMember(1, signed=False, octets=2)
    Cluster = tlv.IntMember(2, signed=False, octets=4)


class DataVersionFilterIB(tlv.TLVStructure):
    Path = tlv.StructMember(0, ClusterPathIB)
    DataVersion = tlv.IntMember(1, signed=False, octets=4)


class StatusIB(tlv.TLVStructure):
    Status = tlv.IntMember(0, signed=False, octets=1)
    ClusterStatus = tlv.IntMember(1, signed=False, octets=1)


class AttributeDataIB(tlv.TLVStructure):
    DataVersion = tlv.IntMember(0, signed=False, octets=4)
    Path = tlv.StructMember(1, AttributePathIB)
    Data = tlv.AnythingMember(
        2
    )  # This is a weird one because the TLV type can be anything.


class AttributeStatusIB(tlv.TLVStructure):
    Path = tlv.StructMember(0, AttributePathIB)
    Status = tlv.StructMember(1, StatusIB)


class AttributeReportIB(tlv.TLVStructure):
    AttributeStatus = tlv.StructMember(0, AttributeStatusIB)
    AttributeData = tlv.StructMember(1, AttributeDataIB)


class ReadRequestMessage(tlv.TLVStructure):
    AttributeRequests = tlv.ArrayMember(0, tlv.List(AttributePathIB))
    EventRequests = tlv.ArrayMember(1, EventPathIB)
    EventFilters = tlv.ArrayMember(2, EventFilterIB)
    FabricFiltered = tlv.BoolMember(3)
    DataVersionFilters = tlv.ArrayMember(4, DataVersionFilterIB)


class EventStatusIB(tlv.TLVStructure):
    Path = tlv.StructMember(0, EventPathIB)
    Status = tlv.StructMember(1, StatusIB)


class EventDataIB(tlv.TLVStructure):
    Path = tlv.StructMember(0, EventPathIB)
    EventNumber = tlv.IntMember(1, signed=False, octets=8)
    PriorityLevel = tlv.IntMember(2, signed=False, octets=1)

    # Only one of the below values
    EpochTimestamp = tlv.IntMember(3, signed=False, octets=8, optional=True)
    SystemTimestamp = tlv.IntMember(4, signed=False, octets=8, optional=True)
    DeltaEpochTimestamp = tlv.IntMember(5, signed=True, octets=8, optional=True)
    DeltaSystemTimestamp = tlv.IntMember(6, signed=True, octets=8, optional=True)

    Data = tlv.AnythingMember(
        7
    )  # This is a weird one because the TLV type can be anything.


class EventReportIB(tlv.TLVStructure):
    EventStatus = tlv.StructMember(0, EventStatusIB)
    EventData = tlv.StructMember(1, EventDataIB)


class ReportDataMessage(tlv.TLVStructure):
    SubscriptionId = tlv.IntMember(0, signed=False, octets=4)
    AttributeReports = tlv.ArrayMember(1, AttributeReportIB)
    EventReports = tlv.ArrayMember(2, EventReportIB)
    MoreChunkedMessages = tlv.BoolMember(3, optional=True)
    SuppressResponse = tlv.BoolMember(4, optional=True)


class MessageReceptionState:
    def __init__(self, starting_value, rollover=True, encrypted=False):
        """Implements 4.6.5.1"""
        self.message_counter = starting_value
        self.window_bitmap = (1 << MSG_COUNTER_WINDOW_SIZE) - 1
        self.mask = self.window_bitmap
        self.encrypted = encrypted
        self.rollover = rollover

    def process_counter(self, counter) -> bool:
        """Returns True if the counter number is a duplicate"""
        # Process the current window first. Behavior outside the window varies.
        if counter == self.message_counter:
            return True
        if self.message_counter <= MSG_COUNTER_WINDOW_SIZE < counter:
            # Window wraps
            bit_position = 0xFFFFFFFF - counter + self.message_counter
        else:
            bit_position = self.message_counter - counter - 1
        if 0 <= bit_position < MSG_COUNTER_WINDOW_SIZE:
            if self.window_bitmap & (1 << bit_position) != 0:
                # This is a duplicate message
                return True
            self.window_bitmap |= 1 << bit_position
            return False

        new_start = (self.message_counter + 1) & self.mask  # Inclusive
        new_end = (
            self.message_counter - MSG_COUNTER_WINDOW_SIZE
        ) & self.mask  # Exclusive
        if not self.rollover:
            new_end = (1 << MSG_COUNTER_WINDOW_SIZE) - 1
        elif self.encrypted:
            new_end = (
                self.message_counter + (1 << (MSG_COUNTER_WINDOW_SIZE - 1))
            ) & self.mask

        if new_start <= new_end:
            if not (new_start <= counter < new_end):
                return True
        else:
            if not (counter < new_end or new_start <= counter):
                return True

        # This is a new message
        shift = counter - self.message_counter
        if counter < self.message_counter:
            shift += 0x100000000
        if shift > MSG_COUNTER_WINDOW_SIZE:
            self.window_bitmap = 0
        else:
            new_bitmap = (self.window_bitmap << shift) & self.mask
            self.window_bitmap = new_bitmap
        if 1 < shift < MSG_COUNTER_WINDOW_SIZE:
            self.window_bitmap |= 1 << (shift - 1)
        self.message_counter = counter
        return False


class MessageCounter:
    def __init__(self, starting_value=None):
        if starting_value is None:
            starting_value = os.urandom(4)
            starting_value = struct.unpack("<I", starting_value)[0]
            starting_value >>= 4
            starting_value += 1
        self.value = starting_value

    def __next__(self):
        self.value = (self.value + 1) % 0xFFFFFFFF
        return self.value


class Exchange:
    def __init__(self, session, initiator: bool, exchange_id: int, protocols):
        self.initiator = initiator
        self.exchange_id = exchange_id
        self.protocols = protocols
        self.session = session

        self.pending_acknowledgement = None
        """Message number that is waiting for an ack from us"""
        self.send_standalone_time = None

        self.next_retransmission_time = None
        """When to next resend the message that hasn't been acked"""
        self.pending_retransmission = None
        """Message that we've attempted to send but hasn't been acked"""

    def send(self, protocol_id, protocol_opcode, application_payload=None):
        message = Message()
        message.exchange_flags = ExchangeFlags(0)
        if self.initiator:
            message.exchange_flags |= ExchangeFlags.I
        if self.pending_acknowledgement is not None:
            message.exchange_flags |= ExchangeFlags.A
            self.send_standalone_time = None
            message.acknowledged_message_counter = self.pending_acknowledgement
            self.pending_acknowledgement = None
        message.protocol_id = protocol_id
        message.protocol_opcode = protocol_opcode
        message.exchange_id = self.exchange_id
        message.application_payload = application_payload
        self.session.send(message)

    def send_standalone(self):
        self.send(
            ProtocolId.SECURE_CHANNEL, SecureProtocolOpcode.MRP_STANDALONE_ACK, None
        )

    def receive(self, message) -> bool:
        """Process the message and return if the packet should be dropped."""
        if message.protocol_id not in self.protocols:
            # Drop messages that don't match the protocols we're waiting for.
            return True

        # Section 4.12.5.2.1
        if message.exchange_flags & ExchangeFlags.A:
            if message.acknowledged_message_counter is None:
                # Drop messages that are missing an acknowledgement counter.
                return True
            if message.acknowledged_message_counter != self.pending_acknowledgement:
                # Drop messages that have the wrong acknowledgement counter.
                return True
            self.pending_retransmission = None
            self.next_retransmission_time = None

        # Section 4.12.5.2.2
        # Incoming packets that are marked Reliable.
        if message.exchange_flags & ExchangeFlags.R:
            if message.duplicate:
                # Send a standalone acknowledgement.
                return True
            if self.pending_acknowledgement is not None:
                # Send a standalone acknowledgement with the message counter we're about to overwrite.
                pass
            self.pending_acknowledgement = message.message_counter
            self.send_standalone_time = (
                time.monotonic() + MRP_STANDALONE_ACK_TIMEOUT_MS / 1000
            )

        if message.duplicate:
            return True
        return False


class UnsecuredSessionContext:
    def __init__(
        self,
        socket,
        message_counter,
        initiator,
        ephemeral_initiator_node_id,
        node_ipaddress,
    ):
        self.socket = socket
        self.initiator = initiator
        self.ephemeral_initiator_node_id = ephemeral_initiator_node_id
        self.message_reception_state = None
        self.message_counter = message_counter
        self.node_ipaddress = node_ipaddress
        self.exchanges = {}

    def send(self, message):
        message.destination_node_id = self.ephemeral_initiator_node_id
        if message.message_counter is None:
            message.message_counter = next(self.message_counter)
        buf = memoryview(bytearray(1280))
        nbytes = message.encode_into(buf)
        self.socket.sendto(buf[:nbytes], self.node_ipaddress)


class SecureSessionContext:
    def __init__(self, local_session_id):
        self.session_type = None
        """Records whether the session was established using CASE or PASE."""
        self.session_role_initiator = False
        """Records whether the node is the session initiator or responder."""
        self.local_session_id = local_session_id
        """Individually selected by each participant in secure unicast communication during session establishment and used as a unique identifier to recover encryption keys, authenticate incoming messages and associate them to existing sessions."""
        self.peer_session_id = None
        """Assigned by the peer during session establishment"""
        self.i2r_key = None
        """Encrypts data in messages sent from the initiator of session establishment to the responder."""
        self.r2i_key = None
        """Encrypts data in messages sent from the session establishment responder to the initiator."""
        self.shared_secret = None
        """Computed during the CASE protocol execution and re-used when CASE session resumption is implemented."""
        self.local_message_counter = None
        """Secure Session Message Counter for outbound messages."""
        self.message_reception_state = None
        """Provides tracking for the Secure Session Message Counter of the remote"""
        self.local_fabric_index = None
        """Records the local Index for the session’s Fabric, which MAY be used to look up Fabric metadata related to the Fabric for which this session context applies."""
        self.peer_node_id = None
        """Records the authenticated node ID of the remote peer, when available."""
        self.resumption_id = None
        """The ID used when resuming a session between the local and remote peer."""
        self.session_timestamp = None
        """A timestamp indicating the time at which the last message was sent or received. This timestamp SHALL be initialized with the time the session was created."""
        self.active_timestamp = None
        """A timestamp indicating the time at which the last message was received. This timestamp SHALL be initialized with the time the session was created."""
        self.session_idle_interval = None
        self.session_active_interval = None
        self.session_active_threshold = None
        self.exchanges = {}

        self._nonce = bytearray(CRYPTO_AEAD_NONCE_LENGTH_BYTES)

    @property
    def peer_active(self):
        return (time.monotonic() - self.active_timestamp) < self.session_active_interval

    def decrypt_and_verify(self, message):
        cipher = self.i2r
        if self.session_role_initiator:
            cipher = self.r2i
        try:
            source_node_id = 0  # for secure unicast messages
            # TODO: Support group messages
            struct.pack_into(
                "<BIQ",
                self._nonce,
                0,
                message.security_flags,
                message.message_counter,
                source_node_id,
            )
            decrypted_payload = cipher.decrypt(
                self._nonce, bytes(message.payload), bytes(message.header)
            )
        except cryptography.exceptions.InvalidTag:
            return False

        message.decrypted = True
        message.payload = decrypted_payload
        return True


class Message:
    def __init__(self):
        self.clear()

    def clear(self):
        self.flags: int = 0
        self.session_id: int = 0
        self.security_flags: SecurityFlags = SecurityFlags(0)
        self.message_counter: Optional[int] = None
        self.source_node_id = None
        self.destination_node_id = None
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
        self.protocol_opcode = PROTOCOL_OPCODES[self.protocol_id](self.protocol_opcode)

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
            self.source_node_id = None

        if (self.flags >> 4) != 0:
            raise RuntimeError("Incorrect version")
        self.secure_session = not (
            not (self.security_flags & SecurityFlags.GROUP) and self.session_id == 0
        )
        self.decrypted = not self.secure_session

        self.header = memoryview(buffer)[:offset]
        self.payload = memoryview(buffer)[offset:]
        self.duplicate = None

    def encode_into(self, buffer):
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
        offset += 8
        if self.source_node_id is not None:
            struct.pack_into("<Q", buffer, offset, self.source_node_id)
            offset += 8
        if self.destination_node_id is not None:
            if self.destination_node_id > 0xFFFF_FFFF_FFFF_0000:
                struct.pack_into(
                    "<H", buffer, offset, self.destination_node_id & 0xFFFF
                )
                offset += 2
            else:
                struct.pack_into("<Q", buffer, offset, self.destination_node_id)
                offset += 8
        struct.pack_into(
            "BBHH",
            buffer,
            offset,
            self.exchange_flags,
            self.protocol_opcode,
            self.exchange_id,
            self.protocol_id,
        )
        offset += 6
        if self.acknowledged_message_counter is not None:
            struct.pack_into("I", buffer, offset, self.acknowledged_message_counter)
            offset += 4
        if self.application_payload is not None:
            if isinstance(self.application_payload, tlv.TLVStructure):
                # Wrap the structure in an anonymous tag.
                buffer[offset] = 0x15
                offset += 1
                offset = self.application_payload.encode_into(buffer, offset)
                buffer[offset] = 0x18
                offset += 1
            elif isinstance(self.application_payload, StatusReport):
                offset = self.application_payload.encode_into(buffer, offset)
            else:
                buffer[offset : offset + len(self.application_payload)] = (
                    self.application_payload
                )
                offset += len(self.application_payload)
        return offset

    @property
    def source_node_id(self):
        return self._source_node_id

    @source_node_id.setter
    def source_node_id(self, value):
        self._source_node_id = value
        if value is not None:
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
        if value is None:
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


class GeneralCode(enum.IntEnum):
    SUCCESS = 0
    """Operation completed successfully."""

    FAILURE = 1
    """Generic failure, additional details may be included in the protocol specific status."""

    BAD_PRECONDITION = 2
    """Operation was rejected by the system because the system is in an invalid state."""

    OUT_OF_RANGE = 3
    """A value was out of a required range"""

    BAD_REQUEST = 4
    """A request was unrecognized or malformed"""

    UNSUPPORTED = 5
    """An unrecognized or unsupported request was received"""

    UNEXPECTED = 6
    """A request was not expected at this time"""

    RESOURCE_EXHAUSTED = 7
    """Insufficient resources to process the given request"""

    BUSY = 8
    """Device is busy and cannot handle this request at this time"""

    TIMEOUT = 9
    """A timeout occurred"""

    CONTINUE = 10
    """Context-specific signal to proceed"""

    ABORTED = 11
    """Failure, may be due to a concurrency error."""

    INVALID_ARGUMENT = 12
    """An invalid/unsupported argument was provided"""

    NOT_FOUND = 13
    """Some requested entity was not found"""

    ALREADY_EXISTS = 14
    """The sender attempted to create something that already exists"""

    PERMISSION_DENIED = 15
    """The sender does not have sufficient permissions to execute the requested operations."""

    DATA_LOSS = 16
    """Unrecoverable data loss or corruption has occurred."""

    MESSAGE_TOO_LARGE = 17
    """Message size is larger than the recipient can handle."""


class SecureChannelProtocolCode(enum.IntEnum):
    SESSION_ESTABLISHMENT_SUCCESS = 0x0000
    """Indication that the last session establishment message was successfully processed."""

    NO_SHARED_TRUST_ROOTS = 0x0001
    """Failure to find a common set of shared roots."""

    INVALID_PARAMETER = 0x0002
    """Generic failure during session establishment."""

    CLOSE_SESSION = 0x0003
    """Indication that the sender will close the current session."""

    BUSY = 0x0004
    """Indication that the sender cannot currently fulfill the request."""


class StatusReport:
    def __init__(self):
        self.clear()

    def clear(self):
        self.general_code: GeneralCode = 0
        self.protocol_id = 0
        self.protocol_code = 0
        self.protocol_data = None

    def __len__(self):
        return 8 + len(self.protocol_data) if self.protocol_data else 0

    def encode_into(self, buffer, offset=0) -> int:
        struct.pack_into(
            "<HIH",
            buffer,
            offset,
            self.general_code,
            self.protocol_id,
            self.protocol_code,
        )
        offset += 8
        if self.protocol_data:
            buffer[offset : offset + len(self.protocol_data)] = self.protocol_data
            offset += len(self.protocol_data)
        return offset

    def decode(self, buffer):
        self.general_code, self.protocol_id, self.protocol_code = struct.unpack_from(
            "<HIH", buffer
        )
        self.general_code = GeneralCode(self.general_code)
        self.protocol_data = buffer[8:]

    def __str__(self):
        return f"StatusReport: General Code: {self.general_code!r}, Protocol ID: {self.protocol_id}, Protocol Code: {self.protocol_code}, Protocol Data: {self.protocol_data.hex() if self.protocol_data else None}"


class SessionManager:
    def __init__(self, socket):
        persist_path = pathlib.Path("counters.json")
        if persist_path.exists():
            self.nonvolatile = json.loads(persist_path.read_text())
        else:
            self.nonvolatile = {}
            self.nonvolatile["check_in_counter"] = None
            self.nonvolatile["group_encrypted_data_message_counter"] = None
            self.nonvolatile["group_encrypted_control_message_counter"] = None
        self.unencrypted_message_counter = MessageCounter()
        self.group_encrypted_data_message_counter = MessageCounter(
            self.nonvolatile["group_encrypted_data_message_counter"]
        )
        self.group_encrypted_control_message_counter = MessageCounter(
            self.nonvolatile["group_encrypted_control_message_counter"]
        )
        self.check_in_counter = MessageCounter(self.nonvolatile["check_in_counter"])
        self.unsecured_session_context = {}
        self.secure_session_contexts = ["reserved"]
        self.socket = socket

    def _increment(self, value):
        return (value + 1) % 0xFFFFFFFF

    def get_session(self, message):
        if message.secure_session:
            if message.security_flags & SecurityFlags.GROUP:
                if message.source_node_id is None:
                    return None
                # TODO: Get MRS for source node id and message type
            else:
                session_context = self.secure_session_contexts[message.session_id]
        else:
            if message.source_node_id not in self.unsecured_session_context:
                self.unsecured_session_context[message.source_node_id] = (
                    UnsecuredSessionContext(
                        self.socket,
                        self.unencrypted_message_counter,
                        initiator=False,
                        ephemeral_initiator_node_id=message.source_node_id,
                        node_ipaddress=message.source_ipaddress,
                    )
                )
            session_context = self.unsecured_session_context[message.source_node_id]
        return session_context

    def mark_duplicate(self, message):
        """Implements 4.6.7"""
        session_context = self.get_session(message)

        if session_context.message_reception_state is None:
            session_context.message_reception_state = MessageReceptionState(
                message.message_counter,
                rollover=False,
                encrypted=message.secure_session,
            )
            message.duplicate = False
            return

        message.duplicate = session_context.message_reception_state.process_counter(
            message.message_counter
        )

    def next_message_counter(self, message):
        """Implements 4.6.6"""
        if not message.secure_session:
            value = self.unencrypted_message_counter
            self.unencrypted_message_counter = self._increment(
                self.unencrypted_message_counter
            )
            return value
        elif message.security_flags & SecurityFlags.GROUP:
            if message.security_flags & SecurityFlags.C:
                value = self.group_encrypted_control_message_counter
                self.group_encrypted_control_message_counter = self._increment(
                    self.group_encrypted_control_message_counter
                )
                return value
            else:
                value = self.group_encrypted_data_message_counter
                self.group_encrypted_data_message_counter = self._increment(
                    self.group_encrypted_data_message_counter
                )
                return value
        session = self.secure_session_contexts[message.session_id]
        value = session.local_message_counter
        next_value = self._increment(value)
        session.local_message_counter = next_value
        if next_value == 0:
            # TODO expire the encryption key
            raise NotImplementedError("Expire the encryption key 4.6.6")
        return next_value

    def new_context(self):
        if None not in self.secure_session_contexts:
            self.secure_session_contexts.append(None)
        session_id = self.secure_session_contexts.index(None)

        self.secure_session_contexts[session_id] = SecureSessionContext(session_id)
        return self.secure_session_contexts[session_id]

    def process_exchange(self, message):
        session = self.get_session(message)
        if session is None:
            return None
        # Step 1 of 4.12.5.2
        if (
            message.exchange_flags & (ExchangeFlags.R | ExchangeFlags.A)
            and not message.security_flags & SecurityFlags.C
            and message.security_flags & SecurityFlags.GROUP
        ):
            # Drop illegal combination of flags.
            return None
        if message.exchange_id not in session.exchanges:
            # Section 4.10.5.2
            initiator = message.exchange_flags & ExchangeFlags.I
            if initiator and not message.duplicate:
                session.exchanges[message.exchange_id] = Exchange(
                    session, not initiator, message.exchange_id, [message.protocol_id]
                )
                # Drop because the message isn't from an initiator.
            elif message.exchange_flags & ExchangeFlags.R:
                # Send a bare acknowledgement back.
                raise NotImplementedError("Send a bare acknowledgement back")
                return None
            else:
                # Just drop it.
                return None

        exchange = session.exchanges[message.exchange_id]
        if exchange.receive(message):
            # If we want to drop the message, then return None.
            return None

        return exchange


M = PointJacobi.from_bytes(
    NIST256p.curve,
    b"\x02\x88\x6e\x2f\x97\xac\xe4\x6e\x55\xba\x9d\xd7\x24\x25\x79\xf2\x99\x3b\x64\xe1\x6e\xf3\xdc\xab\x95\xaf\xd4\x97\x33\x3d\x8f\xa1\x2f",
)
N = PointJacobi.from_bytes(
    NIST256p.curve,
    b"\x03\xd8\xbb\xd6\xc6\x39\xc6\x29\x37\xb0\x4d\x99\x7f\x38\xc3\x77\x07\x19\xc6\x29\xd7\x01\x4d\x49\xa2\x4b\x4f\x98\xba\xa1\x29\x2b\x49",
)
CRYPTO_W_SIZE_BYTES = CRYPTO_GROUP_SIZE_BYTES + 8


# in the spake2p math P is NIST256p.generator
# in the spake2p math p is NIST256p.order
def _pbkdf2(passcode, salt, iterations):
    ws = hashlib.pbkdf2_hmac(
        "sha256", struct.pack("<I", passcode), salt, iterations, CRYPTO_W_SIZE_BYTES * 2
    )
    w0 = int.from_bytes(ws[:CRYPTO_W_SIZE_BYTES], byteorder="big") % NIST256p.order
    w1 = int.from_bytes(ws[CRYPTO_W_SIZE_BYTES:], byteorder="big") % NIST256p.order
    return w0, w1


def initiator_values(passcode, salt, iterations) -> tuple[bytes, bytes]:
    w0, w1 = _pbkdf2(passcode, salt, iterations)
    return w0.to_bytes(NIST256p.baselen, byteorder="big"), w1.to_bytes(
        NIST256p.baselen, byteorder="big"
    )


def verifier_values(passcode: int, salt: bytes, iterations: int) -> tuple[bytes, bytes]:
    w0, w1 = _pbkdf2(passcode, salt, iterations)
    L = NIST256p.generator * w1

    return w0.to_bytes(NIST256p.baselen, byteorder="big"), L.to_bytes("uncompressed")


# w0 and w1 are big-endian encoded
def Crypto_pA(w0, w1) -> bytes:
    return b""


def Crypto_pB(random_source, w0: int, L: Point) -> tuple[int, AbstractPoint]:
    y = random_source.randbelow(NIST256p.order)
    Y = y * NIST256p.generator + w0 * N
    return y, Y


def Crypto_Transcript(context, pA, pB, Z, V, w0) -> bytes:
    elements = [
        context,
        b"",
        b"",
        M.to_bytes("uncompressed"),
        N.to_bytes("uncompressed"),
        pA,
        pB,
        Z,
        V,
        w0,
    ]
    total_length = 0
    for e in elements:
        total_length += len(e) + 8
    tt = bytearray(total_length)
    offset = 0
    for e in elements:
        struct.pack_into("<Q", tt, offset, len(e))
        offset += 8

        tt[offset : offset + len(e)] = e
        offset += len(e)
    return tt


def Crypto_Hash(message) -> bytes:
    return hashlib.sha256(message).digest()


def Crypto_HMAC(key, message) -> bytes:
    m = hmac.new(key, digestmod=hashlib.sha256)
    m.update(message)
    return m.digest()


def HKDF_Extract(salt, input_key) -> bytes:
    return Crypto_HMAC(salt, input_key)


def HKDF_Expand(prk, info, length) -> bytes:
    if length > 255:
        raise ValueError("length must be less than 256")
    last_hash = b""
    bytes_generated = []
    num_bytes_generated = 0
    i = 1
    while num_bytes_generated < length:
        num_bytes_generated += CRYPTO_HASH_LEN_BYTES
        # Do the hmac directly so we don't need to allocate a buffer for last_hash + info + i.
        m = hmac.new(prk, digestmod=hashlib.sha256)
        m.update(last_hash)
        m.update(info)
        m.update(struct.pack("b", i))
        last_hash = m.digest()
        bytes_generated.append(last_hash)
        i += 1
    return b"".join(bytes_generated)


def Crypto_KDF(input_key, salt, info, length):
    if salt is None:
        salt = b"\x00" * CRYPTO_HASH_LEN_BYTES
    return HKDF_Expand(HKDF_Extract(salt, input_key), info, length / 8)


def KDF(salt, key, info):
    # Section 3.10 defines the mapping from KDF to Crypto_KDF but it is wrong!
    # The arg order is correct above.
    return Crypto_KDF(key, salt, info, CRYPTO_HASH_LEN_BITS)


def Crypto_P2(tt, pA, pB) -> tuple[bytes, bytes, bytes]:
    KaKe = Crypto_Hash(tt)
    Ka = KaKe[: CRYPTO_HASH_LEN_BYTES // 2]
    Ke = KaKe[CRYPTO_HASH_LEN_BYTES // 2 :]
    # https://github.com/project-chip/connectedhomeip/blob/c88d5cf83cd3e3323ac196630acc34f196a2f405/src/crypto/CHIPCryptoPAL.cpp#L458-L468
    KcAKcB = KDF(None, Ka, b"ConfirmationKeys")
    KcA = KcAKcB[: CRYPTO_HASH_LEN_BYTES // 2]
    KcB = KcAKcB[CRYPTO_HASH_LEN_BYTES // 2 :]
    cA = Crypto_HMAC(KcA, pB)
    cB = Crypto_HMAC(KcB, pA)
    return (cA, cB, Ke)


class Attribute:
    def __init__(self, _id, default=None):
        self.id = _id
        self.default = default

    def __get__(self, instance, cls):
        v = instance._attribute_values.get(self.id, None)
        if v is None:
            return self.default
        return v

    def __set__(self, instance, value):
        old_value = instance._attribute_values[self.id]
        if old_value == value:
            return
        instance._attribute_values[self.id] = value
        instance.data_version += 1

    def encode(self, value):
        raise NotImplementedError()


class FeatureMap(Attribute):
    def __init__(self):
        super().__init__(0xFFFC)


class NumberAttribute(Attribute):
    pass


class ListAttribute(Attribute):
    pass


class BoolAttribute(Attribute):
    pass


class StructAttribute(Attribute):
    def __init__(self, _id, struct_type):
        self.struct_type = struct_type
        super().__init__(_id)


class EnumAttribute(Attribute):
    def __init__(self, _id, enum_type):
        self.enum_type = enum_type
        super().__init__(_id)


class OctetStringAttribute(Attribute):
    def __init__(self, _id, min_length, max_length):
        self.min_length = min_length
        self.max_length = max_length
        super().__init__(_id)


class UTF8StringAttribute(Attribute):
    def __init__(self, _id, min_length=0, max_length=1200, default=None):
        self.min_length = min_length
        self.max_length = max_length
        super().__init__(_id, default=default)


class BitmapAttribute(Attribute):
    pass


class Cluster:
    feature_map = FeatureMap()

    def __init__(self):
        self._attribute_values = {}
        # Use random since this isn't for security or replayability.
        self.data_version = random.randint(0, 0xFFFFFFFF)

    @classmethod
    def _attributes(cls) -> Iterable[tuple[str, Attribute]]:
        for field_name, descriptor in vars(cls).items():
            if not field_name.startswith("_") and isinstance(descriptor, Attribute):
                yield field_name, descriptor
        for field_name, descriptor in vars(Cluster).items():
            if not field_name.startswith("_") and isinstance(descriptor, Attribute):
                yield field_name, descriptor

    def get_attribute_data(self, path) -> AttributeDataIB:
        print("get_attribute_data", path.Attribute)
        data = AttributeDataIB()
        data.Path = path
        found = False
        for field_name, descriptor in self._attributes():
            if descriptor.id != path.Attribute:
                continue
            print("read", field_name)
            data.Data = descriptor.encode(getattr(self, field_name))
            found = True
            break
        if not found:
            print("not found", path.Attribute)
        return data


class ProductFinish(enum.IntEnum):
    OTHER = 0
    MATTE = 1
    SATIN = 2
    POLISHED = 3
    RUGGED = 4
    FABRIC = 5


class Color(enum.IntEnum):
    BLACK = 0
    NAVY = 1
    GREEN = 2
    TEAL = 3
    MAROON = 4
    PURPLE = 5
    OLIVE = 6
    GRAY = 7
    BLUE = 8
    LIME = 9
    AQUA = 10
    RED = 11
    FUCHSIA = 12
    YELLOW = 13
    WHITE = 14
    NICKEL = 15
    CHROME = 16
    BRASS = 17
    COPPER = 18
    SILVER = 19
    GOLD = 20


class BasicInformationCluster(Cluster):
    CLUSTER_ID = 0x0028

    class CapabilityMinima(tlv.TLVStructure):
        CaseSessionsPerFabric = tlv.IntMember(
            0, signed=False, octets=2, minimum=3, default=3
        )
        SubscriptionsPerFabric = tlv.IntMember(
            1, signed=False, octets=2, minimum=3, default=3
        )

    class ProductAppearance(tlv.TLVStructure):
        Finish = tlv.EnumMember(0, ProductFinish)
        PrimaryColor = tlv.EnumMember(1, Color)

    data_model_revision = NumberAttribute(0x00)
    vendor_name = UTF8StringAttribute(0x01, max_length=32)
    vendor_id = NumberAttribute(0x02)
    product_name = UTF8StringAttribute(0x03, max_length=32)
    product_id = NumberAttribute(0x04)
    node_label = UTF8StringAttribute(0x05, max_length=32, default="")
    location = UTF8StringAttribute(0x06, max_length=2, default="XX")
    hardware_version = NumberAttribute(0x07)
    hardware_version_string = UTF8StringAttribute(0x08, min_length=1, max_length=64)
    software_version = NumberAttribute(0x09)
    software_version_string = UTF8StringAttribute(0x0A, min_length=1, max_length=64)
    manufacturing_date = UTF8StringAttribute(0x0B, min_length=8, max_length=16)
    part_number = UTF8StringAttribute(0x0C, max_length=32)
    product_url = UTF8StringAttribute(0x0D, max_length=256)
    product_label = UTF8StringAttribute(0x0E, max_length=64)
    serial_number = UTF8StringAttribute(0x0F, max_length=32)
    local_config_disabled = BoolAttribute(0x10, default=False)
    reachable = BoolAttribute(0x11, default=True)
    unique_id = UTF8StringAttribute(0x12, max_length=32)
    capability_minima = StructAttribute(0x13, CapabilityMinima)
    product_appearance = StructAttribute(0x14, ProductAppearance)
    specification_version = NumberAttribute(0x15, default=0)
    max_paths_per_invoke = NumberAttribute(0x16, default=1)


class GeneralCommissioningCluster(Cluster):
    CLUSTER_ID = 0x0030

    class BasicCommissioningInfo(tlv.TLVStructure):
        FailSafeExpiryLengthSeconds = tlv.IntMember(0, signed=False, octets=2)
        MaxCumulativeFailsafeSeconds = tlv.IntMember(1, signed=False, octets=2)

    class RegulatoryLocationType(enum.IntEnum):
        INDOOR = 0
        OUTDOOR = 1
        INDOOR_OUTDOOR = 2

    breadcrumb = NumberAttribute(0)
    basic_commissioning_info = StructAttribute(1, BasicCommissioningInfo)
    regulatory_config = EnumAttribute(2, RegulatoryLocationType)
    location_capability = EnumAttribute(3, RegulatoryLocationType)
    support_concurrent_connection = BoolAttribute(4)


class NetworkComissioningCluster(Cluster):
    CLUSTER_ID = 0x0031

    class FeatureBitmap(enum.IntFlag):
        WIFI_NETWORK_INTERFACE = 0b001
        THREAD_NETWORK_INTERFACE = 0b010
        ETHERNET_NETWORK_INTERFACE = 0b100

    class NetworkCommissioningStatus(enum.IntEnum):
        SUCCESS = 0
        """Ok, no error"""

        OUT_OF_RANGE = 1
        """Value Outside Range"""

        BOUNDS_EXCEEDED = 2
        """A collection would exceed its size limit"""

        NETWORK_ID_NOT_FOUND = 3
        """The NetworkID is not among the collection of added networks"""

        DUPLICATE_NETWORK_ID = 4
        """The NetworkID is already among the collection of added networks"""

        NETWORK_NOT_FOUND = 5
        """Cannot find AP: SSID Not found"""

        REGULATORY_ERROR = 6
        """Cannot find AP: Mismatch on band/channels/regulatory domain / 2.4GHz vs 5GHz"""

        AUTH_FAILURE = 7
        """Cannot associate due to authentication failure"""

        UNSUPPORTED_SECURITY = 8
        """Cannot associate due to unsupported security mode"""

        OTHER_CONNECTION_FAILURE = 9
        """Other association failure"""

        IPV6_FAILED = 10
        """Failure to generate an IPv6 address"""

        IP_BIND_FAILED = 11
        """Failure to bind Wi-Fi <-> IP interfaces"""

        UNKNOWN_ERROR = 12
        """Unknown error"""

    max_networks = NumberAttribute(0)
    networks = ListAttribute(1)
    scan_max_time_seconds = NumberAttribute(2)
    connect_max_time_seconds = NumberAttribute(3)
    interface_enabled = BoolAttribute(4)
    last_network_status = EnumAttribute(5, NetworkCommissioningStatus)
    last_network_id = OctetStringAttribute(6, min_length=1, max_length=32)
    last_connect_error_value = NumberAttribute(7)
    supported_wifi_bands = ListAttribute(8)
    supported_thread_features = BitmapAttribute(9)
    thread_version = NumberAttribute(10)


class CircuitMatter:
    def __init__(self, socketpool, mdns_server, random_source, state_filename):
        self.socketpool = socketpool
        self.mdns_server = mdns_server
        self.random = random_source

        with open(state_filename, "r") as state_file:
            self.nonvolatile = json.load(state_file)

        for key in ["descriminator", "salt", "iteration-count", "verifier"]:
            if key not in self.nonvolatile:
                raise RuntimeError(f"Missing key {key} in state file")

        commission = "fabrics" not in self.nonvolatile

        self.packet_buffer = memoryview(bytearray(1280))

        # Define the UDP IP address and port
        UDP_IP = "::"  # Listen on all available network interfaces
        self.UDP_PORT = 5540

        # Create the UDP socket
        self.socket = self.socketpool.socket(
            self.socketpool.AF_INET6, self.socketpool.SOCK_DGRAM
        )

        # Bind the socket to the IP and port
        self.socket.bind((UDP_IP, self.UDP_PORT))
        self.socket.setblocking(False)

        self.manager = SessionManager(self.socket)

        print(f"Listening on UDP port {self.UDP_PORT}")

        if commission:
            self.start_commissioning()

        self._endpoints = {}
        self.add_cluster(0, BasicInformationCluster())
        self.add_cluster(0, NetworkComissioningCluster())
        self.add_cluster(0, GeneralCommissioningCluster())

    def start_commissioning(self):
        descriminator = self.nonvolatile["descriminator"]
        txt_records = {
            "PI": "",
            "PH": "33",
            "CM": "1",
            "D": str(descriminator),
            "CRI": "3000",
            "CRA": "4000",
            "T": "1",
            "VP": "65521+32769",
        }
        instance_name = self.random.urandom(8).hex().upper()
        self.mdns_server.advertise_service(
            "_matterc",
            "_udp",
            self.UDP_PORT,
            txt_records=txt_records,
            instance_name=instance_name,
            subtypes=[
                f"_L{descriminator}._sub._matterc._udp",
                "_CM._sub._matterc._udp",
            ],
        )

    def add_cluster(self, endpoint, cluster):
        if endpoint not in self._endpoints:
            self._endpoints[endpoint] = {}
        self._endpoints[endpoint][cluster.CLUSTER_ID] = cluster

    def process_packets(self):
        while True:
            try:
                nbytes, addr = self.socket.recvfrom_into(
                    self.packet_buffer, len(self.packet_buffer)
                )
            except BlockingIOError:
                break
            if nbytes == 0:
                break

            self.process_packet(addr, self.packet_buffer[:nbytes])

    def get_report(self, cluster, path):
        report = AttributeReportIB()
        astatus = AttributeStatusIB()
        astatus.Path = path
        status = StatusIB()
        astatus.Status = status
        report.AttributeStatus = astatus
        report.AttributeData = cluster.get_attribute_data(path)
        return report

    def process_packet(self, address, data):
        # Print the received data and the address of the sender
        # This is section 4.7.2
        message = Message()
        message.decode(data)
        message.source_ipaddress = address
        if message.secure_session:
            # Decrypt the payload
            secure_session_context = self.manager.secure_session_contexts[
                message.session_id
            ]
            ok = secure_session_context.decrypt_and_verify(message)
            if not ok:
                raise RuntimeError("Failed to decrypt message")
        message.parse_protocol_header()
        self.manager.mark_duplicate(message)

        exchange = self.manager.process_exchange(message)
        if exchange is None:
            print(f"Dropping message {message.message_counter}")
            return

        protocol_id = message.protocol_id
        protocol_opcode = message.protocol_opcode

        if protocol_id == ProtocolId.SECURE_CHANNEL:
            if protocol_opcode == SecureProtocolOpcode.MSG_COUNTER_SYNC_REQ:
                print("Received Message Counter Synchronization Request")
            elif protocol_opcode == SecureProtocolOpcode.MSG_COUNTER_SYNC_RSP:
                print("Received Message Counter Synchronization Response")
            elif protocol_opcode == SecureProtocolOpcode.PBKDF_PARAM_REQUEST:
                print("Received PBKDF Parameter Request")
                # This is Section 4.14.1.2
                request = PBKDFParamRequest(message.application_payload[1:-1])
                exchange.commissioning_hash = hashlib.sha256(
                    b"CHIP PAKE V1 Commissioning"
                )
                exchange.commissioning_hash.update(message.application_payload)
                if request.passcodeId == 0:
                    pass
                    # Send back failure
                    # response = StatusReport()
                    # response.GeneralCode
                # print(request)
                response = PBKDFParamResponse()
                response.initiatorRandom = request.initiatorRandom

                # Generate a random number
                response.responderRandom = self.random.urandom(32)
                session_context = self.manager.new_context()
                response.responderSessionId = session_context.local_session_id
                exchange.secure_session_context = session_context
                session_context.peer_session_id = request.initiatorSessionId
                if not request.hasPBKDFParameters:
                    params = Crypto_PBKDFParameterSet()
                    params.iterations = self.nonvolatile["iteration-count"]
                    params.salt = binascii.a2b_base64(self.nonvolatile["salt"])
                    response.pbkdf_parameters = params

                encoded = b"\x15" + response.encode() + b"\x18"
                exchange.commissioning_hash.update(encoded)
                exchange.send(
                    ProtocolId.SECURE_CHANNEL,
                    SecureProtocolOpcode.PBKDF_PARAM_RESPONSE,
                    response,
                )

            elif protocol_opcode == SecureProtocolOpcode.PBKDF_PARAM_RESPONSE:
                print("Received PBKDF Parameter Response")
            elif protocol_opcode == SecureProtocolOpcode.PASE_PAKE1:
                print("Received PASE PAKE1")
                pake1 = PAKE1(message.application_payload[1:-1])
                pake2 = PAKE2()
                verifier = binascii.a2b_base64(self.nonvolatile["verifier"])
                w0 = memoryview(verifier)[:CRYPTO_GROUP_SIZE_BYTES]
                L = memoryview(verifier)[CRYPTO_GROUP_SIZE_BYTES:]
                L = Point.from_bytes(NIST256p.curve, L)
                w0 = int.from_bytes(w0, byteorder="big")
                y, Y = Crypto_pB(self.random, w0, L)
                # pB is Y encoded uncompressed
                # pA is X encoded uncompressed
                pake2.pB = Y.to_bytes("uncompressed")
                h = NIST256p.curve.cofactor()
                # Use negation because the class doesn't support subtraction. 🤦
                X = Point.from_bytes(NIST256p.curve, pake1.pA)
                Z = h * y * (X + (-(w0 * M)))
                # Z is wrong. V is right
                V = h * y * L
                context = exchange.commissioning_hash.digest()
                del exchange.commissioning_hash
                tt = Crypto_Transcript(
                    context,
                    pake1.pA,
                    pake2.pB,
                    Z.to_bytes("uncompressed"),
                    V.to_bytes("uncompressed"),
                    w0.to_bytes(NIST256p.baselen, byteorder="big"),
                )
                cA, cB, Ke = Crypto_P2(tt, pake1.pA, pake2.pB)
                pake2.cB = cB
                exchange.cA = cA
                exchange.Ke = Ke
                exchange.send(
                    ProtocolId.SECURE_CHANNEL, SecureProtocolOpcode.PASE_PAKE2, pake2
                )
            elif protocol_opcode == SecureProtocolOpcode.PASE_PAKE2:
                print("Received PASE PAKE2")
                raise NotImplementedError("Implement SPAKE2+ prover")
            elif protocol_opcode == SecureProtocolOpcode.PASE_PAKE3:
                print("Received PASE PAKE3")
                pake3 = PAKE3(message.application_payload[1:-1])
                if pake3.cA != exchange.cA:
                    del exchange.cA
                    del exchange.Ke
                    print("cA mismatch")
                    error_status = StatusReport()
                    error_status.general_code = GeneralCode.FAILURE
                    error_status.protocol_id = ProtocolId.SECURE_CHANNEL
                    error_status.protocol_code = (
                        SecureChannelProtocolCode.INVALID_PARAMETER
                    )
                    exchange.send(
                        ProtocolId.SECURE_CHANNEL,
                        SecureProtocolOpcode.STATUS_REPORT,
                        error_status,
                    )
                else:
                    exchange.session.session_timestamp = time.monotonic()
                    status_ok = StatusReport()
                    status_ok.general_code = GeneralCode.SUCCESS
                    status_ok.protocol_id = ProtocolId.SECURE_CHANNEL
                    status_ok.protocol_code = (
                        SecureChannelProtocolCode.SESSION_ESTABLISHMENT_SUCCESS
                    )
                    exchange.send(
                        ProtocolId.SECURE_CHANNEL,
                        SecureProtocolOpcode.STATUS_REPORT,
                        status_ok,
                    )

                    # Fully initialize the secure session context we'll use going
                    # forwards.
                    secure_session_context = exchange.secure_session_context

                    # Compute session keys
                    keys = Crypto_KDF(
                        exchange.Ke,
                        b"",
                        b"SessionKeys",
                        3 * CRYPTO_SYMMETRIC_KEY_LENGTH_BITS,
                    )
                    secure_session_context.i2r_key = keys[
                        :CRYPTO_SYMMETRIC_KEY_LENGTH_BYTES
                    ]
                    secure_session_context.i2r = AESCCM(
                        secure_session_context.i2r_key,
                        tag_length=CRYPTO_AEAD_MIC_LENGTH_BYTES,
                    )
                    secure_session_context.r2i_key = keys[
                        CRYPTO_SYMMETRIC_KEY_LENGTH_BYTES : 2
                        * CRYPTO_SYMMETRIC_KEY_LENGTH_BYTES
                    ]
                    secure_session_context.r2i = AESCCM(
                        secure_session_context.r2i_key,
                        tag_length=CRYPTO_AEAD_MIC_LENGTH_BYTES,
                    )
                    secure_session_context.attestation_challenge = keys[
                        2 * CRYPTO_SYMMETRIC_KEY_LENGTH_BYTES :
                    ]
                    print("PASE succeeded")
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
                report = StatusReport()
                report.decode(message.application_payload)
                print(report)
            elif protocol_opcode == SecureProtocolOpcode.ICD_CHECK_IN:
                print("Received ICD Check-in")
        elif message.protocol_id == ProtocolId.INTERACTION_MODEL:
            print(message)
            print("application payload", message.application_payload.hex(" "))
            if protocol_opcode == InteractionModelOpcode.READ_REQUEST:
                print("Received Read Request")
                read_request = ReadRequestMessage(message.application_payload[1:-1])
                attribute_reports = []
                for attribute in read_request.AttributeRequests:
                    for path in attribute:
                        attribute = (
                            "*" if path.Attribute is None else f"0x{path.Attribute:04x}"
                        )
                        print(
                            f"Endpoint: {path.Endpoint}, Cluster: 0x{path.Cluster:02x}, Attribute: {attribute}"
                        )
                        if path.Endpoint is None:
                            # Wildcard so we get it from every endpoint.
                            for endpoint in self._endpoints:
                                if path.Cluster in self._endpoints[endpoint]:
                                    cluster = self._endpoints[endpoint][path.Cluster]
                                    path.Endpoint = endpoint
                                    attribute_reports.append(
                                        self.get_report(cluster, path)
                                    )
                                else:
                                    print(f"Cluster 0x{path.Cluster:02x} not found")
                        else:
                            if path.Cluster in self._endpoints[path.Endpoint]:
                                cluster = self._endpoints[path.Endpoint][path.Cluster]
                                attribute_reports.append(self.get_report(cluster, path))
                            else:
                                print(f"Cluster 0x{path.Cluster:02x} not found")
                response = ReportDataMessage()
                response.AttributeReports = attribute_reports
                print(read_request)
            if protocol_opcode == InteractionModelOpcode.INVOKE_REQUEST:
                print("Received Invoke Request")
            elif protocol_opcode == InteractionModelOpcode.INVOKE_RESPONSE:
                print("Received Invoke Response")
