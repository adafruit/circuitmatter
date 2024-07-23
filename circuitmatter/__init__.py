"""Pure Python implementation of the Matter IOT protocol."""

import binascii
import enum
import pathlib
import json
import os
import struct
import time

from typing import Optional

from . import tlv

__version__ = "0.0.0"

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
        print(message)
        buf = memoryview(bytearray(1280))
        nbytes = message.encode_into(buf)
        print(nbytes, buf[:nbytes].hex(" "))
        self.socket.sendto(buf[:nbytes], self.node_ipaddress)


class SecureSessionContext:
    def __init__(self, local_session_id):
        self.session_type = None
        """Records whether the session was established using CASE or PASE."""
        self.session_role = None
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

    @property
    def peer_active(self):
        return (time.monotonic() - self.active_timestamp) < self.session_active_interval


class Message:
    def __init__(self):
        self.clear()

    def clear(self):
        self.flags: int = 0
        self.session_id: int = 0
        self.security_flags: SecurityFlags = SecurityFlags(0)
        self.message_counter: Optional[int] = None
        self.source_node_id = None
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

        if not self.secure_session:
            self.payload = memoryview(buffer)[offset:]
        else:
            self.payload = None

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
        if value > 0xFFFF_FFFF_FFFF_0000:
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


class StatusReport:
    def __init__(self):
        self.clear()

    def clear(self):
        self.general_code: GeneralCode = 0
        self.protocol_id = 0
        self.protocol_code = 0
        self.protocol_data = None

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
        print(buffer.hex(" "))
        self.general_code, self.protocol_id, self.protocol_code = struct.unpack_from(
            "<HIH", buffer
        )
        self.general_code = GeneralCode(self.general_code)
        self.protocol_data = buffer[8:]

    def __str__(self):
        return f"StatusReport: General Code: {self.general_code!r}, Protocol ID: {self.protocol_id}, Protocol Code: {self.protocol_code}, Protocol Data: {self.protocol_data.hex()}"


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


class CircuitMatter:
    def __init__(self, socketpool, mdns_server, state_filename, record_to=None):
        self.socketpool = socketpool
        self.mdns_server = mdns_server
        self.record_to = record_to
        if self.record_to:
            self.recorded_packets = []
        else:
            self.recorded_packets = None

        with open(state_filename, "r") as state_file:
            self.nonvolatile = json.load(state_file)

        for key in ["descriminator", "salt", "iteration-count"]:
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
        instance_name = os.urandom(8).hex().upper()
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
            if self.recorded_packets is not None:
                self.recorded_packets.append(
                    (
                        "receive",
                        time.monotonic_ns(),
                        addr,
                        binascii.b2a_base64(
                            self.packet_buffer[:nbytes], newline=False
                        ).decode("utf-8"),
                    )
                )

            self.process_packet(addr, self.packet_buffer[:nbytes])

    def process_packet(self, address, data):
        # Print the received data and the address of the sender
        # This is section 4.7.2
        message = Message()
        message.decode(data)
        message.source_ipaddress = address
        if message.secure_session:
            # Decrypt the payload
            pass
        message.parse_protocol_header()
        self.manager.mark_duplicate(message)

        exchange = self.manager.process_exchange(message)
        if exchange is None:
            print(f"Dropping message {message.message_counter}")
            return

        print(f"Received packet from {address}:")
        print(f"{data.hex(' ')}")
        print(f"Message counter {message.message_counter}")
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
                if request.passcodeId == 0:
                    pass
                    # Send back failure
                    # response = StatusReport()
                    # response.GeneralCode
                print(request)
                response = PBKDFParamResponse()
                response.initiatorRandom = request.initiatorRandom

                # Generate a random number
                response.responderRandom = os.urandom(32)
                session_context = self.manager.new_context()
                response.responderSessionId = session_context.local_session_id
                session_context.peer_session_id = request.initiatorSessionId
                if not request.hasPBKDFParameters:
                    params = Crypto_PBKDFParameterSet()
                    params.iterations = self.nonvolatile["iteration-count"]
                    params.salt = binascii.a2b_base64(self.nonvolatile["salt"])
                    response.pbkdf_parameters = params
                exchange.send(
                    ProtocolId.SECURE_CHANNEL,
                    SecureProtocolOpcode.PBKDF_PARAM_RESPONSE,
                    response,
                )

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
                report = StatusReport()
                report.decode(message.application_payload)
                print(report)
            elif protocol_opcode == SecureProtocolOpcode.ICD_CHECK_IN:
                print("Received ICD Check-in")

    def __del__(self):
        if self.recorded_packets and self.record_to:
            with open(self.record_to, "w") as record_file:
                json.dump(self.recorded_packets, record_file)
