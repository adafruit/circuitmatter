"""Pure Python implementation of the Matter IOT protocol."""

import binascii
import enum
import hashlib
import pathlib
import json
import struct
import time

import cryptography
import ecdsa

from typing import Optional

from . import data_model
from . import interaction_model
from . import session
from . import tlv

TEST_CERTS = pathlib.Path(
    "/home/tannewt/repos/esp-matter/connectedhomeip/connectedhomeip/credentials/test/attestation/"
)
TEST_PAI_CERT_DER = TEST_CERTS / "Chip-Test-PAI-FFF1-8000-Cert.der"
TEST_PAI_CERT_PEM = TEST_CERTS / "Chip-Test-PAI-FFF1-8000-Cert.pem"
TEST_DAC_CERT_DER = TEST_CERTS / "Chip-Test-DAC-FFF1-8000-0000-Cert.der"
TEST_DAC_CERT_PEM = TEST_CERTS / "Chip-Test-DAC-FFF1-8000-0000-Cert.pem"
TEST_DAC_KEY_DER = TEST_CERTS / "Chip-Test-DAC-FFF1-8000-0000-Key.der"
TEST_DAC_KEY_PEM = TEST_CERTS / "Chip-Test-DAC-FFF1-8000-0000-Key.pem"

TEST_CD_CERT_DER = pathlib.Path("certification_declaration.der")

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
    def __init__(self, starting_value=None, random_source=None):
        if starting_value is None:
            starting_value = random_source.urandom(4)
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
    def __init__(self, random_source, socket, local_session_id):
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
        self.local_message_counter = MessageCounter(random_source=random_source)
        """Secure Session Message Counter for outbound messages."""
        self.message_reception_state = None
        """Provides tracking for the Secure Session Message Counter of the remote"""
        self.local_fabric_index = None
        """Records the local Index for the session’s Fabric, which MAY be used to look up Fabric metadata related to the Fabric for which this session context applies."""
        self.peer_node_id = 0
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

        self._nonce = bytearray(session.CRYPTO_AEAD_NONCE_LENGTH_BYTES)
        self.socket = socket
        self.node_ipaddress = None

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

    def send(self, message):
        message.session_id = self.peer_session_id
        cipher = self.r2i
        if self.session_role_initiator:
            cipher = self.i2r

        self.session_timestamp = time.monotonic()

        message.destination_node_id = self.peer_node_id
        if message.message_counter is None:
            message.message_counter = next(self.local_message_counter)

        buf = memoryview(bytearray(1280))
        nbytes = message.encode_into(buf, cipher)
        self.socket.sendto(buf[:nbytes], self.node_ipaddress)


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
            elif isinstance(self.application_payload, StatusReport):
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
    def __init__(self, random_source, socket):
        persist_path = pathlib.Path("counters.json")
        if persist_path.exists():
            self.nonvolatile = json.loads(persist_path.read_text())
        else:
            self.nonvolatile = {}
            self.nonvolatile["check_in_counter"] = None
            self.nonvolatile["group_encrypted_data_message_counter"] = None
            self.nonvolatile["group_encrypted_control_message_counter"] = None
        self.unencrypted_message_counter = MessageCounter(random_source=random_source)
        self.group_encrypted_data_message_counter = MessageCounter(
            self.nonvolatile["group_encrypted_data_message_counter"],
            random_source=random_source,
        )
        self.group_encrypted_control_message_counter = MessageCounter(
            self.nonvolatile["group_encrypted_control_message_counter"],
            random_source=random_source,
        )
        self.check_in_counter = MessageCounter(
            self.nonvolatile["check_in_counter"], random_source=random_source
        )
        self.unsecured_session_context = {}
        self.secure_session_contexts = ["reserved"]
        self.socket = socket
        self.random = random_source

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
                session_context.node_ipaddress = message.source_ipaddress
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

        self.secure_session_contexts[session_id] = SecureSessionContext(
            self.random, self.socket, session_id
        )
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


class GeneralCommissioningCluster(data_model.GeneralCommissioningCluster):
    def __init__(self):
        super().__init__()
        basic_commissioning_info = (
            data_model.GeneralCommissioningCluster.BasicCommissioningInfo()
        )
        basic_commissioning_info.FailSafeExpiryLengthSeconds = 10
        basic_commissioning_info.MaxCumulativeFailsafeSeconds = 900
        self.basic_commissioning_info = basic_commissioning_info

    def arm_fail_safe(
        self, session, args: data_model.GeneralCommissioningCluster.ArmFailSafe
    ) -> data_model.GeneralCommissioningCluster.ArmFailSafeResponse:
        response = data_model.GeneralCommissioningCluster.ArmFailSafeResponse()
        response.ErrorCode = data_model.CommissioningErrorEnum.OK
        return response

    def set_regulatory_config(
        self, session, args: data_model.GeneralCommissioningCluster.SetRegulatoryConfig
    ) -> data_model.GeneralCommissioningCluster.SetRegulatoryConfigResponse:
        response = data_model.GeneralCommissioningCluster.SetRegulatoryConfigResponse()
        response.ErrorCode = data_model.CommissioningErrorEnum.OK
        return response


class AttestationElements(tlv.Structure):
    certification_declaration = tlv.OctetStringMember(0x01, max_length=400)
    attestation_nonce = tlv.OctetStringMember(0x02, max_length=32)
    timestamp = tlv.IntMember(0x03, signed=False, octets=4)
    firmware_information = tlv.OctetStringMember(0x04, max_length=16, optional=True)
    """Used for secure boot. We don't support it."""


class NOCSRElements(tlv.Structure):
    csr = tlv.OctetStringMember(0x01, max_length=1024)
    CSRNonce = tlv.OctetStringMember(0x02, max_length=32)
    # Skip vendor reserved


class NodeOperationalCredentialsCluster(data_model.NodeOperationalCredentialsCluster):
    def __init__(self):
        self.dac_key = ecdsa.keys.SigningKey.from_der(
            TEST_DAC_KEY_DER.read_bytes(), hashfunc=hashlib.sha256
        )

        self.new_key_for_update = False

    def certificate_chain_request(
        self,
        session,
        args: data_model.NodeOperationalCredentialsCluster.CertificateChainRequest,
    ) -> data_model.NodeOperationalCredentialsCluster.CertificateChainResponse:
        response = (
            data_model.NodeOperationalCredentialsCluster.CertificateChainResponse()
        )
        if args.CertificateType == data_model.CertificateChainTypeEnum.PAI:
            print("PAI")
            response.Certificate = TEST_PAI_CERT_DER.read_bytes()
        elif args.CertificateType == data_model.CertificateChainTypeEnum.DAC:
            print("DAC")
            response.Certificate = TEST_DAC_CERT_DER.read_bytes()
        return response

    def attestation_request(
        self,
        session,
        args: data_model.NodeOperationalCredentialsCluster.AttestationRequest,
    ) -> data_model.NodeOperationalCredentialsCluster.AttestationResponse:
        print("attestation")
        elements = AttestationElements()
        elements.certification_declaration = TEST_CD_CERT_DER.read_bytes()
        elements.attestation_nonce = args.AttestationNonce
        elements.timestamp = int(time.time())
        elements = elements.encode()
        print("elements", len(elements), elements[:3].hex(" "))
        print(
            "challeng",
            len(session.attestation_challenge),
            session.attestation_challenge[:3].hex(" "),
        )
        attestation_tbs = elements.tobytes() + session.attestation_challenge
        response = data_model.NodeOperationalCredentialsCluster.AttestationResponse()
        response.AttestationElements = elements
        response.AttestationSignature = self.dac_key.sign_deterministic(
            attestation_tbs,
            hashfunc=hashlib.sha256,
            sigencode=ecdsa.util.sigencode_string,
        )
        return response

    def csr_request(
        self, session, args: data_model.NodeOperationalCredentialsCluster.CsrRequest
    ) -> data_model.NodeOperationalCredentialsCluster.CsrResponse:
        # Section 6.4.6.1
        # CSR stands for Certificate Signing Request. A NOCSR is a Node Operational Certificate Signing Request

        self.new_key_for_update = args.IsForUpdateNOC

        # class CSRRequest(tlv.Structure):
        #     CSRNonce = tlv.OctetStringMember(0, 32)
        #     IsForUpdateNOC = tlv.BoolMember(1, optional=True, default=False)

        # Generate a new key pair.
        new_key_csr = b"TODO"

        # Create a CSR to reply back with. Sign it with the new private key.
        elements = NOCSRElements()
        elements.csr = new_key_csr
        elements.CSRNonce = args.CSRNonce
        elements = elements.encode()
        nocsr_tbs = elements.tobytes() + session.attestation_challenge

        # class CSRResponse(tlv.Structure):
        #     NOCSRElements = tlv.OctetStringMember(0, RESP_MAX)
        #     AttestationSignature = tlv.OctetStringMember(1, 64)
        response = data_model.NodeOperationalCredentialsCluster.CsrResponse()
        response.NOCSRElements = elements
        response.AttestationSignature = self.dac_key.sign_deterministic(
            nocsr_tbs, hashfunc=hashlib.sha256, sigencode=ecdsa.util.sigencode_string
        )
        return response


class CircuitMatter:
    def __init__(
        self,
        socketpool,
        mdns_server,
        random_source,
        state_filename,
        vendor_id=0xFFF1,
        product_id=0x8000,
    ):
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

        self.manager = SessionManager(self.random, self.socket)

        print(f"Listening on UDP port {self.UDP_PORT}")

        if commission:
            self.start_commissioning()

        self._endpoints = {}
        basic_info = data_model.BasicInformationCluster()
        basic_info.vendor_id = vendor_id
        basic_info.product_id = product_id
        self.add_cluster(0, basic_info)
        network_info = data_model.NetworkCommissioningCluster()
        network_info.connect_max_time_seconds = 10
        self.add_cluster(0, network_info)
        general_commissioning = GeneralCommissioningCluster()
        self.add_cluster(0, general_commissioning)
        noc = NodeOperationalCredentialsCluster()
        self.add_cluster(0, noc)

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
        report = interaction_model.AttributeReportIB()
        report.AttributeData = cluster.get_attribute_data(path)
        # Only add status if an error occurs
        # astatus = interaction_model.AttributeStatusIB()
        # astatus.Path = path
        # status = interaction_model.StatusIB()
        # status.Status = 0
        # status.ClusterStatus = 0
        # astatus.Status = status
        # report.AttributeStatus = astatus
        return report

    def invoke(self, session, cluster, path, fields, command_ref):
        print("invoke", path)
        response = interaction_model.InvokeResponseIB()
        cdata = cluster.invoke(session, path, fields)
        if cdata is None:
            cstatus = interaction_model.CommandStatusIB()
            cstatus.CommandPath = path
            status = interaction_model.StatusIB()
            status.Status = interaction_model.StatusCode.UNSUPPORTED_COMMAND
            cstatus.Status = status
            if command_ref is not None:
                cstatus.CommandRef = command_ref
            response.Status = cstatus
            return response

        if command_ref is not None:
            cdata.CommandRef = command_ref
        print("cdata", cdata)
        response.Command = cdata
        return response

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
                from . import pase

                # This is Section 4.14.1.2
                request, _ = pase.PBKDFParamRequest.decode(
                    message.application_payload[0], message.application_payload[1:]
                )
                print("PBKDF", request)
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
                response = pase.PBKDFParamResponse()
                response.initiatorRandom = request.initiatorRandom

                # Generate a random number
                response.responderRandom = self.random.urandom(32)
                session_context = self.manager.new_context()
                response.responderSessionId = session_context.local_session_id
                exchange.secure_session_context = session_context
                session_context.peer_session_id = request.initiatorSessionId
                if not request.hasPBKDFParameters:
                    params = pase.Crypto_PBKDFParameterSet()
                    params.iterations = self.nonvolatile["iteration-count"]
                    params.salt = binascii.a2b_base64(self.nonvolatile["salt"])
                    response.pbkdf_parameters = params

                encoded = response.encode()
                exchange.commissioning_hash.update(encoded)
                exchange.send(
                    ProtocolId.SECURE_CHANNEL,
                    SecureProtocolOpcode.PBKDF_PARAM_RESPONSE,
                    response,
                )

            elif protocol_opcode == SecureProtocolOpcode.PBKDF_PARAM_RESPONSE:
                print("Received PBKDF Parameter Response")
            elif protocol_opcode == SecureProtocolOpcode.PASE_PAKE1:
                from . import pase

                print("Received PASE PAKE1")
                pake1, _ = pase.PAKE1.decode(
                    message.application_payload[0], message.application_payload[1:]
                )
                pake2 = pase.PAKE2()
                verifier = binascii.a2b_base64(self.nonvolatile["verifier"])
                context = exchange.commissioning_hash.digest()
                del exchange.commissioning_hash

                cA, Ke = pase.compute_verification(
                    self.random, pake1, pake2, context, verifier
                )
                exchange.cA = cA
                exchange.Ke = Ke
                exchange.send(
                    ProtocolId.SECURE_CHANNEL, SecureProtocolOpcode.PASE_PAKE2, pake2
                )
            elif protocol_opcode == SecureProtocolOpcode.PASE_PAKE2:
                print("Received PASE PAKE2")
                raise NotImplementedError("Implement SPAKE2+ prover")
            elif protocol_opcode == SecureProtocolOpcode.PASE_PAKE3:
                from . import pase

                print("Received PASE PAKE3")
                pake3, _ = pase.PAKE3.decode(
                    message.application_payload[0], message.application_payload[1:]
                )
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
                    pase.compute_session_keys(exchange.Ke, secure_session_context)
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
            secure_session_context = self.manager.secure_session_contexts[
                message.session_id
            ]
            if protocol_opcode == InteractionModelOpcode.READ_REQUEST:
                print("Received Read Request")
                read_request, _ = interaction_model.ReadRequestMessage.decode(
                    message.application_payload[0], message.application_payload[1:]
                )
                attribute_reports = []
                for path in read_request.AttributeRequests:
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
                                # TODO: The path object probably needs to be cloned. Otherwise we'll
                                # change the endpoint for all uses.
                                path.Endpoint = endpoint
                                print(path.Endpoint)
                                print(path)
                                attribute_reports.append(self.get_report(cluster, path))
                            else:
                                print(f"Cluster 0x{path.Cluster:02x} not found")
                    else:
                        if path.Cluster in self._endpoints[path.Endpoint]:
                            cluster = self._endpoints[path.Endpoint][path.Cluster]
                            attribute_reports.append(self.get_report(cluster, path))
                        else:
                            print(f"Cluster 0x{path.Cluster:02x} not found")
                response = interaction_model.ReportDataMessage()
                response.AttributeReports = attribute_reports
                for a in attribute_reports:
                    print(a)
                exchange.send(
                    ProtocolId.INTERACTION_MODEL,
                    InteractionModelOpcode.REPORT_DATA,
                    response,
                )
            elif protocol_opcode == InteractionModelOpcode.INVOKE_REQUEST:
                print("Received Invoke Request")
                invoke_request, _ = interaction_model.InvokeRequestMessage.decode(
                    message.application_payload[0], message.application_payload[1:]
                )
                for invoke in invoke_request.InvokeRequests:
                    path = invoke.CommandPath
                    invoke_responses = []
                    if path.Endpoint is None:
                        # Wildcard so we get it from every endpoint.
                        for endpoint in self._endpoints:
                            if path.Cluster in self._endpoints[endpoint]:
                                cluster = self._endpoints[endpoint][path.Cluster]
                                path.Endpoint = endpoint
                                invoke_responses.append(
                                    self.invoke(
                                        secure_session_context,
                                        cluster,
                                        path,
                                        invoke.CommandFields,
                                    )
                                )
                            else:
                                print(f"Cluster 0x{path.Cluster:02x} not found")
                    else:
                        if path.Cluster in self._endpoints[path.Endpoint]:
                            cluster = self._endpoints[path.Endpoint][path.Cluster]
                            invoke_responses.append(
                                self.invoke(
                                    secure_session_context,
                                    cluster,
                                    path,
                                    invoke.CommandFields,
                                    invoke.CommandRef,
                                )
                            )
                        else:
                            print(f"Cluster 0x{path.Cluster:02x} not found")
                response = interaction_model.InvokeResponseMessage()
                response.SuppressResponse = False
                response.InvokeResponses = invoke_responses
                exchange.send(
                    ProtocolId.INTERACTION_MODEL,
                    InteractionModelOpcode.INVOKE_RESPONSE,
                    response,
                )
            elif protocol_opcode == InteractionModelOpcode.INVOKE_RESPONSE:
                print("Received Invoke Response")
            else:
                print(message)
                print("application payload", message.application_payload.hex(" "))
        print()
