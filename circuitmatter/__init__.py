"""Pure Python implementation of the Matter IOT protocol."""

import binascii
import enum
import pathlib
import json
import os
import struct
import time

from . import tlv

__version__ = "0.0.0"

# Section 4.11.2
MSG_COUNTER_WINDOW_SIZE = 32
MSG_COUNTER_SYNC_REQ_JITTER_MS = 500
MSG_COUNTER_SYNC_TIMEOUT_MS = 400


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
    # This is actually 2 bits but the top bit is reserved and always zero.
    GROUP = 1 << 0


class ExchangeFlags(enum.Flag):
    V = 1 << 4
    SX = 1 << 3
    R = 1 << 2
    A = 1 << 1
    I = 1 << 0  # noqa: E741


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


class Exchange:
    def __init__(self, initiator: bool, exchange_id: int, protocols):
        self.initiator = initiator
        self.exchange_id = exchange_id
        self.protocols = protocols

        self.pending_acknowledgement = None
        self.next_retransmission_time = None
        self.pending_retransmission = None

    def send(self, message):
        pass

    def receive(self, message) -> bool:
        """Process the message and return if the packet should be dropped."""
        if message.protocol_id not in self.protocols:
            # Drop messages that don't match the protocols we're waiting for.
            return True

        # Section 4.10.5.2.1
        if message.exchange_flags & ExchangeFlags.A:
            if message.acknowledged_message_counter is None:
                # Drop messages that are missing an acknowledgement counter.
                return True
            if self.pending_acknowledgement is None:
                # Drop messages that are not waiting for an acknowledgement.
                return True
            if message.acknowledged_message_counter != self.pending_acknowledgement:
                # Drop messages that have the wrong acknowledgement counter.
                return True
            self.pending_acknowledgement = None
            self.pending_retransmission = None
            self.next_retransmission_time = None

        # Section 4.10.5.2.2
        # if message.exchange_flags & ExchangeFlags.R:
        #     if message
        if message.duplicate:
            return True
        return False


class UnsecuredSessionContext:
    def __init__(self, initiator, ephemeral_initiator_node_id):
        self.initiator = initiator
        self.ephemeral_initiator_node_id = ephemeral_initiator_node_id
        self.message_reception_state = None
        self.exchanges = {}


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
    def __init__(self, buffer):
        self.buffer = buffer
        self.flags, self.session_id, self.security_flags, self.message_counter = (
            struct.unpack_from("<BHBI", buffer)
        )
        self.security_flags = SecurityFlags(self.security_flags)
        offset = 8
        self.source_node_id = None
        if self.flags & (1 << 2):
            self.source_node_id = struct.unpack_from("<Q", buffer, 8)[0]
            offset += 8

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

    def reply(self, payload, protocol_id=None, protocol_opcode=None) -> memoryview:
        reply = bytearray(1280)
        offset = 0

        # struct.pack_into(
        #     "<BHBI", reply, offset, flags, session_id, security_flags, message_counter
        # )
        # offset += 8
        return memoryview(reply)[:offset]


class SessionManager:
    def __init__(self):
        persist_path = pathlib.Path("counters.json")
        if persist_path.exists():
            self.nonvolatile = json.loads(persist_path.read_text())
        else:
            self.nonvolatile = {}
            self.nonvolatile["unencrypted_message_counter"] = 0
            self.nonvolatile["group_encrypted_data_message_counter"] = 0
            self.nonvolatile["group_encrypted_control_message_counter"] = 0
        self.unencrypted_message_counter = self.nonvolatile[
            "unencrypted_message_counter"
        ]
        self.group_encrypted_data_message_counter = self.nonvolatile[
            "group_encrypted_data_message_counter"
        ]
        self.group_encrypted_control_message_counter = self.nonvolatile[
            "group_encrypted_control_message_counter"
        ]
        self.check_in_counter = 0
        self.unsecured_session_context = {}
        self.secure_session_contexts = ["reserved"]

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
                        initiator=False,
                        ephemeral_initiator_node_id=message.source_node_id,
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
                    not initiator, message.exchange_id, [message.protocol_id]
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
        self.avahi = None
        self.record_to = record_to
        if self.record_to:
            self.recorded_packets = []
        else:
            self.recorded_packets = None
        self.manager = SessionManager()

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
        self.mdns_server.advertise_service(
            "_matterc",
            "_udp",
            self.UDP_PORT,
            txt_records=txt_records,
            instance_name="FA93546B21F5FB54",
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
        message = Message(data)
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

    def __del__(self):
        if self.avahi:
            self.avahi.kill()
        if self.recorded_packets and self.record_to:
            with open(self.record_to, "w") as record_file:
                json.dump(self.recorded_packets, record_file)
