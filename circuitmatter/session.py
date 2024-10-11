import enum
import json
import time

from . import case
from . import crypto
from . import protocol
from . import tlv
from .exchange import Exchange
from .message import ExchangeFlags, SecurityFlags

import cryptography
from cryptography.hazmat.primitives.ciphers.aead import AESCCM
import ecdsa
import hashlib
import pathlib
import struct


# Section 4.11.2
MSG_COUNTER_WINDOW_SIZE = 32
MSG_COUNTER_SYNC_REQ_JITTER_MS = 500
MSG_COUNTER_SYNC_TIMEOUT_MS = 400


class SessionParameterStruct(tlv.Structure):
    session_idle_interval = tlv.IntMember(1, signed=False, octets=4, optional=True)
    session_active_interval = tlv.IntMember(2, signed=False, octets=4, optional=True)
    session_active_threshold = tlv.IntMember(3, signed=False, octets=2, optional=True)
    data_model_revision = tlv.IntMember(4, signed=False, octets=2)
    interaction_model_revision = tlv.IntMember(5, signed=False, octets=2)
    specification_version = tlv.IntMember(6, signed=False, octets=4)
    max_paths_per_invoke = tlv.IntMember(7, signed=False, octets=2)


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
    PROTOCOL_ID = protocol.ProtocolId.SECURE_CHANNEL
    PROTOCOL_OPCODE = protocol.SecureProtocolOpcode.STATUS_REPORT

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
        if self.protocol_id in protocol.ProtocolId:
            self.protocol_id = protocol.ProtocolId(self.protocol_id)

        if self.protocol_id == protocol.ProtocolId.SECURE_CHANNEL:
            self.protocol_code = SecureChannelProtocolCode(self.protocol_code)

    def __str__(self):
        return f"StatusReport: General Code: {self.general_code!r}, Protocol ID: {self.protocol_id!r}, Protocol Code: {self.protocol_code!r}, Protocol Data: {self.protocol_data.hex() if self.protocol_data else None}"


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

        self.local_node_id = 0

    def send(self, message):
        message.flags |= 1  # DSIZ = 1 for destination node
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

        self.local_node_id = 0

        self._nonce = bytearray(crypto.AEAD_NONCE_LENGTH_BYTES)
        self.socket = socket
        self.node_ipaddress = None

    def __str__(self):
        return f"Secure Session #{self.local_session_id} with {self.peer_node_id:x}"

    @property
    def peer_active(self):
        return (time.monotonic() - self.active_timestamp) < self.session_active_interval

    def decrypt_and_verify(self, message):
        cipher = self.i2r
        if self.session_role_initiator:
            cipher = self.r2i
        try:
            # TODO: Support group messages
            struct.pack_into(
                "<BIQ",
                self._nonce,
                0,
                message.security_flags,
                message.message_counter,
                self.peer_node_id,
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


class SessionManager:
    def __init__(self, random_source, socket, node_credentials):
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
        self.node_credentials = node_credentials

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

    def reply_to_sigma1(self, exchange, sigma1):
        if sigma1.resumptionID is None != sigma1.initiatorResumeMIC is None:
            print("Invalid resumption ID")
            error_status = StatusReport()
            error_status.general_code = GeneralCode.FAILURE
            error_status.protocol_id = protocol.ProtocolId.SECURE_CHANNEL
            error_status.protocol_code = SecureChannelProtocolCode.INVALID_PARAMETER
            return error_status
        if sigma1.resumptionID is not None:
            # Resume
            print("Ignoring resumptionID")

        matching_noc = None
        identity_protection_key = b""
        for i, fabric in enumerate(self.node_credentials.fabrics):
            root_public_key = self.node_credentials.root_certs[i].ec_pub_key
            key_set = self.node_credentials.group_key_manager.key_sets[i]
            compressed_fabric_id = self.node_credentials.compressed_fabric_ids[i]
            ipk_epoch_key = key_set.EpochKey0
            identity_protection_key = crypto.KDF(
                ipk_epoch_key,
                compressed_fabric_id,
                b"GroupKey v1.0",
                crypto.SYMMETRIC_KEY_LENGTH_BITS,
            )
            fabric_id = struct.pack("<Q", fabric.FabricID)
            node_id = struct.pack("<Q", fabric.NodeID)
            candidate_destination_id = case.compute_destination_id(
                root_public_key,
                fabric_id,
                node_id,
                sigma1.initiatorRandom,
                identity_protection_key,
            )
            if sigma1.destinationId == candidate_destination_id:
                matching_noc = i
                break

        if matching_noc is None:
            error_status = StatusReport()
            error_status.general_code = GeneralCode.FAILURE
            error_status.protocol_id = protocol.ProtocolId.SECURE_CHANNEL
            error_status.protocol_code = SecureChannelProtocolCode.NO_SHARED_TRUST_ROOTS
            return error_status

        fabric = self.node_credentials.fabrics[matching_noc]

        session_context = self.new_context()
        exchange.secure_session_context = session_context
        session_context.session_role_initiator = False
        session_context.peer_session_id = sigma1.initiatorSessionId
        session_context.local_fabric_index = matching_noc + 1
        session_context.resumption_id = self.random.urandom(16)
        session_context.local_node_id = fabric.NodeID

        ephemeral_key_pair = ecdsa.keys.SigningKey.generate(
            curve=ecdsa.NIST256p, hashfunc=hashlib.sha256, entropy=self.random.urandom
        )

        ephemeral_public_key = ephemeral_key_pair.verifying_key.to_string(
            encoding="uncompressed"
        )

        session_context.shared_secret = crypto.ECDH(
            ephemeral_key_pair, sigma1.initiatorEphPubKey
        )

        tbsdata = case.Sigma2TbsData()
        tbedata = case.Sigma2TbeData()

        tbsdata.responderNOC = self.node_credentials.nocs[matching_noc].NOC
        tbedata.responderNOC = self.node_credentials.nocs[matching_noc].NOC

        icac = self.node_credentials.nocs[matching_noc].ICAC
        if icac:
            tbsdata.responderICAC = self.node_credentials.nocs[matching_noc].ICAC
            tbedata.responderICAC = self.node_credentials.nocs[matching_noc].ICAC

        tbsdata.responderEphPubKey = ephemeral_public_key
        tbsdata.initiatorEphPubKey = sigma1.initiatorEphPubKey

        tbsdata = tbsdata.encode()

        tbedata.signature = self.node_credentials.noc_keys[
            matching_noc
        ].sign_deterministic(
            tbsdata,
            hashfunc=hashlib.sha256,
            sigencode=ecdsa.util.sigencode_string,
        )
        tbedata.resumptionID = session_context.resumption_id

        random = self.random.urandom(32)
        exchange.transcript_hash = hashlib.sha256(sigma1.encode())
        salt = (
            identity_protection_key
            + random
            + ephemeral_public_key
            + exchange.transcript_hash.digest()
        )
        s2k = crypto.KDF(
            session_context.shared_secret,
            salt,
            b"Sigma2",
            crypto.SYMMETRIC_KEY_LENGTH_BITS,
        )

        sigma2 = case.Sigma2()
        sigma2.responderRandom = random
        sigma2.responderSessionId = session_context.local_session_id
        sigma2.responderEphPubKey = ephemeral_public_key

        s2k_cipher = AESCCM(
            s2k,
            tag_length=crypto.AEAD_MIC_LENGTH_BYTES,
        )
        sigma2.encrypted2 = s2k_cipher.encrypt(
            b"NCASE_Sigma2N", bytes(tbedata.encode()), b""
        )

        exchange.transcript_hash.update(sigma2.encode())
        exchange.identity_protection_key = identity_protection_key
        exchange.s3k = crypto.KDF(
            session_context.shared_secret,
            identity_protection_key + exchange.transcript_hash.digest(),
            b"Sigma3",
            crypto.SYMMETRIC_KEY_LENGTH_BITS,
        )
        return sigma2

    def reply_to_sigma3(self, exchange, sigma3) -> SecureChannelProtocolCode:
        s3k_cipher = AESCCM(
            exchange.s3k,
            tag_length=crypto.AEAD_MIC_LENGTH_BYTES,
        )
        try:
            decrypted = s3k_cipher.decrypt(b"NCASE_Sigma3N", sigma3.encrypted3, b"")
        except cryptography.exceptions.InvalidTag:
            return SecureChannelProtocolCode.INVALID_PARAMETER
        sigma3_tbe, _ = case.Sigma3TbeData.decode(decrypted[0], decrypted[1:])

        # TODO: Implement checks 4a-4d. INVALID_PARAMETER if they fail.

        # TODO: Verify NOC chain. Checks 6a-6b. INVALID_PARAMETER if they fail.

        # TODO: Verify with TBS data. Steps 8 and 9. INVALID_PARAMETER if they fail.

        secure_session_context = exchange.secure_session_context

        peer_noc = sigma3_tbe.initiatorNOC
        peer_noc, _ = crypto.MatterCertificate.decode(
            peer_noc[0], memoryview(peer_noc)[1:]
        )
        secure_session_context.peer_node_id = peer_noc.subject.matter_node_id

        exchange.transcript_hash.update(sigma3.encode())

        # Generate session keys
        keys = crypto.KDF(
            secure_session_context.shared_secret,
            exchange.identity_protection_key + exchange.transcript_hash.digest(),
            b"SessionKeys",
            3 * crypto.SYMMETRIC_KEY_LENGTH_BITS,
        )
        secure_session_context.i2r_key = keys[: crypto.SYMMETRIC_KEY_LENGTH_BYTES]
        secure_session_context.i2r = AESCCM(
            secure_session_context.i2r_key,
            tag_length=crypto.AEAD_MIC_LENGTH_BYTES,
        )
        secure_session_context.r2i_key = keys[
            crypto.SYMMETRIC_KEY_LENGTH_BYTES : 2 * crypto.SYMMETRIC_KEY_LENGTH_BYTES
        ]
        secure_session_context.r2i = AESCCM(
            secure_session_context.r2i_key,
            tag_length=crypto.AEAD_MIC_LENGTH_BYTES,
        )
        secure_session_context.attestation_challenge = keys[
            2 * crypto.SYMMETRIC_KEY_LENGTH_BYTES :
        ]

        secure_session_context.session_timestamp = time.monotonic()
        return SecureChannelProtocolCode.SESSION_ESTABLISHMENT_SUCCESS
