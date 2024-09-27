import time

from .message import Message, ExchangeFlags, ProtocolId
from .protocol import SecureProtocolOpcode

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
