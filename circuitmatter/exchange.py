# SPDX-FileCopyrightText: Copyright (c) 2024 Scott Shawcroft for Adafruit Industries
#
# SPDX-License-Identifier: MIT

import random
import time

from .interaction_model import ChunkedMessage
from .message import ExchangeFlags, Message, ProtocolId
from .protocol import SecureProtocolOpcode

# Section 4.12.8
MRP_MAX_TRANSMISSIONS = 5
"""The maximum number of transmission attempts for a given reliable message. The sender MAY choose
this value as it sees fit."""

MRP_BACKOFF_BASE = 1.6
"""The base number for the exponential backoff equation."""

MRP_BACKOFF_JITTER = 0.25
"""The scaler for random jitter in the backoff equation."""

MRP_BACKOFF_MARGIN = 1.1
"""The scaler margin increase to backoff over the peer idle interval."""

MRP_BACKOFF_THRESHOLD = 1
"""The number of retransmissions before transitioning from linear to exponential backoff."""

MRP_STANDALONE_ACK_TIMEOUT_MS = 200
"""Amount of time to wait for an opportunity to piggyback an acknowledgement on an outbound message
before falling back to sending a standalone acknowledgement."""


class Exchange:
    def __init__(self, session, protocols, initiator: bool = True, exchange_id: int = -1):
        self.initiator = initiator
        self.exchange_id = session.next_exchange_id if exchange_id < 0 else exchange_id
        print(f"\033[93mnew exchange {self.exchange_id}\033[0m")
        self.protocols = protocols
        self.session = session

        if self.initiator:
            self.session.initiator_exchanges[self.exchange_id] = self
        else:
            self.session.responder_exchanges[self.exchange_id] = self

        self.pending_acknowledgement = None
        """Message number that is waiting for an ack from us"""
        self.send_standalone_time = None

        self.retry_count = 0
        self.next_retransmission_time = None
        """When to next resend the message that hasn't been acked"""
        self.pending_retransmission = None
        """Message that we've attempted to send but hasn't been acked"""
        self.pending_payloads = []

        self._closing = False

    def send(
        self,
        application_payload=None,
        protocol_id=None,
        protocol_opcode=None,
        reliable=True,
    ):
        if self.pending_retransmission is not None:
            raise RuntimeError("Cannot send a message while waiting for an ack.")
        message = Message()
        message.exchange_flags = ExchangeFlags(0)
        if self.initiator:
            message.exchange_flags |= ExchangeFlags.I
        if self.pending_acknowledgement is not None:
            message.exchange_flags |= ExchangeFlags.A
            self.send_standalone_time = None
            message.acknowledged_message_counter = self.pending_acknowledgement
            self.pending_acknowledgement = None
        if reliable:
            message.exchange_flags |= ExchangeFlags.R
            self.pending_retransmission = message
            self.next_retransmission_time = None
            self.retry_count = 0
        message.source_node_id = self.session.local_node_id
        if protocol_id is None:
            protocol_id = application_payload.PROTOCOL_ID
        message.protocol_id = protocol_id
        if protocol_opcode is None:
            protocol_opcode = application_payload.PROTOCOL_OPCODE
        message.protocol_opcode = protocol_opcode
        message.exchange_id = self.exchange_id
        if isinstance(application_payload, ChunkedMessage):
            chunk = memoryview(bytearray(1280))[:1200]
            offset = application_payload.encode_into(chunk)
            if application_payload.MoreChunkedMessages:
                self.pending_payloads.insert(0, application_payload)
            message.application_payload = chunk[:offset]
        else:
            message.application_payload = application_payload
        if reliable:
            self.send_pending()
        else:
            self.session.send(message)

    def send_pending(self, ignore_time=False) -> bool:
        if self.pending_retransmission is None:
            return False
        if not ignore_time and self.next_retransmission_time is not None:
            if time.monotonic() < self.next_retransmission_time:
                return False
        self.session.send(self.pending_retransmission)
        self.retry_count += 1
        session_interval = (
            self.session.session_active_interval
            if self.session.peer_active
            else self.session.session_idle_interval
        )
        difference = (
            session_interval
            * (MRP_BACKOFF_BASE ** (max(0, self.retry_count - MRP_BACKOFF_THRESHOLD)))
            * (1 + random.random() * MRP_BACKOFF_JITTER)
        )
        self.next_retransmission_time = time.monotonic() + difference
        return True

    def send_standalone(self):
        # Resend the pending message when set.
        if self.send_pending(ignore_time=True):
            return
        self.send(
            protocol_id=ProtocolId.SECURE_CHANNEL,
            protocol_opcode=SecureProtocolOpcode.MRP_STANDALONE_ACK,
            reliable=False,
        )

    def queue(self, payload):
        self.pending_payloads.append(payload)

    def receive(self, message) -> bool:
        """Process the message and return if the packet should be dropped."""
        # Section 4.12.5.2.1
        if message.exchange_flags & ExchangeFlags.A:
            if message.acknowledged_message_counter is None:
                # Drop messages that are missing an acknowledgement counter.
                return True
            if (
                self.pending_retransmission is not None
                and message.acknowledged_message_counter
                != self.pending_retransmission.message_counter
            ):
                # Drop messages that have the wrong acknowledgement counter.
                return True
            self.pending_retransmission = None
            self.next_retransmission_time = None
            # Close if we're acked by a standalone packet that won't be handled higher up.
            if (
                self._closing
                and not self.pending_payloads
                and message.protocol_id == ProtocolId.SECURE_CHANNEL
                and message.protocol_opcode == SecureProtocolOpcode.MRP_STANDALONE_ACK
            ):
                print(f"\033[93mexchange closed after ack {self.exchange_id}\033[0m")
                if self.initiator:
                    self.session.initiator_exchanges.pop(self.exchange_id)
                else:
                    self.session.responder_exchanges.pop(self.exchange_id)

        if message.protocol_id not in self.protocols:
            # Drop messages that don't match the protocols we're waiting for.
            # This is likely a standalone ACK to an interaction model response.
            return True

        # Section 4.12.5.2.2
        # Incoming packets that are marked Reliable.
        if message.exchange_flags & ExchangeFlags.R:
            if message.duplicate:
                if self.pending_acknowledgement is None:
                    self.pending_acknowledgement = message.message_counter
                # Send a standalone acknowledgement.
                self.send_standalone()
                return True
            if (
                self.pending_acknowledgement is not None
                and self.pending_acknowledgement != message.message_counter
            ):
                # Send a standalone acknowledgement with the message counter we're about to
                # overwrite.
                self.send_standalone()
            self.pending_acknowledgement = message.message_counter
            self.send_standalone_time = time.monotonic() + MRP_STANDALONE_ACK_TIMEOUT_MS / 1000

        if message.duplicate:
            return True
        return False

    def close(self):
        if self._closing:
            print("Double+ close!")
            return
        self._closing = True
        print(f"\033[93mclosing {self.exchange_id}\033[0m")

        if self.pending_retransmission is not None:
            print(f"\033[93mpending retransmissions {self.exchange_id}\033[0m")
            self.resend_pending()
            return

        if self.pending_acknowledgement is not None:
            print(f"\033[93mpending ack {self.exchange_id}\033[0m")
            self.send_standalone()
            return

        if self.initiator:
            self.session.initiator_exchanges.pop(self.exchange_id)
        else:
            self.session.responder_exchanges.pop(self.exchange_id)
        print(f"\033[93mexchange closed {self.exchange_id}\033[0m")

    def resend_pending(self):
        self.send_pending()
