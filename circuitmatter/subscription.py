# SPDX-FileCopyrightText: Copyright (c) 2024 Scott Shawcroft for Adafruit Industries
#
# SPDX-License-Identifier: MIT

import time

from . import interaction_model
from .exchange import Exchange
from .protocol import ProtocolId


class Subscription:
    def __init__(self, _id, session, min_interval, max_interval):
        self.id = _id
        session.subscriptions[self.id] = self
        self.active = True
        self._reports = []
        self._session = session
        self._min_interval = min_interval
        self._max_interval = max_interval
        # Initial transmit is handled during the subscription call.
        self._last_transmit = time.monotonic()

    def send_reports(self, exchange=None):
        time_since = time.monotonic() - self._last_transmit
        if time_since < self._min_interval:
            return
        if not self._reports and time_since < (self._max_interval - 1):
            return

        # create a new exchange and send reports.
        exchange = Exchange(self._session, [ProtocolId.INTERACTION_MODEL])

        response = interaction_model.ReportDataMessage()
        response.SubscriptionId = self.id
        response.AttributeReports = self._reports
        if not self._reports:
            # No response on empty reports
            response.SuppressResponse = True
        exchange.send(response)
        if not self._reports:
            exchange.close()
        print(
            "reporting",
            self._reports,
            self._min_interval,
            time_since,
            self._max_interval,
        )
        # Use a new list so we don't clear the one we're sending.
        self._reports = []
        self._last_transmit = time.monotonic()

    def append_report(self, report):
        self._reports.append(report)

    def ack_report(self):
        pass
