# SPDX-FileCopyrightText: Copyright (c) 2024 Scott Shawcroft for Adafruit Industries
#
# SPDX-License-Identifier: MIT


class DummyMDNS:
    def advertise_service(
        self,
        service_type,
        protocol,
        port,
        txt_records=[],
        subtypes=[],
        instance_name="",
    ):
        print(f"Advertise service {service_type} {protocol} {port} {txt_records}")
