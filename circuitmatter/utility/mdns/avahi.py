# SPDX-FileCopyrightText: Copyright (c) 2024 Scott Shawcroft for Adafruit Industries
#
# SPDX-License-Identifier: MIT

import subprocess


class Avahi:
    def __init__(self):
        self.active_services = {}

    def advertise_service(
        self,
        service_type,
        protocol,
        port,
        txt_records={},
        subtypes=[],
        instance_name="",
    ):
        subtypes = [f"--subtype={subtype}" for subtype in subtypes]
        txt_records = [f"{key}={value}" for key, value in txt_records.items()]
        command = [
            "avahi-publish-service",
            *subtypes,
            instance_name,
            f"{service_type}.{protocol}",
            str(port),
            *txt_records,
        ]
        self.active_services[service_type + instance_name] = subprocess.Popen(command)

    def __del__(self):
        for active_service in self.active_services.values():
            active_service.kill()
