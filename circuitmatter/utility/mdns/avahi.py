import subprocess


class Avahi:
    def __init__(self):
        self.active_services = {}
        self.publish_address = None

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
        if self.publish_address is None:
            command = [
                "avahi-publish-address",
                "dalinar.local",
                "fd98:bbab:bd61:8040:642:1aff:fe0c:9f2a",  # "fe80::642:1aff:fe0c:9f2a",
            ]
            self.publish_address = subprocess.Popen(command)

    def __del__(self):
        for active_service in self.active_services.values():
            active_service.kill()
        if self.publish_address is not None:
            self.publish_address.kill()
