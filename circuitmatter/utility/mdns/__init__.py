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
