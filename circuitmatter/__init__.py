"""Pure Python implementation of the Matter IOT protocol."""

import binascii
import hashlib
import json
import time

from . import case
from .clusters import core
from . import data_model
from . import interaction_model
from .message import Message
from .protocol import InteractionModelOpcode, ProtocolId, SecureProtocolOpcode
from . import session

__version__ = "0.0.0"


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

        for key in ["discriminator", "salt", "iteration-count", "verifier"]:
            if key not in self.nonvolatile:
                raise RuntimeError(f"Missing key {key} in state file")

        commission = "fabrics" not in self.nonvolatile

        self.packet_buffer = memoryview(bytearray(1280))

        # Define the UDP IP address and port
        UDP_IP = "::"  # Listen on all available network interfaces
        self.UDP_PORT = 5541

        # Create the UDP socket
        self.socket = self.socketpool.socket(
            self.socketpool.AF_INET6, self.socketpool.SOCK_DGRAM
        )

        # Bind the socket to the IP and port
        self.socket.bind((UDP_IP, self.UDP_PORT))
        self.socket.setblocking(False)

        self._endpoints = {}
        self._next_endpoint = 0
        self._descriptor = data_model.DescriptorCluster()
        self._descriptor.PartsList = []
        self._descriptor.ServerList = []
        self.add_cluster(0, self._descriptor)
        basic_info = data_model.BasicInformationCluster()
        basic_info.vendor_id = vendor_id
        basic_info.product_id = product_id
        basic_info.product_name = "CircuitMatter"
        self.add_cluster(0, basic_info)
        group_keys = core.GroupKeyManagementCluster()
        self.add_cluster(0, group_keys)
        network_info = data_model.NetworkCommissioningCluster()

        ethernet = data_model.NetworkCommissioningCluster.NetworkInfoStruct()
        ethernet.NetworkID = "enp13s0".encode("utf-8")
        ethernet.Connected = True
        network_info.networks = [ethernet]
        network_info.connect_max_time_seconds = 10
        self.add_cluster(0, network_info)
        general_commissioning = core.GeneralCommissioningCluster()
        self.add_cluster(0, general_commissioning)
        noc = core.NodeOperationalCredentialsCluster(
            group_keys, random_source, self.mdns_server, self.UDP_PORT
        )
        self.add_cluster(0, noc)

        self.vendor_id = vendor_id
        self.product_id = product_id

        self.manager = session.SessionManager(self.random, self.socket, noc)

        print(f"Listening on UDP port {self.UDP_PORT}")

        if commission:
            self.start_commissioning()

    def start_commissioning(self):
        discriminator = self.nonvolatile["discriminator"]
        passcode = self.nonvolatile["passcode"]
        txt_records = {
            "PI": "",
            "PH": "33",
            "CM": "1",
            "D": str(discriminator),
            "CRI": "3000",
            "CRA": "4000",
            "T": "1",
            "VP": f"{self.vendor_id}+{self.product_id}",
        }
        from . import pase

        pase.show_qr_code(self.vendor_id, self.product_id, discriminator, passcode)
        instance_name = self.random.urandom(8).hex().upper()
        self.mdns_server.advertise_service(
            "_matterc",
            "_udp",
            self.UDP_PORT,
            txt_records=txt_records,
            instance_name=instance_name,
            subtypes=[
                f"_L{discriminator}._sub._matterc._udp",
                "_CM._sub._matterc._udp",
            ],
        )

    def add_cluster(self, endpoint, cluster):
        if endpoint not in self._endpoints:
            self._endpoints[endpoint] = {}
            if endpoint > 0:
                self._descriptor.PartsList.append(endpoint)
            self._next_endpoint = max(self._next_endpoint, endpoint + 1)
        if endpoint == 0:
            self._descriptor.ServerList.append(cluster.CLUSTER_ID)
        self._endpoints[endpoint][cluster.CLUSTER_ID] = cluster

    def add_device(self, device):
        self._endpoints[self._next_endpoint] = {}
        if self._next_endpoint > 0:
            self._descriptor.PartsList.append(self._next_endpoint)
        self._next_endpoint += 1

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
        reports = []
        for data in cluster.get_attribute_data(path):
            report = interaction_model.AttributeReportIB()
            report.AttributeData = data
            reports.append(report)
        # Only add status if an error occurs
        # astatus = interaction_model.AttributeStatusIB()
        # astatus.Path = path
        # status = interaction_model.StatusIB()
        # status.Status = 0
        # status.ClusterStatus = 0
        # astatus.Status = status
        # report.AttributeStatus = astatus
        return reports

    def invoke(self, session, cluster, path, fields, command_ref):
        print("invoke", path)
        response = interaction_model.InvokeResponseIB()
        cdata = cluster.invoke(session, path, fields)
        if isinstance(cdata, interaction_model.CommandDataIB):
            if command_ref is not None:
                cdata.CommandRef = command_ref
            response.Command = cdata
        else:
            cstatus = interaction_model.CommandStatusIB()
            cstatus.CommandPath = path
            status = interaction_model.StatusIB()
            if cdata is None:
                status.Status = interaction_model.StatusCode.UNSUPPORTED_COMMAND
                print("UNSUPPORTED_COMMAND")
            else:
                status.Status = cdata
            cstatus.Status = status
            if command_ref is not None:
                cstatus.CommandRef = command_ref
            response.Status = cstatus
            return response

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
                    error_status = session.StatusReport()
                    error_status.general_code = session.GeneralCode.FAILURE
                    error_status.protocol_id = ProtocolId.SECURE_CHANNEL
                    error_status.protocol_code = (
                        session.SecureChannelProtocolCode.INVALID_PARAMETER
                    )
                    exchange.send(
                        ProtocolId.SECURE_CHANNEL,
                        SecureProtocolOpcode.STATUS_REPORT,
                        error_status,
                    )
                else:
                    exchange.session.session_timestamp = time.monotonic()
                    status_ok = session.StatusReport()
                    status_ok.general_code = session.GeneralCode.SUCCESS
                    status_ok.protocol_id = ProtocolId.SECURE_CHANNEL
                    status_ok.protocol_code = (
                        session.SecureChannelProtocolCode.SESSION_ESTABLISHMENT_SUCCESS
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
                sigma1, _ = case.Sigma1.decode(
                    message.application_payload[0], message.application_payload[1:]
                )
                response = self.manager.reply_to_sigma1(exchange, sigma1)

                opcode = SecureProtocolOpcode.STATUS_REPORT
                if isinstance(response, case.Sigma2Resume):
                    opcode = SecureProtocolOpcode.CASE_SIGMA2_RESUME
                elif isinstance(response, case.Sigma2):
                    opcode = SecureProtocolOpcode.CASE_SIGMA2
                exchange.send(
                    ProtocolId.SECURE_CHANNEL,
                    opcode,
                    response,
                )
            elif protocol_opcode == SecureProtocolOpcode.CASE_SIGMA2:
                print("Received CASE Sigma2")
            elif protocol_opcode == SecureProtocolOpcode.CASE_SIGMA3:
                print("Received CASE Sigma3")
                sigma3, _ = case.Sigma3.decode(
                    message.application_payload[0], message.application_payload[1:]
                )
                protocol_code = self.manager.reply_to_sigma3(exchange, sigma3)

                error_status = session.StatusReport()
                general_code = session.GeneralCode.FAILURE
                if (
                    protocol_code
                    == session.SecureChannelProtocolCode.SESSION_ESTABLISHMENT_SUCCESS
                ):
                    general_code = session.GeneralCode.SUCCESS
                error_status.general_code = general_code
                error_status.protocol_id = ProtocolId.SECURE_CHANNEL
                error_status.protocol_code = protocol_code
                exchange.send(
                    ProtocolId.SECURE_CHANNEL,
                    SecureProtocolOpcode.STATUS_REPORT,
                    error_status,
                )
            elif protocol_opcode == SecureProtocolOpcode.CASE_SIGMA2_RESUME:
                print("Received CASE Sigma2 Resume")
            elif protocol_opcode == SecureProtocolOpcode.STATUS_REPORT:
                print("Received Status Report")
                report = session.StatusReport()
                report.decode(message.application_payload)
                print(report)

                # Acknowledge the message because we have no further reply.
                if message.exchange_flags & session.ExchangeFlags.R:
                    exchange.send_standalone()
            elif protocol_opcode == SecureProtocolOpcode.ICD_CHECK_IN:
                print("Received ICD Check-in")
            elif protocol_opcode == SecureProtocolOpcode.MRP_STANDALONE_ACK:
                print("Received MRP Standalone Ack")
            else:
                print("Unhandled secure channel opcode", protocol_opcode)
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
                                attribute_reports.extend(self.get_report(cluster, path))
                            else:
                                print(f"Cluster 0x{path.Cluster:02x} not found")
                    else:
                        if path.Cluster in self._endpoints[path.Endpoint]:
                            cluster = self._endpoints[path.Endpoint][path.Cluster]
                            attribute_reports.extend(self.get_report(cluster, path))
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
            elif protocol_opcode == InteractionModelOpcode.SUBSCRIBE_REQUEST:
                print("Received Subscribe Request")
                subscribe_request, _ = interaction_model.SubscribeRequestMessage.decode(
                    message.application_payload[0], message.application_payload[1:]
                )
                print(subscribe_request)
                error_status = session.StatusReport()
                error_status.general_code = session.GeneralCode.UNSUPPORTED
                error_status.protocol_id = ProtocolId.SECURE_CHANNEL
                exchange.send(
                    ProtocolId.SECURE_CHANNEL,
                    SecureProtocolOpcode.STATUS_REPORT,
                    error_status,
                )

            else:
                print(message)
                print("application payload", message.application_payload.hex(" "))
        else:
            print("Unknown protocol", message.protocol_id, message.protocol_opcode)
        print()
