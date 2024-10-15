import ecdsa
from ecdsa import der
import hashlib
import pathlib
import struct
import time

from circuitmatter import crypto, interaction_model, tlv
from circuitmatter.clusters.device_management.basic_information import (
    BasicInformationCluster,
)
from circuitmatter.clusters.device_management.general_diagnostics import (
    GeneralDiagnosticsCluster,
)
from circuitmatter.clusters.device_management.general_commissioning import (
    GeneralCommissioningCluster,
    CommissioningErrorEnum,
)
from circuitmatter.clusters.device_management.group_key_management import (
    GroupKeyManagementCluster,
    GroupKeySetSecurityPolicyEnum,
    GroupKeySetStruct,
)
from circuitmatter.clusters.device_management.network_commissioning import (
    NetworkCommissioningCluster,
)
from circuitmatter.clusters.device_management.node_operational_credentials import (
    CertificateChainTypeEnum,
    NodeOperationalCredentialsCluster,
    NodeOperationalCertStatusEnum,
)
from circuitmatter.clusters.system_model import user_label
from circuitmatter.clusters.system_model.access_control import AccessControlCluster

from .. import simple_device

TEST_CERTS = pathlib.Path(
    "../esp-matter/connectedhomeip/connectedhomeip/credentials/test/attestation/"
)
TEST_PAI_CERT_DER = TEST_CERTS / "Chip-Test-PAI-FFF1-8000-Cert.der"
TEST_PAI_CERT_PEM = TEST_CERTS / "Chip-Test-PAI-FFF1-8000-Cert.pem"
TEST_DAC_CERT_DER = TEST_CERTS / "Chip-Test-DAC-FFF1-8000-0000-Cert.der"
TEST_DAC_CERT_PEM = TEST_CERTS / "Chip-Test-DAC-FFF1-8000-0000-Cert.pem"
TEST_DAC_KEY_DER = TEST_CERTS / "Chip-Test-DAC-FFF1-8000-0000-Key.der"
TEST_DAC_KEY_PEM = TEST_CERTS / "Chip-Test-DAC-FFF1-8000-0000-Key.pem"

TEST_CD_CERT_DER = pathlib.Path("test_data/certification_declaration.der")


class _GeneralCommissioningCluster(GeneralCommissioningCluster):
    def __init__(self):
        super().__init__()
        basic_commissioning_info = GeneralCommissioningCluster.BasicCommissioningInfo()
        basic_commissioning_info.FailSafeExpiryLengthSeconds = 10
        basic_commissioning_info.MaxCumulativeFailsafeSeconds = 900
        self.basic_commissioning_info = basic_commissioning_info

    def arm_fail_safe(
        self, session, args: GeneralCommissioningCluster.ArmFailSafe
    ) -> GeneralCommissioningCluster.ArmFailSafeResponse:
        self.breadcrumb = args.Breadcrumb
        response = GeneralCommissioningCluster.ArmFailSafeResponse()
        response.ErrorCode = CommissioningErrorEnum.OK
        return response

    def set_regulatory_config(
        self, session, args: GeneralCommissioningCluster.SetRegulatoryConfig
    ) -> GeneralCommissioningCluster.SetRegulatoryConfigResponse:
        self.breadcrumb = args.Breadcrumb
        response = GeneralCommissioningCluster.SetRegulatoryConfigResponse()
        response.ErrorCode = CommissioningErrorEnum.OK
        return response

    def commissioning_complete(
        self, session
    ) -> GeneralCommissioningCluster.CommissioningCompleteResponse:
        response = GeneralCommissioningCluster.CommissioningCompleteResponse()
        response.ErrorCode = CommissioningErrorEnum.OK
        print("Commissioning done!")
        return response


class AttestationElements(tlv.Structure):
    certification_declaration = tlv.OctetStringMember(0x01, max_length=400)
    attestation_nonce = tlv.OctetStringMember(0x02, max_length=32)
    timestamp = tlv.IntMember(0x03, signed=False, octets=4)
    firmware_information = tlv.OctetStringMember(0x04, max_length=16, optional=True)
    """Used for secure boot. We don't support it."""


class NOCSRElements(tlv.Structure):
    csr = tlv.OctetStringMember(0x01, max_length=1024)
    CSRNonce = tlv.OctetStringMember(0x02, max_length=32)
    # Skip vendor reserved


def encode_set(*encoded_pieces):
    total_len = sum([len(p) for p in encoded_pieces])
    return b"\x31" + der.encode_length(total_len) + b"".join(encoded_pieces)


def encode_utf8_string(s):
    encoded = s.encode("utf-8")
    return b"\x0c" + der.encode_length(len(encoded)) + encoded


class _NodeOperationalCredentialsCluster(NodeOperationalCredentialsCluster):
    def __init__(self, group_key_manager, random_source, mdns_server, port):
        super().__init__()

        self.group_key_manager = group_key_manager

        self.dac_key = ecdsa.keys.SigningKey.from_der(
            TEST_DAC_KEY_DER.read_bytes(), hashfunc=hashlib.sha256
        )

        self.new_key_for_update = False
        self.pending_root_cert = None
        self.pending_signing_key = None

        self.nocs = []
        self.fabrics = []
        self.supported_fabrics = 10
        self.commissioned_fabrics = 0
        self.trusted_root_certificates = []

        self.root_certs = []
        self.compressed_fabric_ids = []
        self.noc_keys = []

        self.mdns_server = mdns_server
        self.port = port
        self.random = random_source

    def certificate_chain_request(
        self,
        session,
        args: NodeOperationalCredentialsCluster.CertificateChainRequest,
    ) -> NodeOperationalCredentialsCluster.CertificateChainResponse:
        response = NodeOperationalCredentialsCluster.CertificateChainResponse()
        if args.CertificateType == CertificateChainTypeEnum.PAI:
            response.Certificate = TEST_PAI_CERT_DER.read_bytes()
        elif args.CertificateType == CertificateChainTypeEnum.DAC:
            response.Certificate = TEST_DAC_CERT_DER.read_bytes()
        return response

    def attestation_request(
        self,
        session,
        args: NodeOperationalCredentialsCluster.AttestationRequest,
    ) -> NodeOperationalCredentialsCluster.AttestationResponse:
        elements = AttestationElements()
        elements.certification_declaration = TEST_CD_CERT_DER.read_bytes()
        elements.attestation_nonce = args.AttestationNonce
        elements.timestamp = int(time.time())
        elements = elements.encode()
        attestation_tbs = elements.tobytes() + session.attestation_challenge
        response = NodeOperationalCredentialsCluster.AttestationResponse()
        response.AttestationElements = elements
        response.AttestationSignature = self.dac_key.sign_deterministic(
            attestation_tbs,
            hashfunc=hashlib.sha256,
            sigencode=ecdsa.util.sigencode_string,
        )
        return response

    def csr_request(
        self, session, args: NodeOperationalCredentialsCluster.CSRRequest
    ) -> NodeOperationalCredentialsCluster.CSRResponse:
        # Section 6.4.6.1
        # CSR stands for Certificate Signing Request. A NOCSR is a Node Operational Certificate Signing Request

        self.new_key_for_update = args.IsForUpdateNOC
        self.pending_signing_key = ecdsa.keys.SigningKey.generate(
            curve=ecdsa.NIST256p, hashfunc=hashlib.sha256, entropy=self.random.urandom
        )

        # DER encode the request
        # https://www.rfc-editor.org/rfc/rfc2986 Section 4.2
        certification_request = []

        certification_request_info = []

        # Version
        certification_request_info.append(der.encode_integer(0))

        # subject
        attribute_type = der.encode_oid(2, 5, 4, 10)
        value = encode_utf8_string("CSA")

        subject = der.encode_sequence(
            encode_set(der.encode_sequence(attribute_type, value))
        )
        certification_request_info.append(subject)

        # Subject Public Key Info
        algorithm = der.encode_sequence(
            der.encode_oid(1, 2, 840, 10045, 2, 1),
            der.encode_oid(1, 2, 840, 10045, 3, 1, 7),
        )
        self.pending_public_key = self.pending_signing_key.verifying_key.to_string(
            encoding="uncompressed"
        )
        public_key = der.encode_bitstring(self.pending_public_key, unused=0)
        spki = der.encode_sequence(algorithm, public_key)
        certification_request_info.append(spki)

        # Extensions
        extension_request = der.encode_sequence(
            der.encode_oid(1, 2, 840, 113549, 1, 9, 14),
            encode_set(der.encode_sequence()),
        )
        certification_request_info.append(der.encode_constructed(0, extension_request))

        certification_request_info = der.encode_sequence(*certification_request_info)
        certification_request.append(certification_request_info)

        signature_algorithm = der.encode_sequence(
            der.encode_oid(1, 2, 840, 10045, 4, 3, 2)
        )
        certification_request.append(signature_algorithm)

        # Signature
        signature = self.pending_signing_key.sign_deterministic(
            certification_request_info,
            hashfunc=hashlib.sha256,
            sigencode=ecdsa.util.sigencode_der_canonize,
        )
        certification_request.append(der.encode_bitstring(signature, unused=0))

        # Generate a new key pair.
        new_key_csr = der.encode_sequence(*certification_request)

        # Create a CSR to reply back with. Sign it with the new private key.
        elements = NOCSRElements()
        elements.csr = new_key_csr
        elements.CSRNonce = args.CSRNonce
        elements = elements.encode()
        nocsr_tbs = elements.tobytes() + session.attestation_challenge

        # class CSRResponse(tlv.Structure):
        #     NOCSRElements = tlv.OctetStringMember(0, RESP_MAX)
        #     AttestationSignature = tlv.OctetStringMember(1, 64)
        response = NodeOperationalCredentialsCluster.CSRResponse()
        response.NOCSRElements = elements
        response.AttestationSignature = self.dac_key.sign_deterministic(
            nocsr_tbs, hashfunc=hashlib.sha256, sigencode=ecdsa.util.sigencode_string
        )
        return response

    def add_trusted_root_certificate(
        self,
        session,
        args: NodeOperationalCredentialsCluster.AddTrustedRootCertificate,
    ) -> interaction_model.StatusCode:
        self.pending_root_cert = args.RootCACertificate
        return interaction_model.StatusCode.SUCCESS

    def add_noc(
        self, session, args: NodeOperationalCredentialsCluster.AddNOC
    ) -> NodeOperationalCredentialsCluster.NOCResponse:
        # Section 11.18.6.8
        noc, _ = crypto.MatterCertificate.decode(
            args.NOCValue[0], memoryview(args.NOCValue)[1:]
        )
        if args.ICACValue:
            icac, _ = crypto.MatterCertificate.decode(
                args.ICACValue[0], memoryview(args.ICACValue)[1:]
            )

        response = NodeOperationalCredentialsCluster.NOCResponse()

        if noc.ec_pub_key != self.pending_public_key:
            print(noc.ec_pub_key, self.pending_public_key)
            response.StatusCode = NodeOperationalCertStatusEnum.INVALID_PUBLIC_KEY
            return response

        # Save info about the fabric.
        new_fabric_index = len(self.fabrics)
        if new_fabric_index >= self.supported_fabrics:
            response.StatusCode = NodeOperationalCertStatusEnum.TABLE_FULL
            return response

        session.local_fabric_index = new_fabric_index

        # Store the NOC.
        noc_struct = NodeOperationalCredentialsCluster.NOCStruct()
        noc_struct.NOC = args.NOCValue
        if args.ICACValue:
            noc_struct.ICAC = args.ICACValue
        self.nocs.append(noc_struct)

        # Get the root cert public key so we can create the compressed fabric id.
        root_cert, _ = crypto.MatterCertificate.decode(
            self.pending_root_cert[0], memoryview(self.pending_root_cert)[1:]
        )

        # Store the fabric
        new_fabric = NodeOperationalCredentialsCluster.FabricDescriptorStruct()
        new_fabric.RootPublicKey = root_cert.ec_pub_key
        new_fabric.VendorID = args.AdminVendorId
        new_fabric.FabricID = noc.subject.matter_fabric_id
        new_fabric.NodeID = noc.subject.matter_node_id
        print(f"Adding fabric {new_fabric.FabricID} with node id {new_fabric.NodeID:x}")
        self.fabrics.append(new_fabric)

        new_group_key = GroupKeyManagementCluster.KeySetWrite()
        key_set = GroupKeySetStruct()
        key_set.GroupKeySetID = 0
        key_set.GroupKeySecurityPolicy = GroupKeySetSecurityPolicyEnum.TRUST_FIRST
        key_set.EpochKey0 = args.IPKValue
        key_set.EpochStartTime0 = 0

        new_group_key.GroupKeySet = key_set
        self.group_key_manager.key_set_write(session, new_group_key)

        self.commissioned_fabrics += 1

        self.noc_keys.append(self.pending_signing_key)

        self.trusted_root_certificates.append(self.pending_root_cert)

        self.root_certs.append(root_cert)
        fabric_id = struct.pack(">Q", noc.subject.matter_fabric_id)
        self.compressed_fabric_ids.append(
            crypto.KDF(root_cert.ec_pub_key[1:], fabric_id, b"CompressedFabric", 64)
        )
        compressed_fabric_id = self.compressed_fabric_ids[-1].hex().upper()

        node_id = struct.pack(">Q", new_fabric.NodeID).hex().upper()
        instance_name = f"{compressed_fabric_id}-{node_id}"
        self.mdns_server.advertise_service(
            "_matter",
            "_tcp",
            self.port,
            instance_name=instance_name,
            subtypes=[
                f"_I{compressed_fabric_id}._sub._matter._tcp",
            ],
        )

        response.StatusCode = NodeOperationalCertStatusEnum.OK
        return response

    def remove_fabric(
        self,
        session,
        args: NodeOperationalCredentialsCluster.RemoveFabric,
    ) -> NodeOperationalCredentialsCluster.NOCResponse:
        index = args.FabricIndex
        self.commissioned_fabrics -= 1

        self.noc_keys[index] = None
        self.root_certs[index] = None
        self.compressed_fabric_ids[index] = None
        self.fabrics[index] = None
        self.nocs[index] = None

        response = NodeOperationalCredentialsCluster.NOCResponse()
        response.StatusCode = NodeOperationalCertStatusEnum.OK
        return response


class _GroupKeyManagementCluster(GroupKeyManagementCluster):
    def __init__(self):
        super().__init__()
        self.key_sets = []

    def key_set_write(
        self, session, args: GroupKeyManagementCluster.KeySetWrite
    ) -> interaction_model.StatusCode:
        self.key_sets.append(args.GroupKeySet)
        return interaction_model.StatusCode.SUCCESS


class RootNode(simple_device.SimpleDevice):
    DEVICE_TYPE_ID = 0x0011
    REVISION = 2

    def __init__(self, random_source, mdns_server, port, vendor_id, product_id):
        super().__init__()

        basic_info = BasicInformationCluster()
        basic_info.vendor_id = vendor_id
        basic_info.product_id = product_id
        basic_info.product_name = "CircuitMatter"
        basic_info.serial_number = "1234"
        self.servers.append(basic_info)
        access_control = AccessControlCluster()
        self.servers.append(access_control)
        group_keys = _GroupKeyManagementCluster()
        self.servers.append(group_keys)
        network_info = NetworkCommissioningCluster()
        network_info.feature_map = (
            NetworkCommissioningCluster.FeatureBitmap.WIFI_NETWORK_INTERFACE
        )

        ethernet = NetworkCommissioningCluster.NetworkInfoStruct()
        ethernet.NetworkID = "enp13s0".encode("utf-8")
        ethernet.Connected = True
        network_info.networks = [ethernet]
        network_info.scan_max_time_seconds = 10
        network_info.connect_max_time_seconds = 10
        network_info.supported_wifi_bands = [
            NetworkCommissioningCluster.WifiBandEnum.BAND_2G4
        ]
        network_info.last_network_status = (
            NetworkCommissioningCluster.NetworkCommissioningStatus.SUCCESS
        )
        network_info.last_network_id = ethernet.NetworkID
        self.servers.append(network_info)
        general_commissioning = _GeneralCommissioningCluster()
        self.servers.append(general_commissioning)
        self.noc = _NodeOperationalCredentialsCluster(
            group_keys, random_source, mdns_server, port
        )
        self.servers.append(self.noc)

        self.general_diagnostics = GeneralDiagnosticsCluster()
        self.servers.append(self.general_diagnostics)

        self.user_label = user_label.UserLabelCluster()
        self.servers.append(self.user_label)
