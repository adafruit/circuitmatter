from .. import crypto
from .. import data_model
from .. import interaction_model
from .. import tlv

import ecdsa
from ecdsa import der
import hashlib
import pathlib
import struct
import time


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


class GeneralCommissioningCluster(data_model.GeneralCommissioningCluster):
    def __init__(self):
        super().__init__()
        basic_commissioning_info = (
            data_model.GeneralCommissioningCluster.BasicCommissioningInfo()
        )
        basic_commissioning_info.FailSafeExpiryLengthSeconds = 10
        basic_commissioning_info.MaxCumulativeFailsafeSeconds = 900
        self.basic_commissioning_info = basic_commissioning_info

    def arm_fail_safe(
        self, session, args: data_model.GeneralCommissioningCluster.ArmFailSafe
    ) -> data_model.GeneralCommissioningCluster.ArmFailSafeResponse:
        response = data_model.GeneralCommissioningCluster.ArmFailSafeResponse()
        response.ErrorCode = data_model.CommissioningErrorEnum.OK
        return response

    def set_regulatory_config(
        self, session, args: data_model.GeneralCommissioningCluster.SetRegulatoryConfig
    ) -> data_model.GeneralCommissioningCluster.SetRegulatoryConfigResponse:
        response = data_model.GeneralCommissioningCluster.SetRegulatoryConfigResponse()
        response.ErrorCode = data_model.CommissioningErrorEnum.OK
        return response

    def commissioning_complete(
        self, session
    ) -> data_model.GeneralCommissioningCluster.CommissioningCompleteResponse:
        response = (
            data_model.GeneralCommissioningCluster.CommissioningCompleteResponse()
        )
        response.ErrorCode = data_model.CommissioningErrorEnum.OK
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


class NodeOperationalCredentialsCluster(data_model.NodeOperationalCredentialsCluster):
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
        self.commissioned_fabrics = 0
        self.supported_fabrics = 10

        self.root_certs = []
        self.compressed_fabric_ids = []
        self.noc_keys = []

        self.mdns_server = mdns_server
        self.port = port
        self.random = random_source

    def certificate_chain_request(
        self,
        session,
        args: data_model.NodeOperationalCredentialsCluster.CertificateChainRequest,
    ) -> data_model.NodeOperationalCredentialsCluster.CertificateChainResponse:
        response = (
            data_model.NodeOperationalCredentialsCluster.CertificateChainResponse()
        )
        if args.CertificateType == data_model.CertificateChainTypeEnum.PAI:
            print("PAI")
            response.Certificate = TEST_PAI_CERT_DER.read_bytes()
        elif args.CertificateType == data_model.CertificateChainTypeEnum.DAC:
            print("DAC")
            response.Certificate = TEST_DAC_CERT_DER.read_bytes()
        return response

    def attestation_request(
        self,
        session,
        args: data_model.NodeOperationalCredentialsCluster.AttestationRequest,
    ) -> data_model.NodeOperationalCredentialsCluster.AttestationResponse:
        print("attestation")
        elements = AttestationElements()
        elements.certification_declaration = TEST_CD_CERT_DER.read_bytes()
        elements.attestation_nonce = args.AttestationNonce
        elements.timestamp = int(time.time())
        elements = elements.encode()
        print("elements", len(elements), elements[:3].hex(" "))
        print(
            "challeng",
            len(session.attestation_challenge),
            session.attestation_challenge[:3].hex(" "),
        )
        attestation_tbs = elements.tobytes() + session.attestation_challenge
        response = data_model.NodeOperationalCredentialsCluster.AttestationResponse()
        response.AttestationElements = elements
        response.AttestationSignature = self.dac_key.sign_deterministic(
            attestation_tbs,
            hashfunc=hashlib.sha256,
            sigencode=ecdsa.util.sigencode_string,
        )
        return response

    def csr_request(
        self, session, args: data_model.NodeOperationalCredentialsCluster.CSRRequest
    ) -> data_model.NodeOperationalCredentialsCluster.CSRResponse:
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
        response = data_model.NodeOperationalCredentialsCluster.CSRResponse()
        response.NOCSRElements = elements
        response.AttestationSignature = self.dac_key.sign_deterministic(
            nocsr_tbs, hashfunc=hashlib.sha256, sigencode=ecdsa.util.sigencode_string
        )
        return response

    def add_trusted_root_certificate(
        self,
        session,
        args: data_model.NodeOperationalCredentialsCluster.AddTrustedRootCertificate,
    ) -> interaction_model.StatusCode:
        self.pending_root_cert = args.RootCACertificate
        return interaction_model.StatusCode.SUCCESS

    def add_noc(
        self, session, args: data_model.NodeOperationalCredentialsCluster.AddNOC
    ) -> data_model.NodeOperationalCredentialsCluster.NOCResponse:
        # Section 11.18.6.8
        noc, _ = crypto.MatterCertificate.decode(
            args.NOCValue[0], memoryview(args.NOCValue)[1:]
        )
        icac, _ = crypto.MatterCertificate.decode(
            args.ICACValue[0], memoryview(args.ICACValue)[1:]
        )

        response = data_model.NodeOperationalCredentialsCluster.NOCResponse()

        if noc.ec_pub_key != self.pending_public_key:
            print(noc.ec_pub_key, self.pending_public_key)
            response.StatusCode = (
                data_model.NodeOperationalCertStatusEnum.INVALID_PUBLIC_KEY
            )
            return response

        # Save info about the fabric.
        new_fabric_index = len(self.fabrics)
        if new_fabric_index >= self.supported_fabrics:
            response.StatusCode = data_model.NodeOperationalCertStatusEnum.TABLE_FULL
            return response

        session.local_fabric_index = new_fabric_index

        # Store the NOC.
        noc_struct = data_model.NodeOperationalCredentialsCluster.NOCStruct()
        noc_struct.NOC = args.NOCValue
        noc_struct.ICAC = args.ICACValue
        self.nocs.append(noc_struct)

        # Get the root cert public key so we can create the compressed fabric id.
        root_cert, _ = crypto.MatterCertificate.decode(
            self.pending_root_cert[0], memoryview(self.pending_root_cert)[1:]
        )

        # Store the fabric
        new_fabric = (
            data_model.NodeOperationalCredentialsCluster.FabricDescriptorStruct()
        )
        new_fabric.RootPublicKey = root_cert.ec_pub_key
        new_fabric.VendorID = args.AdminVendorId
        new_fabric.FabricID = noc.subject.matter_fabric_id
        new_fabric.NodeID = noc.subject.matter_node_id
        self.fabrics.append(new_fabric)

        new_group_key = data_model.GroupKeyManagementCluster.KeySetWrite()
        key_set = data_model.GroupKeySetStruct()
        key_set.GroupKeySetID = 0
        key_set.GroupKeySecurityPolicy = (
            data_model.GroupKeySetSecurityPolicyEnum.TRUST_FIRST
        )
        key_set.EpochKey0 = args.IPKValue
        key_set.EpochStartTime0 = 0

        new_group_key.GroupKeySet = key_set
        self.group_key_manager.key_set_write(session, new_group_key)

        self.commissioned_fabrics += 1

        self.noc_keys.append(self.pending_signing_key)

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

        response.StatusCode = data_model.NodeOperationalCertStatusEnum.OK
        return response


class GroupKeyManagementCluster(data_model.GroupKeyManagementCluster):
    def __init__(self):
        super().__init__()
        self.key_sets = []

    def key_set_write(
        self, session, args: data_model.GroupKeyManagementCluster.KeySetWrite
    ) -> interaction_model.StatusCode:
        self.key_sets.append(args.GroupKeySet)
        return interaction_model.StatusCode.SUCCESS
