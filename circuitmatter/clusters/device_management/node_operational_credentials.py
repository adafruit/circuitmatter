from circuitmatter.data_model import (
    Enum8,
    NumberAttribute,
    ListAttribute,
    Command,
    Cluster,
)
from circuitmatter import tlv


class CertificateChainTypeEnum(Enum8):
    DAC = 1
    PAI = 2


class NodeOperationalCertStatusEnum(Enum8):
    OK = 0
    """OK, no error"""
    INVALID_PUBLIC_KEY = 1
    """Public Key in the NOC does not match the public key in the NOCSR"""
    INVALID_NODE_OP_ID = 2
    """The Node Operational ID in the NOC is not formatted correctly."""
    INVALID_NOC = 3
    """Any other validation error in NOC chain"""
    MISSING_CSR = 4
    """No record of prior CSR for which this NOC could match"""
    TABLE_FULL = 5
    """NOCs table full, cannot add another one"""
    INVALID_ADMIN_SUBJECT = 6
    """Invalid CaseAdminSubject field for an AddNOC command."""
    FABRIC_CONFLICT = 9
    """Trying to AddNOC instead of UpdateNOC against an existing Fabric."""
    LABEL_CONFLICT = 10
    """Label already exists on another Fabric."""
    INVALID_FABRIC_INDEX = 11
    """FabricIndex argument is invalid."""


RESP_MAX = 900


class NodeOperationalCredentialsCluster(Cluster):
    CLUSTER_ID = 0x003E

    class NOCStruct(tlv.Structure):
        NOC = tlv.OctetStringMember(1, 400)
        ICAC = tlv.OctetStringMember(2, 400, nullable=True)

    class FabricDescriptorStruct(tlv.Structure):
        RootPublicKey = tlv.OctetStringMember(1, 65)
        VendorID = tlv.IntMember(2, signed=False, octets=2)
        FabricID = tlv.IntMember(3, signed=False, octets=8)
        NodeID = tlv.IntMember(4, signed=False, octets=8)
        Label = tlv.UTF8StringMember(5, max_length=32, default="")

    class AttestationRequest(tlv.Structure):
        AttestationNonce = tlv.OctetStringMember(0, 32)

    class AttestationResponse(tlv.Structure):
        AttestationElements = tlv.OctetStringMember(0, RESP_MAX)
        AttestationSignature = tlv.OctetStringMember(1, 64)

    class CertificateChainRequest(tlv.Structure):
        CertificateType = tlv.EnumMember(0, CertificateChainTypeEnum)

    class CertificateChainResponse(tlv.Structure):
        Certificate = tlv.OctetStringMember(0, 600)

    class CSRRequest(tlv.Structure):
        CSRNonce = tlv.OctetStringMember(0, 32)
        IsForUpdateNOC = tlv.BoolMember(1, optional=True, default=False)

    class CSRResponse(tlv.Structure):
        NOCSRElements = tlv.OctetStringMember(0, RESP_MAX)
        AttestationSignature = tlv.OctetStringMember(1, 64)

    class AddNOC(tlv.Structure):
        NOCValue = tlv.OctetStringMember(0, 400)
        ICACValue = tlv.OctetStringMember(1, 400, optional=True)
        IPKValue = tlv.OctetStringMember(2, 16)
        CaseAdminSubject = tlv.IntMember(3, signed=False, octets=8)
        AdminVendorId = tlv.IntMember(4, signed=False, octets=2)

    class UpdateNOC(tlv.Structure):
        NOCValue = tlv.OctetStringMember(0, 400)
        ICACValue = tlv.OctetStringMember(1, 400, optional=True)

    class NOCResponse(tlv.Structure):
        StatusCode = tlv.EnumMember(0, NodeOperationalCertStatusEnum)
        FabricIndex = tlv.IntMember(1, signed=False, octets=1, optional=True)
        DebugText = tlv.UTF8StringMember(2, max_length=128, optional=True)

    class UpdateFabricLabel(tlv.Structure):
        Label = tlv.UTF8StringMember(0, max_length=32)

    class RemoveFabric(tlv.Structure):
        FabricIndex = tlv.IntMember(0, signed=False, octets=1)

    class AddTrustedRootCertificate(tlv.Structure):
        RootCACertificate = tlv.OctetStringMember(0, 400)

    nocs = ListAttribute(
        0, NOCStruct, N_nonvolatile=True, C_changes_omitted=True, default=[]
    )
    fabrics = ListAttribute(1, FabricDescriptorStruct, N_nonvolatile=True, default=[])
    supported_fabrics = NumberAttribute(2, signed=False, bits=8, F_fixed=True)
    commissioned_fabrics = NumberAttribute(
        3, signed=False, bits=8, N_nonvolatile=True, default=0
    )
    trusted_root_certificates = ListAttribute(
        4,
        tlv.OctetStringMember(None, 400),
        N_nonvolatile=True,
        C_changes_omitted=True,
        default=[],
    )
    # This attribute is weird because it is fabric sensitive but not marked as such.
    # Cluster sets current_fabric_index for use in fabric sensitive attributes and
    # happens to make this work as well.
    current_fabric_index = NumberAttribute(
        5, signed=False, bits=8, default=0, C_changes_omitted=True
    )

    attestation_request = Command(0x00, AttestationRequest, 0x01, AttestationResponse)

    certificate_chain_request = Command(
        0x02, CertificateChainRequest, 0x03, CertificateChainResponse
    )

    csr_request = Command(0x04, CSRRequest, 0x05, CSRResponse)

    add_noc = Command(0x06, AddNOC, 0x08, NOCResponse)

    update_noc = Command(0x07, UpdateNOC, 0x08, NOCResponse)

    update_fabric_label = Command(0x09, UpdateFabricLabel, 0x08, NOCResponse)

    remove_fabric = Command(0x0A, RemoveFabric, 0x08, NOCResponse)

    add_trusted_root_certificate = Command(0x0B, AddTrustedRootCertificate, None, None)
