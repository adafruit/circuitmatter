# This file should only be needed when generating certificates.

import hashlib

from . import tlv
from .data_model import Enum8

import ecdsa
from ecdsa import der

import pathlib


class CertificationType(Enum8):
    DEVELOPMENT_AND_TEST = 0
    PROVISIONAL = 1
    OFFICIAL = 2


class CertificationDeclaration(tlv.Structure):
    format_version = tlv.IntMember(0, signed=False, octets=1)
    vendor_id = tlv.IntMember(1, signed=False, octets=2)
    product_id_array = tlv.ArrayMember(
        2, tlv.IntMember(0, signed=False, octets=2), max_length=100
    )
    device_type_id = tlv.IntMember(3, signed=False, octets=4)
    certificate_id = tlv.UTF8StringMember(4, max_length=19)
    security_level = tlv.IntMember(5, signed=False, octets=1)
    security_information = tlv.IntMember(6, signed=False, octets=2)
    version_number = tlv.IntMember(7, signed=False, octets=2)
    certification_type = tlv.EnumMember(8, CertificationType)
    dac_origin_vendor_id = tlv.IntMember(9, signed=False, octets=2, optional=True)
    dac_origin_product_id = tlv.IntMember(10, signed=False, octets=2, optional=True)
    authorized_paa_list = tlv.ArrayMember(
        11, tlv.OctetStringMember(None, max_length=20), optional=True, max_length=10
    )


def encode_set(*encoded_pieces):
    total_len = sum([len(p) for p in encoded_pieces])
    return b"\x31" + der.encode_length(total_len) + b"".join(encoded_pieces)


def generate_certificates(
    vendor_id=0xFFF1, product_id=0x8000, device_type=22, prefix=None
):
    declaration = CertificationDeclaration()
    declaration.format_version = 1  # Always 1
    declaration.vendor_id = vendor_id
    declaration.product_id_array = [product_id]
    declaration.device_type_id = 0x1234  # device_type
    declaration.certificate_id = "ZIG20141ZB330001-24"  # "CSA00000SWC00000-00"
    declaration.security_level = 0  # Always 0
    declaration.security_information = 0  # Always 0
    declaration.version_number = 0x2694  # 1 # Always 1
    declaration.certification_type = CertificationType.DEVELOPMENT_AND_TEST
    declaration = declaration.encode()

    for i in range(0, len(declaration), 16):
        print(f"{i:08x}", declaration[i : i + 16].hex(" "))

    # From: https://github.com/project-chip/matter.js/blob/main/packages/protocol/src/certificate/CertificationDeclarationManager.ts
    # NIST256p is the same as secp256r1
    private_key = ecdsa.keys.SigningKey.from_string(
        b"\xae\xf3\x48\x41\x16\xe9\x48\x1e\xc5\x7b\xe0\x47\x2d\xf4\x1b\xf4\x99\x06\x4e\x50\x24\xad\x86\x9e\xca\x5e\x88\x98\x02\xd4\x80\x75",
        curve=ecdsa.curves.NIST256p,
        hashfunc=hashlib.sha256,
    )
    print(private_key.to_string().hex().upper())
    subject_key_identifier = b"\x62\xfa\x82\x33\x59\xac\xfa\xa9\x96\x3e\x1c\xfa\x14\x0a\xdd\xf5\x04\xf3\x71\x60"
    signature = private_key.sign_deterministic(
        declaration,
        hashfunc=hashlib.sha256,
        sigencode=ecdsa.util.sigencode_der_canonize,
    )
    print("signature", signature.hex(" "))

    certification_declaration = []
    # version
    certification_declaration.append(der.encode_integer(3))
    # Digest algorithm
    certification_declaration.append(
        encode_set(der.encode_sequence(der.encode_oid(2, 16, 840, 1, 101, 3, 4, 2, 1)))
    )
    # encap content info
    encap_content_info = []
    # content type
    encap_content_info.append(der.encode_oid(1, 2, 840, 113549, 1, 7, 1))
    # content
    encap_content_info.append(
        der.encode_constructed(0, der.encode_octet_string(declaration))
    )
    certification_declaration.append(der.encode_sequence(*encap_content_info))

    signer_info = []
    # version
    signer_info.append(der.encode_integer(3))
    # subject key identifier
    signer_info.append(
        b"\x80"
        + der.encode_length(len(subject_key_identifier))
        + subject_key_identifier
    )
    # digest algorithm
    signer_info.append(
        der.encode_sequence(der.encode_oid(2, 16, 840, 1, 101, 3, 4, 2, 1))
    )
    # signature algorithm
    signer_info.append(der.encode_sequence(der.encode_oid(1, 2, 840, 10045, 4, 3, 2)))
    # signature
    signer_info.append(der.encode_octet_string(signature))
    certification_declaration.append(encode_set(der.encode_sequence(*signer_info)))

    signed_data = []
    signed_data.append(der.encode_oid(1, 2, 840, 113549, 1, 7, 2))
    cd = der.encode_sequence(*certification_declaration)
    signed_data.append(der.encode_constructed(0, cd))
    cms_signed = der.encode_sequence(*signed_data)

    return cms_signed


if __name__ == "__main__":
    cd = generate_certificates()
    pathlib.Path("certification_declaration.der").write_bytes(cd)
    for i in range(0, len(cd), 16):
        print(f"{i:08x}", cd[i : i + 16].hex(" "))
    print(cd.hex(" "))
