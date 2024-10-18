# This file should only be needed when generating certificates.

import binascii
import hashlib

from . import tlv
from . import pase
from .data_model import Enum8

import ecdsa
from ecdsa.curves import NIST256p
from ecdsa import der

PAI_KEY_DER = b"\x30\x77\x02\x01\x01\x04\x20\xbb\x76\xa5\x80\x5f\x97\x26\x49\xaf\x1e\x8a\x87\xdc\x45\x57\xe6\x2c\x09\x00\xe5\x07\x09\xe8\x5c\x79\xc6\x44\xdf\x78\x90\xe5\x96\xa0\x0a\x06\x08\x2a\x86\x48\xce\x3d\x03\x01\x07\xa1\x44\x03\x42\x00\x04\x37\x5d\x2b\xc8\xc6\x15\x27\x5b\xfd\x84\x8b\x52\xfe\x21\x96\xe2\xa1\x4e\xf3\xcc\x91\xae\xf0\x5d\xff\x85\x1c\xbc\x19\xb1\xa9\x35\x45\x8c\xfe\x04\xaa\x42\x4e\x01\x6d\xe3\xd6\x74\xdc\x5b\x73\x29\xbd\x77\x57\xfd\xdb\x32\x38\xd6\x26\x73\x62\x9b\x3c\x79\x08\x45"

INVALID_PASSCODES = [
    0,
    11111111,
    22222222,
    33333333,
    44444444,
    55555555,
    66666666,
    77777777,
    88888888,
    12345678,
    87654321,
]


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


def encode_utf8_string(s):
    encoded = s.encode("utf-8")
    return b"\x0c" + der.encode_length(len(encoded)) + encoded


def generate_certificates(
    vendor_id=0xFFF1, product_id=0x8000, device_type=22, prefix=None
):
    declaration = CertificationDeclaration()
    declaration.format_version = 1  # Always 1
    declaration.vendor_id = vendor_id
    declaration.product_id_array = [product_id]
    declaration.device_type_id = device_type
    declaration.certificate_id = "CSA00000SWC00000-00"
    declaration.security_level = 0  # Always 0
    declaration.security_information = 0  # Always 0
    declaration.version_number = 1  # Always 1
    declaration.certification_type = CertificationType.DEVELOPMENT_AND_TEST
    declaration = declaration.encode()

    # From: https://github.com/project-chip/matter.js/blob/main/packages/protocol/src/certificate/CertificationDeclarationManager.ts
    # NIST256p is the same as secp256r1
    private_key = ecdsa.keys.SigningKey.from_string(
        b"\xae\xf3\x48\x41\x16\xe9\x48\x1e\xc5\x7b\xe0\x47\x2d\xf4\x1b\xf4\x99\x06\x4e\x50\x24\xad\x86\x9e\xca\x5e\x88\x98\x02\xd4\x80\x75",
        curve=ecdsa.curves.NIST256p,
        hashfunc=hashlib.sha256,
    )
    subject_key_identifier = b"\x62\xfa\x82\x33\x59\xac\xfa\xa9\x96\x3e\x1c\xfa\x14\x0a\xdd\xf5\x04\xf3\x71\x60"
    signature = private_key.sign_deterministic(
        declaration,
        hashfunc=hashlib.sha256,
        sigencode=ecdsa.util.sigencode_der_canonize,
    )

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


def generate_dac(
    vendor_id, product_id, product_name, random_source
) -> tuple[bytes, bytes]:
    dac_key = ecdsa.keys.SigningKey.generate(
        curve=ecdsa.NIST256p, hashfunc=hashlib.sha256, entropy=random_source.urandom
    )

    version = der.encode_constructed(0, der.encode_integer(2))
    serial_number = der.encode_integer(1)
    signature_algorithm = der.encode_sequence(der.encode_oid(1, 2, 840, 10045, 4, 3, 2))
    # CircuitMatter PAI for vendor ID 0xfff4
    issuer = b"\x30\x32\x31\x1a\x30\x18\x06\x03\x55\x04\x03\x0c\x11\x43\x69\x72\x63\x75\x69\x74\x4d\x61\x74\x74\x65\x72\x20\x50\x41\x49\x31\x14\x30\x12\x06\x0a\x2b\x06\x01\x04\x01\x82\xa2\x7c\x02\x01\x0c\x04\x46\x46\x46\x34"

    # Starting 10/17/2024 and never expiring
    validity = b"\x30\x20\x17\x0d\x32\x34\x31\x30\x31\x37\x30\x30\x30\x30\x30\x30\x5a\x18\x0f\x39\x39\x39\x39\x31\x32\x33\x31\x32\x33\x35\x39\x35\x39\x5a"

    common_name = encode_set(
        der.encode_sequence(
            der.encode_oid(2, 5, 4, 3), encode_utf8_string(product_name)
        )
    )
    encoded_vendor_id = encode_set(
        der.encode_sequence(
            der.encode_oid(1, 3, 6, 1, 4, 1, 37244, 2, 1),
            encode_utf8_string(f"{vendor_id:04X}"),
        )
    )
    encoded_product_id = encode_set(
        der.encode_sequence(
            der.encode_oid(1, 3, 6, 1, 4, 1, 37244, 2, 2),
            encode_utf8_string(f"{product_id:04X}"),
        )
    )
    subject = der.encode_sequence(common_name, encoded_vendor_id, encoded_product_id)

    algorithm_id = b"\x30\x13\x06\x07\x2a\x86\x48\xce\x3d\x02\x01\x06\x08\x2a\x86\x48\xce\x3d\x03\x01\x07"

    public_key = dac_key.verifying_key.to_string(encoding="uncompressed")
    public_key_info = der.encode_sequence(
        algorithm_id, der.encode_bitstring(public_key, unused=0)
    )

    basic_constraints = b"\x30\x0c\x06\x03\x55\x1d\x13\x01\x01\xff\x04\x02\x30\x00"
    key_usage = b"\x30\x0e\x06\x03\x55\x1d\x0f\x01\x01\xff\x04\x04\x03\x02\x07\x80"
    key_id = der.encode_sequence(
        der.encode_oid(2, 5, 29, 14),
        der.encode_octet_string(
            der.encode_octet_string(hashlib.sha1(public_key).digest())
        ),
    )
    # ID of the CircuitMatter 0xFFF4 PAI
    authority_key_id = b"\x30\x1f\x06\x03\x55\x1d\x23\x04\x18\x30\x16\x80\x14\x07\xf8\x38\x0a\x5f\x01\x36\xfc\xe2\x36\xbd\x45\xf2\x88\xff\x22\xdc\xa6\xf4\xa7"
    extensions = der.encode_constructed(
        3, der.encode_sequence(basic_constraints, key_usage, key_id, authority_key_id)
    )

    certificate = der.encode_sequence(
        version,
        serial_number,
        signature_algorithm,
        issuer,
        validity,
        subject,
        public_key_info,
        extensions,
    )

    pai_key = ecdsa.keys.SigningKey.from_der(PAI_KEY_DER, hashfunc=hashlib.sha256)
    signature = pai_key.sign_deterministic(
        certificate,
        hashfunc=hashlib.sha256,
        sigencode=ecdsa.util.sigencode_der_canonize,
    )

    dac_cert = der.encode_sequence(
        certificate, signature_algorithm, der.encode_bitstring(signature, unused=0)
    )
    dac_key = dac_key.to_der()
    return dac_cert, dac_key


def compute_verifier(passcode: int, salt: bytes, iterations: int) -> bytes:
    w0, w1 = pase._pbkdf2(passcode, salt, iterations)
    L = NIST256p.generator * w1

    return w0.to_bytes(NIST256p.baselen, byteorder="big") + L.to_bytes("uncompressed")


# Look up tables for Verhoeff Algorithm
# From: https://en.wikipedia.org/wiki/Verhoeff_algorithm#Table-based_algorithm
D_TABLE = (
    b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09"
    + b"\x01\x02\x03\x04\x00\x06\x07\x08\x09\x05"
    + b"\x02\x03\x04\x00\x01\x07\x08\x09\x05\x06"
    + b"\x03\x04\x00\x01\x02\x08\x09\x05\x06\x07"
    + b"\x04\x00\x01\x02\x03\x09\x05\x06\x07\x08"
    + b"\x05\x09\x08\x07\x06\x00\x04\x03\x02\x01"
    + b"\x06\x05\x09\x08\x07\x01\x00\x04\x03\x02"
    + b"\x07\x06\x05\x09\x08\x02\x01\x00\x04\x03"
    + b"\x08\x07\x06\x05\x09\x03\x02\x01\x00\x04"
    + b"\x09\x08\x07\x06\x05\x04\x03\x02\x01\x00"
)

INV_TABLE = b"\x00\x04\x03\x02\x01\x05\x06\x07\x08\x09"

P_TABLE = (
    b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09"
    + b"\x01\x05\x07\x06\x02\x08\x03\x00\x09\x04"
    + b"\x05\x08\x00\x03\x07\x09\x06\x01\x04\x02"
    b"\x08\x09\x01\x06\x00\x04\x03\x05\x02\x07"
    + b"\x09\x04\x05\x03\x01\x02\x06\x08\x07\x00"
    + b"\x04\x02\x08\x06\x05\x07\x03\x09\x00\x01"
    + b"\x02\x07\x09\x03\x08\x00\x06\x04\x01\x05"
    + b"\x07\x00\x04\x06\x09\x01\x03\x02\x05\x08"
)


def _bcd(buf, n):
    div = 10 ** (len(buf) - 1)
    for i in range(len(buf)):
        buf[i] = (n // div) % 10
        div //= 10


def compute_manual_code(
    discriminator, passcode, vendor_id=None, product_id=None
) -> str:
    vid_pid_present = 0
    if vendor_id is not None and product_id is not None:
        vid_pid_present = 1

    digits = memoryview(bytearray(11))
    digits[0] = (vid_pid_present << 2) | (discriminator >> 10)
    d2_6 = ((discriminator & 0x300) << 6) | (passcode & 0x3FFF)
    _bcd(digits[1:6], d2_6)
    d7_10 = passcode >> 14
    _bcd(digits[6:10], d7_10)

    # Checksum of zero. We'll overwrite it.
    digits[10] = 0

    c = 0
    for i, n in enumerate(reversed(digits)):
        c = D_TABLE[c * 10 + P_TABLE[(i % 8) * 10 + n]]

    digits[10] = INV_TABLE[c]
    digits = [str(x) for x in digits]
    digits.insert(4, "-")
    digits.insert(8, "-")

    return "".join(digits)


def generate_initial_state(vendor_id, product_id, product_name, random_source):
    if vendor_id != 0xFFF4 or product_id != 0x1234:
        raise ValueError("Invalid vendor_id or product_id")

    cd = generate_certificates(vendor_id=vendor_id, product_id=product_id)

    dac_cert, dac_key = generate_dac(vendor_id, product_id, product_name, random_source)

    passcode = 0
    while passcode in INVALID_PASSCODES:
        passcode = random_source.randbelow(99999999)
    discriminator = random_source.randbelow(1 << 12)  # A 12-bit random number
    iteration_count = 10000
    salt = random_source.urandom(32)
    verifier = compute_verifier(passcode, salt, iteration_count)
    # This does *NOT* follow the spec because the passcode is stored alongside the verifier.
    # The spec wants the passcode stored physically on the box and package of the device in
    # the setup code and QR Code. The verifier is in the device only.
    initial_state = {
        "discriminator": discriminator,
        "passcode": passcode,
        "manual_code": compute_manual_code(discriminator, passcode),
        "iteration-count": iteration_count,
        "salt": binascii.b2a_base64(salt, newline=False).decode("utf-8"),
        "verifier": binascii.b2a_base64(verifier, newline=False).decode("utf-8"),
        "devices": {
            "root": {
                "0x3e": {
                    "cd": binascii.b2a_base64(cd, newline=False).decode("utf-8"),
                    "dac_cert": binascii.b2a_base64(dac_cert, newline=False).decode(
                        "utf-8"
                    ),
                    "dac_key": binascii.b2a_base64(dac_key, newline=False).decode(
                        "utf-8"
                    ),
                }
            },
        },
    }
    return initial_state


if __name__ == "__main__":
    from circuitmatter.utility import random

    initial_state = generate_initial_state(0xFFF4, 0x1234, "CircuitMatter", random)
    print(initial_state)
